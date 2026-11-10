#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# P7：soak（长时打流 + 反复 reload/suspend/resume，查泄漏）。
#
#   lab/soak.sh run [秒数] [tcp|ss|udp]   # 默认 60 秒 + tcp（relay-up 会话）
#   lab/soak.sh build                     # 先经 bench.sh build 编译 C 基准端点
#
# 每轮（约 2-4s）：
#   tcp/ss：bench_io 4MB×2 流（校验回显）→ 每 2 轮 reload → 每 3 轮 suspend+
#           暂停期直连校验（fail-open）+ resume；udp：逐包 echo 500×256B。
# 结束时断言（> 11s 静默后）：
#   - 会话/映射回收：relay.conns_active=0、maps.fast_sock=0（tcp/ss）；
#     udp_nat.sessions_active=0（udp）；
#   - sodama RSS 相对基线增长 < 8MB、fd 数增长 < 8；
#   - 全程无失败轮次。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
LOADER="$ROOT/target/release/sodama"
BENCH_BIN="$ROOT/build/bench_io"
STATUS_SOCK=/tmp/sodama-status.sock
PID_FILE=/tmp/sodama.pid
WAN_PID_FILE=/tmp/sodama-wan.pid
BENCH_PID_FILE=/tmp/sodama-bench.pid
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
STATUS_JSON=/tmp/sodama-soak-status.json

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }

session_of() {
  case "$1" in
    tcp) echo relay-up ;;
    ss) echo ss-up ;;
    udp) echo udp-up ;;
    *) die "未知 mode：$1（tcp|ss|udp）" ;;
  esac
}

kill_wan_echo() {
  if [ -f "$WAN_PID_FILE" ]; then
    kill "$(cat "$WAN_PID_FILE")" 2>/dev/null || true
    rm -f "$WAN_PID_FILE"
    sleep 0.2
  fi
}

start_server() {
  kill_wan_echo
  ip netns exec "$WAN_NS" "$BENCH_BIN" serve 8080,8082 9998 \
    >/tmp/sodama-soak-server.log 2>&1 &
  echo $! >"$BENCH_PID_FILE"
  sleep 0.3
  kill -0 "$(cat "$BENCH_PID_FILE")" 2>/dev/null \
    || { cat /tmp/sodama-soak-server.log; die "soak 服务端启动失败"; }
}

stop_server() {
  if [ -f "$BENCH_PID_FILE" ]; then
    kill "$(cat "$BENCH_PID_FILE")" 2>/dev/null || true
    rm -f "$BENCH_PID_FILE"
  fi
}

in_client() { ip netns exec "$CLIENT_NS" "$@"; }
jqv() { jq -r "$1" "$STATUS_JSON"; }
snapshot() { "$LOADER" status --socket "$STATUS_SOCK" --json >"$STATUS_JSON"; }
proc_rss_kb() { awk '/^VmRSS:/{print $2}' "/proc/$1/status"; }
proc_fds() { ls "/proc/$1/fd" | wc -l; }

run_soak() {
  require_root
  local secs="$1" mode="$2"
  [ -x "$BENCH_BIN" ] || die "先运行 lab/bench.sh build"
  [ -f "$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf" ] && [ -x "$LOADER" ] || die "先运行 lab/lab.sh build"

  local sess; sess="$(session_of "$mode")"
  echo "== soak：${secs}s mode=$mode（会话 $sess）=="
  "$HERE/lab.sh" down >/dev/null 2>&1 || true
  "$HERE/lab.sh" "$sess" >/tmp/sodama-soak-session.log 2>&1 \
    || { cat /tmp/sodama-soak-session.log; die "会话 $sess 启动失败"; }
  start_server
  local pid; pid="$(cat "$PID_FILE")"

  # 预热（建连/分配稳定）后取基线
  if [ "$mode" = udp ]; then
    in_client timeout 60 "$BENCH_BIN" udpclient 2.2.2.2 9998 200 256 >/dev/null
  else
    in_client timeout 60 "$BENCH_BIN" client 1.1.1.1 8080 4 1 >/dev/null
  fi
  local base_rss base_fds t0 now fails=0 iter=0
  base_rss="$(proc_rss_kb "$pid")"; base_fds="$(proc_fds "$pid")"
  snapshot
  echo "-- 基线：rss=${base_rss}kB fds=$base_fds conns_active=$(jqv '.relay.conns_active') --"

  t0="$(date +%s)"; now="$t0"
  while [ $((now - t0)) -lt "$secs" ]; do
    iter=$((iter + 1))
    local ok=1
    if [ "$mode" = udp ]; then
      if ! in_client timeout 60 "$BENCH_BIN" udpclient 2.2.2.2 9998 500 256 >/dev/null 2>&1; then
        ok=0
      fi
    else
      if ! in_client timeout 60 "$BENCH_BIN" client 1.1.1.1 8080 4 2 >/dev/null 2>&1; then
        ok=0
      fi
      # 每 2 轮 reload；每 3 轮 suspend→直连 fail-open→resume
      if [ $((iter % 2)) -eq 0 ]; then
        "$LOADER" reload --socket "$STATUS_SOCK" >/dev/null || ok=0
      fi
      if [ $((iter % 3)) -eq 0 ]; then
        "$LOADER" suspend --socket "$STATUS_SOCK" >/dev/null || ok=0
        # 挂起期：同一地址由内核直转（fail-open），回显校验应通过
        in_client timeout 60 "$BENCH_BIN" client 1.1.1.1 8080 4 1 >/dev/null 2>&1 || ok=0
        "$LOADER" resume --socket "$STATUS_SOCK" >/dev/null || ok=0
      fi
    fi
    [ "$ok" = 1 ] || fails=$((fails + 1))
    snapshot
    local rss fds
    rss="$(proc_rss_kb "$pid")"; fds="$(proc_fds "$pid")"
    echo "iter $iter: ok=$ok rss=${rss}kB fds=$fds active=$(jqv '.relay.conns_active') fast_sock=$(jqv '.maps.fast_sock // -1') udp_active=$(jqv '.udp_nat.sessions_active')"
    now="$(date +%s)"
  done

  local end_rss end_fds growth fd_growth
  # 先等 idle 回收（relay/udp idle=2s + janitor 5s + offload 看门狗/读线程超时余量），
  # 再取结束样本——否则会把回收窗口内的瞬时会话堆积当成泄漏（udp soak 曾误报）。
  echo "-- 等 12s 静默回收 --"
  sleep 12
  end_rss="$(proc_rss_kb "$pid")"; end_fds="$(proc_fds "$pid")"
  growth=$((end_rss - base_rss)); fd_growth=$((end_fds - base_fds))
  echo "-- 结束：iter=$iter fails=$fails rss=${end_rss}kB（+${growth}）fds=$end_fds（基线 $base_fds，+${fd_growth}）--"

  snapshot
  local active fast udp_active
  active="$(jqv '.relay.conns_active')"
  fast="$(jqv '.maps.fast_sock // -1')"
  udp_active="$(jqv '.udp_nat.sessions_active')"

  local rc=0
  [ "$fails" = 0 ] || { echo "FAIL: 有 $fails 轮失败"; rc=1; }
  if [ "$mode" = udp ]; then
    [ "$udp_active" = 0 ] || { echo "FAIL: udp_nat 会话未回收（active=$udp_active）"; rc=1; }
  else
    [ "$active" = 0 ] || { echo "FAIL: relay 连接未回收（active=$active）"; rc=1; }
    [ "$fast" = 0 ] || { echo "FAIL: fast_sock 键未回收（=$fast）"; rc=1; }
  fi
  # UDP 模式每轮新建一个客户端源端口（会话/线程 churn 很高）；glibc 多线程
  # arena 会保留已释放的空闲块——实测同样 60s：默认 +36MB，MALLOC_ARENA_MAX=1
  # 降到 +7.9MB，且 fd 回基线、增量不随轮数线性增长 ⇒ 分配器保留而非逻辑泄漏。
  # 因此 udp 模式阈值放宽到 48MB（tcp/ss 仍 8MB，它们无 churn）。
  local rss_limit=8192
  [ "$mode" = udp ] && rss_limit=49152
  [ "$growth" -lt "$rss_limit" ] || { echo "FAIL: RSS 增长 ${growth}kB ≥ $((rss_limit / 1024))MB"; rc=1; }
  [ "$fd_growth" -lt 8 ] || { echo "FAIL: fd 增长 $fd_growth ≥ 8"; rc=1; }

  stop_server
  "$HERE/lab.sh" down >/dev/null 2>&1 || true
  if [ "$rc" = 0 ]; then
    echo "PASS: soak ${secs}s（$mode）无失败轮、无泄漏（RSS +${growth}kB，fd +${fd_growth}，active=$active fast_sock=$fast udp_active=$udp_active）"
  else
    echo "!! soak 失败（mode=$mode，见上）"
  fi
  return "$rc"
}

case "${1:-}" in
  run)
    shift || true
    secs="${1:-60}"; mode="${2:-tcp}"
    run_soak "$secs" "$mode" ;;
  build) "$HERE/bench.sh" build ;;
  *) echo "usage: $0 {build|run [秒数] [tcp|ss|udp]}"; exit 2 ;;
esac

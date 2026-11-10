#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# M4 连接规模/风暴基准：客户端（client ns）→ sodama relay（direct/splice 路径）→ epoll 回显。
#
# 用法：
#   sudo lab/scale/run.sh build                          # 编译夹具
#   sudo lab/scale/run.sh hold <n> <秒>                  # 并发持有 n 条（ping 验证后保持）
#   sudo lab/scale/run.sh churn <秒>                     # 限时连接风暴（conn/s）
#   sudo lab/scale/run.sh all                            # 1000/5000/10000 持有 + 风暴
# 环境：SODAMA_ARGS（透传 loader，如 --no-reactor）、OUT=/tmp/scale.tsv
# 输出：OUT 每行 `mode n_ok rss_kb threads setup_s conn_per_s`（RSS/线程为峰值）。
set -euo pipefail
ulimit -n 1048576 2>/dev/null || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"
LAB="$ROOT/lab/lab.sh"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
DIR=/tmp/scale-lab
OUT="${OUT:-/tmp/scale.tsv}"
PID_FILE=/tmp/scale-sodama.pid

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
in_wan() { ip netns exec "$WAN_NS" "$@"; }

build() {
  mkdir -p "$DIR" "$ROOT/build"
  gcc -O2 -Wall -o "$ROOT/build/echo_server" "$HERE/echo_server.c" -lpthread
  gcc -O2 -Wall -pthread -o "$ROOT/build/conn_scale" "$HERE/conn_scale.c"
  echo "== 夹具已编译：$ROOT/build/{echo_server,conn_scale} =="
}

prepare() {
  require_root
  mkdir -p "$DIR"
  [ -x "$ROOT/build/echo_server" ] || build
  "$LAB" down >/dev/null 2>&1 || true
  # 清理旧进程
  for p in $(pgrep -x sodama); do kill -9 "$p" 2>/dev/null || true; done
  for p in $(pgrep -x echo_server); do kill -9 "$p" 2>/dev/null || true; done
  TOPO_ONLY=1 "$LAB" up >/dev/null
  # client ns 端口回收加速（连接风暴；sodama 上游拨号在 host ns，同样需要）
  in_client sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  in_wan bash -c "ulimit -n 1048576; exec \"$ROOT/build/echo_server\" 8080" >"$DIR/echo.log" 2>&1 &
  echo $! >"$DIR/echo.pid"
  # sodama：direct 拨号 + 1.1.1.1→proxy（splice 路径）
  bash -c "ulimit -n 1048576; exec \"$LOADER\" --ebpf \"$OBJ\" --lan landae --wan wan \
    --dae0 dae0 --dae0peer dae0peer --daens sodamans \
    --rules \"$HERE/rules.dae\" --dialer direct --relay-idle-timeout 600 \
    --status-socket /tmp/sodama-status.sock ${SODAMA_ARGS:-} >\"$DIR/sodama.log\" 2>&1" &
  echo $! >"$PID_FILE"
  sleep 2.0
  kill -0 "$(cat "$PID_FILE")" || { tail -20 "$DIR/sodama.log"; die "sodama 启动失败"; }
  in_wan timeout 3 bash -c ": >/dev/tcp/1.1.1.1/8080" || die "回显未就绪"
  echo "== 规模夹具就绪（echo:1.1.1.1:8080，sodama relay direct${SODAMA_ARGS:+ [$SODAMA_ARGS]}） =="
}

# 采样 sodama RSS/线程峰值（后台，200ms）
start_sampler() {
  : >"$DIR/samples"
  ( while kill -0 "$(cat "$PID_FILE")" 2>/dev/null; do
      pid="$(cat "$PID_FILE")"
      rss="$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
      thr="$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
      echo "$rss $thr" >>"$DIR/samples"
      sleep 0.2
    done ) &
  echo $! >"$DIR/sampler.pid"
}

stop_sampler() {
  [ -f "$DIR/sampler.pid" ] && { kill "$(cat "$DIR/sampler.pid")" 2>/dev/null || true; rm -f "$DIR/sampler.pid"; }
}

peak() { # <col>
  awk -v c="$1" 'BEGIN{m=0} {v=$c+0; if(v>m)m=v} END{print m}' "$DIR/samples" 2>/dev/null || echo 0
}

run_hold() {
  local n="$1" secs="$2" line ok fail setup sps rss thr
  start_sampler
  line="$(in_client timeout $((secs + n / 50 + 120)) "$ROOT/build/conn_scale" hold 1.1.1.1 8080 "$n" "$secs" 2>"$DIR/client.log" | tail -1)" \
    || { stop_sampler; echo "!! hold n=$n 失败"; tail -5 "$DIR/client.log"; return 1; }
  stop_sampler
  ok="$(echo "$line" | sed -n 's/.*ok=\([0-9]*\).*/\1/p')"
  fail="$(echo "$line" | sed -n 's/.*fail=\([0-9]*\).*/\1/p')"
  setup="$(echo "$line" | sed -n 's/.*setup_s=\([0-9.]*\).*/\1/p')"
  sps="$(awk -v n="$ok" -v s="$setup" 'BEGIN{printf "%.0f", (s>0? n/s : 0)}')"
  rss="$(peak 1)"; thr="$(peak 2)"
  printf 'hold\t%s\t%s\t%s\t%s\t%s\n' "$ok" "$rss" "$thr" "$setup" "$sps" | tee -a "$OUT"
  echo "   hold n=$n ok=$ok fail=$fail setup=${setup}s(${sps}/s) peak_rss=${rss}KB peak_threads=$thr"
}

run_churn() {
  local secs="$1" line conns wall cps rss thr
  start_sampler
  line="$(in_client timeout $((secs + 60)) "$ROOT/build/conn_scale" churn 1.1.1.1 8080 "$secs" 2>"$DIR/client.log" | tail -1)" \
    || { stop_sampler; echo "!! churn 失败"; tail -5 "$DIR/client.log"; return 1; }
  stop_sampler
  conns="$(echo "$line" | sed -n 's/.*conns=\([0-9]*\).*/\1/p')"
  wall="$(echo "$line" | sed -n 's/.*wall_s=\([0-9.]*\).*/\1/p')"
  cps="$(echo "$line" | sed -n 's/.*conn_per_s=\([0-9]*\).*/\1/p')"
  rss="$(peak 1)"; thr="$(peak 2)"
  printf 'churn\t%s\t%s\t%s\t%s\t%s\n' "$conns" "$rss" "$thr" "$wall" "$cps" | tee -a "$OUT"
  echo "   churn ${secs}s conns=$conns wall=${wall}s（${cps}/s）peak_rss=${rss}KB peak_threads=$thr"
}

down() {
  require_root
  stop_sampler
  for p in $(cat "$PID_FILE" 2>/dev/null) $(cat "$DIR/echo.pid" 2>/dev/null); do
    kill -9 "$p" 2>/dev/null || true
  done
  for p in $(pgrep -x sodama) $(pgrep -x echo_server); do kill -9 "$p" 2>/dev/null || true; done
  "$LAB" down >/dev/null 2>&1 || true
  echo "== 已清理 =="
}

case "${1:-}" in
  build) build ;;
  prepare) prepare ;;
  hold) prepare; run_hold "${2:?n}" "${3:?秒}" ;;
  churn) prepare; run_churn "${2:?秒}" ;;
  all)
    : >"$OUT"
    prepare
    run_hold 1000 5
    run_hold 5000 5
    run_hold 10000 5
    run_churn 10
    ;;
  down) down ;;
  *) die "usage: $0 {build|prepare|hold <n> <secs>|churn <secs>|all|down}" ;;
esac

#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# 内存终测：五方（sodama / dae / sing-box / v2ray / mihomo[Clash Verge 内核]）同拓扑内存足迹对比。
#
# 拓扑（复用 run.sh）：client ns — 网关（被测实现）— WAN ns（bench_io 全双工 echo + VLESS 上游）。
# 阶段：idle 3s → 吞吐（vless 4×MEM_MB）→ hold HOLD_N 连接 → churn CHURN_SECS → 静置 RECOVER_SECS
# 指标：每阶段 RSS/线程/fd 峰值（200ms 采样）+ 静置后 RSS（回收线）。
#
# 用法：
#   sudo lab/perf/mem.sh prepare
#   sudo lab/perf/mem.sh bench sodama|dae|singbox|v2ray|mihomo
#   sudo lab/perf/mem.sh all
#   sudo lab/perf/mem.sh down
#
# 环境：
#   MEM_MB=128 MEM_STREAMS=4 HOLD_N=2000 HOLD_SECS=10 CHURN_SECS=10 RECOVER_SECS=30
#   RESULTS=/tmp/mem-results.tsv  DAE_BIN/SINGBOX_BIN/V2RAY_BIN/MIHOMO_BIN
set -euo pipefail
ulimit -n 1048576 2>/dev/null || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"
LAB="$ROOT/lab/lab.sh"
RUN="$HERE/run.sh"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
BENCH_BIN="$ROOT/build/bench_io"
CONN_SCALE="$ROOT/build/conn_scale"
DAE_BIN="${DAE_BIN:-/tmp/perf/usr/bin/dae}"
SINGBOX_BIN="${SINGBOX_BIN:-sing-box}"
V2RAY_BIN="${V2RAY_BIN:-v2ray}"
MIHOMO_BIN="${MIHOMO_BIN:-mihomo}"
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
VLESS_UUID=b831381d-6324-4d53-ad4f-8cda48b30811

MEM_MB="${MEM_MB:-128}"
MEM_STREAMS="${MEM_STREAMS:-4}"
HOLD_N="${HOLD_N:-2000}"
HOLD_SECS="${HOLD_SECS:-10}"
CHURN_SECS="${CHURN_SECS:-10}"
RECOVER_SECS="${RECOVER_SECS:-30}"
RESULTS="${RESULTS:-/tmp/mem-results.tsv}"

MEMDIR=/tmp/mem-lab
SAMPLES="$MEMDIR/samples"
IMPL_PID_FILE="$MEMDIR/impl.pid"
SAMPLER_PID="$MEMDIR/sampler.pid"
SAMPLER_STOP="$MEMDIR/sampler.stop"

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }

build_tools() {
  mkdir -p "$MEMDIR" "$ROOT/build"
  [ -x "$BENCH_BIN" ] || gcc -O2 -Wall -Wextra -pthread -o "$BENCH_BIN" "$ROOT/lab/bench_io.c"
  if [ ! -x "$CONN_SCALE" ]; then
    gcc -O2 -Wall -pthread -o "$CONN_SCALE" "$ROOT/lab/scale/conn_scale.c"
  fi
}

prepare() {
  require_root
  build_tools
  "$RUN" prepare
  # 连接风暴/持有：放宽端口回收（scale/run.sh 同口径）
  in_client sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  echo "== 内存终测拓扑就绪（vless 上游 :8543 / echo 1.1.1.1:8080）=="
}

# ---------------------------------------------------------------- tproxy（sing-box/v2ray/mihomo）

nft_add() {
  local port="$1"
  nft delete table inet perfproxy 2>/dev/null || true
  nft add table inet perfproxy
  nft "add chain inet perfproxy prerouting { type filter hook prerouting priority mangle; }"
  nft add rule inet perfproxy prerouting iifname landae ip protocol tcp meta mark set 1 tproxy ip to ":$port"
  ip rule add fwmark 1 lookup 100 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
}

nft_del() {
  nft delete table inet perfproxy 2>/dev/null || true
  ip rule del fwmark 1 lookup 100 2>/dev/null || true
  ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
}

impl_env_cleanup() {
  nft_del
  ip netns del dae 2>/dev/null || true
  ip netns del daed 2>/dev/null || true
}

start_impl() {
  local impl="$1" pid
  local sodama_dialer="vless://$VLESS_UUID@10.9.9.2:8543?type=tcp&security=none"
  case "$impl" in
  sodama)
    [ -x "$LOADER" ] && [ -f "$OBJ" ] || die "先构建 sodama（lab.sh build + cargo build --release）"
    # shellcheck disable=SC2086
    "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
      --dae0 dae0 --dae0peer dae0peer --daens sodamans \
      --rules "$HERE/rules.perf.dae" --dialer "$sodama_dialer" \
      --status-socket /tmp/sodama-status.sock ${SODAMA_ARGS:-} >/tmp/mem-sodama.log 2>&1 &
    pid=$!
    ;;
  dae)
    [ -x "$DAE_BIN" ] || die "缺 dae（DAE_BIN=$DAE_BIN）"
    chmod 640 "$HERE/dae.vless.dae" 2>/dev/null || true
    "$DAE_BIN" run --config "$HERE/dae.vless.dae" --disable-pidfile >/tmp/mem-dae.log 2>&1 &
    pid=$!
    ;;
  singbox)
    command -v "$SINGBOX_BIN" >/dev/null || die "缺 sing-box"
    nft_add 7895
    "$SINGBOX_BIN" run -c "$HERE/singbox.vless.json" >/tmp/mem-singbox.log 2>&1 &
    pid=$!
    ;;
  v2ray)
    command -v "$V2RAY_BIN" >/dev/null || die "缺 v2ray"
    nft_add 7896
    "$V2RAY_BIN" run -c "$HERE/v2ray.vless.json" >/tmp/mem-v2ray.log 2>&1 &
    pid=$!
    ;;
  mihomo)
    command -v "$MIHOMO_BIN" >/dev/null || die "缺 mihomo（Clash Verge 内核）"
    mkdir -p "$MEMDIR/mihomo"
    nft_add 7897
    "$MIHOMO_BIN" -d "$MEMDIR/mihomo" -f "$HERE/mihomo.vless.yaml" >/tmp/mem-mihomo.log 2>&1 &
    pid=$!
    ;;
  *) die "未知实现：$impl" ;;
  esac
  echo "$pid" >"$IMPL_PID_FILE"
  sleep 3
  kill -0 "$pid" 2>/dev/null || { tail -20 "/tmp/mem-$impl.log" 2>/dev/null; die "$impl 启动失败"; }
  echo "== $impl 运行中（pid $pid）=="
}

stop_impl() {
  if [ -f "$IMPL_PID_FILE" ]; then
    local pid
    pid="$(cat "$IMPL_PID_FILE")"
    kill "$pid" 2>/dev/null || true
    sleep 1.0
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$IMPL_PID_FILE"
  fi
  impl_env_cleanup
}

# ---------------------------------------------------------------- 采样器

start_sampler() {
  : >"$SAMPLES"
  rm -f "$SAMPLER_STOP"
  (
    while [ ! -f "$SAMPLER_STOP" ]; do
      local pid rss thr fds
      pid="$(cat "$IMPL_PID_FILE" 2>/dev/null || true)"
      if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
        rss="$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
        thr="$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
        fds="$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)"
        printf '%s %s %s\n' "${rss:-0}" "${thr:-0}" "$fds" >>"$SAMPLES"
      fi
      sleep 0.2
    done
  ) &
  echo $! >"$SAMPLER_PID"
}

stop_sampler() {
  touch "$SAMPLER_STOP"
  sleep 0.4
  kill "$(cat "$SAMPLER_PID" 2>/dev/null)" 2>/dev/null || true
}

mark() { sleep 0.3; printf 'M %s\n' "$1" >>"$SAMPLES"; sleep 0.3; }
read_now() { # -> "rss thr fds"
  local pid; pid="$(cat "$IMPL_PID_FILE" 2>/dev/null || true)"
  if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
    awk -v fds="$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)" \
      '/^VmRSS:/{r=$2} /^Threads:/{t=$2} END{printf "%s %s %s", (r?r:0), (t?t:0), fds}' "/proc/$pid/status"
  else
    echo "0 0 0"
  fi
}

# ---------------------------------------------------------------- 阶段

run_phases() {
  local impl="$1"
  start_sampler
  mark idle
  sleep 3
  mark load
  in_client timeout 300 "$BENCH_BIN" client 1.1.1.1 8080 "$MEM_MB" "$MEM_STREAMS" >"$MEMDIR/load.log" 2>&1 || true
  sleep 0.5
  mark hold
  in_client timeout $((HOLD_SECS + HOLD_N / 50 + 180)) "$CONN_SCALE" hold 1.1.1.1 8080 "$HOLD_N" "$HOLD_SECS" \
    >"$MEMDIR/hold.log" 2>&1 || true
  sleep 0.5
  mark churn
  in_client timeout $((CHURN_SECS + 90)) "$CONN_SCALE" churn 1.1.1.1 8080 "$CHURN_SECS" \
    >"$MEMDIR/churn.log" 2>&1 || true
  mark recovery
  sleep "$RECOVER_SECS"
  local now; now="$(read_now)"
  stop_sampler
  # 解析各阶段峰值 → TSV
  python3 - "$SAMPLES" "$impl" "$now" "$RESULTS" <<'PY'
import sys
samples, impl, now, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
phases = ["idle", "load", "hold", "churn"]
cur = None
peak = {p: [0, 0, 0] for p in phases}
with open(samples) as f:
    for line in f:
        if line.startswith("M "):
            cur = line[2:].strip()
            continue
        if cur not in peak:
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            vals = [int(x) for x in parts]
        except ValueError:
            continue
        for i, v in enumerate(vals):
            if v > peak[cur][i]:
                peak[cur][i] = v
lines = []
for p in phases:
    rss, thr, fds = peak[p]
    lines.append(f"{impl}\t{p}\t{rss}\t{thr}\t{fds}")
rss, thr, fds = now.split()
lines.append(f"{impl}\trecovery\t{rss}\t{thr}\t{fds}")
with open(out, "a") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
}

bench_impl() {
  local impl="$1"
  require_root
  prepare
  start_impl "$impl"
  run_phases "$impl"
  # 连通性/阶段日志快检
  grep -q '^tcp-ok' "$MEMDIR/load.log" 2>/dev/null || echo "  警告：[$impl] 吞吐阶段未见 tcp-ok：$(tail -1 "$MEMDIR/load.log" 2>/dev/null)"
  grep -q '^hold ok=' "$MEMDIR/hold.log" 2>/dev/null && echo "  hold: $(cat "$MEMDIR/hold.log")" || echo "  警告：[$impl] hold 失败：$(tail -1 "$MEMDIR/hold.log" 2>/dev/null)"
  grep -q '^churn conns=' "$MEMDIR/churn.log" 2>/dev/null && echo "  churn: $(cat "$MEMDIR/churn.log")" || echo "  警告：[$impl] churn 失败：$(tail -1 "$MEMDIR/churn.log" 2>/dev/null)"
  stop_impl
  echo "== $impl 完成 =="
}

summarize() {
  echo
  echo "== 汇总：RSS / 线程 / fd（峰值；recovery 为静置 ${RECOVER_SECS}s 后）=="
  python3 - "$RESULTS" <<'PY'
import sys, collections
rows = collections.OrderedDict()
for line in open(sys.argv[1]):
    p = line.rstrip("\n").split("\t")
    if len(p) != 5:
        continue
    rows.setdefault(p[0], []).append(p[1:])
order = ["idle", "load", "hold", "churn", "recovery"]
print(f"{'impl':10} {'phase':9} {'RSS_MB':>8} {'threads':>8} {'fds':>6}")
for impl, rs in rows.items():
    for phase in order:
        for r in rs:
            if r[0] == phase:
                print(f"{impl:10} {phase:9} {int(r[1])/1024:8.1f} {r[2]:>8} {r[3]:>6}")
PY
}

down() {
  require_root
  stop_sampler 2>/dev/null || true
  stop_impl || true
  for p in $(pgrep -x mihomo) $(pgrep -x sing-box) $(pgrep -x v2ray) $(pgrep -x sodama); do
    kill -9 "$p" 2>/dev/null || true
  done
  rm -f "$SAMPLER_STOP"
  "$RUN" down >/dev/null 2>&1 || true
  echo "== 已清理 =="
}

case "${1:-}" in
prepare) prepare ;;
bench)
  shift
  : >"$RESULTS"
  bench_impl "${1:?impl}"
  summarize
  ;;
all)
  : >"$RESULTS"
  for impl in sodama dae singbox v2ray mihomo; do
    bench_impl "$impl" || echo "!! $impl 跳过"
  done
  summarize
  ;;
down) down ;;
*)
  sed -n '2,18p' "$0"
  exit 2
  ;;
esac

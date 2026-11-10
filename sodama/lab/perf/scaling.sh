#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# sodama 扩展性/效率测量：并发流 1/2/4/8（大流量）+ 64（小流量，看每连接内存/线程）。
# 路径：direct（eBPF 直转）、ss（Rust ss + 用户态泵）、relay（无加密用户态泵）。
# 前置：先跑 `sudo PROXY_PROTO=vless lab/perf/run.sh prepare`（默认 vless；建拓扑 + WAN 侧服务）。
# 用法：sudo lab/perf/scaling.sh [direct|ss|relay|all]
# 输出：OUT=/tmp/scaling.tsv（path/streams/MB/mbps/p50_us/cpu_ms/rss_kb/threads）
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SODAMA="$(dirname "$(dirname "$HERE")")"
LOADER="$SODAMA/target/release/sodama"
OBJ="$SODAMA/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
BENCH_BIN="$SODAMA/build/bench_io"
CLIENT_NS=sodama_client
OUT="${OUT:-/tmp/scaling.tsv}"
IMPL_PID=/tmp/perf-impl.pid

export BENCH_NOSHUT=1
MB="${MB:-64}"        # 大流量每流 MB
SMALL_MB="${SMALL_MB:-1}"  # 64 流小流量每流 MB

die() { echo "!! $*" >&2; exit 1; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
kv() { echo "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2; exit}'; }
cpu_ms() { sed 's/^.*) //' "/proc/$1/stat" | awk -v hz="$(getconf CLK_TCK)" '{printf "%.1f", (($12+$13)*1000.0)/hz}'; }
rss_kb() { awk '/^VmRSS:/{print $2}' "/proc/$1/status"; }
thr() { awk '/^Threads:/{print $2}' "/proc/$1/status"; }

start_loader() { # <dialer>
  # SODAMA_ARGS：附加参数（如 M2 kTLS 实验：SODAMA_ARGS=--ktls）
  # shellcheck disable=SC2086
  "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
    --dae0 dae0 --dae0peer dae0peer --daens sodamans \
    --rules "$HERE/rules.perf.dae" --dialer "$1" \
    --status-socket /tmp/sodama-status.sock ${SODAMA_ARGS:-} >/tmp/scaling-sodama.log 2>&1 &
  echo $! >"$IMPL_PID"
  sleep 2.5
  kill -0 "$(cat "$IMPL_PID")" 2>/dev/null || { tail -10 /tmp/scaling-sodama.log; die "loader 启动失败"; }
}

stop_loader() {
  [ -f "$IMPL_PID" ] && { kill "$(cat "$IMPL_PID")" 2>/dev/null || true; sleep 0.8; }
  rm -f "$IMPL_PID"
}

# row <path> <streams> <mb> <host> <port>
row() {
  local path="$1" streams="$2" mb="$3" host="$4" port="$5"
  local pid; pid="$(cat "$IMPL_PID")"
  local c0 c1 out lat mbps p50
  c0="$(cpu_ms "$pid")"
  out="$(in_client timeout 300 "$BENCH_BIN" client "$host" "$port" "$mb" "$streams" 2>&1 || true)"
  lat="$(in_client timeout 120 "$BENCH_BIN" lat "$host" "$port" 200 2>&1 || true)"
  c1="$(cpu_ms "$pid")"
  echo "$out" | grep -q '^tcp-ok' || die "[$path s=$streams] client: $out"
  mbps="$(kv "$out" oneway_mbps)"; p50="$(kv "$lat" p50_us)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$streams" "$mb" "$mbps" "$p50" \
    "$(awk -v a="$c0" -v b="$c1" 'BEGIN{printf "%.1f", b-a}')" "$(rss_kb "$pid")" "$(thr "$pid")" \
    | tee -a "$OUT"
}

measure() { # <path> <dialer> <host> <port>
  local path="$1" dialer="$2" host="$3" port="$4" s
  start_loader "$dialer"
  # 预热
  in_client timeout 120 "$BENCH_BIN" client "$host" "$port" 8 1 >/dev/null 2>&1 || true
  for s in 1 2 4 8; do row "$path" "$s" "$MB" "$host" "$port"; done
  row "$path" 64 "$SMALL_MB" "$host" "$port"
  stop_loader
}

# 代理路径拨号器（PROXY_PROTO 选择，与 run.sh 对齐；默认 vless；先跑 run.sh prepare 建拓扑）
VLESS_UUID=b831381d-6324-4d53-ad4f-8cda48b30811
PROXY_PROTO="${PROXY_PROTO:-vless}"
case "$PROXY_PROTO" in
  ss) PROXY_DIALER='ss://chacha20-ietf-poly1305:testpass@10.9.9.2:8388' ;;
  vless) PROXY_DIALER="vless://$VLESS_UUID@10.9.9.2:8543?type=tcp&security=none" ;;
  vless-tls) PROXY_DIALER="vless://$VLESS_UUID@10.9.9.2:8544?type=tcp&security=tls&sni=localhost&allowinsecure=1" ;;
  *) echo "!! PROXY_PROTO=$PROXY_PROTO 未知（ss|vless|vless-tls）" >&2; exit 1 ;;
esac

case "${1:-all}" in
  direct) measure direct "$PROXY_DIALER" 10.9.9.2 9999 ;;
  ss | vless | vless-tls) measure "$PROXY_PROTO" "$PROXY_DIALER" 1.1.1.1 8080 ;;
  relay) measure relay direct 1.1.1.1 8080 ;;
  all)
    : >"$OUT"
    measure direct "$PROXY_DIALER" 10.9.9.2 9999
    measure "$PROXY_PROTO" "$PROXY_DIALER" 1.1.1.1 8080
    measure relay direct 1.1.1.1 8080
    ;;
  *) die "usage: $0 [direct|ss|vless|vless-tls|relay|all]" ;;
esac
echo "== 写入 $OUT =="

#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# O7：UDP 批量收发基准（sodama 批/非批 A/B + 同机四方对拍）。
#
# 拓扑与 lab/perf/run.sh 相同（client ns — 网关 — WAN ns）；WAN 侧 bench_io 的
# UDP echo（端口 9998），上游为 ssserver（-u，与 TCP 轮同方法）。
# 代理目标 1.1.1.1:9998（规则 → proxy），直连基线 10.9.9.2:9998。
#
# 用法：
#   sudo lab/perf/udp.sh build
#   sudo lab/perf/udp.sh prepare
#   sudo lab/perf/udp.sh bench sodama            # 默认批（SODAMA_UDP_BATCH 未设）
#   sudo lab/perf/udp.sh bench sodama-nobatch    # 逐包对照（SODAMA_UDP_BATCH=0）
#   sudo lab/perf/udp.sh bench dae|singbox|v2ray
#   sudo lab/perf/udp.sh direct                  # 无实现时的直连基线
#   sudo lab/perf/udp.sh all
#   sudo lab/perf/udp.sh down
#
# 环境：
#   UDP_COUNT=20000 UDP_SIZE=256 ROUNDS=3
#   SS_METHOD=chacha20-ietf-poly1305（可用 aes-256-gcm 复测）
#   DAE_BIN=/path/to/dae（默认 /tmp/perf/usr/bin/dae，官方 v2.1.1 预编译；
#   本地构建版 dae/dae 在 6.18 内核上验证器拒绝加载，仅作源码参考）
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"
LAB="$ROOT/lab/lab.sh"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
BENCH_BIN="$ROOT/build/bench_io"
DAE_BIN="${DAE_BIN:-/tmp/perf/usr/bin/dae}"
SINGBOX_BIN="${SINGBOX_BIN:-sing-box}"
V2RAY_BIN="${V2RAY_BIN:-v2ray}"
MIHOMO_BIN="${MIHOMO_BIN:-mihomo}"
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
UDP_ECHO_PORT=9998
SS_PORT=8388
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
UDP_COUNT="${UDP_COUNT:-40000}"
UDP_SIZE="${UDP_SIZE:-256}"
# 限速发送（固定 PPS，可持续对拍）；0 = 不限速突发。
UDP_PPS="${UDP_PPS:-20000}"
ROUNDS="${ROUNDS:-3}"
PROXY_TARGET="1.1.1.1:$UDP_ECHO_PORT"
DIRECT_TARGET="10.9.9.2:$UDP_ECHO_PORT"
RESULTS="${RESULTS:-/tmp/perf-udp.tsv}"
IMPL_PID_FILE=/tmp/perf-udp-impl.pid
SS_PID_FILE=/tmp/perf-udp-ss.pid

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
proc_cpu_ms() { sed 's/^.*) //' "/proc/$1/stat" | awk -v hz="$(getconf CLK_TCK)" '{printf "%.1f", (($12+$13)*1000.0)/hz}'; }

build() {
  gcc -O2 -Wall -Wextra -pthread -o "$BENCH_BIN" "$ROOT/lab/bench_io.c"
  echo "== bench_io 就绪：$BENCH_BIN =="
}

stop_wan_servers() {
  [ -f "$SS_PID_FILE" ] && kill "$(cat "$SS_PID_FILE")" 2>/dev/null || true
  pkill -f "bench_io serve" 2>/dev/null || true
  pkill -f "http.server 8390" 2>/dev/null || true
  rm -f "$SS_PID_FILE"
}

prepare() {
  require_root
  [ -x "$BENCH_BIN" ] || build
  # 高 PPS UDP 需要更大的套接字缓冲（rmem/wmem_max 默认 ~212KB 会先丢包）。
  sysctl -qw net.core.rmem_max=16777216 net.core.wmem_max=16777216 || true
  "$LAB" down >/dev/null 2>&1 || true
  TOPO_ONLY=1 "$LAB" up
  stop_wan_servers
  ip netns exec "$WAN_NS" env BENCH_RING_MB=64 "$BENCH_BIN" serve 8080,9999 "$UDP_ECHO_PORT" \
    >/tmp/perf-udp-bench.log 2>&1 &
  # dae 节点存活检查需要 10.9.9.2:8390（HEAD 200）。
  ip netns exec "$WAN_NS" python3 -m http.server 8390 --bind 10.9.9.2 >/tmp/perf-udp-http.log 2>&1 &
  command -v ssserver >/dev/null || die "缺 ssserver（shadowsocks-rust）"
  ip netns exec "$WAN_NS" ssserver -s "10.9.9.2:$SS_PORT" \
    -k testpass -m "$SS_METHOD" -u --tcp-no-delay >/tmp/perf-udp-ss.stdout 2>&1 &
  echo $! >"$SS_PID_FILE"
  sleep 0.8
  echo "== 拓扑 + WAN UDP echo(:$UDP_ECHO_PORT) + ssserver(-u, $SS_METHOD) 就绪 =="
}

nft_add() {
  local port="$1"
  nft delete table inet perfproxy 2>/dev/null || true
  nft add table inet perfproxy
  nft "add chain inet perfproxy prerouting { type filter hook prerouting priority mangle; }"
  nft add rule inet perfproxy prerouting iifname landae ip protocol udp meta mark set 1 tproxy ip to ":$port"
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
  pkill -f "sing-box run -c $HERE" 2>/dev/null || true
  pkill -f "v2ray run -c $HERE" 2>/dev/null || true
}

# 方法参数化：把配置模板里的方法替换到 /tmp 副本（四种实现同方法对拍）。
sed_method() {
  local src="$1" dst="$2"
  sed "s/chacha20-ietf-poly1305/$SS_METHOD/g" "$src" >"$dst"
}

start_impl() {
  local impl="$1"
  local pid
  local sodama_dialer="ss://$SS_METHOD:testpass@10.9.9.2:$SS_PORT"
  case "$impl" in
  sodama)
    if [ ! -x "$LOADER" ] || [ ! -f "$OBJ" ]; then
      echo "!! 先构建 sodama（lab.sh build + cargo build --release）"
      return 1
    fi
    "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
      --dae0 dae0 --dae0peer dae0peer --daens sodamans \
      --rules "$HERE/rules.perf.dae" \
      --dialer "$sodama_dialer" \
      --status-socket /tmp/sodama-status.sock >/tmp/perf-udp-sodama.log 2>&1 &
    pid=$!
    ;;
  sodama-nobatch)
    if [ ! -x "$LOADER" ] || [ ! -f "$OBJ" ]; then
      echo "!! 先构建 sodama"
      return 1
    fi
    SODAMA_UDP_BATCH=0 "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
      --dae0 dae0 --dae0peer dae0peer --daens sodamans \
      --rules "$HERE/rules.perf.dae" \
      --dialer "$sodama_dialer" \
      --status-socket /tmp/sodama-status.sock >/tmp/perf-udp-sodama.log 2>&1 &
    pid=$!
    ;;
  dae)
    if [ ! -x "$DAE_BIN" ]; then
      echo "!! 缺 dae 二进制（DAE_BIN=$DAE_BIN）"
      return 1
    fi
    local cfg="$HERE/dae.dae"
    if [ "$SS_METHOD" != "chacha20-ietf-poly1305" ]; then
      sed_method "$HERE/dae.dae" /tmp/perf-udp-dae.dae
      cfg=/tmp/perf-udp-dae.dae
    fi
    chmod 640 "$cfg" 2>/dev/null || true
    "$DAE_BIN" run --config "$cfg" --disable-pidfile >/tmp/perf-udp-dae.log 2>&1 &
    pid=$!
    ;;
  singbox)
    nft_add 7895
    local cfg="$HERE/singbox.json"
    if [ "$SS_METHOD" != "chacha20-ietf-poly1305" ]; then
      sed_method "$HERE/singbox.json" /tmp/perf-udp-singbox.json
      cfg=/tmp/perf-udp-singbox.json
    fi
    "$SINGBOX_BIN" run -c "$cfg" >/tmp/perf-udp-singbox.log 2>&1 &
    pid=$!
    ;;
  v2ray)
    nft_add 7896
    local cfg="$HERE/v2ray.json"
    if [ "$SS_METHOD" != "chacha20-ietf-poly1305" ]; then
      sed_method "$HERE/v2ray.json" /tmp/perf-udp-v2ray.json
      cfg=/tmp/perf-udp-v2ray.json
    fi
    "$V2RAY_BIN" run -c "$cfg" >/tmp/perf-udp-v2ray.log 2>&1 &
    pid=$!
    ;;
  mihomo)
    command -v "$MIHOMO_BIN" >/dev/null || { echo "!! 缺 mihomo（Clash Verge 内核）"; return 1; }
    mkdir -p /tmp/perf-udp-mihomo
    nft_add 7897
    local cfg="$HERE/mihomo.ss.yaml"
    if [ "$SS_METHOD" != "chacha20-ietf-poly1305" ]; then
      sed_method "$HERE/mihomo.ss.yaml" /tmp/perf-udp-mihomo.yaml
      cfg=/tmp/perf-udp-mihomo.yaml
    fi
    "$MIHOMO_BIN" -d /tmp/perf-udp-mihomo -f "$cfg" >/tmp/perf-udp-mihomo.log 2>&1 &
    pid=$!
    ;;
  direct) ;; # 直连基线：不启实现
  *) die "未知实现：$impl" ;;
  esac
  if [ -n "${pid:-}" ]; then
    echo "$pid" >"$IMPL_PID_FILE"
  else
    rm -f "$IMPL_PID_FILE"
  fi
  sleep 2.5
  if [ -n "${pid:-}" ]; then
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -20 "/tmp/perf-udp-$impl.log" 2>/dev/null
      echo "!! $impl 启动失败"
      rm -f "$IMPL_PID_FILE"
      return 1
    fi
    echo "== $impl 运行中（pid $pid） =="
  else
    echo "== $impl：直连基线（无实现） =="
  fi
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

# 一轮 udpblast（proxy 或 direct 目标），输出 TSV 行：impl target mbps pps loss cpu_ms rss threads
run_one() {
  local impl="$1" wl="$2" target="$3"
  local host="${target%%:*}"
  local port="${target##*:}"
  local pid=""
  if [ -f "$IMPL_PID_FILE" ]; then pid="$(cat "$IMPL_PID_FILE")"; fi
  local cpu0="0" cpu1="0"
  if [ -n "$pid" ]; then cpu0="$(proc_cpu_ms "$pid")"; fi
  local out
  out="$(in_client timeout 120 "$BENCH_BIN" udpblast "$host" "$port" "$UDP_COUNT" "$UDP_SIZE" "$UDP_PPS" 2>&1 || true)"
  if [ -n "$pid" ]; then cpu1="$(proc_cpu_ms "$pid")"; fi
  echo "$out" | grep -q '^udpblast-ok' || {
    stop_impl
    die "[$impl/$wl] udpblast 失败：$out"
  }
  local wall mbps loss rss thr recv
  wall="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^wall_s=/) {sub("wall_s=","",$i); print $i}}' <<<"$out")"
  mbps="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^mbps=/) {sub("mbps=","",$i); print $i}}' <<<"$out")"
  loss="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^loss=/) {sub("loss=","",$i); print $i}}' <<<"$out")"
  recv="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^recv=/) {sub("recv=","",$i); print $i}}' <<<"$out")"
  local pps
  pps="$(awk -v c="$recv" -v w="$wall" 'BEGIN{printf "%.0f", c/w}')"
  rss="0"; thr="0"
  if [ -n "$pid" ]; then
    rss="$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
    thr="$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
  fi
  local cpu
  cpu="$(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN{printf "%.1f", b-a}')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$impl" "$wl" "$mbps" "$pps" "$loss" "$cpu" "$wall" "$rss" "$thr" | tee -a "$RESULTS"
}

bench_impl() {
  local impl="$1"
  if ! start_impl "$impl"; then
    return 1
  fi
  run_one "$impl" "proxy" "$PROXY_TARGET"
  run_one "$impl" "direct" "$DIRECT_TARGET"
  stop_impl
}

medians() {
  python3 - "$RESULTS" <<'PY'
import sys, statistics as st, collections
rows = collections.defaultdict(list)
for line in open(sys.argv[1]):
    p = line.rstrip("\n").split("\t")
    if len(p) != 9:
        continue
    rows[(p[0], p[1])].append(p)
print(f"{'impl':16} {'path':7} {'mbps(med)':>10} {'pps(med)':>10} {'loss%':>7} {'cpu_ms(med)':>12} {'rss_kb':>8} {'thr':>5}")
for (impl, path), rs in rows.items():
    mb = st.median(float(r[2]) for r in rs)
    pps = st.median(float(r[3]) for r in rs)
    loss = st.median(float(r[4]) for r in rs)
    cpu = st.median(float(r[5]) for r in rs)
    rss = rs[-1][7]
    thr = rs[-1][8]
    print(f"{impl:16} {path:7} {mb:10.1f} {pps:10.0f} {loss:7.1f} {cpu:12.1f} {rss:>8} {thr:>5}")
PY
}

all() {
  require_root
  : >"$RESULTS"
  for r in $(seq 1 "$ROUNDS"); do
    echo "-- 轮 $r/$ROUNDS --"
    bench_impl sodama || echo "!! sodama 跳过"
    bench_impl sodama-nobatch || echo "!! sodama-nobatch 跳过"
    bench_impl dae || echo "!! dae 跳过"
    bench_impl singbox || echo "!! singbox 跳过"
    bench_impl v2ray || echo "!! v2ray 跳过"
    bench_impl mihomo || echo "!! mihomo 跳过"
    # 直连基线（拓扑已在，无实现）
    rm -f "$IMPL_PID_FILE"
    run_one direct direct "$DIRECT_TARGET"
  done
  echo "== 汇总（中位数）=="
  medians
}

down() {
  stop_impl
  stop_wan_servers
  "$LAB" down >/dev/null 2>&1 || true
  echo "== 已清理 =="
}

case "${1:-}" in
build) build ;;
prepare) prepare ;;
bench)
  require_root
  case "${2:-}" in
  sodama | sodama-nobatch | dae | singbox | v2ray | mihomo)
    : >"$RESULTS"
    for r in $(seq 1 "$ROUNDS"); do
      echo "-- 轮 $r/$ROUNDS --"
      bench_impl "$2"
    done
    medians
    ;;
  direct)
    : >"$RESULTS"
    for r in $(seq 1 "$ROUNDS"); do
      rm -f "$IMPL_PID_FILE"
      run_one direct direct "$DIRECT_TARGET"
    done
    medians
    ;;
  *) die "用法：bench sodama|sodama-nobatch|dae|singbox|v2ray|mihomo|direct" ;;
  esac
  ;;
all)
  all
  ;;
down) down ;;
*)
  sed -n '2,24p' "$0"
  exit 2
  ;;
esac

#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# sodama 性能对比：sodama vs dae vs sing-box vs v2ray。
#
# 同一 lab 拓扑（client ns — 网关 — WAN ns）、同一 ss 上游、同一 C 负载（bench_io）：
# direct 内核基线 + ss 代理路径 + RTT。
#
# 用法：
#   lab/perf/run.sh build                     # 构建 bench_io
#   sudo lab/perf/run.sh prepare              # 建拓扑 + WAN 侧服务（bench_io/http/ss）
#   sudo lab/perf/run.sh bench <impl>         # 跑一个实现：sodama|dae|singbox|v2ray
#   sudo lab/perf/run.sh all                  # 四个实现依次跑并汇总
#   sudo lab/perf/run.sh down
#
# 环境变量：
#   DAE_BIN=/tmp/perf/usr/bin/dae   SINGBOX_BIN=sing-box   V2RAY_BIN=v2ray
#   BENCH_MB=48（每流）BENCH_STREAMS=4 ROUNDS=3 WARMUP=1 BENCH_LAT=500
#   SS_UPSTREAM=python|ssserver   # ss 上游选择（默认 python；性能测量用 ssserver）
#   PROXY_PROTO=ss|vless|vless-tls # 代理路径协议（默认 vless；ss 为兼容对照）
#   BENCH_RING_MB=128             # 全双工 echo 夹具 ring 容量
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
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
SS_PORT=8388
HTTP_PORT=8390
VLESS_PORT=8543
VLESS_TLS_PORT=8544
VLESS_UUID=b831381d-6324-4d53-ad4f-8cda48b30811
# 代理路径协议（默认 vless——VLESS 为主测/优化方向；ss 为兼容对照）
PROXY_PROTO="${PROXY_PROTO:-vless}"
# O6：ss 方法可参数化（AES-GCM 对比 chacha；四方使用同一方法）。
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
case "$PROXY_PROTO" in
  ss) UPSTREAM_PORT="$SS_PORT" ;;
  vless) UPSTREAM_PORT="$VLESS_PORT" ;;
  vless-tls) UPSTREAM_PORT="$VLESS_TLS_PORT" ;;
  *) echo "!! PROXY_PROTO=$PROXY_PROTO 未知（ss|vless|vless-tls）" >&2; exit 1 ;;
esac
IMPL_PID_FILE=/tmp/perf-impl.pid
RESULTS="${RESULTS:-/tmp/perf-results.tsv}"

BENCH_MB="${BENCH_MB:-48}"
BENCH_STREAMS="${BENCH_STREAMS:-4}"
ROUNDS="${ROUNDS:-3}"
WARMUP="${WARMUP:-1}"
BENCH_LAT="${BENCH_LAT:-500}"
# 跨实现吞吐对比：跳过半关闭（各家语义差异，另有专项覆盖）。
export BENCH_NOSHUT=1

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
kv() { echo "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2; exit}'; }
proc_cpu_ms() { sed 's/^.*) //' "/proc/$1/stat" | awk -v hz="$(getconf CLK_TCK)" '{printf "%.1f", (($12+$13)*1000.0)/hz}'; }

build() {
  mkdir -p "$ROOT/build"
  gcc -O2 -Wall -Wextra -pthread -o "$BENCH_BIN" "$ROOT/lab/bench_io.c"
  echo "== bench_io 就绪：$BENCH_BIN =="
}

# ---------------------------------------------------------------- 拓扑与 WAN 侧服务

stop_wan_servers() {
  for f in /tmp/perf-bench.pid /tmp/perf-http.pid /tmp/perf-ss.pid /tmp/perf-vless.pid; do
    if [ -f "$f" ]; then
      kill "$(cat "$f")" 2>/dev/null || true
      rm -f "$f"
    fi
  done
}

prepare() {
  require_root
  [ -x "$BENCH_BIN" ] || build
  "$LAB" down >/dev/null 2>&1 || true
  TOPO_ONLY=1 "$LAB" up
  stop_wan_servers
  ip netns exec "$WAN_NS" env BENCH_RING_MB="${BENCH_RING_MB:-128}" "$BENCH_BIN" serve 8080,9999 >/tmp/perf-bench.log 2>&1 &
  echo $! >/tmp/perf-bench.pid
  ip netns exec "$WAN_NS" python3 -m http.server "$HTTP_PORT" --bind 10.9.9.2 \
    >/tmp/perf-http.log 2>&1 &
  echo $! >/tmp/perf-http.pid
  if [ "$PROXY_PROTO" = ss ]; then
    if [ "${SS_UPSTREAM:-python}" = ssserver ]; then
      # 高速上游（shadowsocks-rust；性能测量用，python 上游有 GIL 〜2.4Gbps 上限）
      command -v ssserver >/dev/null || die "SS_UPSTREAM=ssserver 但未安装 ssserver"
      ip netns exec "$WAN_NS" ssserver -s "10.9.9.2:$SS_PORT" \
        -k testpass -m "$SS_METHOD" --tcp-no-delay \
        >/tmp/perf-ss.stdout 2>&1 &
      echo $! >/tmp/perf-ss.pid
    else
      ip netns exec "$WAN_NS" python3 "$ROOT/lab/ss_server.py" /tmp/perf-ss.log \
        "$SS_METHOD" testpass "$SS_PORT" 10.9.9.2 >/tmp/perf-ss.stdout 2>&1 &
      echo $! >/tmp/perf-ss.pid
    fi
  else
    # VLESS 上游：sing-box 服务端（同进程同时监听 8543 明文 / 8544 自签 TLS）。
    # 证书相对路径以 $ROOT 为工作目录（env -C）解析。
    command -v "$SINGBOX_BIN" >/dev/null || die "PROXY_PROTO=$PROXY_PROTO 但未安装 sing-box"
    ip netns exec "$WAN_NS" env -C "$ROOT" "$SINGBOX_BIN" run -c "$HERE/singbox.vless-server.json" \
      >/tmp/perf-vless-server.log 2>&1 &
    echo $! >/tmp/perf-vless.pid
  fi
  sleep 0.6
  # 上游就绪探测（从 host ns）
  timeout 3 bash -c ": >/dev/tcp/10.9.9.2/$UPSTREAM_PORT" 2>/dev/null \
    || die "WAN ns $PROXY_PROTO 上游(:$UPSTREAM_PORT) 未就绪（见 /tmp/perf-ss.stdout 或 /tmp/perf-vless-server.log）"
  echo "== 拓扑 + WAN 侧服务（bench_io:8080,9999 / http:$HTTP_PORT / $PROXY_PROTO:$UPSTREAM_PORT）就绪 =="
}

# ---------------------------------------------------------------- tproxy（sing-box/v2ray）

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

# ---------------------------------------------------------------- 各实现启停

impl_env_cleanup() {
  nft_del
  # dae 会把 wan 接口移进自己的 netns；退出后若未归还，由 lab down 兜底清理。
  ip netns del dae 2>/dev/null || true
  ip netns del daed 2>/dev/null || true
}

start_impl() {
  local impl="$1"
  local pid
  # 代理协议 → 各实现的拨号参数/配置选择
  local sodama_dialer dae_cfg singbox_cfg v2ray_cfg
  case "$PROXY_PROTO" in
    ss)
      sodama_dialer="ss://$SS_METHOD:testpass@10.9.9.2:8388"
      dae_cfg="$HERE/dae.dae"; singbox_cfg="$HERE/singbox.json"; v2ray_cfg="$HERE/v2ray.json"
      # O6：非默认方法时把四份配置模板替换到 /tmp（四方同方法对拍）。
      if [ "$SS_METHOD" != "chacha20-ietf-poly1305" ]; then
        sed "s/chacha20-ietf-poly1305/$SS_METHOD/g" "$HERE/dae.dae" >/tmp/perf-dae.dae
        sed "s/chacha20-ietf-poly1305/$SS_METHOD/g" "$HERE/singbox.json" >/tmp/perf-singbox.json
        sed "s/chacha20-ietf-poly1305/$SS_METHOD/g" "$HERE/v2ray.json" >/tmp/perf-v2ray.json
        dae_cfg=/tmp/perf-dae.dae; singbox_cfg=/tmp/perf-singbox.json; v2ray_cfg=/tmp/perf-v2ray.json
      fi
      ;;
    vless)
      sodama_dialer="vless://$VLESS_UUID@10.9.9.2:$VLESS_PORT?type=tcp&security=none"
      dae_cfg="$HERE/dae.vless.dae"; singbox_cfg="$HERE/singbox.vless.json"; v2ray_cfg="$HERE/v2ray.vless.json" ;;
    vless-tls)
      sodama_dialer="vless://$VLESS_UUID@10.9.9.2:$VLESS_TLS_PORT?type=tcp&security=tls&sni=localhost&allowinsecure=1"
      dae_cfg="$HERE/dae.vless-tls.dae"; singbox_cfg="$HERE/singbox.vless-tls.json"; v2ray_cfg="$HERE/v2ray.vless-tls.json" ;;
  esac
  case "$impl" in
    sodama)
      [ -x "$LOADER" ] && [ -f "$OBJ" ] || die "先构建 sodama（lab.sh build + cargo build --release）"
      # SODAMA_ARGS：附加参数（如 M2 kTLS 实验：SODAMA_ARGS=--ktls）
      # shellcheck disable=SC2086
      "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
        --dae0 dae0 --dae0peer dae0peer --daens sodamans \
        --rules "$HERE/rules.perf.dae" \
        --dialer "$sodama_dialer" \
        --status-socket /tmp/sodama-status.sock ${SODAMA_ARGS:-} >/tmp/perf-sodama.log 2>&1 &
      pid=$!
      ;;
    dae)
      [ -x "$DAE_BIN" ] || die "缺 dae 二进制（DAE_BIN=$DAE_BIN）"
      # dae 要求配置不可被 group/other 读写
      chmod 640 "$dae_cfg" 2>/dev/null || true
      "$DAE_BIN" run --config "$dae_cfg" --disable-pidfile >/tmp/perf-dae.log 2>&1 &
      pid=$!
      ;;
    singbox)
      nft_add 7895
      "$SINGBOX_BIN" run -c "$singbox_cfg" >/tmp/perf-singbox.log 2>&1 &
      pid=$!
      ;;
    v2ray)
      nft_add 7896
      "$V2RAY_BIN" run -c "$v2ray_cfg" >/tmp/perf-v2ray.log 2>&1 &
      pid=$!
      ;;
    *) die "未知实现：$impl" ;;
  esac
  echo "$pid" >"$IMPL_PID_FILE"
  sleep 2.5
  kill -0 "$pid" 2>/dev/null || { tail -20 "/tmp/perf-$impl.log" 2>/dev/null; die "$impl 启动失败"; }
  echo "== $impl 运行中（pid $pid） =="
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

# ---------------------------------------------------------------- 工作负载

# run_one <impl> <workload> <host> <port> -> TSV 行
run_one() {
  local impl="$1" wl="$2" host="$3" port="$4"
  local pid; pid="$(cat "$IMPL_PID_FILE")"
  local cpu0 cpu1 out lat mbps p50 p99
  cpu0="$(proc_cpu_ms "$pid")"
  out="$(in_client timeout 180 "$BENCH_BIN" client "$host" "$port" "$BENCH_MB" "$BENCH_STREAMS" 2>&1 || true)"
  lat="$(in_client timeout 120 "$BENCH_BIN" lat "$host" "$port" "$BENCH_LAT" 2>&1 || true)"
  cpu1="$(proc_cpu_ms "$pid")"
  echo "$out" | grep -q '^tcp-ok' || { stop_impl; echo "!! [$impl/$wl] client 失败：$out"; return 1; }
  echo "$lat" | grep -q '^lat-ok' || { stop_impl; echo "!! [$impl/$wl] lat 失败：$lat"; return 1; }
  mbps="$(kv "$out" oneway_mbps)"
  p50="$(kv "$lat" p50_us)"
  p99="$(kv "$lat" p99_us)"
  local rss thr
  rss="$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
  thr="$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$impl" "$wl" "$mbps" "$p50" "$p99" \
    "$(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN{printf "%.1f", b-a}')" "$(kv "$out" wall_s)" \
    "$rss" "$thr" | tee -a "$RESULTS"
}

bench_impl() {
  local impl="$1"
  require_root
  # ss 上游若不在（例如上一轮被异常流量打挂），自动重建拓扑与服务。
  if ! timeout 3 bash -c ": >/dev/tcp/10.9.9.2/$UPSTREAM_PORT" 2>/dev/null; then
    prepare
  fi
  start_impl "$impl"
  # 预热（丢弃）
  local i
  for i in $(seq 1 "$WARMUP"); do
    in_client timeout 180 "$BENCH_BIN" client 10.9.9.2 9999 "$BENCH_MB" "$BENCH_STREAMS" >/dev/null 2>&1 || true
    in_client timeout 180 "$BENCH_BIN" client 1.1.1.1 8080 "$BENCH_MB" "$BENCH_STREAMS" >/dev/null 2>&1 || true
  done
  for i in $(seq 1 "$ROUNDS"); do
    run_one "$impl" direct 10.9.9.2 9999 || return 1
    run_one "$impl" "$PROXY_PROTO" 1.1.1.1 8080 || return 1
  done
  stop_impl
  echo "== $impl 完成 =="
}

summarize() {
  echo
  echo "== 汇总（中位吞吐 / 中位 p50 / 中位 CPU ms / 中位 RSS KB / 中位线程数） =="
  printf '%-10s %-8s %10s %10s %10s %10s %8s\n' impl workload mbps p50_us cpu_ms rss_kb threads
  python3 - "$RESULTS" <<'PY'
import statistics, sys
rows = {}
for line in open(sys.argv[1]):
    p = line.rstrip("\n").split("\t")
    if len(p) < 9:
        continue
    impl, wl, mbps, p50, _p99, cpu, _wall, rss, thr = p
    rows.setdefault((impl, wl), []).append((float(mbps), float(p50), float(cpu), float(rss), float(thr)))
for (impl, wl) in sorted(rows, key=lambda k: (k[0], k[1])):
    mb = [x[0] for x in rows[(impl, wl)]]
    la = [x[1] for x in rows[(impl, wl)]]
    cp = [x[2] for x in rows[(impl, wl)]]
    rs = [x[3] for x in rows[(impl, wl)]]
    th = [x[4] for x in rows[(impl, wl)]]
    print(f"{impl:<10} {wl:<8} {statistics.median(mb):>10.1f} {statistics.median(la):>10.1f} {statistics.median(cp):>10.1f} {statistics.median(rs):>10.0f} {statistics.median(th):>8.0f}")
PY
}

case "${1:-}" in
  build) build ;;
  prepare) prepare ;;
  bench) shift; bench_impl "${1:?impl}" ;;
  all)
    : >"$RESULTS"
    for impl in sodama dae singbox v2ray; do
      prepare
      bench_impl "$impl" || true
    done
    summarize
    ;;
  down)
    require_root
    stop_impl || true
    stop_wan_servers
    "$LAB" down >/dev/null 2>&1 || true
    ;;
  *) echo "usage: $0 {build|prepare|bench <impl>|all|down}"; exit 2 ;;
esac

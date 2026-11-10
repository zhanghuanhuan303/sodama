#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# I1：系统内存基准（四层模型）——Process / Kernel / Total / per-connection。
#
# 拓扑（复用 run.sh）：client ns — 网关（sodama/dae/singbox）— WAN ns（bench_io echo + VLESS 上游）。
# 扫描并发连接数，对每个点采样：
#   userspace：VmRSS / Threads / fd 分类计数 / smaps_rollup(Private_Dirty)
#   kernel   ：/proc/meminfo（Slab/SReclaimable/SUnreclaim/PageTables）、/proc/slabinfo 关键 cache、
#              /proc/net/sockstat{,6}（TCP mem）、conntrack、bpftool map 内存合计
# 对照组（MODE=control）：同拓扑、同夹具、不放任何实现，用于同刻系统噪声/夹具的基线扣除。
#
# 用法：
#   sudo lab/perf/mem-system.sh prepare
#   sudo lab/perf/mem-system.sh run            # 扫描（默认 100..20000）
#   sudo MODE=control ... run-control
#   IMPL=dae sudo lab/perf/mem-system.sh run   # 同口径对照实现（sodama|dae|singbox）
#   sudo lab/perf/mem-system.sh down
# 环境：
#   POINTS="100 500 1000 2000 5000 10000 20000" HOLD_SECS=6 RESULTS=/tmp/mem-system.tsv
#   SETUP_MAX=1500（建连等待上限，×0.2s；万级连接建连需数十秒）
#   IMPL=sodama|dae|singbox MODE=impl|control
set -euo pipefail
ulimit -n 1048576 2>/dev/null || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"
RUN="$HERE/run.sh"
LAB="$ROOT/lab/lab.sh"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
CONN_SCALE="$ROOT/build/conn_scale"
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
VLESS_UUID=b831381d-6324-4d53-ad4f-8cda48b30811

POINTS="${POINTS:-100 500 1000 2000 5000 10000 20000}"
HOLD_SECS="${HOLD_SECS:-6}"
RESULTS="${RESULTS:-/tmp/mem-system.tsv}"
# 建连等待上限（×0.2s）；万级连接建连需数十秒（实测 35k ≈ 79s、444 conn/s），
# 默认 60s 会把「建立成功但慢」误判为失败。
SETUP_MAX="${SETUP_MAX:-300}"
IMPL="${IMPL:-sodama}"
DIR=/tmp/mem-system-lab
PID_FILE=$DIR/impl.pid
BASE="$DIR/baseline.env"

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
in_wan() { ip netns exec "$WAN_NS" "$@"; }

# WAN 侧回显夹具替换：bench_io 每连接一线程（万级连接 = 数万线程，污染 task_struct
# 且触发 scope pids 上限）；用 epoll 单线程 echo_server（与 scale 夹具同口径）。
swap_echo() {
  mkdir -p "$DIR" "$ROOT/build"
  [ -x "$ROOT/build/echo_server" ] \
    || gcc -O2 -Wall -o "$ROOT/build/echo_server" "$ROOT/lab/scale/echo_server.c" -lpthread
  for p in $(pgrep -x bench_io); do kill -9 "$p" 2>/dev/null || true; done
  in_wan bash -c "ulimit -n 1048576; exec \"$ROOT/build/echo_server\" 8080" >"$DIR/echo.log" 2>&1 &
  echo $! >"$DIR/echo.pid"
  sleep 0.3
}

kill_echo() {
  [ -f "$DIR/echo.pid" ] && { kill "$(cat "$DIR/echo.pid")" 2>/dev/null || true; rm -f "$DIR/echo.pid"; }
}

build_tools() {
  mkdir -p "$DIR" "$ROOT/build"
  [ -x "$ROOT/build/bench_io" ] || gcc -O2 -Wall -Wextra -pthread -o "$ROOT/build/bench_io" "$ROOT/lab/bench_io.c"
  [ -x "$CONN_SCALE" ] || gcc -O2 -Wall -pthread -o "$CONN_SCALE" "$ROOT/lab/scale/conn_scale.c"
}

prepare() {
  require_root
  build_tools
  "$RUN" prepare
  swap_echo
  # 高并发夹具需要更大端口范围（与 mem.sh/scale 同口径）
  in_client sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  ip netns exec "$WAN_NS" sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  # 清掉可能残留的旧实例（含 scale 夹具）
  for p in $(pgrep -x sodama) $(pgrep -x dae); do kill -9 "$p" 2>/dev/null || true; done
  sleep 0.5
}

# ---- nft tproxy（sing-box 用；dae 自管规则） ----
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

start_impl() {
  case "$IMPL" in
    sodama)
      [ -x "$LOADER" ] && [ -f "$OBJ" ] || die "先构建 sodama"
      "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
        --dae0 dae0 --dae0peer dae0peer --daens sodamans \
        --rules "$HERE/rules.perf.dae" \
        --dialer "vless://$VLESS_UUID@10.9.9.2:8543?type=tcp&security=none" \
        --status-socket /tmp/sodama-status.sock >"$DIR/sodama.log" 2>&1 &
      ;;
    dae)
      local dae_bin="${DAE_BIN:-/tmp/perf/usr/bin/dae}"
      [ -x "$dae_bin" ] || die "缺 dae 二进制（DAE_BIN=$dae_bin）"
      chmod 640 "$HERE/dae.vless.dae" 2>/dev/null || true
      "$dae_bin" run --config "$HERE/dae.vless.dae" --disable-pidfile >"$DIR/dae.log" 2>&1 &
      ;;
    singbox)
      nft_add 7895
      sing-box run -c "$HERE/singbox.vless.json" >"$DIR/singbox.log" 2>&1 &
      ;;
    *) die "未知 IMPL=$IMPL（sodama|dae|singbox）" ;;
  esac
  echo $! >"$PID_FILE"
  sleep 2.5
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null || { tail -10 "$DIR/$IMPL.log" 2>/dev/null; die "$IMPL 启动失败"; }
  echo "== $IMPL 运行中（pid $(cat "$PID_FILE")）=="
}

stop_impl() {
  [ -f "$PID_FILE" ] && { kill "$(cat "$PID_FILE")" 2>/dev/null || true; sleep 1; kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true; rm -f "$PID_FILE"; }
  nft_del
  kill_echo
  # dae 会把 wan 接口移进自己的 netns；
  ip netns del dae 2>/dev/null || true
  ip netns del daed 2>/dev/null || true
}

# ---- 采样 ----
slab_subset_pairs() {
  awk '
    BEGIN {
      split("sock_inode_cache TCP TCPv6 pipe_inode_cache skbuff_head_cache filp kmalloc-4k kmalloc-2k kmalloc-1k kmalloc-512 kmalloc-256 kmalloc-192 kmalloc-128 kmalloc-96 kmalloc-8k kmalloc-16k kmalloc-32k kmalloc-64k", names, " ")
      for (i in names) want[names[i]] = 1
    }
    /^slabinfo/ { next }
    {
      # $1=name $2=active_objs $3=num_objs $4=objsize → 活跃对象内存 = $2*$4
      if ($1 in want && $4 != "") printf "%s_kb=%d,", $1, $2 * $4 / 1024
    }
  ' /proc/slabinfo
}

bpf_map_kb() {
  if command -v bpftool >/dev/null 2>&1; then
    bpftool -j map show 2>/dev/null | python3 -c '
import json, sys
try:
    ms = json.load(sys.stdin)
except Exception:
    print("0"); sys.exit()
total = sum(int(m.get("bytes_memlock", 0)) for m in ms)
print(total // 1024)
' || echo 0
  else
    echo 0
  fi
}

sockstat_field() { # <file> <proto> <field>
  awk -v p="$2" -v f="$3" '{n=$1; sub(/:$/,"",n); if(n==p) {for(i=1;i<=NF;i++) if($i==f) {print $(i+1); exit}}}' "$1" 2>/dev/null || true
}

smaps_private_dirty_kb() { # <pid>
  awk '/^Private_Dirty:/{print $2}' "/proc/$1/smaps_rollup" 2>/dev/null || echo 0
}

conntrack_count() {
  [ -r /proc/sys/net/netfilter/nf_conntrack_count ] \
    && cat /proc/sys/net/netfilter/nf_conntrack_count \
    || echo 0
}

snapshot() { # <label> >> RESULTS
  local label="$1"
  local pid="0"
  [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE")"
  local rss=0 thr=0 fds_total=0 fds_sock=0 fds_pipe=0 priv_dirty=0
  if [ -d "/proc/$pid" ]; then
    rss="$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
    thr="$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
    fds_total="$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)"
    fds_sock="$(ls -l "/proc/$pid/fd" 2>/dev/null | grep -c 'socket:' || true)"
    fds_pipe="$(ls -l "/proc/$pid/fd" 2>/dev/null | grep -c 'pipe:' || true)"
    priv_dirty="$(smaps_private_dirty_kb "$pid")"
  fi
  local slab sunrec slrec pt
  slab="$(awk '/^Slab:/{print $2}' /proc/meminfo)"
  sunrec="$(awk '/^SUnreclaim:/{print $2}' /proc/meminfo)"
  slrec="$(awk '/^SReclaimable:/{print $2}' /proc/meminfo)"
  pt="$(awk '/^PageTables:/{print $2}' /proc/meminfo)"
  local tcp_mem tcp6_mem ct
  tcp_mem="$(sockstat_field /proc/net/sockstat TCP mem)"
  tcp6_mem="$(sockstat_field /proc/net/sockstat6 TCP6 mem)"
  ct="$(conntrack_count)"
  local subset bpfm
  subset="$(slab_subset_pairs)"
  bpfm="$(bpf_map_kb)"
  # TSV：label rss thr fds fds_sock fds_pipe priv_dirty slab sunrec slrec pt tcp_mem tcp6_mem ct bpf_map_kb | subset(k=v,…)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$rss" "$thr" "$fds_total" "$fds_sock" "$fds_pipe" "$priv_dirty" "$slab" "$sunrec" "$slrec" "$pt" \
    "${tcp_mem:-0}" "${tcp6_mem:-0}" "${ct:-0}" "$bpfm" "${subset%,}" >>"$RESULTS"
}

wait_setup() { # <log> <max_s>
  local f="$1" max="$2" i=0
  while [ "$i" -lt "$max" ]; do
    grep -q 'setup 完成' "$f" 2>/dev/null && return 0
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

run_sweep() {
  require_root
  : >"$RESULTS"
  : >"$DIR/peak-fds.tsv"
  local mode="${MODE:-impl}"
  echo -e "#label\trss_kb\tthreads\tfds\tfds_sock\tfds_pipe\tpriv_dirty_kb\tslab_kb\tsunrec_kb\tslrec_kb\tpagetables_kb\ttcp_mem\ttcp6_mem\tct\tbpf_map_kb\tslab_subset" >"$RESULTS"
  if [ "$mode" = "impl" ]; then
    start_impl
    sleep 2
  else
    echo "== 对照组：无实现（夹具基线）=="
    rm -f "$PID_FILE"
  fi
  local lbl=""; [ "$mode" = impl ] || lbl="ctl:"
  echo "== 基线（0 连接）=="
  snapshot "${lbl}N=0"
  for n in $POINTS; do
    local log="$DIR/hold-$n.log"
    : >"$log"
    # 每点前快照（pre），用于「同点邻近时段」增量，避免多分钟扫描期的背景漂移
    sleep 1
    snapshot "${lbl}N=$n/pre"
    in_client "$CONN_SCALE" hold 1.1.1.1 8080 "$n" "$HOLD_SECS" >"$log" 2>&1 &
    local hpid=$!
    # setup 期间采样 fd 峰值（每 1s），用于 fd 拓扑「建立峰值」数据
    (
      local max=0 f p
      while kill -0 "$hpid" 2>/dev/null; do
        [ -f "$PID_FILE" ] || { sleep 1; continue; }
        p="$(cat "$PID_FILE")"
        f="$(ls "/proc/$p/fd" 2>/dev/null | wc -l)"
        [ "$f" -gt "$max" ] 2>/dev/null && max=$f
        sleep 1
      done
      echo "N=$n max_fds=$max" >>"$DIR/peak-fds.tsv"
    ) &
    local ppid=$!
    if ! wait_setup "$log" "$SETUP_MAX"; then
      echo "!! N=$n 建立失败（$((SETUP_MAX / 5))s 内未完成）：$(tail -1 "$log")"
      # 夹具是 `in_client` 函数背景运行，$hpid 只是壳；按进程名在 ns 内杀干净
      kill "$hpid" 2>/dev/null || true
      in_client pkill -x conn_scale 2>/dev/null || true
      wait "$ppid" 2>/dev/null || true
      continue
    fi
    sleep 1
    echo "== N=$n（活跃）=="
    snapshot "${lbl}N=$n/active"
    wait "$hpid" 2>/dev/null || true
    in_client pkill -x conn_scale 2>/dev/null || true
    wait "$ppid" 2>/dev/null || true
    sleep 2
    echo "== N=$n（释放后 2s）=="
    snapshot "${lbl}N=$n/after"
    sleep 1
  done
  if [ "$mode" = "impl" ] && [ "$IMPL" = "sodama" ]; then
    "$LOADER" status --socket /tmp/sodama-status.sock --json >"$DIR/status.json" 2>/dev/null || true
  fi
  if [ "$mode" = "impl" ]; then
    stop_impl
  fi
  echo "== 结果：$RESULTS =="
  column -t -s $'\t' "$RESULTS" 2>/dev/null | cut -c1-200 || cat "$RESULTS"
}

case "${1:-}" in
prepare) prepare ;;
run) run_sweep ;;
run-control)
  MODE=control run_sweep
  ;;
down)
  require_root
  stop_impl
  kill_echo
  "$RUN" down >/dev/null 2>&1 || true
  echo "== 已清理 =="
  ;;
*)
  sed -n '2,22p' "$0"
  exit 2
  ;;
esac

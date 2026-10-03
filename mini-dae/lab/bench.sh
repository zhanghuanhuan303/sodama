#!/usr/bin/env bash
# P7 性能剖面（如实口径：perf 不可用 → 墙钟/吞吐 + 状态面 counters + /proc CPU/RSS）。
#
#   lab/bench.sh build            # 编译 C 基准端点（gcc，不需要 root）
#   sudo lab/bench.sh all         # 依次跑 6 条路径，输出 RESULT 行与汇总表
#   sudo lab/bench.sh run <path>  # 跑单条路径（会自动起/停对应会话）
#   sudo lab/bench.sh list        # 列出路径
#
# 路径 → lab.sh 会话 → 工作负载（客户端在 mini_client ns）：
#   direct      bench-up     TCP 10.9.9.2:8082   内核三层直转（基线）
#   relay       relay-up     TCP 1.1.1.1:8080    用户态 relay 泵（--dialer direct）
#   offload     offload-up   TCP 1.1.1.1:8080    relay + fast_sock/sk_skb（Rust 数据面）
#   ss          ss-up        TCP 1.1.1.1:8080    shadowsocks 协议栈（AEAD + 泵）
#   udp-direct  bench-up     UDP 10.9.9.2:9998   内核直转
#   udp-nat     udp-up       UDP 2.2.2.2:9998    UDP NAT（用户态会话表）
#
# 工作负载（可用环境变量覆盖）：
#   BENCH_MB=32（每流 MB）BENCH_STREAMS=4 BENCH_LAT=200（ping-pong 次数）
#   BENCH_UDP_N=2000（逐包 echo）BENCH_UDP_BLAST=20000（洪峰包数）
#
# 每个 RESULT 的 CPU/RSS 是 mini-dae 进程在该路径期间的增量/峰值：
#   cpu_ms    = utime+stime 增量（/proc/<pid>/stat）
#   ms_per_gb = cpu_ms / 该路径 userspace 转发量（(bytes_up+bytes_down)/1e9；直连为 -）
#   rss_kb    = 该路径结束时 VmRSS
# 注意：offload 的字节在注册后被内核搬运，counters（userspace 泵）会低估传输量；
# 直连路径 counters 恒为 0（数据面零用户态）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
LAB="$HERE/lab.sh"
LOADER="$ROOT/target/release/mini-dae"
BENCH_BIN="$ROOT/build/bench_io"
STATUS_SOCK=/tmp/mini-dae-status.sock
PID_FILE=/tmp/mini-dae.pid
WAN_PID_FILE=/tmp/mini-dae-wan.pid
BENCH_PID_FILE=/tmp/mini-dae-bench.pid
RESULTS=/tmp/mini-dae-bench-results.tsv
CLIENT_NS=mini_client
WAN_NS=mini_wan

BENCH_MB="${BENCH_MB:-32}"
BENCH_STREAMS="${BENCH_STREAMS:-4}"
BENCH_LAT="${BENCH_LAT:-200}"
BENCH_UDP_N="${BENCH_UDP_N:-2000}"
BENCH_UDP_BLAST="${BENCH_UDP_BLAST:-20000}"

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 $*"; }
as_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != root ]; then
    sudo -u "$SUDO_USER" -H "$@"
  else
    "$@"
  fi
}

build() {
  echo "== gcc: C 基准端点 =="
  mkdir -p "$ROOT/build"
  as_user gcc -O2 -Wall -Wextra -pthread -o "$BENCH_BIN" "$HERE/bench_io.c"
  echo "== 构建完成：$BENCH_BIN =="
}

session_of() {
  case "$1" in
    direct | udp-direct) echo bench-up ;;
    relay) echo relay-up ;;
    offload) echo offload-up ;;
    ss) echo ss-up ;;
    udp-nat) echo udp-up ;;
    *) die "未知路径：$1（可用：$("$0" list 2>/dev/null || echo 'direct relay offload ss udp-direct udp-nat')）" ;;
  esac
}

session_up() {
  local s; s="$(session_of "$1")"
  echo "== 起会话：lab.sh $s =="
  "$LAB" "$s" >/tmp/mini-dae-bench-session.log 2>&1 \
    || { cat /tmp/mini-dae-bench-session.log; die "会话 $s 启动失败"; }
}
session_down() { "$LAB" down >/dev/null 2>&1 || true; }

kill_wan_echo() {
  if [ -f "$WAN_PID_FILE" ]; then
    kill "$(cat "$WAN_PID_FILE")" 2>/dev/null || true
    rm -f "$WAN_PID_FILE"
    sleep 0.2
  fi
}

# start_server <tcp_ports_csv> [udp_port]
start_server() {
  kill_wan_echo
  if [ -n "${2:-}" ]; then
    ip netns exec "$WAN_NS" "$BENCH_BIN" serve "$1" "$2" \
      >/tmp/mini-dae-bench-server.log 2>&1 &
  else
    ip netns exec "$WAN_NS" "$BENCH_BIN" serve "$1" \
      >/tmp/mini-dae-bench-server.log 2>&1 &
  fi
  echo $! >"$BENCH_PID_FILE"
  sleep 0.3
  kill -0 "$(cat "$BENCH_PID_FILE")" 2>/dev/null \
    || { cat /tmp/mini-dae-bench-server.log; die "bench 服务端启动失败"; }
}

stop_server() {
  if [ -f "$BENCH_PID_FILE" ]; then
    kill "$(cat "$BENCH_PID_FILE")" 2>/dev/null || true
    rm -f "$BENCH_PID_FILE"
  fi
}

proc_cpu_ms() { sed 's/^.*) //' "/proc/$1/stat" | awk -v hz="$(getconf CLK_TCK)" '{printf "%.1f", (($12+$13)*1000.0)/hz}'; }
proc_rss_kb() { awk '/^VmRSS:/{print $2}' "/proc/$1/status"; }
metric() {
  # 注意：先完整读完 metrics（多行文本，客户端要读到 EOF），不能让管道提前关闭
  # 触发 EPIPE（pitfall #10 变体）。
  local out
  out="$("$LOADER" metrics --socket "$STATUS_SOCK")"
  echo "$out" | awk -v k="$1" '$1==k{print $2; exit}'
}
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
# kv "<bench_io 输出>" <key>
kv() { echo "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2; exit}'; }

run_case() {
  require_root
  local path="$1"
  [ -x "$BENCH_BIN" ] || die "先运行 $0 build"
  [ -f "$ROOT/ebpf-rs/target/bpfel-unknown-none/release/mini-dae-ebpf" ] && [ -x "$LOADER" ] || die "先运行 lab/lab.sh build"

  local udp=0 host port server_tcp=8080,8082 server_udp=""
  case "$path" in
    direct) host=10.9.9.2; port=8082 ;;
    relay | offload | ss) host=1.1.1.1; port=8080 ;;
    udp-direct) host=10.9.9.2; udp=1; server_udp=9998 ;;
    udp-nat) host=2.2.2.2; udp=1; server_udp=9998 ;;
    *) die "未知路径：$path" ;;
  esac

  session_down
  session_up "$path"
  start_server "$server_tcp" "$server_udp"
  local pid; pid="$(cat "$PID_FILE")"

  local cpu0 rss0 up0 down0 off0 conns0
  cpu0="$(proc_cpu_ms "$pid")"
  rss0="$(proc_rss_kb "$pid")"
  up0="$(metric mini_dae_relay_bytes_up)"
  down0="$(metric mini_dae_relay_bytes_down)"
  off0="$(metric mini_dae_offloaded_total)"
  conns0="$(metric mini_dae_relay_conns_total)"

  local log="/tmp/mini-dae-bench-$path.log"
  : >"$log"
  local mbps="-" lat50="-" lat99="-" loss="-" mb_recv="-" mb_sent="-"
  if [ "$udp" = 1 ]; then
    local uout bout
    uout="$(in_client timeout 120 "$BENCH_BIN" udpclient "$host" 9998 "$BENCH_UDP_N" 256 2>&1 || true)"
    bout="$(in_client timeout 120 "$BENCH_BIN" udpblast "$host" 9998 "$BENCH_UDP_BLAST" 256 2>&1 || true)"
    echo "$uout" | tee -a "$log"
    echo "$bout" | tee -a "$log"
    echo "$uout" | grep -q '^udp-ok' || { echo "FAIL[$path] udpclient: $uout"; exit 1; }
    lat50="$(kv "$uout" p50_us)"; lat99="$(kv "$uout" p99_us)"
    loss="$(kv "$bout" loss)"; mbps="$(kv "$bout" mbps)"
    local ubytes; ubytes="$(kv "$uout" recv)"
    mb_recv="$(awk -v n="$ubytes" 'BEGIN{printf "%.1f", n*256/1048576}')"
  else
    local tout lout
    tout="$(in_client timeout 180 "$BENCH_BIN" client "$host" "$port" "$BENCH_MB" "$BENCH_STREAMS" 2>&1 || true)"
    lout="$(in_client timeout 120 "$BENCH_BIN" lat "$host" "$port" "$BENCH_LAT" 2>&1 || true)"
    echo "$tout" | tee -a "$log"
    echo "$lout" | tee -a "$log"
    echo "$tout" | grep -q '^tcp-ok' || { echo "FAIL[$path] client: $tout"; exit 1; }
    echo "$lout" | grep -q '^lat-ok' || { echo "FAIL[$path] lat: $lout"; exit 1; }
    mbps="$(kv "$tout" oneway_mbps)"
    lat50="$(kv "$lout" p50_us)"; lat99="$(kv "$lout" p99_us)"
    mb_sent="$(kv "$tout" mb_sent)"; mb_recv="$(kv "$tout" mb_recv)"
  fi

  local cpu1 up1 down1 off1 conns1
  cpu1="$(proc_cpu_ms "$pid")"
  up1="$(metric mini_dae_relay_bytes_up)"
  down1="$(metric mini_dae_relay_bytes_down)"
  off1="$(metric mini_dae_offloaded_total)"
  conns1="$(metric mini_dae_relay_conns_total)"
  local cpu_ms rss_kb up_delta down_delta off_delta conns_delta pergb
  cpu_ms="$(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN{printf "%.1f", b-a}')"
  rss_kb="$(proc_rss_kb "$pid")"
  up_delta=$((up1 - up0)); down_delta=$((down1 - down0))
  off_delta=$((off1 - off0)); conns_delta=$((conns1 - conns0))
  local up_mb down_mb
  up_mb="$(awk -v n="$up_delta" 'BEGIN{printf "%.1f", n/1048576}')"
  down_mb="$(awk -v n="$down_delta" 'BEGIN{printf "%.1f", n/1048576}')"
  pergb="$(awk -v ms="$cpu_ms" -v up="$up_delta" -v dn="$down_delta" \
    'BEGIN{g=(up+dn)/1e9; if(g>=0.01) printf "%.1f", ms/g; else printf "-"}')"

  printf 'RESULT %s tcp_mbps=%s lat_p50_us=%s lat_p99_us=%s udp_loss=%s udp_blast_mbps=%s mb_sent=%s mb_recv=%s cpu_ms=%s ms_per_gb=%s rss_kb=%s bytes_up_mb=%s bytes_down_mb=%s offloaded=%s conns=%s\n' \
    "$path" "$mbps" "$lat50" "$lat99" "$loss" "$mbps" "$mb_sent" "$mb_recv" \
    "$cpu_ms" "$pergb" "$rss_kb" "$up_mb" "$down_mb" "$off_delta" "$conns_delta"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$path" "$mbps" "$lat50" "$lat99" "$loss" "$cpu_ms" "$pergb" "$rss_kb" \
    "$up_mb" "$down_mb" "$off_delta" "$conns_delta" "$mb_recv" >>"$RESULTS"

  stop_server
  session_down
}

print_table() {
  [ -f "$RESULTS" ] || die "没有结果（先 run/all）"
  echo
  echo "路径          吞吐Mbps  p50µs  p99µs  丢包   cpu_ms  ms/GB  rss_kB  up_MB  down_MB  offload  conns"
  awk -F'\t' '{printf "%-13s %8s %6s %6s %5s %7s %6s %7s %6s %8s %8s %6s\n", $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12}' "$RESULTS"
  echo "（吞吐 = TCP 单向往返的 oneway Mbps / UDP blast；丢包仅 UDP blast；"
  echo "  直连 ms/GB 为 -；offload 的 up/down 会低估内核搬运量；perf 不可用，无采样热点）"
}

list_paths() { echo "direct relay offload ss udp-direct udp-nat"; }

case "${1:-}" in
  build) build ;;
  list) list_paths ;;
  run) require_root; shift; [ $# -ge 1 ] || die "run 需要路径"; rm -f "$RESULTS"; run_case "$1" ;;
  all)
    require_root
    shift || true
    rm -f "$RESULTS"
    for p in $("$0" list); do run_case "$p"; done
    print_table ;;
  *) echo "usage: $0 {build|list|run <path>|all}"; exit 2 ;;
esac

#!/usr/bin/env bash
# I4：长稳曲线化（bounded-memory）——轻负载 + 周期采样，输出 CSV 曲线与漂移判据。
#
# 负载（轻量，避免压垮测试机）：
#   - 常驻 hold：HOLD_N 条长连接（全链路回显校验）贯穿全程；
#   - 微量 churn：每 CHURN_EVERY 秒一波 CHURN_BURST 秒的连接风暴（reactor 复用/回收）；
#   - 周期负载：每 LOAD_EVERY 秒一次 LOAD_MB×LOAD_STREAMS 全双工传输（字节校验）；
#   - 时延采样：每 SAMPLE_SECS 秒一次 LAT_N 次 RTT（p50/p99）。
# 采样（每 SAMPLE_SECS 秒）：RSS/线程/fd 分类/slab/SUnreclaim/SReclaimable/TCP mem/conntrack/
#   eBPF map/进程 CPU/RTT p50 p99。
#
# 用法：
#   sudo lab/perf/soak-curve.sh run [秒数]        # 默认 3600s
#   sudo lab/perf/soak-curve.sh down
# 环境：SAMPLE_SECS=15 HOLD_N=200 CHURN_BURST=0.1 CHURN_EVERY=5 LOAD_EVERY=60 LOAD_MB=8
#      LOAD_STREAMS=2 LAT_N=20 OUT_DIR=/tmp/soak-curve
#
# 判据（脚本结束时自动计算）：末样本相对基线（t=120s 起首个样本）
#   RSS/fd/Slab/SUnreclaim 漂移 ≤5% 且 fail=0 → bounded PASS。
set -euo pipefail
ulimit -n 1048576 2>/dev/null || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"
RUN="$HERE/run.sh"
LAB="$ROOT/lab/lab.sh"
LOADER="$ROOT/target/release/sodama"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
BENCH="$ROOT/build/bench_io"
CONN_SCALE="$ROOT/build/conn_scale"
CLIENT_NS=sodama_client
WAN_NS=sodama_wan
VLESS_UUID=b831381d-6324-4d53-ad4f-8cda48b30811

SOAK_SECS="${SOAK_SECS:-}"
SAMPLE_SECS="${SAMPLE_SECS:-15}"
HOLD_N="${HOLD_N:-200}"
CHURN_BURST="${CHURN_BURST:-0.1}"
CHURN_EVERY="${CHURN_EVERY:-5}"
LOAD_EVERY="${LOAD_EVERY:-60}"
LOAD_MB="${LOAD_MB:-8}"
LOAD_STREAMS="${LOAD_STREAMS:-2}"
LAT_N="${LAT_N:-20}"
OUT_DIR="${OUT_DIR:-/tmp/soak-curve}"

DIR=$OUT_DIR
CSV=$DIR/curve.csv
SUMMARY=$DIR/summary.txt
PID_FILE=$DIR/impl.pid
export BENCH_NOSHUT=1

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo $0 run"; }
in_client() { ip netns exec "$CLIENT_NS" "$@"; }
# WAN 侧回显夹具：bench_io 每连接一线程（万级连接=数万线程，且污染 task_struct）；
# 用 epoll 单线程 echo_server（与 scale 夹具同口径）。
swap_echo() {
  [ -x "$ROOT/build/echo_server" ] \
    || gcc -O2 -Wall -o "$ROOT/build/echo_server" "$ROOT/lab/scale/echo_server.c" -lpthread
  for p in $(pgrep -x bench_io); do kill -9 "$p" 2>/dev/null || true; done
  ip netns exec "$WAN_NS" bash -c "ulimit -n 1048576; exec \"$ROOT/build/echo_server\" 8080" >"$DIR/echo.log" 2>&1 &
  echo $! >"$DIR/echo.pid"
  sleep 0.3
}
proc_cpu_ms() { sed 's/^.*) //' "/proc/$1/stat" | awk -v hz="$(getconf CLK_TCK)" '{printf "%.1f", (($12+$13)*1000.0)/hz}'; }
sockstat_mem() { awk '/^TCP:/{for(i=1;i<=NF;i++) if($i=="mem") {print $(i+1); exit}}' /proc/net/sockstat; }

cleanup() {
  [ -f "$DIR/holder.pid" ] && { kill "$(cat "$DIR/holder.pid")" 2>/dev/null || true; rm -f "$DIR/holder.pid"; }
  [ -f "$DIR/echo.pid" ] && { kill "$(cat "$DIR/echo.pid")" 2>/dev/null || true; rm -f "$DIR/echo.pid"; }
  if [ -f "$PID_FILE" ]; then kill "$(cat "$PID_FILE")" 2>/dev/null || true; sleep 1; kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true; rm -f "$PID_FILE"; fi
  "$RUN" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_impl() {
  "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
    --dae0 dae0 --dae0peer dae0peer --daens sodamans \
    --rules "$HERE/rules.perf.dae" \
    --dialer "vless://$VLESS_UUID@10.9.9.2:8543?type=tcp&security=none" \
    --status-socket /tmp/sodama-status.sock >"$DIR/sodama.log" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 2.5
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null || { tail -10 "$DIR/sodama.log"; die "sodama 启动失败"; }
}

sample() { # <phase> <lat_p50> <lat_p99> <notes>
  local phase="$1" p50="${2:-}" p99="${3:-}" notes="${4:-}"
  local pid; pid="$(cat "$PID_FILE")"
  local rss thr fds fs fp slab sunrec slrec tcp ct bpfm cpu
  rss="$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status")"
  thr="$(awk '/^Threads:/{print $2}' "/proc/$pid/status")"
  fds="$(ls "/proc/$pid/fd" | wc -l)"
  fs="$(ls -l "/proc/$pid/fd" | grep -c 'socket:' || true)"
  fp="$(ls -l "/proc/$pid/fd" | grep -c 'pipe:' || true)"
  slab="$(awk '/^Slab:/{print $2}' /proc/meminfo)"
  sunrec="$(awk '/^SUnreclaim:/{print $2}' /proc/meminfo)"
  slrec="$(awk '/^SReclaimable:/{print $2}' /proc/meminfo)"
  tcp="$(sockstat_mem)"
  ct="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
  bpfm="$( { bpftool -j map show 2>/dev/null | python3 -c 'import json,sys
try: ms=json.load(sys.stdin)
except Exception: print(0); raise SystemExit
print(sum(int(m.get("bytes_memlock",0)) for m in ms)//1024)' ; } || echo 0)"
  cpu="$(proc_cpu_ms "$pid")"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date +%s)" "$phase" "$rss" "$thr" "$fds" "$fs" "$fp" "$slab" "$sunrec" "$slrec" \
    "$tcp" "$ct" "$bpfm" "$cpu" "$p50" "$p99" "$notes" >>"$CSV"
  echo "-- $phase: rss=${rss}kB thr=$thr fds=$fds($fs/$fp) slab=$((slab/1024))MB sunrec=$((sunrec/1024))MB tcp_mem=${tcp}p ct=$ct bpf=${bpfm}kB cpu=${cpu}ms p50=${p50}us p99=${p99}us $notes"
}

lat_sample() {
  local out; out="$(in_client timeout 30 "$BENCH" lat 1.1.1.1 8080 "$LAT_N" 2>/dev/null || true)"
  echo "$out" | awk -F'[= ]' '/p50_us=/{for(i=1;i<=NF;i++){if($i=="p50_us")p50=$(i+1); if($i=="p99_us")p99=$(i+1)}} END{if(p50)printf "%s %s",p50,p99}'
}

run() {
  require_root
  mkdir -p "$DIR"
  "$RUN" prepare
  swap_echo
  in_client sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  sysctl -qw net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range="10000 65000" || true
  start_impl
  echo "t_s,phase,rss_kb,threads,fds,fds_sock,fds_pipe,slab_kb,sunrec_kb,slrec_kb,tcp_mem_pages,ct,bpf_map_kb,cpu_ms,lat_p50_us,lat_p99_us,notes" >"$CSV"

  local pid; pid="$(cat "$PID_FILE")"
  # 先取 0 点
  sample baseline0 "" "" "start"
  # 常驻长连接（失败则退出）
  in_client "$CONN_SCALE" hold 1.1.1.1 8080 "$HOLD_N" "$((SOAK_SECS + 120))" >"$DIR/holder.log" 2>&1 &
  echo $! >"$DIR/holder.pid"
  sleep 5
  grep -q 'setup 完成' "$DIR/holder.log" || { cat "$DIR/holder.log"; die "hold 建立失败"; }
  echo "== soak 开始：${SOAK_SECS}s hold=$HOLD_N churn=${CHURN_EVERY}s×${CHURN_BURST}s load=${LOAD_EVERY}s×${LOAD_MB}MB×${LOAD_STREAMS} =="

  local t0 now fails=0 it=0 last_churn=0 last_load=0 last_lat=0
  t0="$(date +%s)"
  while :; do
    now="$(date +%s)"
    local elapsed=$((now - t0))
    [ "$elapsed" -ge "$SOAK_SECS" ] && break
    local notes=""
    if [ $((elapsed - last_churn)) -ge "$CHURN_EVERY" ]; then
      last_churn=$elapsed
      local cout; cout="$(in_client timeout 60 "$CONN_SCALE" churn 1.1.1.1 8080 "$CHURN_BURST" 2>&1 || true)"
      local cf; cf="$(echo "$cout" | awk -F'[= ]' '/churn conns=/{for(i=1;i<=NF;i++) if($i=="fail"){print $(i+1); exit}}')"
      if [ -z "$cf" ]; then fails=$((fails + 1)); notes="${notes}churn_ERR;"; else
        fails=$((fails + cf)); if [ "$cf" != 0 ]; then notes="${notes}churn_fail=$cf;"; fi
      fi
    fi
    if [ $((elapsed - last_load)) -ge "$LOAD_EVERY" ]; then
      last_load=$elapsed
      local lout; lout="$(in_client timeout 180 "$BENCH" client 1.1.1.1 8080 "$LOAD_MB" "$LOAD_STREAMS" 2>&1 || true)"
      if ! echo "$lout" | grep -q '^tcp-ok'; then fails=$((fails + 1)); notes="${notes}load_ERR;"; fi
    fi
    local p50="" p99=""
    if [ $((elapsed - last_lat)) -ge "$SAMPLE_SECS" ]; then
      last_lat=$elapsed
      local lat; lat="$(lat_sample || true)"
      p50="${lat%% *}"; p99="${lat##* }"
      [ "$lat" = "$p50" ] && p99=""
    fi
    sleep "$SAMPLE_SECS"
    it=$((it + 1))
    sample "t=$elapsed" "$p50" "$p99" "$notes"
  done

  # 收尾：主动结束常驻 hold（释放事件）→ 等 idle 回收 15s → final
  sample "pre-final" "" "" "holder=$HOLD_N"
  if [ -f "$DIR/holder.pid" ]; then
    kill "$(cat "$DIR/holder.pid")" 2>/dev/null || true
    wait "$(cat "$DIR/holder.pid")" 2>/dev/null || true
    rm -f "$DIR/holder.pid"
  fi
  echo "-- 等 15s 静默回收 --"
  sleep 15
  sample final "" "" "idle15s"

  # 漂移判据：baseline = 第一个 t>=120 的样本（如无则取 baseline0），final = final 样本
  python3 - "$CSV" "$SUMMARY" <<'PY'
import csv, re, sys
rows = list(csv.DictReader(open(sys.argv[1])))
def num(r, k):
    try: return float(r[k] or 0)
    except ValueError: return 0.0
base = next((r for r in rows if r["phase"].startswith("t=") and int(r["phase"].split("=")[1]) >= 120), rows[0])
fin = next((r for r in rows if r["phase"] == "final"), rows[-1])
lines = []
ok = True
for k, label, limit in (("rss_kb", "RSS", 5), ("slab_kb", "Slab", 5), ("sunrec_kb", "SUnreclaim", 5)):
    b, f = num(base, k), num(fin, k)
    drift = (f - b) / b * 100 if b else 0.0
    passed = drift <= limit
    ok &= passed
    lines.append(f"{label:12s} base={b:9.0f} final={f:9.0f} drift={drift:+6.2f}% (≤{limit}%) {'PASS' if passed else 'FAIL'}")
# fd：验收「无增长」（资源回落是期望行为，降低不算失败）
b, f = num(base, "fds"), num(fin, "fds")
drift = (f - b) / b * 100 if b else 0.0
passed = f <= b * 1.05
ok &= passed
lines.append(f"{'fd':12s} base={b:9.0f} final={f:9.0f} drift={drift:+6.2f}% (无增长) {'PASS' if passed else 'FAIL'}")
fails = 0
for r in rows:
    n = r["notes"] or ""
    fails += sum(int(m.group(1)) for m in re.finditer(r"churn_fail=(\d+)", n))
    fails += len(re.findall(r"ERR", n))
lines.append(f"fail 记录：{'无' if fails == 0 else f'{fails} 次'}")
if fails: ok = False
lines.append(f"bounded-memory 判据：{'PASS' if ok else 'FAIL'}")
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
  echo "== 曲线：$CSV ；摘要：$SUMMARY =="
}

case "${1:-}" in
run)
  shift || true
  SOAK_SECS="${SOAK_SECS:-${1:-3600}}"
  run ;;
down) require_root; cleanup; trap - EXIT; echo "== 已清理 ==" ;;
*) sed -n '2,20p' "$0"; exit 2 ;;
esac

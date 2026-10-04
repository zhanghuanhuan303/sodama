#!/usr/bin/env bash
# M4 stage 2 codec 压力：反复 4/8/64 流 vless-tls（长尾卡死回归；
# 配合 SODAMA_REACTOR_DEBUG=1 输出会话状态周期转储，见 ADR-0058 stage 2 节）。
#
# 前置：先跑 `sudo PROXY_PROTO=vless-tls lab/perf/run.sh prepare`（建拓扑 + WAN 侧 vless 服务）。
# 用法：sudo lab/perf/codec-stress.sh [每档轮数，默认 15]
# 退出码：0=全过；1=有失败（保留 /tmp/codec-stress-sodama.log 现场）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SODAMA="$(dirname "$(dirname "$HERE")")"
LOADER="$SODAMA/target/release/sodama"
OBJ="$SODAMA/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
BIN="$SODAMA/build/bench_io"
VLESS_UUID=b831381d-6324-4d53-ad4f-8cda48b30811
ROUNDS="${1:-15}"

export BENCH_NOSHUT=1
killall -9 sodama 2>/dev/null || true
sleep 0.5
SODAMA_REACTOR_DEBUG=1 "$LOADER" --ebpf "$OBJ" --lan landae --wan wan \
  --dae0 dae0 --dae0peer dae0peer --daens sodamans \
  --rules "$HERE/rules.perf.dae" \
  --dialer "vless://$VLESS_UUID@10.9.9.2:8544?type=tcp&security=tls&sni=localhost&allowinsecure=1" \
  --status-socket /tmp/sodama-status.sock >/tmp/codec-stress-sodama.log 2>&1 &
pid=$!
sleep 2.5
kill -0 $pid 2>/dev/null || { echo "loader 启动失败"; tail -5 /tmp/codec-stress-sodama.log; exit 1; }

fail=0
run() { # <streams> <mb> <iters>
  local s=$1 mb=$2 it=$3 i out rc
  for i in $(seq 1 "$it"); do
    out=$(ip netns exec sodama_client timeout 30 "$BIN" client 1.1.1.1 8080 "$mb" "$s" 2>&1) || rc=$?
    rc=${rc:-0}
    if [ "$rc" -ne 0 ] || ! echo "$out" | grep -q 'tcp-ok'; then
      echo "!! s=$s mb=$mb iter $i rc=$rc: $out"
      fail=1
      return 1
    fi
  done
  echo "s=$s mb=$mb ×$it OK"
}

run 4 64 "$ROUNDS" && run 8 64 "$ROUNDS" && run 64 1 "$ROUNDS" || true
if [ "$fail" -eq 0 ]; then
  echo "ALL OK（reactor 日志：/tmp/codec-stress-sodama.log；补泵触发 $(grep -c '预算耗尽' /tmp/codec-stress-sodama.log || true) 次）"
else
  echo "FAIL：现场保留 /tmp/codec-stress-sodama.log（loader pid=$pid）"
  exit 1
fi
kill -9 "$pid" 2>/dev/null || true

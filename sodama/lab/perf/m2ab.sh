#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# M2 kTLS 路径 A/B：8×64MB 下对比 rustls / kTLS / kTLS+no-splice 的吞吐与 CPU。
#
# 用法：
#   sudo lab/perf/m2ab.sh [reps]                    # 默认 CONFIGS=--ktls，跑 reps（默认 3）轮
#   sudo CONFIGS="rustls" lab/perf/m2ab.sh 3        # rustls 默认路径
#   sudo CONFIGS="--ktls rustls" lab/perf/m2ab.sh 3 # 两条路径依次
#   sudo CONFIGS="--ktls --no-splice" lab/perf/m2ab.sh 3
#
# 前置：先 `sudo PROXY_PROTO=vless-tls lab/perf/run.sh prepare`（建拓扑 + WAN 侧 sing-box 服务）。
# 输出：每行一次 client 运行（oneway_mbps/verify + sodama/sing-box 进程 CPU 增量）。
set -euo pipefail
ROOT="$(cd "$(dirname "$(dirname "$(dirname "${BASH_SOURCE[0]}")")")" && pwd)"
cd "$ROOT"
REPS="${1:-3}"
BENCH="$ROOT/build/bench_io"
DIALER='vless://b831381d-6324-4d53-ad4f-8cda48b30811@10.9.9.2:8544?type=tcp&security=tls&sni=localhost&allowinsecure=1'
CONFIGS="${CONFIGS---ktls}"
cpu_ms() { sed 's/^.*) //' "/proc/$1/stat" | awk -v hz="$(getconf CLK_TCK)" '{printf "%.1f", (($12+$13)*1000.0)/hz}'; }

stop() { for p in $(pgrep -x sodama); do kill -9 "$p"; done; sleep 1; }
run() { # <label>
  local label="$1" so sb c0 c1 s0 s1 out
  so="$(pgrep -x sodama)"; sb="$(pgrep -x sing-box)"
  c0="$(cpu_ms "$so")"; s0="$(cpu_ms "$sb")"
  out="$(ip netns exec sodama_client env BENCH_NOSHUT=1 timeout 180 "$BENCH" client 1.1.1.1 8080 64 8 2>&1 | tail -1)"
  c1="$(cpu_ms "$so")"; s1="$(cpu_ms "$sb")"
  printf '%-16s %s  sodama_cpu=%5.0f  singbox_cpu=%5.0f\n' "$label" "$out" \
    "$(awk -v a="$c0" -v b="$c1" 'BEGIN{print b-a}')" \
    "$(awk -v a="$s0" -v b="$s1" 'BEGIN{print b-a}')"
}

for cfg in $CONFIGS; do
  [ "$cfg" = "rustls" ] && cfg=""
  stop
  # shellcheck disable=SC2086
  setsid ./target/release/sodama --ebpf "$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf" \
    --lan landae --wan wan --dae0 dae0 --dae0peer dae0peer --daens sodamans \
    --rules "$ROOT/lab/perf/rules.perf.dae" --dialer "$DIALER" \
    --status-socket /tmp/sodama-status.sock ${cfg:+"$cfg"} >/tmp/m2ab-sodama.log 2>&1 < /dev/null &
  sleep 2.5
  label="${cfg:-rustls}"
  for _ in $(seq 1 "$REPS"); do run "$label"; done
done
stop
echo "== done =="

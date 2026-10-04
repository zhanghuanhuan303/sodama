#!/usr/bin/env bash
# 规则编译对拍：sodama 的 Rust 编译器 vs dae 原版 Go 编译器。
#
#   lab/parity.sh                 # 对拍 lab/rules.dae 与 lab/rules.reload.dae
#   lab/parity.sh <rules>...      # 对拍指定规则文件
#
# dae 侧：lab/parity/run.sh（把 dae 源码副本 + 一个同包测试塞进 go test，
# 用 component/routing + control 的真实 builder 编译并 dump 出最终数组）。
# sodama 侧：sodama --compile-dump（不加载 eBPF、不需要 root）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
LOADER="$ROOT/target/release/sodama"

[ -x "$LOADER" ] || { echo "!! 先构建加载器：lab/lab.sh build" >&2; exit 2; }
[ -x "$HERE/parity/run.sh" ] || { echo "!! 缺少 lab/parity/run.sh" >&2; exit 2; }

files=("$@")
if [ "${#files[@]}" = 0 ]; then
  files=("$HERE/rules.dae" "$HERE/rules.reload.dae" "$HERE/rules.v6.dae" "$HERE/rules.geoip.dae" "$HERE/rules.pname.dae")
fi

# P17a：geoip 展开对拍需要夹具 geoip.dat/geosite.dat；DAE_LOCATION_ASSET 同时作用于
# Go 侧（assets.LocationFinder）与 sodama 侧（--compile-dump 的 geodata 搜索）。
GEO_FIXTURE="$(mktemp -d)"
trap 'rm -rf "$GEO_FIXTURE"' EXIT
python3 "$HERE/gen-geo-dat.py" "$GEO_FIXTURE" >/dev/null
export DAE_LOCATION_ASSET="$GEO_FIXTURE"

fails=0
for f in "${files[@]}"; do
  go_out="$(mktemp)"
  rs_out="$(mktemp)"
  "$HERE/parity/run.sh" "$f" >"$go_out"
  "$LOADER" --compile-dump "$f" >"$rs_out"
  if diff -u "$go_out" "$rs_out" >/tmp/sodama-parity.diff; then
    echo "PARITY $(basename "$f"): PASS（$(wc -l <"$rs_out") 行，逐字节一致）"
  else
    echo "PARITY $(basename "$f"): FAIL"
    cat /tmp/sodama-parity.diff
    fails=$((fails + 1))
  fi
  rm -f "$go_out" "$rs_out"
done

if [ "$fails" != 0 ]; then
  echo "!! $fails 个规则集对拍不一致"
  exit 1
fi

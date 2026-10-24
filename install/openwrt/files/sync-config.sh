#!/bin/sh
# 从 packaging/arch/ 同步 OpenWrt 包内资产（唯一事实来源 = packaging/arch/）。
#
# OpenWrt 与 Arch 只有「接口名默认值」不同：
#   wan0 → wan（OpenWrt 的 WAN 逻辑接口）
#   br0  → br-lan
#
# 用法：
#   sh install/openwrt/files/sync-config.sh          # 重新生成
#   sh install/openwrt/files/sync-config.sh --check  # 只检查是否已同步（发布前用，退出码 1 = 过期）
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../.." && pwd)
SRC="$ROOT/packaging/arch"
DST="$HERE"
MODE="${1:-sync}"

mkdir -p "$DST/rules"
changed=0

# 注意：OpenWrt 的 procd 总是显式传 `--wan/--lan/--dual`（uci 值），命令行优先于
# config.dae 里的 `*_interface`；因此这里把 lan 默认值写 none（钩子由 uci 决定）。
NOTE='# 注意（OpenWrt）：WAN/LAN/DUAL 钩子由 procd 按 uci 显式传参（/etc/config/sodama），
# 命令行优先于本文件的 wan_interface/lan_interface；下面写 none 仅作说明用途。
'

# 配置文件：只替换接口名默认值
for pair in "config.dae:config.example.dae" "config-gateway.dae:config.gateway.dae"; do
  s=${pair%%:*}
  d=${pair##*:}
  { printf '%s' "$NOTE"; sed -e 's/^\( *wan_interface:\) *wan0 *$/\1 wan/' \
      -e 's/^\( *lan_interface:\) *br0 *$/\1 none/' "$SRC/$s"; } >"$DST/$d.tmp"
  if ! cmp -s "$DST/$d" "$DST/$d.tmp"; then
    changed=1
    mv "$DST/$d.tmp" "$DST/$d"
    [ "$MODE" = sync ] && echo "更新 $d"
  else
    rm -f "$DST/$d.tmp"
  fi
done

# 原样复制：拦截名单 + 规则集
cp_tracked() {
  src=$1
  dst=$2
  if ! cmp -s "$src" "$dst"; then
    changed=1
    cp "$src" "$dst"
    [ "$MODE" = sync ] && echo "更新 ${dst#$DST/}"
  fi
}

cp_tracked "$SRC/blocklist.txt" "$DST/blocklist.txt"
for f in cn_direct user_proxy user_direct; do
  cp_tracked "$SRC/rules/$f.txt" "$DST/rules/$f.txt"
done

# 用户文档：以 docs/openwrt-guide.md 为准
if [ -f "$ROOT/docs/openwrt-guide.md" ]; then
  cp_tracked "$ROOT/docs/openwrt-guide.md" "$DST/README.md"
fi

if [ "$MODE" = "--check" ] && [ "$changed" = "1" ]; then
  echo "!! install/openwrt/files 与 packaging/arch 不同步（跑一次 sync-config.sh 并提交）" >&2
  exit 1
fi
exit 0

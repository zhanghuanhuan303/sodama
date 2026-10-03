#!/usr/bin/env bash
# 真实节点端到端验收（dialer 可为 vless/ws、anytls、hy2、socks5 桥接等任意支持项）。
#
#   REAL_NODE_URL='anytls://pass@host:port?sni=...&insecure=1'   sudo lab/real-node-e2e.sh
#   REAL_NODE_URL='vless://uuid@host:port?type=ws&...'           sudo lab/real-node-e2e.sh
#
# 可选：
#   VLESS_WS_TARGET_HOST=www.gstatic.com   # 目标域名（默认）
#   VLESS_WS_TARGET_PATH=/generate_204     # 目标路径（默认）
#
# 语义：client ns → mini-dae（tproxy + relay）→ 真实节点 → 目标。
# 目标 IP 在宿主解析后写进 IP 规则（不依赖 DNS 接管）；节点 URL 仅经环境变量传递。
# （兼容旧名：VLESS_WS_URL）
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

die() { echo "!! $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = 0 ] || die "需要 root：sudo VLESS_WS_URL='vless://...' $0"; }

[ -n "${REAL_NODE_URL:-}${VLESS_WS_URL:-}" ] || die "用法：REAL_NODE_URL='vless://...|anytls://...|socks5://...' sudo $0"
NODE_URL="${REAL_NODE_URL:-${VLESS_WS_URL:-}}"
TARGET_HOST="${VLESS_WS_TARGET_HOST:-www.gstatic.com}"
TARGET_PATH="${VLESS_WS_TARGET_PATH:-/generate_204}"

require_root
target_ip="$(getent ahostsv4 "$TARGET_HOST" | awk 'NR==1{print $1}')"
[ -n "$target_ip" ] || die "解析 $TARGET_HOST 失败"

rules="$(mktemp /tmp/mini-dae-real-rules.XXXXXX.dae)"
cleanup() {
  "$HERE/lab.sh" down >/dev/null 2>&1 || true
  rm -f "$rules"
}
trap cleanup EXIT

{
  echo "dip($target_ip/32) && dport(443) -> proxy"
  echo "fallback -> direct"
} >"$rules"
chmod 640 "$rules"

echo "== 启动 mini-dae（relay → 真实节点）=="
USE_RULES="$rules" USE_DIALER="$NODE_URL" USE_RELAY_IDLE=30 "$HERE/lab.sh" up

echo "== 客户端经网关请求 https://$TARGET_HOST$TARGET_PATH =="
code="$(ip netns exec mini_client curl -sS -o /dev/null -w '%{http_code}' -m 30 \
  --resolve "$TARGET_HOST:443:$target_ip" "https://$TARGET_HOST$TARGET_PATH" || true)"
echo "gw_http_code=$code"

echo "== 网关计数 =="
"$ROOT/target/release/mini-dae" metrics --socket /tmp/mini-dae-status.sock \
  | awk '$1 ~ /mini_dae_relay_(bytes_up|bytes_down|conns_total|dial_errors)/ {print}'

case "$code" in
  2* | 3*) echo "PASS: 真实节点端到端（→ $TARGET_HOST）" ;;
  *) echo "FAIL: HTTP code=$code"; exit 1 ;;
esac

#!/usr/bin/env bash
# 用 sing-box 作探针客户端，测单个订阅节点的交付带宽（8MB 下载）。
# 用法：probe-node.sh <node-url-file> <tag> [bytes]
# 只输出 tag 与 Mbps；节点 URL 只经文件传递，不打印。
set -euo pipefail

NODE_FILE="${1:?node url file}"
TAG="${2:?tag}"
BYTES="${3:-8388608}"
PORT=10881
CFG=/tmp/probe-node-singbox.json
IP="$(getent ahostsv4 speed.cloudflare.com | awk 'NR==1{print $1}')"

python3 - "$NODE_FILE" "$CFG" <<'PY'
import json, sys
from urllib.parse import urlparse, parse_qs
url = open(sys.argv[1]).read().strip()
u = urlparse(url)
q = parse_qs(u.query)
tls = {
    "enabled": True,
    "server_name": (q.get("sni") or q.get("servername") or [u.hostname])[0],
    "utls": {"enabled": True, "fingerprint": (q.get("fp") or ["chrome"])[0]},
}
if (q.get("security") or [""])[0] == "reality":
    tls["reality"] = {
        "enabled": True,
        "public_key": q["pbk"][0],
        "short_id": (q.get("sid") or [""])[0],
    }
if u.scheme == "vless":
    out = {"type": "vless", "tag": "proxy", "server": u.hostname, "server_port": u.port,
           "uuid": u.username, "flow": (q.get("flow") or [""])[0], "tls": tls}
elif u.scheme == "anytls":
    out = {"type": "anytls", "tag": "proxy", "server": u.hostname, "server_port": u.port,
           "password": u.username, "tls": tls}
else:
    sys.exit("unsupported scheme " + u.scheme)
cfg = {
    "log": {"level": "error"},
    "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": 10881}],
    "outbounds": [out],
}
json.dump(cfg, open(sys.argv[2], "w"))
PY

sing-box run -c "$CFG" >/tmp/probe-node-singbox.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
sleep 1.2
if ! kill -0 "$PID" 2>/dev/null; then
  echo "$TAG  FAIL(启动)"; exit 0
fi
OUT="$(curl -sS -x socks5h://127.0.0.1:$PORT --max-time 30 \
  --resolve "speed.cloudflare.com:443:$IP" -o /dev/null \
  -w '%{speed_download} %{time_total} %{size_download}' \
  "https://speed.cloudflare.com/__down?bytes=$BYTES" 2>/tmp/probe-node-curl.err || true)"
SPD="$(awk '{print $1}' <<<"$OUT")"
SEC="$(awk '{print $2}' <<<"$OUT")"
SZ="$(awk '{print $3}' <<<"$OUT")"
if [ -z "$SPD" ] || [ "${SPD%.*}" -le 0 ] 2>/dev/null; then
  echo "$TAG  FAIL($(tail -c 80 /tmp/probe-node-curl.err | tr '\n' ' '))"; exit 0
fi
awk -v t="$TAG" -v b="$SPD" -v s="$SEC" -v z="$SZ" \
  'BEGIN{printf "%s  %.1f Mbps  %.2fs  %.1f MB\n", t, b*8/1e6, s, z/1e6}'

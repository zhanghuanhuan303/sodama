#!/bin/sh
# P5 G2 生态兼容检查：真实 Go 客户端（dae 依赖的 outbound fork）↔ 独立 Python 服务端。
#
#   lab/proto-check/run.sh vless [tls]
#   lab/proto-check/run.sh vmess [tls]
#
# 需要 parity 的 dae-work 副本（不存在时会先跑一次 parity 建出来）与
# python3（vless 用 stdlib；vmess 用 cryptography）。
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(dirname "$HERE")
PARITY="$LAB/parity"
WORK="$PARITY/dae-work"
LOG=/tmp/sodama-protocheck.log

PROTO=${1:-}
TLS_MODE=${2:-none}
case "$PROTO" in
	vless)
		UUID=b831381d-6324-4d53-ad4f-8cda48b30811
		if [ "$TLS_MODE" = tls ]; then PORT=18544; SEC=tls; else PORT=18543; SEC=none; fi
		LINK="vless://$UUID@127.0.0.1:$PORT?type=tcp&security=$SEC&sni=localhost&allowInsecure=1&encryption=none"
		SERVER_ARGS="$LOG $UUID $PORT"
		SERVER="$LAB/vless_server.py"
		;;
	vmess)
		UUID=de305d54-75b4-431b-adb2-eb6b9e546014
		if [ "$TLS_MODE" = tls ]; then PORT=18644; TLS_FIELD=tls; else PORT=18643; TLS_FIELD=none; fi
		LINK=$(python3 - "$PORT" "$UUID" "$TLS_FIELD" <<'PY'
import base64, json, sys
port, uuid, tls = sys.argv[1:4]
obj = {"v": "2", "ps": "proto-check", "add": "127.0.0.1", "port": port, "id": uuid,
       "aid": "0", "scy": "aes-128-gcm", "net": "tcp", "type": "none"}
if tls == "tls":
    obj.update({"tls": "tls", "sni": "localhost", "allowInsecure": True})
print("vmess://" + base64.b64encode(json.dumps(obj).encode()).decode())
PY
)
		SERVER_ARGS="$LOG $UUID $PORT"
		SERVER="$LAB/vmess_server.py"
		;;
	*)
		echo "usage: $0 vless|vmess [tls]" >&2
		exit 2
		;;
esac

if [ "$TLS_MODE" = tls ]; then
	[ -f "$LAB/certs/cert.pem" ] || { echo "缺证书：先运行 lab/gen-certs.sh" >&2; exit 2; }
	SERVER_ARGS="$SERVER_ARGS $LAB/certs/cert.pem $LAB/certs/key.pem"
fi

# dae-work 不存在时先借 parity 建一次（顺带验证 Go 侧环境可用）。
if [ ! -d "$WORK" ]; then
	echo "== 初始化 dae-work（parity）=="
	"$PARITY/run.sh" "$LAB/rules.dae" >/dev/null
fi
mkdir -p "$WORK/protocheck"
cp "$HERE/zz_proto_check_test.go" "$WORK/protocheck/"

rm -f "$LOG"
python3 -u "$SERVER" $SERVER_ARGS >/tmp/sodama-protocheck.stdout 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT INT TERM
sleep 0.6
kill -0 "$PID" 2>/dev/null || { echo "服务端启动失败:"; cat /tmp/sodama-protocheck.stdout; exit 1; }

echo "== Go 客户端 ↔ Python $PROTO 服务端（$TLS_MODE）=="
echo "   link: $LINK"
(cd "$WORK" && PROTO_LINK="$LINK" go test -count=1 -run '^TestProtoCheck' ./protocheck)
echo "PROTO-CHECK $PROTO/$TLS_MODE: PASS"

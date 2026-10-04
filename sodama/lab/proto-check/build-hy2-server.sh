#!/bin/sh
# 构建 hysteria2 参考服务端（Go + quic-go fork + http3）。需要 parity 的 dae-work
# 模块图与本机 Go module 缓存（离线可构建，GOPROXY=off）。
#
# 用法： lab/proto-check/build-hy2-server.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(dirname "$HERE")
PARITY="$LAB/parity"
WORK="$PARITY/dae-work"

if [ ! -d "$WORK" ]; then
	echo "== 初始化 dae-work（parity）=="
	"$PARITY/run.sh" "$LAB/rules.dae" >/dev/null
fi

mkdir -p "$WORK/protocheck-hy2" "$HERE/bin"
cp "$HERE/hy2-server/main.go" "$WORK/protocheck-hy2/main.go"
(cd "$WORK" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$HERE/bin/hy2-server" ./protocheck-hy2)
echo "built: $HERE/bin/hy2-server"

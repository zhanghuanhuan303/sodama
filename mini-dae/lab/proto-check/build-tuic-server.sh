#!/bin/sh
# 构建 TUIC v5 参考服务端（Go + quic-go）。需要 parity 的 dae-work 模块图与
# 本机 Go module 缓存（离线可构建，GOPROXY=off）。
#
# 用法： lab/proto-check/build-tuic-server.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(dirname "$HERE")
PARITY="$LAB/parity"
WORK="$PARITY/dae-work"

if [ ! -d "$WORK" ]; then
	echo "== 初始化 dae-work（parity）=="
	"$PARITY/run.sh" "$LAB/rules.dae" >/dev/null
fi

mkdir -p "$WORK/protocheck-tuic" "$HERE/bin"
cp "$HERE/tuic-server/main.go" "$WORK/protocheck-tuic/main.go"
(cd "$WORK" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$HERE/bin/tuic-server" ./protocheck-tuic)
echo "built: $HERE/bin/tuic-server"

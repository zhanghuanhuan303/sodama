#!/bin/sh
# 构建 shadowsocksr-stream（origin proto + plain obfs）参考服务端（Go；复用
# parity dae-work 的 outbound/ciphers 模块图）。需要本机 Go module 缓存（离线
# 可构建，GOPROXY=off）。
#
# 用法： lab/proto-check/build-ssr-server.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(dirname "$HERE")
PARITY="$LAB/parity"
WORK="$PARITY/dae-work"

if [ ! -d "$WORK" ]; then
	echo "== 初始化 dae-work（parity）=="
	"$PARITY/run.sh" "$LAB/rules.dae" >/dev/null
fi

mkdir -p "$WORK/protocheck-ssr" "$HERE/bin"
cp "$HERE/ssr-server/main.go" "$WORK/protocheck-ssr/main.go"
(cd "$WORK" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$HERE/bin/ssr-server" ./protocheck-ssr)
echo "built: $HERE/bin/ssr-server"

#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# 构建 DoH over HTTP/3 参考服务端（Go + quic-go fork + http3）。需要 parity 的
# dae-work 模块图与本机 Go module 缓存（离线可构建，GOPROXY=off）。
#
# 用法： lab/proto-check/build-doh-h3-server.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(dirname "$HERE")
PARITY="$LAB/parity"
WORK="$PARITY/dae-work"

if [ ! -d "$WORK" ]; then
	echo "== 初始化 dae-work（parity）=="
	"$PARITY/run.sh" "$LAB/rules.dae" >/dev/null
fi

mkdir -p "$WORK/protocheck-doh-h3" "$HERE/bin"
cp "$HERE/doh-h3-server/main.go" "$WORK/protocheck-doh-h3/main.go"
(cd "$WORK" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$HERE/bin/doh-h3-server" ./protocheck-doh-h3)
echo "built: $HERE/bin/doh-h3-server"

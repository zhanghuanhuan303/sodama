#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# 构建 DoQ 参考服务端（Go + quic-go）。需要 parity 的 dae-work 模块图与
# 本机 Go module 缓存（离线可构建，GOPROXY=off）。
#
# 用法： lab/proto-check/build-doq-server.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=$(dirname "$HERE")
PARITY="$LAB/parity"
WORK="$PARITY/dae-work"

if [ ! -d "$WORK" ]; then
	echo "== 初始化 dae-work（parity）=="
	"$PARITY/run.sh" "$LAB/rules.dae" >/dev/null
fi

mkdir -p "$WORK/protocheck-doq" "$HERE/bin"
cp "$HERE/doq-server/main.go" "$WORK/protocheck-doq/main.go"
(cd "$WORK" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$HERE/bin/doq-server" ./protocheck-doq)
echo "built: $HERE/bin/doq-server"

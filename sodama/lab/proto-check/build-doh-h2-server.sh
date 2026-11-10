#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# 构建 DoH-over-HTTP/2 参考服务端（Go 标准库，无需外部依赖）。
# 用法： lab/proto-check/build-doh-h2-server.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$HERE/bin"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp "$HERE/doh-h2-server/main.go" "$TMP/main.go"
cat >"$TMP/go.mod" <<'EOF'
module protocheck-doh-h2

go 1.21
EOF
(cd "$TMP" && GOPROXY=off GOFLAGS=-mod=mod go build -o "$HERE/bin/doh-h2-server" .)
echo "built: $HERE/bin/doh-h2-server"

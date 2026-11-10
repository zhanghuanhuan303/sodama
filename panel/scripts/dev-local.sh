#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# 本机开发：后端跑在 127.0.0.1:8099，数据经 SSH 从路由器取；前端产物改完重跑 wasm-pack。
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST:?请设置 HOST=user@host}"
# 密码不落盘：通过环境变量传入（PASS=xxx scripts/dev-local.sh）
PASS="${PASS:?请提供路由器密码：PASS=xxx $0}"
S="sshpass -p $PASS ssh -o StrictHostKeyChecking=no $HOST"

~/.cargo/bin/wasm-pack build frontend --target web --release --out-dir dist/pkg --out-name panel
cp frontend/index.html frontend/styles.css frontend/dist/
cargo build -p backend

exec ./target/debug/backend \
  --bind 127.0.0.1:8099 \
  --static-dir frontend/dist \
  --token "${TOKEN:-}" \
  --status-cmd "$S /tmp/sodama status --socket /var/run/sodama.sock --json" \
  --logs-cmd "$S tail -n {n} /var/log/sodama.log" \
  --metrics-cmd "$S /tmp/sodama metrics --socket /var/run/sodama.sock"

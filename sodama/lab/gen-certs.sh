#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# 生成 trojan 测试用自签证书（CN/SAN=localhost，10 年）。
# 只在本地 lab 使用；证书和私钥都在 lab/certs/ 下（不入库，见 README）。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$HERE/certs"
mkdir -p "$DIR"
if [ -f "$DIR/cert.pem" ] && [ -f "$DIR/key.pem" ]; then
  echo "已存在：$DIR/cert.pem"
  exit 0
fi
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" -days 3650 \
  -subj /CN=localhost -addext "subjectAltName=DNS:localhost"
chmod 600 "$DIR/key.pem"
echo "已生成：$DIR/{cert.pem,key.pem}"

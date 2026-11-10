#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# P7：发布用静态二进制构建 + 最小冒烟（不需要 root、不加载 eBPF）。
#
#   lab/build-static.sh            # 构建并产出 build/sodama-static
#   SMOKE_ALPINE=1 lab/build-static.sh   # 额外在 redis:7-alpine 里跑用户态冒烟
#
# 路线说明（为什么不是 musl target）：
#   - rustls(ring) 需要 musl C 工具链（x86_64-linux-musl-gcc），本机没有；
#   - 本脚本改用 glibc 全静态（-C target-feature=+crt-static，static-pie），
#     产物不依赖动态加载器，可直接在 Alpine 等 musl rootfs 运行；
#   - 已知边界：glibc 静态二进制不适用依赖 NSS 的域名解析、dlopen；DNS 用数字 IP。
#   - 若装上 musl 工具链可直接 `cargo build --release --target
#     x86_64-unknown-linux-musl`（源码里的两处 libc 类型已用 `as _` 兼容；
#     musl 直构本机未验证）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
OUT="$ROOT/build/sodama-static"
TARGET_DIR="${STATIC_TARGET_DIR:-$ROOT/target/static}"
IMAGE="${SMOKE_IMAGE:-redis:7-alpine}"

echo "== 构建 static-pie（glibc crt-static）=="
RUSTFLAGS="-C target-feature=+crt-static" \
  CARGO_TARGET_DIR="$TARGET_DIR" \
  cargo build --release --target x86_64-unknown-linux-gnu --offline --manifest-path "$ROOT/Cargo.toml"
CAND="$TARGET_DIR/x86_64-unknown-linux-gnu/release/sodama"
[ -x "$CAND" ] || { echo "!! 未找到产物 $CAND"; exit 1; }
cp "$CAND" "$OUT"
ls -l "$OUT"
echo "-- file --"; file "$OUT"
echo "-- ldd --"; ldd "$OUT" 2>&1 || true

if [ -n "${SMOKE_ALPINE:-}" ]; then
  command -v docker >/dev/null || { echo "!! 需要 docker 做 alpine 冒烟"; exit 1; }
  echo "== alpine 冒烟（$IMAGE，用户态子命令）=="
  docker run --rm -v "$OUT:/sodama:ro" -v "$HERE:/lab:ro" "$IMAGE" \
    /sodama validate /lab/real-user.dae
  docker run --rm -v "$OUT:/sodama:ro" "$IMAGE" /sodama --help >/dev/null 2>&1 \
    && echo "smoke: --help OK" || echo "smoke: --help 以退出码 2（usage 约定）结束"
  echo "== 冒烟完成（仅用户态路径；eBPF 加载需要在宿主 netns/特权下另测）=="
fi

echo "== 完成：$OUT =="

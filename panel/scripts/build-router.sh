#!/usr/bin/env bash
# 构建路由器产物：前端 wasm + 后端 x86_64-musl 静态二进制
# 产物：dist/sodama-panel（二进制）、dist/www/（静态资源）
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

WASM_PACK="${WASM_PACK:-$HOME/.cargo/bin/wasm-pack}"
CARGO_ZIGBUILD="${CARGO_ZIGBUILD:-$HOME/.cargo/bin/cargo-zigbuild}"
ZIG="${ZIG:-$(command -v zig || echo "$HOME/.local/bin/zig")}"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"

echo "== 前端（wasm-pack release）=="
"$WASM_PACK" build frontend --target web --release --out-dir dist/pkg --out-name panel
cp frontend/index.html frontend/styles.css frontend/dist/

echo "== 后端（cargo-zigbuild $TARGET）=="
PATH="$(dirname "$ZIG"):$PATH" "$CARGO_ZIGBUILD" zigbuild -p backend --target "$TARGET" --release

OUT="$ROOT/dist"
mkdir -p "$OUT"
cp "target/$TARGET/release/backend" "$OUT/sodama-panel"
rm -rf "$OUT/www"
cp -r frontend/dist "$OUT/www"

echo "== 产物 =="
ls -lh "$OUT/sodama-panel"
du -sh "$OUT/www"

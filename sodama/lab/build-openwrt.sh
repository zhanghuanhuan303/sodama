#!/usr/bin/env bash
# OpenWrt（musl）交叉构建与交付物打包。
#
#   lab/build-openwrt.sh                       # 全架构（x86_64/aarch64/armv7）
#   lab/build-openwrt.sh --arch aarch64        # 单架构
#   lab/build-openwrt.sh --arch aarch64 --sdk-payload   # 并填充 install/openwrt/prebuilt/
#   lab/build-openwrt.sh --arch aarch64 --sdk-payload install/openwrt
#
# 产物（每架构）：build/openwrt/<arch>/{sodama,sodama-ebpf,LICENSE,VERSION}
# 依赖：rustup + rustup target + zig + cargo-zigbuild（脚本缺目标时自动 rustup target add）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
LOADER_DIR="$ROOT/loader"
OBJ="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
OUTROOT="$ROOT/build/openwrt"
CARGO_ZIGBUILD="${CARGO_ZIGBUILD:-$HOME/.cargo/bin/cargo-zigbuild}"
ZIG="${ZIG:-$(command -v zig || true)}"

ARCH="all"
SDK_PAYLOAD=""

while [ $# -gt 0 ]; do
  case "$1" in
  --arch)
    ARCH="$2"
    shift 2
    ;;
  --sdk-payload)
    shift
    if [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; then
      SDK_PAYLOAD="$1"
      shift
    else
      SDK_PAYLOAD="$(CDPATH= cd -- "$HERE/../../install/openwrt" && pwd)"
    fi
    ;;
  -h | --help)
    sed -n '2,12p' "$0"
    exit 0
    ;;
  *) echo "!! 未知参数：$1" >&2 && exit 2 ;;
  esac
done

die() { echo "!! $*" >&2; exit 1; }

target_of() {
  case "$1" in
  x86_64) echo x86_64-unknown-linux-musl ;;
  aarch64) echo aarch64-unknown-linux-musl ;;
  armv7) echo armv7-unknown-linux-musleabihf ;;
  *) die "未知架构：$1（x86_64|aarch64|armv7）" ;;
  esac
}

check_tools() {
  [ -x "$CARGO_ZIGBUILD" ] || die "缺 cargo-zigbuild（cargo install cargo-zigbuild）；可用 CARGO_ZIGBUILD= 指定"
  [ -n "$ZIG" ] || die "缺 zig（https://ziglang.org/download/）"
  echo "== 工具：zig $("$ZIG" version) · cargo-zigbuild $("$CARGO_ZIGBUILD" --version | awk '{print $2}') =="
}

ensure_target() {
  local t="$1"
  if ! rustup target list --installed 2>/dev/null | grep -qx "$t"; then
    echo "== rustup target add $t =="
    rustup target add "$t"
  fi
}

ensure_ebpf_object() {
  if [ ! -f "$OBJ" ]; then
    echo "== eBPF 对象缺失，构建中（lab/build-ebpf-rs.sh）=="
    "$HERE/build-ebpf-rs.sh"
  fi
  [ -f "$OBJ" ] || die "eBPF 对象不存在：$OBJ"
}

build_one() {
  local arch="$1" target out
  target="$(target_of "$arch")"
  out="$OUTROOT/$arch"
  ensure_target "$target"
  echo "== [$arch] cargo zigbuild --release --target $target =="
  (
    cd "$LOADER_DIR"
    PATH="$(dirname "$CARGO_ZIGBUILD"):$PATH" "$CARGO_ZIGBUILD" zigbuild --release --target "$target" \
      2>&1 | tail -2
  )
  local bin="$ROOT/target/$target/release/sodama"
  [ -x "$bin" ] || die "未找到产物：$bin"
  mkdir -p "$out"
  cp -f "$bin" "$out/sodama"
  cp -f "$OBJ" "$out/sodama-ebpf"
  [ -f "$ROOT/../LICENSE" ] && cp -f "$ROOT/../LICENSE" "$out/LICENSE" || true
  (cd "$LOADER_DIR" && cargo metadata --no-deps --format-version 1 2>/dev/null |
    python3 -c 'import json,sys;print(json.load(sys.stdin)["packages"][0]["version"])' >"$out/VERSION" 2>/dev/null) || echo "0.1.0" >"$out/VERSION"
  echo "   产物：$out/{sodama,sodama-ebpf}（sodama $(du -h "$out/sodama" | cut -f1) · ebpf $(du -h "$out/sodama-ebpf" | cut -f1)）"
  sha256sum "$out/sodama" "$out/sodama-ebpf" >"$out/SHA256SUMS"
}

if [ "$ARCH" = "all" ]; then
  ARCHES=(x86_64 aarch64 armv7)
else
  ARCHES=("$ARCH")
fi

check_tools
ensure_ebpf_object
for a in "${ARCHES[@]}"; do
  build_one "$a"
done

if [ -n "$SDK_PAYLOAD" ]; then
  [ "${#ARCHES[@]}" = "1" ] || die "--sdk-payload 需要配合单个 --arch（避免产物混淆）"
  mkdir -p "$SDK_PAYLOAD/prebuilt"
  cp -f "$OUTROOT/${ARCHES[0]}/sodama" "$OUTROOT/${ARCHES[0]}/sodama-ebpf" "$SDK_PAYLOAD/prebuilt/"
  echo "== 已填充 $SDK_PAYLOAD/prebuilt/（架构 ${ARCHES[0]}）=="
fi

echo "== 完成 =="

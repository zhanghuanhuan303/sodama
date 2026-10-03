#!/usr/bin/env bash
# P8：编译 Rust/aya-ebpf 数据面对象（offload 垂直切片）。
#
# 依赖（本机已配好，见 NOTES §11.13）：
#   - nightly 工具链 + rust-src 组件（-Z build-std=core）；
#   - bpf-linker（默认 ~/.cargo/bin/bpf-linker）；
#   - crates 镜像（~/.cargo/config.toml 指向 USTC，官方源被拦时必需）。
# 产物：ebpf-rs/target/bpfel-unknown-none/release/mini-dae-ebpf
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
OUT="$ROOT/ebpf-rs/target/bpfel-unknown-none/release/mini-dae-ebpf"

command -v rustup >/dev/null || { echo "!! 缺 rustup"; exit 1; }
rustup toolchain list 2>/dev/null | grep -q "^nightly" || {
  echo "!! 缺 nightly 工具链。安装示例（官方源被拦时用镜像）："
  echo "   RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup \\"
  echo "   RUSTUP_UPDATE_ROOT=https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup \\"
  echo "   rustup toolchain install nightly --profile minimal --component rust-src"
  exit 1
}
export PATH="$HOME/.cargo/bin:$PATH"
command -v bpf-linker >/dev/null || { echo "!! 缺 bpf-linker（cargo install bpf-linker）"; exit 1; }

echo "== cargo +nightly: ebpf-rs（bpfel-unknown-none / build-std=core）=="
(cd "$ROOT/ebpf-rs" && cargo +nightly build --release)
[ -f "$OUT" ] || { echo "!! 未产出 $OUT"; exit 1; }
ls -l "$OUT"
echo "== Rust eBPF 对象就绪：$OUT =="

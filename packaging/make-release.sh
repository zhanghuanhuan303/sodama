#!/usr/bin/env bash
# 生成 AUR `sodama-bin` 用的发布 tarball（x86_64，musl 静态，含 Web 面板）。
#
# 用法：
#   packaging/make-release.sh [版本]     # 默认取 sodama/loader/Cargo.toml 的 version
# 产物：
#   dist/sodama-<ver>-x86_64.tar.gz
#   dist/sodama-<ver>-x86_64.tar.gz.sha256
#
# 发布流程：把 tarball 上传到 GitHub Release（tag v<ver>），PKGBUILD 的 sha256 已固定，
# 两者必须字节一致（本脚本可复现；不同机器构建的产物可能因编译器版本不同而哈希不同，
# 因此发布前应在同一发布机重跑并回填 sha256）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER="${1:-$(grep -m1 '^version' "$ROOT/sodama/loader/Cargo.toml" | cut -d'"' -f2)}"
STAGE_ROOT="$ROOT/dist"
STAGE="$STAGE_ROOT/sodama-$VER-x86_64"
TARBALL="$STAGE_ROOT/sodama-$VER-x86_64.tar.gz"
CHANNEL="${SODAMA_RELEASE_CHANNEL:-stable}"

echo "== 版本：$VER（channel=$CHANNEL） =="

echo "== 1/3 引擎（musl 静态） =="
( cd "$ROOT/sodama" && PATH="$HOME/.cargo/bin:$PATH" sh lab/build-openwrt.sh --arch x86_64 )
ENGINE="$ROOT/sodama/build/openwrt/x86_64"

echo "== 2/3 Web 面板（wasm + musl 静态） =="
( cd "$ROOT/panel" && PATH="$HOME/.cargo/bin:$PATH" sh scripts/build-router.sh )
PANEL="$ROOT/panel/dist"

echo "== 3/3 组装 =="
rm -rf "$STAGE"
install -d "$STAGE"

# 引擎 + eBPF 数据面
install -Dm755 "$ENGINE/sodama" "$STAGE/usr/bin/sodama"
install -Dm644 "$ENGINE/sodama-ebpf" "$STAGE/usr/lib/sodama/sodama-ebpf"
install -Dm755 "$ROOT/packaging/arch/sodama-datapath" "$STAGE/usr/lib/sodama/datapath"

# systemd
install -Dm644 "$ROOT/packaging/arch/sodama.service" "$STAGE/usr/lib/systemd/system/sodama.service"
install -Dm644 "$ROOT/packaging/arch/sodama-panel.service" \
  "$STAGE/usr/lib/systemd/system/sodama-panel.service"

# 配置（权限与校验要求一致：0640）
install -Dm640 "$ROOT/packaging/arch/config.dae" "$STAGE/etc/sodama/config.dae"
install -Dm644 "$ROOT/packaging/arch/sodama.conf" "$STAGE/etc/sodama/sodama.conf"
install -Dm640 "$ROOT/packaging/arch/panel.conf" "$STAGE/etc/sodama-panel/panel.conf"

# 面板（后端二进制 + 前端静态资源）
install -Dm755 "$PANEL/sodama-panel" "$STAGE/usr/bin/sodama-panel"
install -d "$STAGE/usr/share/sodama-panel"
cp -a "$PANEL/www" "$STAGE/usr/share/sodama-panel/dist"
# wasm-pack 会在 pkg/ 里留一个占位 .gitignore（1 字节）；包内不需要
rm -f "$STAGE/usr/share/sodama-panel/dist/pkg/.gitignore"
chmod -R a+rX "$STAGE/usr/share/sodama-panel"

# 补全
install -Dm644 "$ROOT/install/shell-completion/sodama.bash" \
  "$STAGE/usr/share/bash-completion/completions/sodama"
install -Dm644 "$ROOT/install/shell-completion/sodama.zsh" \
  "$STAGE/usr/share/zsh/site-functions/_sodama"
install -Dm644 "$ROOT/install/shell-completion/sodama.fish" \
  "$STAGE/usr/share/fish/vendor_completions.d/sodama.fish"

# 文档
install -Dm644 "$ROOT/LICENSE" "$STAGE/usr/share/licenses/sodama/LICENSE"
install -Dm644 "$ROOT/docs/arch-linux.md" "$STAGE/usr/share/doc/sodama/README.md"
install -Dm644 "$ROOT/docs/config-reference.md" "$STAGE/usr/share/doc/sodama/config-reference.md"
printf '%s\n' "$VER" >"$STAGE/usr/share/doc/sodama/VERSION"

# tar（属主 root、保留权限；gzip -n 去时间戳保证可复现性尽力而为）
echo "== 打包 =="
tar --owner=0 --group=0 --numeric-owner -C "$STAGE_ROOT" -cf - "sodama-$VER-x86_64" \
  | gzip -9n >"$TARBALL"
( cd "$STAGE_ROOT" && sha256sum "sodama-$VER-x86_64.tar.gz" >"sodama-$VER-x86_64.tar.gz.sha256" )

echo
echo "== 产物 =="
ls -lh "$TARBALL" "$TARBALL.sha256"
cat "$TARBALL.sha256"
echo
echo "提示：把 tarball 上传到 $ROOT 对应的 GitHub Release（tag v$VER），"
echo "      并把上面 sha256 回填到 packaging/aur/sodama-bin/PKGBUILD。"

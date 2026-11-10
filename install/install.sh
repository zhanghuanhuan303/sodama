#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# sodama 安装 / 卸载脚本（systemd 部署路径）。
#
# 用法：
#   sudo install/install.sh                 # 缺构建产物则构建；安装并打印 enable/start 提示
#   sudo install/install.sh --build         # 强制重新构建 loader 与 eBPF 对象
#   sudo install/install.sh --no-build      # 只用已构建产物（缺失则报错）
#   install/install.sh --dry-run            # 只打印将执行的命令，零写入（可非 root）
#   sudo install/install.sh --uninstall     # 停止/禁用并删除二进制与单元（保留 /etc/sodama）
#   install/install.sh --help
#
# 安装布局：
#   /usr/local/bin/sodama                     loader
#   /usr/lib/sodama/sodama-ebpf             eBPF 数据面对象
#   /etc/systemd/system/sodama.service        systemd 单元
#   /etc/sodama/config.dae                    仅当不存在时从 sodama/lab/gateway.dae 拷贝
#   /etc/sodama/blocklist.txt                 同上（gateway.dae 的 qname(file:) 相对配置目录解析）
#   shell 补全：bash → /usr/share/bash-completion/completions/sodama
#              zsh  → /usr/share/zsh/site-functions/_sodama
#              fish → /usr/share/fish/vendor_completions.d/sodama.fish
#
# 重要：sodama.service 的 ExecStart 只是骨架，启动前必须补齐节点/订阅与数据面前置；
# 见 docs/deploy.md（脚本结束时会打印同样的提示）。

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$HERE")"
MINI="$REPO_ROOT/sodama"

LOADER_SRC="$MINI/target/release/sodama"
OBJ_SRC="$MINI/ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf"
CONFIG_SAMPLE="$MINI/lab/gateway.dae"
BLOCKLIST_SAMPLE="$MINI/lab/blocklist.txt"
SERVICE_SRC="$HERE/sodama.service"
COMPLETION_SRC="$HERE/shell-completion"

BIN_DST="/usr/local/bin/sodama"
OBJ_DST="/usr/lib/sodama/sodama-ebpf"
SERVICE_DST="/etc/systemd/system/sodama.service"
BASH_COMP_DST="/usr/share/bash-completion/completions/sodama"
ZSH_COMP_DST="/usr/share/zsh/site-functions/_sodama"
FISH_COMP_DST="/usr/share/fish/vendor_completions.d/sodama.fish"
CONFIG_DIR="/etc/sodama"
CONFIG_DST="$CONFIG_DIR/config.dae"
BLOCKLIST_DST="$CONFIG_DIR/blocklist.txt"

MODE="auto" # auto | build | nobuild
DRY_RUN=0
UNINSTALL=0

die() { echo "错误：$*" >&2; exit 1; }
info() { echo "== $* =="; }

usage() {
  cat <<'EOF'
用法：
  sudo install/install.sh [--build | --no-build] [--dry-run]
  sudo install/install.sh --uninstall [--dry-run]
  install/install.sh --help

选项：
  --build      强制重新构建 loader 与 eBPF 对象
               （sodama/lab/build-ebpf-rs.sh + cargo build --release）
  --no-build   只用已构建产物；缺失则报错退出
  --dry-run    只打印将执行的命令，不写任何文件（可非 root 运行）
  --uninstall  停止/禁用并删除已安装的二进制与 systemd 单元（保留 /etc/sodama 配置）
  -h, --help   显示本帮助
EOF
}

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  +'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

require_root() {
  if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "需要 root：sudo $0"
  fi
}

# 构建 loader + eBPF 对象。经 sudo 调用时以 SUDO_USER 身份构建，避免 target/ 变 root 属主。
build_all() {
  local cmd="cd '$MINI' && lab/build-ebpf-rs.sh && cargo build --release"
  if [ "$DRY_RUN" -eq 1 ]; then
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
      echo "  + runuser -u $SUDO_USER -- bash -lc \"$cmd\""
    else
      echo "  + bash -lc \"$cmd\""
    fi
    return 0
  fi
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && command -v runuser >/dev/null 2>&1; then
    runuser -u "$SUDO_USER" -- bash -lc "$cmd"
  else
    bash -lc "$cmd"
  fi
}

ensure_artifacts() {
  case "$MODE" in
  build)
    info "构建 loader 与 eBPF 对象（--build）"
    build_all
    ;;
  nobuild)
    [ -x "$LOADER_SRC" ] || die "--no-build 但缺少 $LOADER_SRC（先跑 sodama/lab/lab.sh build）"
    [ -f "$OBJ_SRC" ] || die "--no-build 但缺少 $OBJ_SRC（先跑 sodama/lab/build-ebpf-rs.sh）"
    info "使用已构建产物（--no-build）"
    ;;
  auto)
    if [ -x "$LOADER_SRC" ] && [ -f "$OBJ_SRC" ]; then
      info "使用已构建产物（--build 可强制重建）"
    else
      info "缺少构建产物，开始构建"
      build_all
    fi
    ;;
  esac
  [ "$DRY_RUN" -eq 1 ] && return 0
  [ -x "$LOADER_SRC" ] || die "构建后仍缺少 $LOADER_SRC"
  [ -f "$OBJ_SRC" ] || die "构建后仍缺少 $OBJ_SRC"
}

check_sources() {
  [ -f "$SERVICE_SRC" ] || die "缺少单元文件：$SERVICE_SRC"
  [ -f "$CONFIG_SAMPLE" ] || die "缺少样例配置：$CONFIG_SAMPLE"
  [ -f "$BLOCKLIST_SAMPLE" ] || die "缺少名单样例：$BLOCKLIST_SAMPLE"
}

systemd_reload() {
  if command -v systemctl >/dev/null 2>&1; then
    run systemctl daemon-reload
  else
    echo "   未找到 systemctl（容器环境？）：跳过 daemon-reload，请手动加载单元" >&2
  fi
}

install_all() {
  info "安装二进制与单元"
  run install -Dm755 "$LOADER_SRC" "$BIN_DST"
  run install -Dm644 "$OBJ_SRC" "$OBJ_DST"
  run install -Dm644 "$SERVICE_SRC" "$SERVICE_DST"

  # P38：shell 补全（预生成副本；缺失则跳过——如裁剪源码树/发行包不含 install/）。
  if [ -f "$COMPLETION_SRC/sodama.bash" ]; then
    info "shell 补全（bash/zsh/fish）"
    run install -Dm644 "$COMPLETION_SRC/sodama.bash" "$BASH_COMP_DST"
    run install -Dm644 "$COMPLETION_SRC/sodama.zsh" "$ZSH_COMP_DST"
    run install -Dm644 "$COMPLETION_SRC/sodama.fish" "$FISH_COMP_DST"
  else
    echo "   未找到 $COMPLETION_SRC（跳过；可用 sodama completion bash|zsh|fish 现拉）" >&2
  fi

  info "配置样例（$CONFIG_DIR）"
  if [ -e "$CONFIG_DST" ]; then
    echo "   已存在 $CONFIG_DST：保留不覆盖"
  else
    run install -Dm640 "$CONFIG_SAMPLE" "$CONFIG_DST"
    run install -Dm644 "$BLOCKLIST_SAMPLE" "$BLOCKLIST_DST"
  fi

  systemd_reload

  echo
  info "完成"
  cat <<'EOF'
下一步（首次安装必读）：
  1) 补齐单元参数（节点/订阅 + 数据面接口）。用 drop-in 覆盖 ExecStart：
       sudo systemctl edit sodama
       [Service]
       ExecStart=
       ExecStart=/usr/local/bin/sodama --config /etc/sodama/config.dae \
           --ebpf /usr/lib/sodama/sodama-ebpf \
           --lan none --wan wlan0 --daens gwdae --dae0 dae0gw --dae0peer dae0gwpeer \
           --dialer 'anytls://<节点>'
       # 或把订阅 URL 写进 /etc/sodama/sub.url（chmod 600）后：
       #   --subscribe file:///etc/sodama/sub.url --group proxy
       # 注意：systemd 单元里 URL 的 % 必须写成 %%；放进文件可绕开。
  2) geodata：样例 dns.routing 用到 geosite，需要 geosite.dat/geoip.dat。
     放到 /etc/sodama/（配置文件所在目录会被自动搜索）或加 --geodata-dir <目录>。
  3) 数据面前置（netns/veth/sysctl）loader 不会自行创建，见 docs/deploy.md。
  4) 启动与观察：
       sudo systemctl enable --now sodama
       systemctl status sodama
       journalctl -u sodama -f
  5) 热重载（SIGHUP）：sudo systemctl reload sodama

若本次拷贝了样例配置，请务必先完成 1)~3) 再启动；否则会启动失败或代理不通。
EOF
}

uninstall_all() {
  info "卸载 sodama（保留 $CONFIG_DIR）"
  if command -v systemctl >/dev/null 2>&1; then
    run systemctl disable --now sodama.service || true
  fi
  run rm -f "$BIN_DST" "$OBJ_DST" "$SERVICE_DST"
  run rm -f "$BASH_COMP_DST" "$ZSH_COMP_DST" "$FISH_COMP_DST"
  if [ "$DRY_RUN" -eq 0 ]; then
    rmdir /usr/lib/sodama 2>/dev/null || true
  fi
  systemd_reload
  echo "已删除二进制与单元；配置保留在 $CONFIG_DIR（如需删除：sudo rm -rf $CONFIG_DIR）"
}

while [ $# -gt 0 ]; do
  case "$1" in
  --build)
    MODE="build"
    shift
    ;;
  --no-build)
    MODE="nobuild"
    shift
    ;;
  --dry-run)
    DRY_RUN=1
    shift
    ;;
  --uninstall)
    UNINSTALL=1
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    die "未知参数：$1（-h 查看用法）"
    ;;
  esac
done

if [ "$UNINSTALL" -eq 1 ]; then
  require_root
  uninstall_all
  exit 0
fi

require_root
check_sources
ensure_artifacts
install_all

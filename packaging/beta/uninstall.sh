#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# sodama 干净卸载脚本（Arch Linux）
#
#   sudo bash uninstall.sh            # 交互确认：停服务 → 清理拓扑/残留 → pacman -R → 询问是否删配置
#   sudo bash uninstall.sh -y         # 不确认，保留 /etc 与日志
#   sudo bash uninstall.sh -y --purge # 不确认，连配置和日志一起删
#   sudo bash uninstall.sh --dry-run  # 只打印将要做什么
#
# 清理范围：
#   服务：sodama-panel、sodama（disable + stop）
#   拓扑：netns daens / veth dae0（调用 /usr/lib/sodama/datapath teardown；rules 都在 netns 内）
#   包：  pacman -R sodama-bin（含 /usr/bin/sodama*、/usr/lib/sodama/*、systemd 单元、面板静态资源）
#   残留：/run/sodama、/etc/systemd/system/{sodama,sodama-panel}.service.d
#   可选（--purge）：/etc/sodama、/etc/sodama-panel、/var/log/sodama.log*
#
# 不做的：内核 sysctl（ip_forward / rp_filter）不回滚——它们可能是你系统本来就需要的。
set -euo pipefail

ASSUME_YES=0
PURGE=0
DRY=0
for a in "$@"; do
  case "$a" in
    -y | --yes) ASSUME_YES=1 ;;
    --purge | --all) PURGE=1 ;;
    --dry-run) DRY=1 ;;
    -h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf '未知参数：%s（-h 看用法）\n' "$a" >&2; exit 2 ;;
  esac
done

die() { printf '✗ %s\n' "$*" >&2; exit 1; }
ok() { printf '✓ %s\n' "$*"; }
warn() { printf '! %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*"; }

[[ "$(id -u)" -eq 0 ]] || die "卸载需要 root：sudo bash $0"
[[ -f /etc/arch-release ]] || die "这不是 Arch Linux"

run() { # 执行或（--dry-run 时）只打印
  if ((DRY == 1)); then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}

# ---------------------------------------------------------------- 计划
step "将要执行"
echo "  1) systemctl disable --now sodama-panel sodama"
echo "  2) /usr/lib/sodama/datapath teardown   （netns daens / veth dae0）"
echo "  3) pacman -R sodama-bin"
echo "  4) 清理 /run/sodama、systemd drop-in"
if ((PURGE == 1)); then
  echo "  5) 删除配置与日志：/etc/sodama、/etc/sodama-panel、/var/log/sodama.log*"
else
  echo "  5) 保留配置与日志（加 --purge 才删）"
fi

if ((ASSUME_YES == 0 && DRY == 0)); then
  printf '\n继续？[y/N]: '
  read -r ans || ans=""
  case "${ans,,}" in y | yes) ;; *) die "已取消" ;; esac
fi

# ---------------------------------------------------------------- 1 服务
step "1/5 停止服务"
for u in sodama-panel sodama; do
  if systemctl list-unit-files "$u.service" >/dev/null 2>&1 &&
    systemctl cat "$u.service" >/dev/null 2>&1; then
    run systemctl disable --now "$u" 2>/dev/null || true
    ok "$u 已停止并取消自启"
  else
    ok "$u 未安装，跳过"
  fi
done

# ---------------------------------------------------------------- 2 拓扑
step "2/5 清理数据面拓扑"
if [[ -x /usr/lib/sodama/datapath ]]; then
  run /usr/lib/sodama/datapath teardown || warn "datapath teardown 失败"
  ok "datapath teardown 已执行"
else
  warn "/usr/lib/sodama/datapath 不存在，手动清理"
  run ip netns del daens 2>/dev/null || true
  run ip link del dae0 2>/dev/null || true
fi

# ---------------------------------------------------------------- 3 包
step "3/5 移除软件包"
if pacman -Qq sodama-bin >/dev/null 2>&1; then
  run pacman -R --noconfirm sodama-bin || warn "pacman -R 失败，可能被其他包依赖；手动处理"
  ok "sodama-bin 已移除"
elif pacman -Qq sodama >/dev/null 2>&1; then
  run pacman -R --noconfirm sodama || warn "pacman -R 失败"
  ok "sodama（源码包）已移除"
else
  ok "未安装 sodama 包，跳过"
fi

# ---------------------------------------------------------------- 4 残留
step "4/5 清理残留"
run rm -rf /run/sodama
for d in /etc/systemd/system/sodama.service.d /etc/systemd/system/sodama-panel.service.d; do
  [[ -d "$d" ]] && { run rm -rf "$d"; ok "删除 $d"; }
done
run systemctl daemon-reload
run systemctl reset-failed sodama sodama-panel 2>/dev/null || true
ok "运行目录与 drop-in 已清理"

# ---------------------------------------------------------------- 5 配置
step "5/5 配置与日志"
if ((PURGE == 0)); then
  if ((ASSUME_YES == 1)); then
    ans=n
  else
    printf '删除配置与日志（/etc/sodama、/etc/sodama-panel、/var/log/sodama.log*）？[y/N]: '
    read -r ans || ans=""
  fi
  case "${ans,,}" in y | yes) PURGE=1 ;; *) PURGE=0 ;; esac
fi

if ((PURGE == 1)); then
  run rm -rf /etc/sodama /etc/sodama-panel
  run rm -f /var/log/sodama.log /var/log/sodama.log.*
  run rm -f "/etc/sodama/config.dae.pacnew" "/etc/sodama/config.dae.pacsave"
  ok "配置与日志已删除"
else
  ok "已保留：/etc/sodama、/etc/sodama-panel、/var/log/sodama.log*"
fi

# ---------------------------------------------------------------- 复核
step "复核"
left=0
if ip netns list 2>/dev/null | grep -qw daens; then
  warn "残留 netns daens：ip netns del daens"; left=1
fi
if ip link show dev dae0 >/dev/null 2>&1; then
  warn "残留接口 dae0：ip link del dae0"; left=1
fi
if pacman -Qq sodama-bin >/dev/null 2>&1; then
  warn "sodama-bin 仍在包数据库：pacman -Ql sodama-bin"; left=1
fi
if systemctl is-active --quiet sodama 2>/dev/null; then
  warn "sodama 仍在运行"; left=1
fi
((left == 0)) && ok "没有发现残留"

cat <<'EOF'

注意：
  - 内核 sysctl 未回滚（ip_forward=1、rp_filter=0）。如需恢复：
      sudo sysctl -w net.ipv4.conf.all.rp_filter=1
    或直接重启。
  - sodama 用 TC/eBPF，不写 nftables/iptables 规则；卸载后不会残留防火墙规则
    （eBPF 钩子随进程退出自动摘除）。
EOF

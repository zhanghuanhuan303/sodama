#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

# OpenWrt x86_64 QEMU 冒烟（P0 验证链）：
#   官方 24.10.4 镜像 + sodama musl 产物 + 离线 kmod/ipk →
#   验证「二进制可运行 → ipk 可装 → veth/datapath 可建 → eBPF 加载/TCX 挂载 → status 可查」。
#
# 用法：
#   sudo lab/openwrt-smoke.sh                 # 首次自动下载镜像/ipk 到 /tmp（有缓存）
#   sudo lab/openwrt-smoke.sh --arch aarch64  # 只用于产物选择（QEMU 仍为 x86_64 宿主模拟）
# 产物来源：build/openwrt/x86_64/（缺则调用 lab/build-openwrt.sh --arch x86_64）
#
# 依赖：qemu-system-x86_64、python3、mkfs.ext4（e2fsprogs）；root（qemu + loop 无关，仅 console 驱动）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
VER=24.10.4
KVER=6.6.110-r1
CACHE=/tmp/owrt-cache
IMG="${OPENWRT_IMG:-/tmp/openwrt-$VER-x86.img}"
IMG_GZ=$IMG.gz
CUSTOM_IMG=0
[ -n "${OPENWRT_IMG:-}" ] && CUSTOM_IMG=1
SHARE=/tmp/owrt-share.ext4
PAYLOAD=/tmp/owrt-payload
CONSOLE=/tmp/owrt-console.cmds
LOG=/tmp/owrt-smoke.log
BASE_URL="https://downloads.openwrt.org/releases/$VER"
KMOD_DIR="$BASE_URL/targets/x86/64/kmods/6.6.110-1-484466e2719a743506c36b4bb2103582"

die() { echo "!! $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "缺 $1"; }

fetch() { # <url> <out>
  [ -s "$2" ] && return 0
  echo "   下载 $(basename "$2") …"
  curl -fsS --retry 2 --max-time 600 "$1" -o "$2"
}

prepare_image() {
  need curl
  if [ "$CUSTOM_IMG" = "1" ]; then
    [ -s "$IMG" ] || die "自定义镜像不存在：$IMG"
    return 0
  fi
  if [ ! -f "$IMG" ]; then
    fetch "$BASE_URL/targets/x86/64/openwrt-$VER-x86-64-generic-ext4-combined.img.gz" "$IMG_GZ"
    # OpenWrt 镜像 gz 带尾部对齐填充，gzip 会以告警码 2 结束——容忍但验证尺寸
    gzip -dc "$IMG_GZ" >"$IMG" 2>/dev/null || true
    [ "$(wc -c <"$IMG")" -gt 100000000 ] || die "镜像解压不完整：$IMG"
  fi
}

prepare_ipks() {
  mkdir -p "$CACHE"
  fetch "$BASE_URL/packages/x86_64/base/ip-full_6.11.0-r1_x86_64.ipk" \
    "$CACHE/ip-full_6.11.0-r1_x86_64.ipk"
  fetch "$KMOD_DIR/kmod-veth_${KVER}_x86_64.ipk" "$CACHE/kmod-veth_${KVER}_x86_64.ipk"
  fetch "$KMOD_DIR/kmod-sched-core_${KVER}_x86_64.ipk" "$CACHE/kmod-sched-core_${KVER}_x86_64.ipk"
  fetch "$KMOD_DIR/kmod-sched-bpf_${KVER}_x86_64.ipk" "$CACHE/kmod-sched-bpf_${KVER}_x86_64.ipk"
}

prepare_payload() {
  local L="$ROOT/build/openwrt/x86_64"
  if [ ! -x "$L/sodama" ] || [ ! -f "$L/sodama-ebpf" ]; then
    "$HERE/build-openwrt.sh" --arch x86_64
  fi
  [ -x "$L/sodama" ] || die "缺产物：$L/sodama"
  rm -rf "$PAYLOAD"
  mkdir -p "$PAYLOAD"
  cp -f "$L/sodama" "$L/sodama-ebpf" "$PAYLOAD/"
  cp -f "$ROOT/../install/openwrt/files/sodama-datapath" "$PAYLOAD/"
  [ "$CUSTOM_IMG" = "0" ] && cp -f "$CACHE"/*.ipk "$PAYLOAD/" && touch "$PAYLOAD/official-image"

  cat >"$PAYLOAD/smoke.sh" <<'EOF'
#!/bin/sh
# guest 内冒烟（root 控制台运行；/mnt = 共享盘）
echo "### SMOKE_BEGIN ###"
echo "-- uname:"; uname -a
echo "-- btf:"; ls /sys/kernel/btf/ 2>/dev/null || echo "no /sys/kernel/btf"
echo "-- cgroup2:"; mount | grep -q cgroup2 && echo "cgroup2 mounted" || echo "no cgroup2 mount"
echo "-- opkg --"
if [ -f /mnt/official-image ]; then
  opkg install /mnt/kmod-veth_*.ipk /mnt/kmod-sched-core_*.ipk /mnt/kmod-sched-bpf_*.ipk /mnt/ip-full_*.ipk 2>&1 | tail -5
else
  echo "自定义镜像：kmod 已内建，仅装 ip-full"
  opkg install /mnt/ip-full_*.ipk 2>&1 | tail -3
fi
modprobe veth 2>&1 || true
modprobe sch_ingress 2>&1 || true
modprobe cls_bpf 2>&1 || true
echo "-- veth --"
ip link add veth0 type veth peer name veth1 && echo VETH_OK || echo VETH_FAIL
ip link set veth0 up 2>/dev/null; ip link set veth1 up 2>/dev/null
echo "-- install --"
mkdir -p /usr/lib/sodama /etc/sodama /var/log /var/run
cp /mnt/sodama /usr/bin/sodama && chmod 755 /usr/bin/sodama
cp /mnt/sodama-ebpf /usr/lib/sodama/sodama-ebpf
cp /mnt/sodama-datapath /usr/lib/sodama/sodama-datapath && chmod 755 /usr/lib/sodama/sodama-datapath
printf 'fallback -> direct\n' >/etc/sodama/rules.dae
chmod 600 /etc/sodama/rules.dae
echo "-- datapath --"
DAE_NS=daens DAE0=dae0 DAE0PEER=dae0peer /usr/lib/sodama/sodama-datapath setup && echo DATAPATH_OK || echo DATAPATH_FAIL
echo "-- loader --"
/usr/bin/sodama --ebpf /usr/lib/sodama/sodama-ebpf --lan none --wan veth0 \
  --dae0 dae0 --dae0peer dae0peer --daens daens \
  --rules /etc/sodama/rules.dae --dialer direct \
  --status-socket /var/run/sodama.sock --log-file /var/log/sodama.log &
sleep 4
if pgrep -f '/usr/bin/sodama' >/dev/null; then echo LOADER_ALIVE; else echo LOADER_DEAD; fi
echo "-- status --"
/usr/bin/sodama status --socket /var/run/sodama.sock 2>&1 | head -14
echo "-- log tail --"
tail -12 /var/log/sodama.log
echo "### SMOKE_END ###"
EOF
  chmod 755 "$PAYLOAD/smoke.sh"
}

build_share() {
  need mkfs.ext4
  dd if=/dev/zero of="$SHARE" bs=1M count=48 status=none
  mkfs.ext4 -q -F -d "$PAYLOAD" "$SHARE"
}

write_console_script() {
  cat >"$CONSOLE" <<'EOF'
# OpenWrt x86 控制台：启动 → Enter → mount 共享盘 → 跑 guest 冒烟
# 注意：官方镜像未设主机名时提示符是 root@(none):~#，故用通用 prompt 匹配
EXPECT Please press Enter|:~#
SEND \n
EXPECT :~#
SEND mkdir -p /mnt; mount /dev/vdb /mnt && ls /mnt
EXPECT :~#
SEND sh /mnt/smoke.sh
EXPECT SMOKE_END|can't open /mnt/smoke.sh
SLEEP 2
MARK guest-done
QUIT
EOF
}

run_qemu() {
  need qemu-system-x86_64
  need python3
  local accel=()
  [ -w /dev/kvm ] && accel=(-accel kvm)
  echo "== QEMU 启动（镜像 $IMG、共享盘 $SHARE）=="
  set +e
  python3 "$HERE/qemu-console.py" "$CONSOLE" -- \
    qemu-system-x86_64 -m 512 -smp 2 -nographic "${accel[@]}" \
    -snapshot \
    -drive "file=$IMG,format=raw,if=virtio" \
    -drive "file=$SHARE,format=raw,if=virtio" \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    2>&1 | tee "$LOG"
  set -e
}

summarize() {
  echo
  echo "========== OpenWrt 冒烟结果 =========="
  local fail=0
  check() { # <标记> <说明>
    if grep -q "$1" "$LOG"; then echo "  PASS  $2"; else echo "  FAIL  $2（未见到 $1）"; fail=1; fi
  }
  check "SMOKE_BEGIN" "guest 冒烟启动"
  check "VETH_OK" "veth 创建（kmod-veth 可用）"
  check "DATAPATH_OK" "数据面对建立（netns/veth/策略路由）"
  check "LOADER_ALIVE" "loader 存活"
  check "LOADER_DEAD" "loader 启动失败（见日志）"
  # loader 存活视为 eBPF 加载成功（启动即加载并挂载 7+6 钩子）
  if grep -q "attached sodama_lan_ingress\|entered netns daens" "$LOG"; then
    echo "  PASS  eBPF 加载与挂载（日志见 attached/entered）"
  else
    echo "  WARN  未见 eBPF 挂载日志（loader 可能未走到挂载阶段）"
  fi
  grep -q "LOADER_DEAD" "$LOG" && fail=1
  grep -q "DATAPATH_FAIL" "$LOG" && fail=1
  [ -f /tmp/owrt-smoke.log ] || true
  echo "====================================="
  echo "完整日志：$LOG"
  return $fail
}

ARCH=x86_64
while [ $# -gt 0 ]; do
  case "$1" in
  --arch)
    ARCH="$2"
    shift 2
    ;;
  *) die "未知参数：$1" ;;
  esac
done
[ "$ARCH" = "x86_64" ] || die "QEMU 冒烟只支持 x86_64 产物（当前 --arch $ARCH）"

echo "== 准备镜像/ipk/产物/共享盘（缓存于 /tmp）=="
prepare_image
prepare_ipks
prepare_payload
build_share
write_console_script
run_qemu
summarize

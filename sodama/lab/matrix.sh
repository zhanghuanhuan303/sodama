#!/usr/bin/env bash
# K2 内核矩阵：同一份 sodama，在不同内核上跑同一套验证。
#
#   lab/matrix.sh check        # 打印当前内核版本与能力门槛（5.17 / 6.6 / 6.14.7）
#   lab/matrix.sh run          # 当前内核：up + verify（需 root），打印 MATRIX-RESULT
#                              # 可用 MATRIX_LOG=<path> 追加落盘（VM 内用）
#   lab/matrix.sh initramfs    # 生成 QEMU 用的 initramfs（宿主用户即可）
#   lab/matrix.sh vm [vmlinuz] # 在 QEMU 里引导第二个内核并跑 run（宿主用户即可）
#
# 宿主内核路径（本机 6.18.54-lts）直接用 run；
# 第二个内核用 /usr/lib/modules/7.2.8-arch1-2/vmlinuz + 自制 initramfs（9p root）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
MATRIX_DIR="$HERE/matrix"
OUT="$MATRIX_DIR/out"
STOCK_INITRAMFS="${STOCK_INITRAMFS:-/boot/initramfs-linux.img}"
KERNEL_PATH="${KERNEL_PATH:-/usr/lib/modules/7.2.8-arch1-2/vmlinuz}"
KVER="${KVER:-7.2.8-arch1-2}"
INITRD="$OUT/initramfs-$KVER.img"

die() { echo "!! $*" >&2; exit 1; }

kernel_gates() {
  local ver mm v1 v2
  ver="$(uname -r)"
  mm="${ver%%-*}"
  v1="${mm%%.*}"
  v2="${mm#*.}"
  v2="${v2%%.*}"
  echo "kernel: $ver"
  if [ "$v1" -gt 5 ] || { [ "$v1" = 5 ] && [ "$v2" -ge 17 ]; }; then
    echo "  bpf_loop (>=5.17): 支持（规则 VM 的前提）"
  else
    echo "  bpf_loop (>=5.17): 不支持 —— 预期 sodama 加载失败（诊断应为 fail-closed）"
  fi
  if [ "$v1" -gt 6 ] || { [ "$v1" = 6 ] && [ "$v2" -ge 6 ]; }; then
    echo "  TCX (>=6.6): 支持（钩子随进程退出自动摘除）"
  else
    echo "  TCX (>=6.6): 不支持 —— aya 会退回 netlink/cls_bpf，摘钩语义不同"
  fi
  if [ "$v1" -gt 6 ] || { [ "$v1" = 6 ] && [ "$v2" -ge 15 ]; }; then
    echo "  bpf_redirect_peer: 该线已含 CVE-2025-37959 修复（mainline>=6.14.7）；sodama 未用，仅记录"
  else
    echo "  bpf_redirect_peer: 是否含 CVE 修复需查 stable 回合（mainline>=6.14.7）；sodama 未用"
  fi
}

check() {
  kernel_gates
  echo "  说明：5.17/6.1/6.6 的下限覆盖需要多内核宿主或虚拟机；本脚本可跑任意满足门槛的内核。"
}

run_body() {
  echo "=== sodama 内核矩阵：kernel $(uname -r) ==="
  date -Is
  check
  "$HERE/lab.sh" up || return 1
  local result=PASS
  "$HERE/lab.sh" verify || result=FAIL
  "$HERE/lab.sh" down || true
  echo "MATRIX-RESULT kernel=$(uname -r) verify=$result"
  [ "$result" = PASS ]
}

run() {
  [ "$(id -u)" = 0 ] || die "run 需要 root（容器/chroot 里跑亦可）"
  mkdir -p "$OUT"
  if [ -n "${MATRIX_LOG:-}" ]; then
    run_body 2>&1 | tee "$MATRIX_LOG"
    return "${PIPESTATUS[0]}"
  fi
  run_body
}

# 生成 QEMU 用的 initramfs：stock initramfs 里没有 9p/virtio 模块，
# 我们从 /usr/lib/modules/<kver> 拷入依赖闭包（netfs→9pnet→9pnet_virtio→9p），
# 并用自制 /init 取代发行版 init：insmod 后把宿主根挂成 9p，再 chroot 跑 vm-init.sh。
build_initramfs() {
  [ -e "$KERNEL_PATH" ] || die "找不到内核 $KERNEL_PATH"
  [ -e "$STOCK_INITRAMFS" ] || die "找不到 initramfs $STOCK_INITRAMFS"
  local work="$MATRIX_DIR/initramfs-$KVER"
  rm -rf "$work"
  mkdir -p "$work" "$OUT"
  ( cd "$work" && lsinitcpio -n -x "$STOCK_INITRAMFS" >/dev/null )

  local modsrc="/usr/lib/modules/$KVER/kernel"
  [ -d "$modsrc" ] || die "找不到模块目录 /usr/lib/modules/$KVER"
  local mods=(
    fs/netfs/netfs.ko.zst
    net/9p/9pnet.ko.zst
    net/9p/9pnet_virtio.ko.zst
    fs/9p/9p.ko.zst
  )
  local m
  for m in "${mods[@]}"; do
    [ -e "$modsrc/$m" ] || die "模块缺失：$modsrc/$m"
    mkdir -p "$work/usr/lib/modules/$KVER/kernel/$(dirname "$m")"
    cp "$modsrc/$m" "$work/usr/lib/modules/$KVER/kernel/$m"
  done

  local bb="$work/usr/bin/busybox"
  [ -e "$bb" ] || die "initramfs 里找不到 busybox"

  cat >"$work/init" <<EOF
#!/usr/bin/sh
# sodama 内核矩阵专用 init（rdinit=/init）。$KVER
# 注意：发行版 busybox 未编译 mount/insmod applet，要用镜像自带的
# util-linux mount 与 kmod insmod；失败一律强制关机，不落到 shell（避免卡住）。
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmp /tmp
for m in fs/netfs/netfs.ko.zst net/9p/9pnet.ko.zst net/9p/9pnet_virtio.ko.zst fs/9p/9p.ko.zst; do
    insmod "/usr/lib/modules/$KVER/kernel/\$m" || echo "insmod \$m failed"
done
mkdir -p /newroot
if ! mount -t 9p -o trans=virtio,version=9p2000.L hostroot /newroot; then
    echo "!! 9p 挂载失败（虚拟机将关机）"
    exec poweroff -f
fi
mkdir -p /newroot/proc /newroot/sys /newroot/dev /newroot/tmp /newroot/run
mount -t proc proc /newroot/proc
mount -t sysfs sys /newroot/sys
mount -t devtmpfs dev /newroot/dev
mount -t tmpfs tmp /newroot/tmp
mount -t tmpfs tmp /newroot/run
ln -s /proc/self/fd /newroot/dev/fd
cp /usr/bin/busybox /newroot/tmp/busybox
chroot /newroot /bin/bash $ROOT/lab/vm-init.sh
echo "!! vm-init 返回，强制关机"
poweroff -f
EOF
  chmod +x "$work/init"

  ( cd "$work" && find . -print0 | cpio --null -o -H newc --owner 0:0 2>/dev/null ) >"$INITRD"
  echo "== initramfs 已生成：$INITRD（kernel modules: $KVER）=="
}

vm() {
  build_initramfs
  local accel=()
  if [ -w /dev/kvm ]; then
    accel=(-enable-kvm -cpu host)
  else
    echo "== /dev/kvm 不可写，退化为 TCG（较慢）=="
    accel=(-accel tcg -cpu max)
  fi
  echo "== QEMU：$KERNEL_PATH =="
  timeout --foreground "${QEMU_TIMEOUT:-600}" qemu-system-x86_64 \
    "${accel[@]}" -smp 2 -m 2048 \
    -kernel "$KERNEL_PATH" -initrd "$INITRD" \
    -append "console=ttyS0 rdinit=/init panic=5" \
    -virtfs local,path=/,mount_tag=hostroot,security_model=none,multidevs=remap \
    -nographic -no-reboot
}

case "${1:-}" in
  check) check ;;
  run) run ;;
  initramfs) build_initramfs ;;
  vm) shift; [ $# -gt 0 ] && KERNEL_PATH="$1"; vm ;;
  *) echo "usage: $0 {check|run|initramfs|vm [vmlinuz]}"; exit 2 ;;
esac

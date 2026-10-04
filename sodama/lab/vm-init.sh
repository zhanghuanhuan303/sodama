#!/usr/bin/env bash
# 在 QEMU 里跑 sodama 内核矩阵（由 sodama/lab/matrix/initramfs-*/init 以
# rdinit=/init 调用；此时 / 是宿主根的 9p 共享，PID1 就是我们）。
#
# 输出写到 lab/matrix/out/vm-kernel-<ver>.log（9p 上以宿主用户身份落盘）。
set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$BASE/lab/matrix/out"
mkdir -p "$OUT"
LOG="$OUT/vm-kernel-$(uname -r).log"
exec > >(tee "$LOG") 2>&1

echo "=== VM 内核矩阵：$(uname -r) ==="
date -Is
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 网络设备类型按需加载（veth/bridge 是模块）
modprobe veth 2>/dev/null || true
modprobe bridge 2>/dev/null || true

"$BASE/lab/matrix.sh" check || true

result=FAIL
if "$BASE/lab/lab.sh" up && "$BASE/lab/lab.sh" verify; then
  result=PASS
fi
"$BASE/lab/lab.sh" down || true
echo "MATRIX-RESULT kernel=$(uname -r) verify=$result"
sync
exec /tmp/busybox poweroff -f

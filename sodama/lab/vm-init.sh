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

# 对标批（ADR-0065）：offload 字节记账需要 `--offload` 会话（up 的基线不带 dialer）。
# 注意：QEMU 环境里 offload 内核路径有**既有抖动**（问候超时/首连降级；基线 5092723 同环境
# 四组对照 9/9 失败，随宿主状态大幅波动，见 devlog §19），故此项为信息项：重试三轮，
# 并把记账三件套（probe_calls / parse_fail / guard_miss）无论成败都打出来作证据。
offload=FAIL
for attempt in 1 2 3; do
  if USE_OFFLOAD=1 "$BASE/lab/lab.sh" offload-up \
    && "$BASE/lab/lab.sh" test-relay-offload \
    && "$BASE/lab/lab.sh" test-offload-lifecycle; then
    offload=PASS
    break
  fi
  echo "offload 阶段第 $attempt 轮失败（环境抖动或真实缺陷，看下方计数）"
  "$BASE/target/release/sodama" status --socket /tmp/sodama-status.sock --json 2>/dev/null \
    | python3 -c 'import json,sys; v=json.load(sys.stdin); print("记账证据:", v.get("offload_sent"))' 2>/dev/null || true
  grep -E "offload 记账" /tmp/sodama.log 2>/dev/null | tail -3 || true
  "$BASE/lab/lab.sh" down || true
done
"$BASE/lab/lab.sh" down || true

# 对标批（ADR-0065）：L3 端到端（经 ipip 隧道）已并入 verify() 门禁（l3 用例），
# 此处不再单列。
# 能力缺口批次（#1–#4）：must 糖 / 订阅 -file scheme / 接口热插拔 / match_set 容量。
# eBPF 余项批次（ADR-0067）：lan_egress/parse 计数/SYN 重绑/handoff、出口连通性、
# offload 背压 fuse、conn_state pinning。
# 每个用例一个专用会话（与 offload 同模式）；全部计入 cap= 汇总。
cap=FAIL
cap_ok=1
for pair in must-up:test-must subfile-up:test-sub-file hotplug-up:test-hotplug rulecap-up:test-rules-cap dns-up:test-domain gaps-up:test-gaps alive-up:test-alive fuse-up:test-fuse pin-up:test-pinning cone-up:test-udp-cone dnsbind-up:test-dns-bind; do
  cap_up="${pair%%:*}"
  cap_tst="${pair##*:}"
  if "$BASE/lab/lab.sh" "$cap_up" >/dev/null 2>&1 && "$BASE/lab/lab.sh" "$cap_tst" >/dev/null 2>&1; then
    echo "cap/$cap_tst: PASS"
  else
    echo "cap/$cap_tst: FAIL"
    cap_ok=0
  fi
  "$BASE/lab/lab.sh" down >/dev/null 2>&1 || true
done
[ "$cap_ok" = 1 ] && cap=PASS
echo "MATRIX-RESULT kernel=$(uname -r) verify=$result offload=$offload cap=$cap"
sync
exec /tmp/busybox poweroff -f

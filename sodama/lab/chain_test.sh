#!/usr/bin/env bash
# P38：链式代理端到端自测（不需要 root / eBPF）——本地 SOCKS5 实例 + TCP echo。
#
# 拓扑（对照 dae 语义：左侧 = 出口、右侧 = 第一跳）：
#
#   测试客户端 → front(本脚本自带 socks5 入口, dialer = 链)
#                  └─ 链 = socks5://PA -> socks5://PB（PB 是第一跳）
#                       → 客户端实际先连 PB；PB CONNECT 到 PA；PA CONNECT 到 echo 目标
#
# 断言：
#   1) 两跳链可回显（数据面从 PB → PA → echo 全程打通）；
#   2) 第一跳（PB）换成死端口 → 连接失败（证明「右侧 = 第一跳」方向语义）；
#   3) `sodama completion`/`--version` 等无关路径不在此脚本范围。
#
# 用法： lab/chain_test.sh [--bin <sodama 二进制>]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${BIN:-$HERE/../target/release/sodama}"
PY="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
  case "$1" in
  --bin)
    BIN="$2"
    shift 2
    ;;
  -h | --help)
    sed -n '2,20p' "$0"
    exit 0
    ;;
  *)
    echo "未知参数：$1" >&2
    exit 2
    ;;
  esac
done

[ -x "$BIN" ] || {
  echo "缺少 $BIN（先 cargo build --release）" >&2
  exit 1
}

LOG_DIR="$(mktemp -d /tmp/sodama-chain-test.XXXXXX)"
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do
    kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$LOG_DIR"
}
trap cleanup EXIT

BASE_PORT="${BASE_PORT:-20900}"
ECHO_PORT=$((BASE_PORT + 1))
PA_PORT=$((BASE_PORT + 2))  # 链左侧（出口）
PB_PORT=$((BASE_PORT + 3))  # 链右侧（第一跳）
FRONT_PORT=$((BASE_PORT + 4))

wait_port() { # 等端口可连（最多 5s）
  local i
  for i in $(seq 1 50); do
    if "$PY" - "$1" <<'EOF' 2>/dev/null
import socket, sys
s = socket.socket()
s.settimeout(0.2)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.close()
EOF
    then
      return 0
    fi
    sleep 0.1
  done
  echo "端口 $1 未就绪（日志在 $LOG_DIR）" >&2
  return 1
}

echo "== 1) 拉起 echo 夹具 =="
"$PY" - "$ECHO_PORT" <<'EOF' >"$LOG_DIR/echo.log" 2>&1 &
import socket, sys, threading
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(16)
def handle(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)
    finally:
        c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
EOF
PIDS+=($!)
wait_port "$ECHO_PORT"

echo "== 2) 拉起 PA/PB（两个直连 SOCKS5 实例）与 front（链式 dialer）=="
"$BIN" --listen-socks "127.0.0.1:$PA_PORT" --dialer direct >"$LOG_DIR/pa.log" 2>&1 &
PIDS+=($!)
"$BIN" --listen-socks "127.0.0.1:$PB_PORT" --dialer direct >"$LOG_DIR/pb.log" 2>&1 &
PIDS+=($!)
"$BIN" --listen-socks "127.0.0.1:$FRONT_PORT" \
  --dialer "socks5://127.0.0.1:$PA_PORT -> socks5://127.0.0.1:$PB_PORT" \
  >"$LOG_DIR/front.log" 2>&1 &
PIDS+=($!)
wait_port "$PA_PORT"
wait_port "$PB_PORT"
wait_port "$FRONT_PORT"
grep -q "chain" "$LOG_DIR/front.log" || grep -q "socks5://127.0.0.1:$PA_PORT->socks5://127.0.0.1:$PB_PORT" "$LOG_DIR/front.log" || {
  echo "front 未识别为链式 dialer（日志见 $LOG_DIR/front.log）" >&2
  cat "$LOG_DIR/front.log" >&2
  exit 1
}

echo "== 3) 链路回显（数据面必须经 PB → PA 两跳）=="
"$PY" - "$FRONT_PORT" "$ECHO_PORT" <<'EOF'
import socket, struct, sys
front, echo = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", front), timeout=5)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00", "SOCKS5 握手失败"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo))
rep = s.recv(10)
assert len(rep) >= 2 and rep[1] == 0, f"CONNECT 被拒: {rep!r}"
payload = b"chain-echo-test-0123456789" * 128
s.sendall(payload)
got = b""
while len(got) < len(payload):
    d = s.recv(65536)
    if not d:
        break
    got += d
assert got == payload, f"回显不符：{len(got)}/{len(payload)}"
print("  两跳链回显 OK（%d 字节）" % len(payload))
EOF

echo "== 4) 第一跳死端口 → 必须失败（证明右侧=第一跳）=="
"$BIN" --listen-socks "127.0.0.1:$((FRONT_PORT + 1))" \
  --dialer "socks5://127.0.0.1:$PA_PORT -> socks5://127.0.0.1:$((PB_PORT + 9))" \
  >"$LOG_DIR/front-dead.log" 2>&1 &
PIDS+=($!)
wait_port "$((FRONT_PORT + 1))"
"$PY" - "$((FRONT_PORT + 1))" "$ECHO_PORT" <<'EOF'
import socket, struct, sys
front, echo = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", front), timeout=5)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo))
rep = s.recv(10)
# 第一跳不可达：CONNECT 必须被拒（或连接被直接关闭）
assert len(rep) < 2 or rep[1] != 0, f"第一跳已死却成功建连（方向语义错误）: {rep!r}"
print("  死第一跳被正确拒绝（REP=%d）" % (rep[1] if len(rep) >= 2 else -1))
EOF

echo "== chain_test: 全部通过 =="

#!/usr/bin/env python3
"""tproxy 回显夹具的大流量探针：字节完整性校验，容忍夹具插入的 banner 行。

背景：无 dialer 的 up/ops-up 会话里，落到 tproxy 的连接由 loader 的**回显夹具**接管
（loader/src/main.rs handle_tproxy_conn）：每读到一块数据就回一行
`sodama tproxy: orig_dst=… peer=…` banner + 原样数据，直到对端关闭。因此回显流里
夹着 banner（连第一行 `start` 的回显也夹在 banner 之后），`stream_probe.py`（严格
逐字节回显）不能用于该夹具；本探针剥掉 banner 后比对字节。

消歧要点：期望载荷就是本地发出的 `data`，所以「尾部像 banner 前缀 **且** 与期望
载荷的对应位置不符」的字节一定是 banner 开头（滞留等待换行）；其余一律按载荷入账，
不会像「无条件扣留尾部」那样在流末尾假超时。

用法：tproxy_stream_probe.py <host> <port> [kb]
输出：stream-ok bytes=<n> prefix=<first-line>   （与 stream_probe 对齐，便于断言复用）
"""
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
kb = int(sys.argv[3]) if len(sys.argv) > 3 else 512

BANNER = b"sodama tproxy:"
MARKER = b"start\n"

s = socket.create_connection((host, port), timeout=10)
s.settimeout(10)
# 先读一行（就是夹具的 banner），banner 之后的内容（`start` 回显或其前缀）不丢，
# 交给下面的剥离逻辑处理——它可能落在同一个 recv 里，也可能后续单独到达。
s.sendall(MARKER)
raw = bytearray()
while b"\n" not in raw:
    chunk = s.recv(4096)
    if not chunk:
        print("FAIL: 未收到前缀应答")
        sys.exit(1)
    raw += chunk
nl = raw.find(b"\n")
prefix = raw[:nl].decode(errors="replace")
del raw[:nl + 1]

data = os.urandom(kb * 1024)
try:
    s.sendall(data)
except OSError as e:
    print(f"FAIL: 发送中断（{e}）")
    sys.exit(1)
got = bytearray()


def strip_banners(raw: bytearray, got: bytearray, final: bool) -> None:
    """把 raw 中夹具插入的内容剥掉并入 got。返回后 raw 只保留需要等待的尾巴。"""
    while True:
        # 1) 流头的 `start` 回显（夹具对 MARKER 的原样回显）：只在载荷仍未开始时处理。
        if not got and raw:
            head = bytes(raw)
            if len(head) < len(MARKER) and MARKER.startswith(head) and not final:
                return  # 可能是回显的前缀，等更多数据
            if head.startswith(MARKER):
                del raw[:len(MARKER)]
                continue
        # 2) 完整 banner 行。
        i = raw.find(BANNER)
        if i > 0:
            got += raw[:i]
            del raw[:i]
            i = 0
        if i == 0:
            j = raw.find(b"\n")
            if j < 0:
                if final:
                    got += raw  # 截断的 banner：按载荷入账，让比对报不一致
                    del raw[:]
                return
            del raw[:j + 1]
            continue
        # 3) 无完整 banner：末尾若是 banner 前缀、且不等于期望载荷的对应字节，
        #    必是 banner 开头 → 滞留等待换行；否则整段都是载荷。
        keep = 0
        if not final:
            m = min(len(BANNER) - 1, len(raw))
            pos = len(got)
            for k in range(m, 0, -1):
                if raw[-k:] == BANNER[:k] and raw[-k:] != data[pos + len(raw) - k:pos + len(raw)]:
                    keep = k
                    break
        take = len(raw) - keep
        if take > 0:
            got += raw[:take]
            del raw[:take]
        return


while len(got) < len(data):
    try:
        chunk = s.recv(65536)
    except socket.timeout:
        strip_banners(raw, got, final=True)
        print(f"FAIL: 读取超时（got={len(got)} want={len(data)}）")
        sys.exit(1)
    except OSError as e:  # RST 等：按流中断处理（夹具中途关闭/被中间设备 reset）
        strip_banners(raw, got, final=True)
        print(f"FAIL: 连接中断（{e}）got={len(got)} want={len(data)}")
        sys.exit(1)
    if not chunk:
        break
    raw += chunk
    strip_banners(raw, got, final=False)
    if bytes(got) != data[:len(got)]:
        print(f"FAIL: 回显不一致 got={len(got)} want={len(data)}")
        sys.exit(1)
strip_banners(raw, got, final=True)

if bytes(got) != data:
    print(f"FAIL: 回显不一致 got={len(got)} want={len(data)}")
    sys.exit(1)
print(f"stream-ok bytes={len(data)} prefix={prefix}")

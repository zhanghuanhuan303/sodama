#!/usr/bin/env python3
"""长连接探针：连接 → 发一行 → 读回显 → 等 gap 秒 → 再发一行 → 再读回显。

用于验证「已建立的连接跨规则热重载仍走原路径」——即 conn_state 里缓存的路由判决
（对照 dae 的 conn_state + mark_tcp_seen）。若判决没有被缓存，热重载后第二条消息
会按新规则处理（测试里是 block），客户端就读不到第二个回显。
"""
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
gap = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0


def recv_until_idle(sock, idle=0.35):
    sock.settimeout(idle)
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        except socket.timeout:
            break
    return b"".join(chunks)


s = socket.create_connection((host, port), timeout=6)
for i, msg in enumerate([b"one\n", b"two\n"]):
    if i:
        time.sleep(gap)
    s.sendall(msg)
    out = recv_until_idle(s)
    print(f"reply{i + 1}: {out.decode(errors='replace').strip()}", flush=True)
s.close()

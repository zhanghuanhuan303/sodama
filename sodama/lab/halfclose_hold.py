#!/usr/bin/env python3
"""半关闭姿态探针：请求 → 读一次应答 → 保持连接（不读、不写、不关）。

回归对象：relay 泵线程泄漏（O9）。wan_echo 的 8083 端点应答后立即关闭，
代理侧「上游 → 客户端」泵随之结束；此时客户端仍静默保持 —— 若收尾逻辑
按「先结束的泵」摘注册表，另一个卡在 recv 的泵既不会被 janitor 看见，
也无法退出，线程/缓冲/fd 永久泄漏。

用法：halfclose_hold.py <host> <port> <hold_secs> <tag>
输出：halfclose-ok tag=<tag> reply=...（建连成功）
      halfclose-done tag=<tag>（保持结束，可被测试提前 kill）
"""
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
hold = float(sys.argv[3]) if len(sys.argv) > 3 else 45.0
tag = sys.argv[4] if len(sys.argv) > 4 else "0"

s = socket.create_connection((host, port), timeout=5)
s.sendall(f"halfclose-{tag}\n".encode())
s.settimeout(5)
reply = s.recv(4096)
print(f"halfclose-ok tag={tag} reply={reply.decode(errors='replace').strip()}", flush=True)
# 关键姿态：读到应答后不再碰 socket（不再 recv → 不回 EOF；不 send → 不发数据；
# 不 close → 不发 FIN）。代理侧另一方向的泵就此失去退出条件。
time.sleep(hold)
print(f"halfclose-done tag={tag}", flush=True)
s.close()

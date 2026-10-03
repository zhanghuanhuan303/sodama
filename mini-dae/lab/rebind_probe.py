#!/usr/bin/env python3
"""单写者（rebind）测试用的长连接探针。

连上 tproxy 目标后按信号文件驱动三个阶段：
  one  → 等 sig1 出现 → two → 等 sig2 出现 → three
two 的期望是「读不到回显」（回程绑定已被测试脚本改成竞争发布者，
回包被送到错误 MAC）；three 之前脚本会把绑定改成陈旧条目，数据面
允许改绑，TCP 重传应该把回显找回来。

输出（stdout，供 lab.sh 解析）：
  local=<ip>:<port>      本端地址（测试脚本用它伪造相同的五元组）
  echo1/echo2/echo3: ...
"""
import os
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
sig1 = sys.argv[3]
sig2 = sys.argv[4]


def recv_idle(sock, idle=0.4, budget=6.0):
    """持续读，直到 idle 时间内没有新数据或总预算耗尽。"""
    sock.settimeout(idle)
    chunks = []
    end = time.time() + budget
    while time.time() < end:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            end = time.time() + budget
        except socket.timeout:
            continue
    return b"".join(chunks)


s = socket.create_connection((host, port), timeout=6)
local = s.getsockname()
print(f"local={local[0]}:{local[1]}", flush=True)

s.sendall(b"one\n")
print(f"echo1: {recv_idle(s).decode(errors='replace').strip()}", flush=True)

while not os.path.exists(sig1):
    time.sleep(0.2)
s.sendall(b"two\n")
out2 = recv_idle(s).decode(errors="replace").strip()
print(f"echo2: {out2 or '(no echo)'}", flush=True)

while not os.path.exists(sig2):
    time.sleep(0.2)
s.sendall(b"three\n")
out3 = recv_idle(s, budget=15.0).decode(errors="replace").strip()
print(f"echo3: {out3 or '(no echo)'}", flush=True)
s.close()
print("done", flush=True)

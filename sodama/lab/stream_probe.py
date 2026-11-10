#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""P4 relay 大流量探针：连 <host>:<port>，先取首行前缀应答，再发 <kb> KB 随机数据并校验回显。

用法： stream_probe.py <host> <port> [kb]
输出：stream-ok bytes=<n> prefix=<first-line>
"""
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
kb = int(sys.argv[3]) if len(sys.argv) > 3 else 512

s = socket.create_connection((host, port), timeout=10)
s.settimeout(10)
s.sendall(b"start\n")
buf = b""
while b"\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        print("FAIL: 未收到前缀应答")
        sys.exit(1)
    buf += chunk
prefix = buf.split(b"\n", 1)[0].decode(errors="replace")

data = os.urandom(kb * 1024)
s.sendall(data)
got = bytearray()
while len(got) < len(data):
    chunk = s.recv(65536)
    if not chunk:
        break
    got += chunk
if bytes(got) != data:
    print(f"FAIL: 回显不一致 got={len(got)} want={len(data)}")
    sys.exit(1)
print(f"stream-ok bytes={len(data)} prefix={prefix}")

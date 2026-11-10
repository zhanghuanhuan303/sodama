#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""P38 full-cone 探针：**同一个客户端 socket** 向两个 UDP 回显目标发报文并收集应答。

用途：验证 UDP 端点按客户端 src 复用（full-cone）——单 socket 双目标应命中同一出口端点
（lab.sh 的 test-udp-cone 用 status 增量断言 sessions_total 只 +1）。

用法： udp_cone_probe.py <host> <port_a> <port_b> [count]
输出：reply=<text> from=<ip:port>（每行一条）；summary=<got>/<sent>（共 count×2 条）
"""
import socket
import sys

host = sys.argv[1]
port_a = int(sys.argv[2])
port_b = int(sys.argv[3])
count = int(sys.argv[4]) if len(sys.argv) > 4 else 2

s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
sent = 0
got = 0
for i in range(count):
    for port in (port_a, port_b):
        s.sendto(f"cone{i}@{port}".encode(), (host, port))
        sent += 1
        try:
            data, peer = s.recvfrom(65536)
            got += 1
            print(f"reply={data.decode(errors='replace')} from={peer[0]}:{peer[1]}")
        except socket.timeout:
            print(f"timeout for cone{i}@{port}")
print(f"summary={got}/{sent}")
sys.exit(0 if got == sent else 1)

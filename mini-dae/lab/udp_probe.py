#!/usr/bin/env python3
"""P4 UDP NAT 探针：向 <host>:<port> 发 <count> 个 UDP 报文并收集应答。

用法： udp_probe.py <host> <port> [count] [interval]
输出：reply=<text> from=<ip:port>（每行一条）；summary=<got>/<sent>
"""
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
count = int(sys.argv[3]) if len(sys.argv) > 3 else 1
interval = float(sys.argv[4]) if len(sys.argv) > 4 else 0.1

s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
got = 0
for i in range(count):
    s.sendto(f"ping{i}".encode(), (host, port))
    try:
        data, peer = s.recvfrom(65536)
        got += 1
        print(f"reply={data.decode(errors='replace')} from={peer[0]}:{peer[1]}")
    except socket.timeout:
        print(f"timeout for ping{i}")
    if interval:
        import time

        time.sleep(interval)
print(f"summary={got}/{count}")
sys.exit(0 if got == count else 1)

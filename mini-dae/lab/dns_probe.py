#!/usr/bin/env python3
"""DNS 客户端探针（P3a/P3b-1）：向 <server>:53 查询 <name>，打印解析结果。

用法： dns_probe.py [--tcp] [--edns <size>] <server> <name> [qtype]

输出（每行一条）：
  rcode=<n>
  proto=udp|tcp
  tc=<0|1>
  answer=<ip> / ttl=<n>     # 每条 A 记录两行
  answer6=<ip6>             # AAAA
  ancount=<n> from=<server>:<port>
"""
import random
import socket
import struct
import sys

argv = sys.argv[1:]
use_tcp = False
edns_size = 0
pos = []
i = 0
while i < len(argv):
    if argv[i] == "--tcp":
        use_tcp = True
    elif argv[i] == "--edns":
        i += 1
        edns_size = int(argv[i])
    else:
        pos.append(argv[i])
    i += 1
server = pos[0]
name = pos[1]
qtype = int(pos[2]) if len(pos) > 2 else 1

txid = random.randint(0, 0xFFFF)
q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 1 if edns_size else 0)
for label in name.split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\x00" + struct.pack("!HH", qtype, 1)
if edns_size:
    q += b"\x00" + struct.pack("!HHIH", 41, edns_size, 0, 0)  # OPT，无 options


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if not use_tcp else socket.SOCK_STREAM)
s.settimeout(5)
try:
    if use_tcp:
        s.connect((server, 53))
        s.sendall(struct.pack("!H", len(q)) + q)
        hdr = recv_exact(s, 2)
        if hdr is None:
            print("timeout: no answer")
            sys.exit(1)
        resp = recv_exact(s, struct.unpack("!H", hdr)[0])
    else:
        s.sendto(q, (server, 53))
        resp, peer = s.recvfrom(4096)
except socket.timeout:
    print("timeout: no answer")
    sys.exit(1)

if resp is None or len(resp) < 12 or resp[0:2] != struct.pack("!H", txid):
    print("bad response")
    sys.exit(1)
rcode = resp[3] & 0x0F
ancount = struct.unpack("!H", resp[6:8])[0]
print(f"rcode={rcode}")
print(f"proto={'tcp' if use_tcp else 'udp'}")
print(f"tc={1 if resp[2] & 0x02 else 0}")
# 跳过 question
off = 12
while resp[off] != 0:
    off += 1 + resp[off]
off += 1 + 4
for _ in range(ancount):
    if resp[off] & 0xC0 == 0xC0:
        off += 2
    else:
        while resp[off] != 0:
            off += 1 + resp[off]
        off += 1
    rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", resp[off : off + 10])
    off += 10
    rdata = resp[off : off + rdlen]
    off += rdlen
    if rtype == 1 and rdlen == 4:
        print(f"answer={socket.inet_ntoa(rdata)}")
        print(f"ttl={ttl}")
    elif rtype == 28 and rdlen == 16:
        print(f"answer6={socket.inet_ntop(socket.AF_INET6, rdata)}")
        print(f"ttl={ttl}")
# UDP 时 peer 是上游地址；TCP 时用连接对端
if use_tcp:
    peer = s.getpeername()
print(f"ancount={ancount} from={peer[0]}:{peer[1]}")

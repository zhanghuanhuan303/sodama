#!/usr/bin/env python3
"""假上游 DNS（P3a/P3b-1 实验用）：UDP + TCP 同一端口，按固定表回答 A 记录。

用法： fake_dns.py <query_log> [port]
默认表：
  proxy.test  -> 10.9.10.3
  direct.test -> 10.9.10.4
  cache.test  -> 10.9.10.9
  tcp.test    -> 10.9.10.6
  api1.regex.test -> 10.9.10.21
  api2.regex.test -> 10.9.10.22
  web.regex.test  -> 10.9.10.23
  big.test    -> 60 条 A 记录（10.99.0.1-60，用于 EDNS 截断测试）
TTL 30s（未知名字回 NODATA）。每条查询追加一行到 query_log：
UDP 为 "QUERY <name> ..."，TCP 为 "QUERY-TCP <name> ..."（lab 用来断言转发/缓存）。
"""
import socket
import struct
import sys
import threading

LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/mini-dae-fake-dns.txt"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5353

TABLE = {
    "proxy.test": "10.9.10.3",
    "direct.test": "10.9.10.4",
    "cache.test": "10.9.10.9",
    "tcp.test": "10.9.10.6",
    "api1.regex.test": "10.9.10.21",
    "api2.regex.test": "10.9.10.22",
    "web.regex.test": "10.9.10.23",
}

# P3b-2a：大应答（60 条 A ≈ 990 字节 > 512，用于验证 UDP 截断/EDNS）
BIG = {"big.test": [f"10.99.0.{i}" for i in range(1, 61)]}


def parse_qname(buf):
    labels = []
    off = 12
    while True:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        labels.append(buf[off + 1 : off + 1 + ln].decode(errors="replace"))
        off += 1 + ln
    return ".".join(labels).lower(), off


def respond(query, proto="UDP"):
    if len(query) < 12:
        return None
    qname, off = parse_qname(query)
    qtype = struct.unpack("!H", query[off : off + 2])[0]
    with open(LOG, "a") as f:
        f.write(f"QUERY{'-TCP' if proto == 'TCP' else ''} {qname} type={qtype}\n")
    # 复制 header + question（含压缩指针可用性：此处直接原样拼接）
    resp = bytearray(query[: off + 4])
    resp[2] |= 0x80
    resp[3] &= 0xF0  # rcode=0
    ip = TABLE.get(qname)
    if ip and qtype == 1:
        resp[6:8] = struct.pack("!H", 1)  # ancount
        resp[8:10] = b"\x00\x00"
        resp[10:12] = b"\x00\x00"
        resp += b"\xc0\x0c"  # 指向 question 的 qname
        resp += struct.pack("!HHI", 1, 1, 30)  # A IN TTL
        resp += struct.pack("!H", 4) + socket.inet_aton(ip)
    elif qname in BIG and qtype == 1:
        addrs = BIG[qname]
        resp[6:8] = struct.pack("!H", len(addrs))
        resp[8:10] = b"\x00\x00"
        resp[10:12] = b"\x00\x00"
        for a in addrs:
            resp += b"\xc0\x0c"
            resp += struct.pack("!HHI", 1, 1, 30)
            resp += struct.pack("!H", 4) + socket.inet_aton(a)
    else:
        resp[6:8] = b"\x00\x00"
        resp[8:10] = b"\x00\x00"
        resp[10:12] = b"\x00\x00"
    return bytes(resp)


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve_tcp():
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", PORT))
    ls.listen(16)
    print(f"fake-dns TCP listening on 127.0.0.1:{PORT}", flush=True)
    while True:
        conn, _ = ls.accept()
        threading.Thread(target=handle_tcp_conn, args=(conn,), daemon=True).start()


def handle_tcp_conn(conn):
    with conn:
        while True:
            hdr = recv_exact(conn, 2)
            if not hdr:
                break
            n = struct.unpack("!H", hdr)[0]
            query = recv_exact(conn, n)
            if not query:
                break
            out = respond(query, proto="TCP")
            if out:
                conn.sendall(struct.pack("!H", len(out)) + out)


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
threading.Thread(target=serve_tcp, daemon=True).start()
print(f"fake-dns UDP listening on 127.0.0.1:{PORT} table={TABLE}", flush=True)
while True:
    data, addr = s.recvfrom(4096)
    out = respond(data)
    if out:
        s.sendto(out, addr)

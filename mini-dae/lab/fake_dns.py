#!/usr/bin/env python3
"""假上游 DNS（P3a/P3b-1 实验用）：UDP + TCP 同一地址，按固定表回答 A 记录。

用法： fake_dns.py <query_log> [port] [bind_host]
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
BIND = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"

TABLE = {
    "proxy.test": "10.9.10.3",
    "direct.test": "10.9.10.4",
    "cache.test": "10.9.10.9",
    "tcp.test": "10.9.10.6",
    "api1.regex.test": "10.9.10.21",
    "api2.regex.test": "10.9.10.22",
    "web.regex.test": "10.9.10.23",
    # P17a：geosite 夹具（lab/rules.geo.dae 的 domain(geosite: cn) 展开自
    # lab/gen-geo-dat.py，suffix 条目 geo.test）
    "geo.test": "10.9.10.3",
    # P18a：DoT/DoH 传输夹具（dns_transport_server.py 转发到本服务）
    "dot.test": "10.9.10.31",
    "dot2.test": "10.9.10.32",
    "doh.test": "10.9.10.33",
    "doh2.test": "10.9.10.34",
    # P18a：显式 udp:// / tcp:// 上游夹具
    "udpup.test": "10.9.10.35",
    "tcpup.test": "10.9.10.36",
    # P18b：DoQ 夹具（doq-server 转发到本服务）
    "doq.test": "10.9.10.37",
    "doq2.test": "10.9.10.38",
    # P26：DoH over HTTP/3 夹具（doh-h3-server 转发到本服务）
    "doh3.test": "10.9.10.39",
    "doh4.test": "10.9.10.40",
    # P18c：dns.routing 夹具
    "blocked.test": "10.9.10.43",
    "via2.test": "10.9.10.42",
    "a.via2.test": "10.9.10.42",
    "other.test": "10.9.10.45",
    "polluted.test": "10.9.10.60",
    "relook.test": "10.9.10.61",
    "asis.test": "10.9.10.44",
    "tcp.asis.test": "10.9.10.46",
    "x.fullblocked.test": "10.9.10.47",
    "ecsroute.test": "10.9.10.48",
    "viacli.test": "10.9.10.49",
    # P18c+：ECS 注入 / 客户端网段路由夹具
    "rsip.test": "10.9.10.62",
    # P23：DNS 选项夹具（fixed_domain_ttl / ipversion_prefer）
    "stale.test": "10.9.10.71",
    "pref.test": "10.9.10.72",
}

# P23：按名覆盖上游 TTL（默认 30）
TTL_OVERRIDE = {
    "stale.test": 30,  # fixed_domain_ttl=1 只影响缓存寿命；上游应答本身 TTL=30
}

# P23：AAAA 表（ipversion_prefer 用；v6only.test 只有 AAAA）
AAAA = {
    "pref.test": "2001:db8::72",
    "v6only.test": "2001:db8::73",
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


def ecs_of(query):
    """提取 OPT(41) 里的 ECS(8) 选项（仅处理无 answer/authority 的无压缩形态；
    mini-dae 注入的 ECS 即尾插 OPT，正好命中）。返回 "1/24/10.0.0"（地址按前缀截断）或 None。"""
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", query[4:12])
        if an or ns:
            return None
        off = 12
        for _ in range(qd):
            while query[off] != 0:
                off += 1 + query[off]
            off += 5  # 0 + qtype + qclass
        for _ in range(ar):
            if query[off] != 0:
                return None
            off += 1
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", query[off : off + 10])
            off += 10
            rdata = query[off : off + rdlen]
            off += rdlen
            if rtype != 41:
                continue
            p = 0
            while p + 4 <= len(rdata):
                code, ln = struct.unpack("!HH", rdata[p : p + 4])
                p += 4
                if code == 8 and ln >= 4:
                    body = rdata[p : p + ln]
                    fam, src, _scope = struct.unpack("!HBB", body[:4])
                    addr = body[4:]
                    if fam == 1:
                        return "1/%d/%s" % (src, ".".join(str(b) for b in addr))
                    return "2/%d/%s" % (src, addr.hex())
                p += ln
    except Exception:
        return None
    return None


def respond(query, proto="UDP"):
    if len(query) < 12:
        return None
    qname, off = parse_qname(query)
    qtype = struct.unpack("!H", query[off : off + 2])[0]
    ecs = ecs_of(query)
    with open(LOG, "a") as f:
        f.write(
            f"QUERY{'-TCP' if proto == 'TCP' else ''} {qname} type={qtype}"
            + (f" ecs={ecs}" if ecs else "")
            + "\n"
        )
    # 复制 header + question（含压缩指针可用性：此处直接原样拼接）
    resp = bytearray(query[: off + 4])
    resp[2] |= 0x80
    resp[3] &= 0xF0  # rcode=0
    ip = TABLE.get(qname)
    ttl = TTL_OVERRIDE.get(qname, 30)
    if ip and qtype == 1:
        resp[6:8] = struct.pack("!H", 1)  # ancount
        resp[8:10] = b"\x00\x00"
        resp[10:12] = b"\x00\x00"
        resp += b"\xc0\x0c"  # 指向 question 的 qname
        resp += struct.pack("!HHI", 1, 1, ttl)  # A IN TTL
        resp += struct.pack("!H", 4) + socket.inet_aton(ip)
    elif qtype == 28 and qname in AAAA:
        resp[6:8] = struct.pack("!H", 1)
        resp[8:10] = b"\x00\x00"
        resp[10:12] = b"\x00\x00"
        resp += b"\xc0\x0c"
        resp += struct.pack("!HHI", 28, 1, ttl)  # AAAA IN TTL
        resp += struct.pack("!H", 16) + socket.inet_pton(socket.AF_INET6, AAAA[qname])
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
    ls.bind((BIND, PORT))
    ls.listen(16)
    print(f"fake-dns TCP listening on {BIND}:{PORT}", flush=True)
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
s.bind((BIND, PORT))
threading.Thread(target=serve_tcp, daemon=True).start()
print(f"fake-dns UDP listening on {BIND}:{PORT} table={TABLE}", flush=True)
while True:
    data, addr = s.recvfrom(4096)
    out = respond(data)
    if out:
        s.sendto(out, addr)

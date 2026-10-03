#!/usr/bin/env python3
"""独立实现的 trojan 服务端（stdlib ssl，P5 的参考对端，lab 用）。

用法： trojan_server.py <log> <password> <port> <cert.pem> <key.pem>
流程：TLS 握手 → 56 字节 hex(SHA224(password)) + CRLF → cmd + ATYP + ADDR + PORT + CRLF
      → 连接目标并双向转发。日志行：CONNECT target=<ip:port>
"""
import hashlib
import socket
import ssl
import struct
import sys
import threading

LOG = sys.argv[1]
PASSWORD = sys.argv[2].encode()
PORT = int(sys.argv[3])
CERT = sys.argv[4]
KEY = sys.argv[5]

# 上游 socket 必须打 SO_MARK：否则被 mini-dae 数据面（wan_egress）再抓一次成环。
SO_MARK = getattr(socket, "SO_MARK", 36)
MARK = 0x233


def dial_tcp(ip, port, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
    s.settimeout(timeout)
    s.connect((ip, port))
    return s

EXPECTED = hashlib.sha224(PASSWORD).hexdigest().encode()


def log_line(line):
    with open(LOG, "a") as f:
        f.write(line + "\n")


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle(conn):
    with conn:
        try:
            got = read_exact(conn, 56)
            if got != EXPECTED:
                log_line("AUTH-FAIL")
                return
            if read_exact(conn, 2) != b"\r\n":
                return
            head = conn.recv(1)
            if not head or head[0] != 0x01:
                log_line(f"UNSUPPORTED cmd={head[0] if head else -1}")
                return
            atyp = conn.recv(1)[0]
            if atyp == 1:
                ip = socket.inet_ntoa(read_exact(conn, 4))
            elif atyp == 3:
                ln = conn.recv(1)[0]
                ip = read_exact(conn, ln).decode()
            elif atyp == 4:
                ip = socket.inet_ntop(socket.AF_INET6, read_exact(conn, 16))
            else:
                return
            port = struct.unpack("!H", read_exact(conn, 2))[0]
            if read_exact(conn, 2) != b"\r\n":
                return
            log_line(f"CONNECT target={ip}:{port}")
            up = dial_tcp(ip, port)
        except (OSError, TypeError, ValueError) as e:
            log_line(f"ERROR {e}")
            return
        with up:
            t1 = threading.Thread(
                target=lambda: pump(conn.recv, up.sendall), daemon=True
            )
            t2 = threading.Thread(
                target=lambda: pump(up.recv, conn.sendall), daemon=True
            )
            t1.start()
            t2.start()
            t1.join()
            t2.join()


def pump(reader, writer):
    while True:
        data = reader(65536)
        if not data:
            break
        try:
            writer(data)
        except OSError:
            break


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(32)
print(f"trojan-server TLS on 127.0.0.1:{PORT}", flush=True)
while True:
    c, _ = s.accept()
    try:
        tls = ctx.wrap_socket(c, server_side=True)
    except ssl.SSLError as e:
        log_line(f"TLS-ERROR {e}")
        c.close()
        continue
    threading.Thread(target=handle, args=(tls,), daemon=True).start()

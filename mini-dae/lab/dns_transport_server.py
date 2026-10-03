#!/usr/bin/env python3
"""P18a 实验：DoT / DoH 上游服务端（自签证书），把 DNS 查询转发到假 UDP DNS。

用法：
  dns_transport_server.py tls   <port> <cert.pem> <key.pem> <udp_upstream host:port> <log>
  dns_transport_server.py https <port> <cert.pem> <key.pem> <udp_upstream host:port> <log>

日志（每次追加一行，lab 用来断言走了哪种传输/是否复用连接）：
  TLS-CONN / DOH-CONN                     新连接（keep-alive 验证：两次查询应只有 1 个 CONN）
  TLS-QUERY <qname> type=<n>              收到的查询
  DOH-QUERY <path> <qname> type=<n>       收到的 DoH POST（含 path）
  TLS-ERR / DOH-ERR <msg>                 服务端内部错误

DoT：TLS + 2 字节长度分帧（RFC 7858），支持一条连接多查询。
DoH：HTTP/1.1 POST application/dns-message（RFC 8484 的 HTTP/1.1 形态），
     keep-alive（Content-Length 分帧），任意 path（记录以便断言）。
"""
import socket
import ssl
import struct
import sys
import threading

MODE = sys.argv[1]
PORT = int(sys.argv[2])
CERT = sys.argv[3]
KEY = sys.argv[4]
UP_HOST, UP_PORT = sys.argv[5].rsplit(":", 1)
UP_PORT = int(UP_PORT)
LOG = sys.argv[6]

TAG = "TLS" if MODE == "tls" else "DOH"
log_lock = threading.Lock()


def logline(s):
    with log_lock:
        with open(LOG, "a") as f:
            f.write(s + "\n")


def parse_qname(buf):
    labels = []
    off = 12
    while off < len(buf) and buf[off]:
        ln = buf[off]
        labels.append(buf[off + 1 : off + 1 + ln].decode(errors="replace"))
        off += 1 + ln
    qname = ".".join(labels).lower()
    qtype = struct.unpack("!H", buf[off + 1 : off + 3])[0]
    return qname, qtype


def forward(query):
    """一次 UDP 上行（每次新 socket，避免响应串包）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(query, (UP_HOST, UP_PORT))
        return s.recvfrom(65535)[0]
    finally:
        s.close()


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_dot(conn):
    with conn:
        logline("TLS-CONN")
        while True:
            hdr = recv_exact(conn, 2)
            if not hdr:
                break
            n = struct.unpack("!H", hdr)[0]
            query = recv_exact(conn, n)
            if not query:
                break
            try:
                qname, qtype = parse_qname(query)
            except Exception:
                qname, qtype = "?", 0
            logline(f"TLS-QUERY {qname} type={qtype}")
            try:
                resp = forward(query)
            except Exception as e:  # noqa: BLE001
                logline(f"TLS-ERR {e}")
                break
            conn.sendall(struct.pack("!H", len(resp)) + resp)


def handle_doh(conn):
    with conn:
        logline("DOH-CONN")
        buf = b""
        while True:
            # 读请求头
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = head.decode(errors="replace").split("\r\n")
            req_line = lines[0].split()
            if len(req_line) < 3 or req_line[0] != "POST":
                logline(f"DOH-ERR bad request line: {lines[0]!r}")
                return
            path = req_line[1]
            length = 0
            close = False
            for l in lines[1:]:
                k, _, v = l.partition(":")
                k = k.strip().lower()
                v = v.strip()
                if k == "content-length":
                    length = int(v)
                elif k == "connection" and v.lower() == "close":
                    close = True
            while len(buf) < length:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            query, buf = buf[:length], buf[length:]
            try:
                qname, qtype = parse_qname(query)
            except Exception:
                qname, qtype = "?", 0
            logline(f"DOH-QUERY {path} {qname} type={qtype}")
            try:
                resp = forward(query)
            except Exception as e:  # noqa: BLE001
                logline(f"DOH-ERR {e}")
                return
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/dns-message\r\n"
                + f"Content-Length: {len(resp)}\r\n".encode()
                + (b"Connection: close\r\n" if close else b"")
                + b"\r\n"
                + resp
            )
            if close:
                return


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)

ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", PORT))
ls.listen(16)
print(f"dns-{MODE} listening on 127.0.0.1:{PORT} -> udp {UP_HOST}:{UP_PORT}", flush=True)

handler = handle_dot if MODE == "tls" else handle_doh
while True:
    raw, _ = ls.accept()
    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except Exception as e:  # noqa: BLE001
        logline(f"{TAG}-ERR tls handshake: {e}")
        raw.close()
        continue
    threading.Thread(target=handler, args=(conn,), daemon=True).start()

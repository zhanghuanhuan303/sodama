#!/usr/bin/env python3
"""独立实现的 shadowsocks classic AEAD 服务端（P5 的参考对端，lab 用）。

与 sodama 的 Rust 客户端互操作是「跨实现」验证：本文件用 Python
`cryptography` 独立实现 SIP004（TCP 分块 + UDP 包），不复用 Rust 侧任何代码。

用法： ss_server.py <log> <method> <password> <port>
  method: aes-256-gcm | chacha20-ietf-poly1305
日志行： TCP target=<ip:port> / UDP target=<ip:port>
"""
import hashlib
import socket
import struct
import sys
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LOG = sys.argv[1]
METHOD = sys.argv[2]
PASSWORD = sys.argv[3].encode()
PORT = int(sys.argv[4])
# 可选第 5 参：监听地址（默认 127.0.0.1；性能对比时在 WAN ns 里用 WAN 地址）。
BIND = sys.argv[5] if len(sys.argv) > 5 else "127.0.0.1"

# 上游 socket 必须打 SO_MARK：否则被 sodama 数据面（wan_egress）再抓一次成环。
SO_MARK = getattr(socket, "SO_MARK", 36)
MARK = 0x233


def dial_tcp(ip, port, timeout=5):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
    s.settimeout(timeout)
    s.connect((ip, port))
    return s

KIND = {"aes-256-gcm": "aes", "chacha20-ietf-poly1305": "chacha"}[METHOD]


def evp_bytes_to_key(password, n):
    out, prev = b"", b""
    while len(out) < n:
        prev = hashlib.md5(prev + password).digest()
        out += prev
    return out[:n]


MASTER = evp_bytes_to_key(PASSWORD, 32)


def subkey(salt):
    return HKDF(
        algorithm=hashes.SHA1(), length=32, salt=salt, info=b"ss-subkey"
    ).derive(MASTER)


def new_aead(key):
    return AESGCM(key) if KIND == "aes" else ChaCha20Poly1305(key)


def nonce(counter):
    return counter.to_bytes(8, "little") + b"\x00" * 4


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


def parse_addr(buf, off):
    atyp = buf[off]
    if atyp == 1:
        ip = socket.inet_ntoa(buf[off + 1 : off + 5])
        off += 5
    elif atyp == 3:
        ln = buf[off + 1]
        ip = buf[off + 2 : off + 2 + ln].decode()
        off += 2 + ln
    elif atyp == 4:
        ip = socket.inet_ntop(socket.AF_INET6, buf[off + 1 : off + 17])
        off += 17
    else:
        raise ValueError(f"bad atyp {atyp}")
    port = struct.unpack("!H", buf[off : off + 2])[0]
    return ip, port, off + 2


class Stream:
    def __init__(self, conn):
        self.conn = conn
        self.recv_key = None
        self.send_key = None
        self.recv_nonce = 0
        self.send_nonce = 0

    # --- 接收方向 ---
    def recv_chunk(self):
        if self.recv_key is None:
            salt = read_exact(self.conn, 32)
            if salt is None:
                return None
            self.recv_key = subkey(salt)
        lb = read_exact(self.conn, 2 + 16)
        if lb is None:
            return None
        aead = new_aead(self.recv_key)
        ln = struct.unpack("!H", aead.decrypt(nonce(self.recv_nonce), lb, None))[0]
        self.recv_nonce += 1
        payload = read_exact(self.conn, ln + 16)
        if payload is None:
            return None
        out = aead.decrypt(nonce(self.recv_nonce), payload, None)
        self.recv_nonce += 1
        return out

    # --- 发送方向 ---
    def send_chunk(self, data):
        if self.send_key is None:
            import os

            salt = os.urandom(32)
            self.conn.sendall(salt)
            self.send_key = subkey(salt)
        aead = new_aead(self.send_key)
        # SIP004：单块明文上限 0x3fff；上游一次 recv 可能更大，必须切块。
        for i in range(0, len(data), 0x3FFF):
            part = data[i : i + 0x3FFF]
            lb = aead.encrypt(nonce(self.send_nonce), struct.pack("!H", len(part)), None)
            self.send_nonce += 1
            payload = aead.encrypt(nonce(self.send_nonce), part, None)
            self.send_nonce += 1
            self.conn.sendall(lb + payload)


def pump(src, dst, sender):
    try:
        while True:
            data = src()
            if data is None:
                break
            sender(dst, data)
    finally:
        # dst 可能是 raw socket（up）或 Stream（回包方向）；后者没有 shutdown。
        try:
            dst.shutdown(socket.SHUT_WR)
        except (OSError, AttributeError):
            pass


def handle_tcp(conn):
    with conn:
        st = Stream(conn)
        first = st.recv_chunk()
        if not first:
            return
        ip, port, off = parse_addr(first, 0)
        log_line(f"TCP target={ip}:{port}")
        try:
            up = dial_tcp(ip, port)
        except OSError as e:
            log_line(f"TCP connect {ip}:{port} failed: {e}")
            return
        with up:
            if len(first) > off:
                up.sendall(first[off:])
            t1 = threading.Thread(
                target=pump,
                args=(st.recv_chunk, up, lambda s, d: s.sendall(d)),
                daemon=True,
            )
            t2 = threading.Thread(
                target=pump,
                args=(
                    lambda: up.recv(65536) or None,
                    st,
                    lambda s, d: s.send_chunk(d),
                ),
                daemon=True,
            )
            t1.start()
            t2.start()
            t1.join()
            t2.join()


def serve_tcp():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND, PORT))
    s.listen(32)
    print(f"ss-server TCP on {BIND}:{PORT} method={METHOD}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle_tcp, args=(c,), daemon=True).start()


def serve_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((BIND, PORT))
    print(f"ss-server UDP on {BIND}:{PORT} method={METHOD}", flush=True)
    # (client addr, 地址族) -> 已建立的出口 socket（回包走同一 socket）
    out = {}
    while True:
        data, peer = s.recvfrom(65536)
        if len(data) <= 32:
            continue
        key = subkey(data[:32])
        aead = new_aead(key)
        try:
            plain = aead.decrypt(nonce(0), data[32:], None)
        except Exception:
            continue
        ip, port, off = parse_addr(plain, 0)
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        us = out.get((peer, fam))
        if us is None:
            us = socket.socket(fam, socket.SOCK_DGRAM)
            us.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
            us.bind(("::" if fam == socket.AF_INET6 else "0.0.0.0", 0))
            out[(peer, fam)] = us
            threading.Thread(target=udp_reply_loop, args=(us, peer, s), daemon=True).start()
        log_line(f"UDP target={ip}:{port}")
        try:
            us.sendto(plain[off:], (ip, port))
        except OSError as e:
            # 目标不可达（例如性能对比时 dae 的 8.8.8.8:53 检查）：只记日志，
            # 绝不能因单个数据包让服务端整体退出。
            log_line(f"UDP send {ip}:{port} failed: {e}")


def udp_reply_loop(us, peer, listener):
    while True:
        try:
            data, _ = us.recvfrom(65536)
        except OSError:
            return
        import os

        salt = os.urandom(32)
        key = subkey(salt)
        aead = new_aead(key)
        ct = aead.encrypt(nonce(0), data, None)
        try:
            listener.sendto(salt + ct, peer)
        except OSError:
            return


threading.Thread(target=serve_tcp, daemon=True).start()
serve_udp()

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""独立实现的 VMess AEAD 服务端（P5 G2 的参考对端，lab 用；cryptography 库）。

按 olicesx/outbound protocol/vmess/{cipher,conn}.go 的 wire 规格独立实现，
不复用 Rust 侧任何代码。

用法： vmess_server.py <log> <uuid> <port> [cert.pem key.pem]
  uuid: 8-4-4-4-12 或 32 位十六进制；aid=0（AEAD）；security 3=AES-128-GCM / 4=ChaCha20
日志行： TCP target=<ip:port> / UDP target=<ip:port> / AUTH-FAIL / BAD-HDR <原因>
"""
import hashlib
import hmac
import os
import socket
import struct
import ssl
import sys
import threading
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

LOG = sys.argv[1]
UUID = bytes.fromhex(sys.argv[2].replace("-", ""))
PORT = int(sys.argv[3])
CERT = sys.argv[4] if len(sys.argv) > 4 else None
KEY = sys.argv[5] if len(sys.argv) > 5 else None

SO_MARK = getattr(socket, "SO_MARK", 36)
MARK = 0x233

SALT_KDF = b"VMess AEAD KDF"
SALT_AUTH = b"AES Auth ID Encryption"
SALT_REQ_LEN_KEY = b"VMess Header AEAD Key_Length"
SALT_REQ_LEN_NONCE = b"VMess Header AEAD Nonce_Length"
SALT_REQ_KEY = b"VMess Header AEAD Key"
SALT_REQ_NONCE = b"VMess Header AEAD Nonce"
SALT_RESP_LEN_KEY = b"AEAD Resp Header Len Key"
SALT_RESP_LEN_IV = b"AEAD Resp Header Len IV"
SALT_RESP_KEY = b"AEAD Resp Header Key"
SALT_RESP_IV = b"AEAD Resp Header IV"
CMD_KEY_MAGIC = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"


def log_line(line):
    with open(LOG, "a") as f:
        f.write(line + "\n")


def kdf(key, *paths):
    """嵌套 HMAC-SHA256（与 Go 的 hmac.New(func() hash.Hash{...}) 构造等价）。"""

    def factory(p):
        if not p:
            return lambda: hmac.new(SALT_KDF, digestmod=hashlib.sha256)
        prev = factory(p[:-1])
        return lambda: hmac.new(p[-1], digestmod=prev)

    m = factory(list(paths))()
    m.update(key)
    return m.digest()


def cmd_key(uuid16):
    return hashlib.md5(uuid16 + CMD_KEY_MAGIC).digest()


def fnv1a32(data):
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class Shake:
    """SHAKE128 流（先抽 padding，再抽 mask）。CPython 的 digest(n) 不推进流，
    这里累积总长度自取尾部。"""

    def __init__(self, seed):
        self.h = hashlib.shake_128(seed)
        self.n = 0

    def draw(self, n):
        need = self.n + n
        out = self.h.digest(need)[self.n : need]
        self.n = need
        return out

    def u16(self):
        return struct.unpack("!H", self.draw(2))[0]


def body_cipher(security, key16):
    if security == 3:
        return AESGCM(key16)
    if security == 4:
        t1 = hashlib.md5(key16).digest()
        t2 = hashlib.md5(t1).digest()
        return ChaCha20Poly1305(t1 + t2)
    raise ValueError(f"bad security {security}")


class Nonce:
    def __init__(self, iv):
        self.iv = iv
        self.counter = 0

    def next(self):
        n = struct.pack("!H", self.counter) + self.iv[2:12]
        self.counter += 1
        return n


class ChunkReader:
    """从 socket 读 VMess 数据块（含 padding/mask/终止块）。"""

    def __init__(self, sock, cipher, iv):
        self.sock = sock
        self.cipher = cipher
        self.nonce = Nonce(iv)
        self.shake = Shake(iv)

    def read_chunk(self):
        head = read_exact(self.sock, 2)
        if head is None:
            return None
        padding = self.shake.u16() % 64
        size = self.shake.u16() ^ struct.unpack("!H", head)[0]
        if size == 16 + padding:
            return b""  # 终止块
        if size < padding + 16:
            raise ValueError(f"bad chunk size {size} padding {padding}")
        frame = read_exact(self.sock, size)
        if frame is None:
            return None
        return self.cipher.decrypt(self.nonce.next(), frame[: size - padding], None)


class ChunkWriter:
    def __init__(self, sock, cipher, iv):
        self.sock = sock
        self.cipher = cipher
        self.nonce = Nonce(iv)
        self.shake = Shake(iv)

    def write_chunk(self, payload):
        padding = self.shake.u16() % 64
        ct = self.cipher.encrypt(self.nonce.next(), payload, None)
        size = len(ct) + padding
        mask = self.shake.u16()
        self.sock.sendall(struct.pack("!H", size ^ mask) + ct + os.urandom(padding))

    def write_terminator(self):
        padding = self.shake.u16() % 64
        ct = self.cipher.encrypt(self.nonce.next(), b"", None)
        size = len(ct) + padding
        mask = self.shake.u16()
        self.sock.sendall(struct.pack("!H", size ^ mask) + ct + os.urandom(padding))


def aes_ecb_decrypt(key, data):
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def parse_instr(instr):
    if len(instr) < 45 or instr[0] != 1:
        raise ValueError("bad version")
    body_iv = instr[1:17]
    body_key = instr[17:33]
    v = instr[33]
    options = instr[34]
    p = instr[35] >> 4
    security = instr[35] & 0x0F
    if instr[36] != 0:
        raise ValueError("reserved != 0")
    cmd = instr[37]
    port = struct.unpack("!H", instr[38:40])[0]
    atyp = instr[40]
    off = 41
    if atyp == 1:
        ip = socket.inet_ntoa(instr[off : off + 4])
        off += 4
    elif atyp == 2:
        ln = instr[off]
        ip = instr[off + 1 : off + 1 + ln].decode()
        off += 1 + ln
    elif atyp == 3:
        ip = socket.inet_ntop(socket.AF_INET6, instr[off : off + 16])
        off += 16
    else:
        raise ValueError(f"bad atyp {atyp}")
    if off + p + 4 != len(instr):
        raise ValueError("padding/checksum length mismatch")
    got = struct.unpack("!I", instr[-4:])[0]
    if fnv1a32(instr[:-4]) != got:
        raise ValueError("fnv1a mismatch")
    return {
        "body_iv": body_iv,
        "body_key": body_key,
        "v": v,
        "options": options,
        "security": security,
        "cmd": cmd,
        "ip": ip,
        "port": port,
    }


def set_mark(sock):
    """上游 socket 打 SO_MARK 防自环；非 root 环境降级为告警（lab 总是 root）。"""
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
    except PermissionError:
        log_line("WARN: SO_MARK 失败（非 root？）")


def dial_tcp(ip, port, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    set_mark(s)
    s.settimeout(timeout)
    s.connect((ip, port))
    return s


def handle(conn, key):
    with conn:
        e_auth = read_exact(conn, 16)
        if e_auth is None:
            return
        auth_key = kdf(key, SALT_AUTH)[:16]
        dec = aes_ecb_decrypt(auth_key, e_auth)
        if zlib.crc32(dec[:12]) != struct.unpack("!I", dec[12:16])[0]:
            log_line("AUTH-FAIL crc")
            return
        sealed_len = read_exact(conn, 18)
        if sealed_len is None:
            return
        conn_nonce = read_exact(conn, 8)
        if conn_nonce is None:
            return
        try:
            ln = AESGCM(kdf(key, SALT_REQ_LEN_KEY, e_auth, conn_nonce)[:16]).decrypt(
                kdf(key, SALT_REQ_LEN_NONCE, e_auth, conn_nonce)[:12], sealed_len, e_auth
            )
            instr_len = struct.unpack("!H", ln)[0]
            sealed_instr = read_exact(conn, instr_len + 16)
            if sealed_instr is None:
                return
            instr = AESGCM(kdf(key, SALT_REQ_KEY, e_auth, conn_nonce)[:16]).decrypt(
                kdf(key, SALT_REQ_NONCE, e_auth, conn_nonce)[:12], sealed_instr, e_auth
            )
            m = parse_instr(instr)
        except Exception as e:  # noqa: BLE001
            log_line(f"BAD-HDR {e}")
            return

        resp_key = hashlib.sha256(m["body_key"]).digest()[:16]
        resp_iv = hashlib.sha256(m["body_iv"]).digest()[:16]
        # 响应头：长度块 + 4 字节 payload [V,0,0,0]
        conn.sendall(
            AESGCM(kdf(resp_key, SALT_RESP_LEN_KEY)[:16]).encrypt(
                kdf(resp_iv, SALT_RESP_LEN_IV)[:12], struct.pack("!H", 4), None
            )
        )
        conn.sendall(
            AESGCM(kdf(resp_key, SALT_RESP_KEY)[:16]).encrypt(
                kdf(resp_iv, SALT_RESP_IV)[:12], bytes([m["v"], 0, 0, 0]), None
            )
        )

        rd = ChunkReader(conn, body_cipher(m["security"], m["body_key"]), m["body_iv"])
        wr = ChunkWriter(conn, body_cipher(m["security"], resp_key), resp_iv)

        if m["cmd"] == 1:
            log_line(f"TCP target={m['ip']}:{m['port']}")
            try:
                up = dial_tcp(m["ip"], m["port"])
            except OSError as e:
                log_line(f"TCP connect {m['ip']}:{m['port']} failed: {e}")
                return
            with up:
                down_done = threading.Event()

                def up_reader():
                    while True:
                        try:
                            data = up.recv(65536)
                        except OSError:
                            break
                        if not data:
                            break
                        wr.write_chunk(data)
                    wr.write_terminator()
                    down_done.set()

                threading.Thread(target=up_reader, daemon=True).start()
                while True:
                    try:
                        chunk = rd.read_chunk()
                    except (OSError, ValueError):
                        break
                    if chunk is None:
                        break
                    if chunk == b"":  # 终止块 → 半关闭目标
                        try:
                            up.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        break
                    up.sendall(chunk)
                down_done.wait(timeout=5)
        elif m["cmd"] == 2:
            log_line(f"UDP target={m['ip']}:{m['port']}")
            # 不用 connect：lab 拓扑里回包源地址会被 tproxy 恢复成 10.9.9.2（非
            # orig_dst），connected socket 会按对端过滤丢弃；sendto/recvfrom 无此问题。
            us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            set_mark(us)
            us.settimeout(0.5)
            stop = threading.Event()

            def up_reader():
                while not stop.is_set():
                    try:
                        data, _peer = us.recvfrom(65536)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    try:
                        wr.write_chunk(data)
                    except OSError:
                        break

            threading.Thread(target=up_reader, daemon=True).start()
            try:
                while True:
                    try:
                        chunk = rd.read_chunk()
                    except (OSError, ValueError):
                        break
                    if chunk is None or chunk == b"":
                        break
                    us.sendto(chunk, (m["ip"], m["port"]))
            finally:
                stop.set()
                us.close()
        else:
            log_line(f"UNSUPPORTED cmd={m['cmd']}")


def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(32)
    kind = "TLS" if CERT else "plain"
    print(f"vmess-server {kind} on 127.0.0.1:{PORT}", flush=True)
    key = cmd_key(UUID)
    ctx = None
    if CERT:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
    while True:
        c, _ = s.accept()
        if ctx:
            try:
                c = ctx.wrap_socket(c, server_side=True)
            except ssl.SSLError as e:
                log_line(f"TLS-ERROR {e}")
                c.close()
                continue
        threading.Thread(target=handle, args=(c, key), daemon=True).start()


serve()

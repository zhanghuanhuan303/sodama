#!/usr/bin/env python3
"""本地最小复现：ss_server.py 当服务端，纯 Python ss 客户端打 512KB。

不依赖 netns；目标是一个本地 echo（127.0.0.1:19999）。
"""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 18388
ECHO = 19999
PASSWORD = b"testpass"
LOG = "/tmp/ss-probe-%d.txt" % os.getpid()


def evp(pw, n=32):
    out, prev = b"", b""
    while len(out) < n:
        prev = hashlib.md5(prev + pw).digest()
        out += prev
    return out[:n]


MASTER = evp(PASSWORD)


def subkey(salt):
    return HKDF(algorithm=hashes.SHA1(), length=32, salt=salt, info=b"ss-subkey").derive(MASTER)


def nonce(i):
    return i.to_bytes(8, "little") + b"\x00" * 4


def echo_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", ECHO))
    s.listen(4)

    def handle(c):
        with c:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


threading.Thread(target=echo_server, daemon=True).start()

proc = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "ss_server.py"), LOG,
     "chacha20-ietf-poly1305", "testpass", str(PORT)],
)
time.sleep(0.5)

s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
s.settimeout(10)
salt = os.urandom(32)
s.sendall(salt)
key = subkey(salt)
aead = ChaCha20Poly1305(key)
n = 0


def send_chunk(payload):
    global n
    lb = aead.encrypt(nonce(n), struct.pack("!H", len(payload)), None)
    n += 1
    body = aead.encrypt(nonce(n), payload, None)
    n += 1
    s.sendall(lb + body)


send_chunk(b"\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", ECHO) + b"ping\n")

recv_key = None
recv_n = 0


def read_exact(k):
    buf = b""
    while len(buf) < k:
        chunk = s.recv(k - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_chunk():
    global recv_key, recv_n
    if recv_key is None:
        salt = read_exact(32)
        if salt is None:
            return None
        recv_key = subkey(salt)
    lb = read_exact(2 + 16)
    if lb is None:
        return None
    a = ChaCha20Poly1305(recv_key)
    ln = struct.unpack("!H", a.decrypt(nonce(recv_n), lb, None))[0]
    recv_n += 1
    body = read_exact(ln + 16)
    if body is None:
        return None
    out = a.decrypt(nonce(recv_n), body, None)
    recv_n += 1
    return out


print("prefix:", recv_chunk())
data = os.urandom(512 * 1024)
# 客户端也按 0x3fff 分块（与 Rust SsWriter 相同上限）
off = 0
while off < len(data):
    send_chunk(data[off:off + 0x3FFF])
    off += 0x3FFF

got = bytearray()
while len(got) < len(data):
    c = recv_chunk()
    if not c:
        break
    got += c
print("echo bytes:", len(got), "match:", bytes(got) == data)
proc.terminate()
print("server log:", open(LOG).read() if os.path.exists(LOG) else "<none>")
try:
    os.unlink(LOG)
except OSError:
    pass

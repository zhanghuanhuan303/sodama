#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""本地最小复现：trojan_server.py 当服务端，纯 Python trojan 客户端打 512KB。

不依赖 netns；目标是一个本地 echo（127.0.0.1:19999）。需要自签证书（lab/certs）。
"""
import hashlib
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 18443
ECHO = 19999
PASSWORD = b"testpass"
LOG = "/tmp/trojan-probe-%d.txt" % os.getpid()


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
    [sys.executable, os.path.join(HERE, "trojan_server.py"), LOG, "testpass", str(PORT),
     os.path.join(HERE, "certs", "cert.pem"), os.path.join(HERE, "certs", "key.pem")],
)
time.sleep(0.5)

raw = socket.create_connection(("127.0.0.1", PORT), timeout=5)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(raw, server_hostname="localhost")
s.settimeout(10)

head = hashlib.sha224(PASSWORD).hexdigest().encode() + b"\r\n\x01"
head += b"\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", ECHO) + b"\r\n"
s.sendall(head)
s.sendall(b"ping\n")
print("prefix:", s.recv(4096))

data = os.urandom(512 * 1024)
s.sendall(data)
got = bytearray()
while len(got) < len(data):
    c = s.recv(65536)
    if not c:
        break
    got += c
print("echo bytes:", len(got), "match:", bytes(got) == data)
proc.terminate()
time.sleep(0.2)
print("server log:", open(LOG).read() if os.path.exists(LOG) else "<none>")
try:
    os.unlink(LOG)
except OSError:
    pass

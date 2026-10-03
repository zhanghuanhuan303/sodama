#!/usr/bin/env python3
"""最小 SOCKS5 后端（无认证，只支持 CONNECT）：K3「过渡一跳」的实验对端。

收到 CONNECT 后把目标写进日志文件（lab 用它断言 orig_dst 被保留），
然后回显 `socks5-backend: target=<ip>:<port>` 与后续数据。
真实部署中这个位置可以是任何 SOCKS5 服务（例如 Go dae 一侧加的本地入口，
或后续 P5 原生协议栈替换）。
"""
import socket
import struct
import sys
import threading

LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/mini-dae-socks5-target.txt"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1081


def handle(conn):
    try:
        hdr = conn.recv(2)
        if len(hdr) < 2 or hdr[0] != 5:
            return
        nmethods = hdr[1]
        conn.recv(nmethods)
        conn.sendall(b"\x05\x00")
        req = conn.recv(4)
        if len(req) < 4 or req[1] != 1:
            return
        atyp = req[3]
        if atyp == 1:
            addr = socket.inet_ntoa(conn.recv(4))
        elif atyp == 4:
            addr = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        elif atyp == 3:
            ln = conn.recv(1)[0]
            addr = conn.recv(ln).decode()
        else:
            return
        port = struct.unpack("!H", conn.recv(2))[0]
        with open(LOG, "a") as f:
            f.write(f"CONNECT {addr}:{port}\n")
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        conn.sendall(f"socks5-backend: target={addr}:{port}\n".encode())
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(b"socks5-backend echo: " + data)
    finally:
        conn.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(16)
print(f"socks5-backend listening on 127.0.0.1:{PORT}", flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()

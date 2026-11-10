#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""最小客户端：连一下，发一行，打印回包。

用法：client_probe.py <host> <port> [lport]
lport：可选，固定本地源端口（同 4 元组重连回归用；带 SO_REUSEADDR 以允许
       TIME_WAIT 端口复用）。
"""
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
lport = int(sys.argv[3]) if len(sys.argv) > 3 else 0
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if lport:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", lport))
s.settimeout(4)
s.connect((host, port))
s.sendall(b"ping\n")
data = s.recv(4096)
sys.stdout.write(data.decode(errors="replace") + "\n")
s.close()

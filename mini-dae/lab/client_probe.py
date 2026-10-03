#!/usr/bin/env python3
"""最小客户端：连一下，发一行，打印回包。"""
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
s = socket.create_connection((host, port), timeout=4)
s.sendall(b"ping\n")
data = s.recv(4096)
sys.stdout.write(data.decode(errors="replace") + "\n")
s.close()

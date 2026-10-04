#!/usr/bin/env python3
"""P21 sniff-punt 探针：发一个带指定 SNI 的最小 TLS ClientHello，观察后续回显。

不依赖任何 TLS 库：ClientHello 按 RFC 8446 手写（与 loader/src/sniffer.rs 的
解析互为跨实现验证）。wan_echo 在 8080 的首包回 "wan-echo-ok data=..."。

用法： tls_sniff_probe.py <host> <port> <sni>
输出： tls-probe-ok sni=<sni>       收到 wan echo（direct / proxy 路径均可用）
      tls-probe-closed sni=<sni>   连接被关闭（block 用例）
      tls-probe-timeout sni=<sni>
"""
import os
import socket
import struct
import sys


def client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = (
        struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    )
    exts = b"\x00\x00" + struct.pack("!H", len(sni_ext)) + sni_ext
    body = (
        b"\x03\x03"
        + os.urandom(32)
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


host, port, sni = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection((host, port), timeout=4)
s.settimeout(5)
s.sendall(client_hello(sni))
try:
    data = b""
    while b"wan-echo-ok" not in data:
        chunk = s.recv(4096)
        if not chunk:
            print(f"tls-probe-closed sni={sni}")
            sys.exit(0)
        data += chunk
    s.sendall(b"ping\n")
    while b"ping" not in data.split(b"wan-echo-ok", 1)[1]:
        chunk = s.recv(4096)
        if not chunk:
            print(f"tls-probe-half-closed sni={sni}")
            sys.exit(1)
        data += chunk
    print(f"tls-probe-ok sni={sni}")
except socket.timeout:
    print(f"tls-probe-timeout sni={sni}")
except (ConnectionResetError, OSError):
    print(f"tls-probe-closed sni={sni}")
finally:
    s.close()

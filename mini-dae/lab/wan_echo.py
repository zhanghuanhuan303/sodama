#!/usr/bin/env python3
"""WAN 侧 echo 服务：验证 direct / relay 路径确实到达 WAN。

监听：
  9999  TCP 单次应答（"wan-echo-ok data=..."，direct 用例）
  8080  TCP 首包应答 + 后续原样回显（fail-open 与 relay 用例）
  8082  TCP 纯回显（P4 relay 大流量完整性用例）
  9998  UDP 回显（P4 UDP NAT 用例，回复 "udp-echo-ok data=..."）
"""
import socket
import threading


def serve(port, first_line):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    print(f"wan-echo listening on 0.0.0.0:{port}", flush=True)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn, first_line), daemon=True).start()


def handle(conn, first_line):
    with conn:
        data = conn.recv(4096)
        if not data:
            return
        if first_line:
            conn.sendall(b"wan-echo-ok data=" + data)
        else:
            conn.sendall(data)
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)


def serve_udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    print(f"wan-echo UDP listening on 0.0.0.0:{port}", flush=True)
    while True:
        data, addr = s.recvfrom(65536)
        s.sendto(b"udp-echo-ok data=" + data, addr)


threading.Thread(target=serve, args=(9999, True), daemon=True).start()
threading.Thread(target=serve, args=(8080, True), daemon=True).start()
threading.Thread(target=serve, args=(8082, False), daemon=True).start()
threading.Thread(target=serve_udp, args=(9998,), daemon=True).start()
threading.Event().wait()

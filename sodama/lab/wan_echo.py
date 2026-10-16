#!/usr/bin/env python3
"""WAN 侧 echo 服务：验证 direct / relay 路径确实到达 WAN。

监听：
  9999  TCP 单次应答（"wan-echo-ok data=..."，direct 用例）
  8080  TCP 首包应答 + 后续原样回显（fail-open 与 relay 用例）
  8082  TCP 纯回显（P4 relay 大流量完整性用例）
  8083  TCP 首包应答后立即关闭（半关闭回归：上游先关，客户端保持）
  9998  UDP 回显（P4 UDP NAT 用例，回复 "udp-echo-ok data=..."；P22 起 v4/v6 双栈）
  9997  UDP 回显（P38 full-cone 用例：同一客户端 socket 向 9998+9997 双目标）
"""
import socket
import threading


def serve(port, first_line, close_after_reply=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    print(f"wan-echo listening on 0.0.0.0:{port}", flush=True)
    # P16：并行监听 IPv6（V6ONLY，不抢 v4 的绑定）
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s6.bind(("::", port))
        s6.listen(16)
        print(f"wan-echo listening on [::]:{port}", flush=True)
    except OSError as e:  # 内核无 IPv6 时降级为仅 v4
        print(f"wan-echo IPv6 不可用，仅 v4: {e}", flush=True)
        s6 = None

    def accept_loop(sock):
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=handle, args=(conn, first_line, close_after_reply), daemon=True).start()

    if s6 is not None:
        threading.Thread(target=accept_loop, args=(s6,), daemon=True).start()
    accept_loop(s)


def handle(conn, first_line, close_after_reply=False):
    with conn:
        data = conn.recv(4096)
        if not data:
            return
        if first_line:
            conn.sendall(b"wan-echo-ok data=" + data)
        else:
            conn.sendall(data)
        if close_after_reply:
            return  # 应答后即关：制造「上游先关、客户端保持」半关闭姿态
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)


def serve_udp_sock(s):
    while True:
        data, addr = s.recvfrom(65536)
        s.sendto(b"udp-echo-ok data=" + data, addr)


def serve_udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    print(f"wan-echo UDP listening on 0.0.0.0:{port}", flush=True)
    # P22：并行监听 IPv6 UDP（V6ONLY），供 v6 UDP relay 用例
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s6.bind(("::", port))
        print(f"wan-echo UDP listening on [::]:{port}", flush=True)
        threading.Thread(target=serve_udp_sock, args=(s6,), daemon=True).start()
    except OSError as e:  # 内核无 IPv6 时降级为仅 v4
        print(f"wan-echo UDP IPv6 不可用，仅 v4: {e}", flush=True)
    serve_udp_sock(s)


threading.Thread(target=serve, args=(9999, True), daemon=True).start()
threading.Thread(target=serve, args=(8080, True), daemon=True).start()
threading.Thread(target=serve, args=(8082, False), daemon=True).start()
threading.Thread(target=serve, args=(8083, True, True), daemon=True).start()
threading.Thread(target=serve_udp, args=(9998,), daemon=True).start()
threading.Thread(target=serve_udp, args=(9997,), daemon=True).start()
threading.Event().wait()

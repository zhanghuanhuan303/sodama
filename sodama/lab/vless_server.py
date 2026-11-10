#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""独立实现的 VLESS 服务端（P5 G2 的参考对端，lab 用，stdlib + ssl）。

与 sodama 的 Rust 客户端互操作是「跨实现」验证：本文件按 VLESS wire 规格独立实现
（对照 olicesx/outbound protocol/vless/conn.go），不复用 Rust 侧任何代码。

用法： vless_server.py <log> <uuid> <port> [cert.pem key.pem]
  uuid: 8-4-4-4-12 或 32 位十六进制
日志行： TCP target=<ip:port> / UDP target=<ip:port> / AUTH-FAIL / UNSUPPORTED cmd=N
"""
import socket
import ssl
import struct
import sys
import threading

LOG = sys.argv[1]
UUID_STR = sys.argv[2].replace("-", "")
PORT = int(sys.argv[3])
CERT = sys.argv[4] if len(sys.argv) > 4 else None
KEY = sys.argv[5] if len(sys.argv) > 5 else None

UUID = bytes.fromhex(UUID_STR)

SO_MARK = getattr(socket, "SO_MARK", 36)
MARK = 0x233


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


def parse_addr(sock):
    port = struct.unpack("!H", read_exact(sock, 2))[0]
    atyp = read_exact(sock, 1)[0]
    if atyp == 1:
        ip = socket.inet_ntoa(read_exact(sock, 4))
    elif atyp == 2:
        ln = read_exact(sock, 1)[0]
        ip = read_exact(sock, ln).decode()
    elif atyp == 3:
        ip = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
    else:
        raise ValueError(f"bad atyp {atyp}")
    return ip, port


def pump(reader, writer):
    """reader: callable n->bytes|None；writer: callable bytes。EOF 时半关闭。"""
    while True:
        data = reader(65536)
        if not data:
            break
        try:
            writer(data)
        except OSError:
            break
    try:
        writer(None)  # 半关闭信号
    except (OSError, TypeError):
        pass


def handle_tcp(conn):
    with conn:
        # 请求头：ver(1) + uuid(16) + addonLen(1) + addons
        head = read_exact(conn, 18)
        if not head or head[0] != 0:
            return
        if head[1:17] != UUID:
            log_line("AUTH-FAIL")
            return
        addon_len = head[17]
        if addon_len and read_exact(conn, addon_len) is None:
            return
        cmd = read_exact(conn, 1)[0]
        if cmd == 3:
            log_line("UNSUPPORTED cmd=3 (mux)")
            return
        ip, port = parse_addr(conn)
        if cmd == 1:
            log_line(f"TCP target={ip}:{port}")
            try:
                up = dial_tcp(ip, port)
            except OSError as e:
                log_line(f"TCP connect {ip}:{port} failed: {e}")
                return
            conn.sendall(b"\x00\x00")  # 响应头：ver=0 + 空 addons
            with up:
                t1 = threading.Thread(
                    target=pump,
                    args=(lambda n: conn.recv(n) or None, lambda d: up.sendall(d)),
                    daemon=True,
                )
                t2 = threading.Thread(
                    target=pump,
                    args=(lambda n: up.recv(n) or None, lambda d: conn.sendall(d)),
                    daemon=True,
                )
                t1.start()
                t2.start()
                t1.join()
                t2.join()
        elif cmd == 2:
            log_line(f"UDP target={ip}:{port}")
            conn.sendall(b"\x00\x00")
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
                    conn.sendall(struct.pack("!H", len(data)) + data)

            threading.Thread(target=up_reader, daemon=True).start()
            try:
                while True:
                    ln = read_exact(conn, 2)
                    if ln is None:
                        break
                    n = struct.unpack("!H", ln)[0]
                    payload = read_exact(conn, n) if n else b""
                    if payload is None:
                        break
                    us.sendto(payload, (ip, port))
            finally:
                stop.set()
                us.close()
        else:
            log_line(f"UNSUPPORTED cmd={cmd}")


def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(32)
    kind = "TLS" if CERT else "plain"
    print(f"vless-server {kind} on 127.0.0.1:{PORT}", flush=True)
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
        threading.Thread(target=handle_tcp, args=(c,), daemon=True).start()


serve()

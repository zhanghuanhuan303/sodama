#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""独立实现的 HTTP CONNECT 代理服务端（P18e `http://` 出站的参考对端，lab 用）。

与 sodama 的 Rust 客户端互操作是「跨实现」验证：本文件只用 Python 标准库
实现 CONNECT 隧道（可选 Basic 认证），不复用 Rust 侧任何代码。

用法： python3 http_connect_server.py <log> <port> [user:pass]
日志行： CONNECT <host>:<port> / AUTH-OK / AUTH-FAIL / BAD <首行>
"""
import base64
import select
import socket
import sys
import threading

LOG = sys.argv[1]
PORT = int(sys.argv[2])
AUTH = sys.argv[3] if len(sys.argv) > 3 else None
SO_MARK = getattr(socket, "SO_MARK", 36)
MARK = 0x233  # 与 lab 其他夹具一致：避免被运行中的 sodama 数据面二次接管


def log(line: str) -> None:
    with open(LOG, "a") as f:
        f.write(line + "\n")


def pump(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 30)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass


def connect_upstream(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
    s.settimeout(5)
    s.connect((host, port))
    s.settimeout(None)
    return s


def handle(conn: socket.socket) -> None:
    try:
        f = conn.makefile("rb")
        line = f.readline(8192)
        if not line:
            return
        first = line.decode("latin1").strip()
        parts = first.split()
        if len(parts) < 2 or parts[0] != "CONNECT":
            log("BAD " + first)
            return
        if AUTH is not None:
            # 读头找 Proxy-Authorization
            ok = False
            while True:
                h = f.readline(8192)
                if h in (b"\r\n", b"\n", b""):
                    break
                if h.lower().startswith(b"proxy-authorization: basic "):
                    got = h.split(None, 2)[2].strip().decode("latin1")
                    ok = got == base64.b64encode(AUTH.encode()).decode()
            if not ok:
                log("AUTH-FAIL")
                conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             b"Proxy-Authenticate: Basic realm=\"lab\"\r\n\r\n")
                return
            log("AUTH-OK")
        else:
            while True:
                h = f.readline(8192)
                if h in (b"\r\n", b"\n", b""):
                    break
        host, _, port = parts[1].rpartition(":")
        log(f"CONNECT {host}:{port}")
        try:
            up = connect_upstream(host, int(port))
        except OSError as e:
            log(f"UPSTREAM-FAIL {host}:{port} {e}")
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        pump(conn, up)
        up.close()
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()

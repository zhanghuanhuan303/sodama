#!/usr/bin/env python3
# Vision 内层 TLS 靶站：确定性内容 + 可选 TLS1.2-only 端口（验证 END 回退）。
# 用法：python3 https_target.py <port> <www-dir> [tls12]
import http.server
import ssl
import sys
import threading
from functools import partial

PORT = int(sys.argv[1])
WWW = sys.argv[2]
MODE = sys.argv[3] if len(sys.argv) > 3 else "tls13"


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):  # 静默
        pass


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/vision-lab/cert.pem", "/tmp/vision-lab/key.pem")
    if MODE == "tls12":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), partial(Handler, directory=WWW))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"https target on :{PORT} mode={MODE}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()

#!/usr/bin/env python3
"""P15：订阅服务器（lab 夹具）——把给定文件内容作为 GET /sub 的响应体返回。

用法：python3 sub_server.py <port> <body-file>
（内容通常是 base64 节点链接列表；不做压缩/编码处理，保持夹具最小。
 文件按请求重读：P18e 订阅热更新用例会改文件后 SIGHUP。）
"""
import http.server
import sys


def main() -> None:
    port = int(sys.argv[1])
    body_file = sys.argv[2]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib 命名)
            if self.path.split("?")[0] in ("/sub", "/"):
                body = open(body_file, "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, *args) -> None:
            pass

    with http.server.HTTPServer(("127.0.0.1", port), Handler) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()

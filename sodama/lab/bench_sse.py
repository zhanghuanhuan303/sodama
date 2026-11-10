#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""sodama lab · SSE 首字延迟（TTFT）/ 帧间抖动基准。

两个模式：
  --serve   起本地 SSE 测试服务器（模拟 AI 逐字流：首字延迟/间隔/块大小可调）；
  --url     对目标做流式测量：请求发出后逐次 recv 打时间戳，统计
            TTFT（首个 body 字节到达）、帧间间隔 p50/p95/max、抖动 σ、总时长。

用法：
  # 1) 自校验（本机环回，测得值应≈服务器参数：TTFT≈first-delay，gap≈interval）
  python3 bench_sse.py --serve --port 18642 &
  python3 bench_sse.py --url http://127.0.0.1:18642/sse --runs 3

  # 2) 真环境对比：同一 SSE 端点在「直连 / 经 sodama 网关」下各跑一次，
  #    对比 TTFT 与 jitter——sodama 两端已关 Nagle + 零聚合转发（对照 43ms 级毛刺）。

  # 3) 机器可读（存档/回归对比）
  python3 bench_sse.py --url <SSE_URL> --runs 5 --json > before.json

为什么用裸 socket 逐 recv 打时间戳：绕开 http.client 的缓冲，测「网络到达节奏」，
能真实暴露 Nagle / 用户态攒批造成的 40ms 级毛刺与逐字流停顿。
仅标准库，无第三方依赖。
"""
import argparse
import json
import socket
import ssl
import statistics
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def now():
    return time.monotonic()


def pct(xs, p):
    """近似分位数（线性插值）。"""
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


# ---------------------------------------------------------------------------
# 测量：裸 socket 逐 recv 打时间戳
# ---------------------------------------------------------------------------

def measure_once(url, timeout, insecure, max_duration):
    u = urlparse(url)
    scheme = u.scheme or "http"
    host = u.hostname
    if not host:
        return {"ok": False, "error": f"bad url: {url}"}
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    raw = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        # 客户端侧关 Nagle（贴近真实 AI SDK 行为；避免上行小包叠加延迟 ACK）
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Accept: text/event-stream\r\n"
            "User-Agent: sodama-bench-sse/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        t_sent = now()

        events = []  # [(t, nbytes)] —— 每次 recv（body 段）到达事件
        hdr_buf = b""
        body_started = False
        while True:
            if now() - t_sent > max_duration:
                break
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            t = now()
            if not data:
                break
            if not body_started:
                hdr_buf += data
                idx = hdr_buf.find(b"\r\n\r\n")
                if idx < 0:
                    if len(hdr_buf) > 65536:  # 响应头异常大，放弃
                        break
                    continue
                body = hdr_buf[idx + 4:]
                body_started = True
                if body:
                    events.append((t, len(body)))
            else:
                events.append((t, len(data)))
    except OSError as e:
        return {"ok": False, "error": str(e)}
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass

    if not events:
        return {"ok": False, "error": "no body bytes"}

    ttft_ms = (events[0][0] - t_sent) * 1000.0
    gaps_ms = [(events[i][0] - events[i - 1][0]) * 1000.0 for i in range(1, len(events))]
    total_ms = (events[-1][0] - t_sent) * 1000.0
    return {
        "ok": True,
        "ttft_ms": round(ttft_ms, 3),
        "gaps_ms": [round(g, 3) for g in gaps_ms],
        "total_ms": round(total_ms, 3),
        "chunks": len(events),
        "bytes": sum(n for _, n in events),
    }


def summarize(runs):
    oks = [r for r in runs if r.get("ok")]
    ttfts = [r["ttft_ms"] for r in oks]
    all_gaps = [g for r in oks for g in r["gaps_ms"]]
    totals = [r["total_ms"] for r in oks]
    return {
        "runs": len(runs),
        "ok": len(oks),
        "ttft_ms": {
            "p50": round(pct(ttfts, 50), 3),
            "p95": round(pct(ttfts, 95), 3),
            "max": round(max(ttfts), 3) if ttfts else 0.0,
        },
        "gap_ms": {
            "p50": round(pct(all_gaps, 50), 3),
            "p95": round(pct(all_gaps, 95), 3),
            "max": round(max(all_gaps), 3) if all_gaps else 0.0,
            "jitter_std": round(statistics.pstdev(all_gaps), 3) if len(all_gaps) > 1 else 0.0,
            "samples": len(all_gaps),
        },
        "total_ms": {"p50": round(pct(totals, 50), 3)},
        "bytes_avg": round(statistics.fmean(r["bytes"] for r in oks), 1) if oks else 0.0,
        "chunks_avg": round(statistics.fmean(r["chunks"] for r in oks), 1) if oks else 0.0,
    }


# ---------------------------------------------------------------------------
# 本地 SSE 测试服务器（模拟 AI 逐字流）
# ---------------------------------------------------------------------------

def serve(port, first_delay_ms, interval_ms, chunk_bytes, chunks):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # 静音
            pass

        def do_GET(self):
            try:
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()

            time.sleep(max(0, first_delay_ms) / 1000.0)  # 模拟模型首字延迟
            body = b"x" * max(1, chunk_bytes)
            for i in range(max(1, chunks)):
                frame = b"data: " + body + b"\n\n"
                try:
                    self.wfile.write(frame)
                    self.wfile.flush()
                except OSError:
                    break
                if i != chunks - 1:
                    time.sleep(max(0, interval_ms) / 1000.0)
            self.close_connection = True

    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    print(
        f"SERVING http://0.0.0.0:{port}/sse  "
        f"first={first_delay_ms}ms interval={interval_ms}ms chunk={chunk_bytes}B n={chunks}",
        flush=True,
    )
    srv.serve_forever()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="sodama SSE/TTFT 基准", allow_abbrev=False)
    ap.add_argument("--serve", action="store_true", help="起本地 SSE 测试服务器")
    ap.add_argument("--url", help="测量模式的 SSE 目标 URL")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=10.0, help="连接/单次 recv 超时（秒）")
    ap.add_argument("--max-duration", type=float, default=60.0, help="单次测量最长时长（秒）")
    ap.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    # serve 模式参数
    ap.add_argument("--port", type=int, default=18642)
    ap.add_argument("--first-delay-ms", type=int, default=300, dest="first_delay_ms")
    ap.add_argument("--interval-ms", type=int, default=50, dest="interval_ms")
    ap.add_argument("--chunk-bytes", type=int, default=32, dest="chunk_bytes")
    ap.add_argument("--chunks", type=int, default=100)
    args = ap.parse_args()

    if args.serve:
        try:
            serve(args.port, args.first_delay_ms, args.interval_ms, args.chunk_bytes, args.chunks)
        except KeyboardInterrupt:
            pass
        return

    if not args.url:
        ap.error("测量模式需要 --url（或 --serve）")

    runs = []
    for i in range(max(1, args.runs)):
        r = measure_once(args.url, args.timeout, args.insecure, args.max_duration)
        runs.append(r)
        if not args.json:
            if r["ok"]:
                print(
                    f"run {i + 1}/{args.runs}: ttft={r['ttft_ms']:.1f}ms "
                    f"chunks={r['chunks']} total={r['total_ms']:.1f}ms bytes={r['bytes']}",
                    flush=True,
                )
            else:
                print(f"run {i + 1}/{args.runs}: FAIL {r['error']}", flush=True)

    summary = summarize(runs)
    out = {"url": args.url, "runs": runs, "summary": summary}
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    s = summary
    print()
    print(f"URL: {args.url}")
    print(f"runs: {s['runs']}  ok: {s['ok']}")
    print(
        f"TTFT(ms)      p50={s['ttft_ms']['p50']:.1f}  p95={s['ttft_ms']['p95']:.1f}"
        f"  max={s['ttft_ms']['max']:.1f}"
    )
    print(
        f"帧间隔(ms)     p50={s['gap_ms']['p50']:.1f}  p95={s['gap_ms']['p95']:.1f}"
        f"  max={s['gap_ms']['max']:.1f}  jitter(σ)={s['gap_ms']['jitter_std']:.1f}"
        f"  (n={s['gap_ms']['samples']})"
    )
    print(f"单次时长(ms)   p50={s['total_ms']['p50']:.1f}")
    print(f"平均块数/字节  {s['chunks_avg']:.1f} / {s['bytes_avg']:.1f}")


if __name__ == "__main__":
    sys.exit(main())

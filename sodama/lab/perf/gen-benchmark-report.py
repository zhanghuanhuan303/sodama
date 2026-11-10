#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""生成 docs/benchmark-report.html —— sodama 性能与资源边界报告 v3.0（合并版）。

合并来源：
  1) docs/perf-report.md          （吞吐/延迟四方对拍、并发扩展、perf 剖面）
  2) docs/memory-report-v2.html   （四层内存模型、FD 治理、转发原语、长稳）
  3) docs/memory-report.html      （v1 五方 RSS 口径，作为存档章节）
  4) 2026-10-06 本机并发压测（1k→50k，附录 E 数据 + fd 硬限修复）

用法：python3 lab/perf/gen-benchmark-report.py [输出路径]
      默认输出 ../docs/benchmark-report.html（相对本脚本）。
所有数字均为实测；口径与边界写在正文 §1/§10。
"""
import sys, os, datetime

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "docs", "benchmark-report.html")
OUT = os.path.normpath(OUT)

CSS = """
:root{
  --ink:#1a1d21; --muted:#5a6570; --rule:#d9dee4; --rule-soft:#e8ecf0;
  --navy:#1f4e79; --navy-soft:#eef3f8; --warm:#a0522d; --warm-soft:#f8f1ec;
  --green:#2e7d4f; --bg:#ffffff; --code:#f4f6f8;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.75 "Segoe UI",system-ui,-apple-system,"Noto Sans SC","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  font-variant-numeric:tabular-nums}
.wrap{max-width:980px;margin:0 auto;padding:48px 40px 96px}
header.doc{border-bottom:2px solid var(--ink);padding-bottom:22px;margin-bottom:34px}
.kicker{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin-bottom:10px}
h1{font-size:27px;line-height:1.35;margin:0 0 10px;font-weight:700;letter-spacing:.01em}
.subtitle{color:var(--muted);font-size:14.5px;margin:0 0 16px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px 28px;font-size:13px;color:var(--muted)}
.meta b{color:var(--ink);font-weight:600}
.badge{display:inline-block;border:1px solid var(--ink);border-radius:3px;padding:1px 8px;font-size:11.5px;letter-spacing:.08em;margin-left:8px;vertical-align:2px}
h2{font-size:19px;margin:44px 0 14px;padding-bottom:6px;border-bottom:1px solid var(--rule);font-weight:700}
h3{font-size:15.5px;margin:28px 0 10px;font-weight:700}
p{margin:10px 0}
ul,ol{margin:10px 0 10px 4px;padding-left:22px}
li{margin:4px 0}
small,.small{font-size:12.5px;color:var(--muted)}
code,kbd{background:var(--code);border:1px solid var(--rule-soft);border-radius:3px;padding:1px 5px;font:12.5px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
pre{background:var(--code);border:1px solid var(--rule-soft);border-radius:4px;padding:12px 14px;overflow:auto;font:12.5px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace}
table{width:100%;border-collapse:collapse;margin:14px 0;font-size:13.5px}
th,td{border-bottom:1px solid var(--rule-soft);padding:7px 10px;text-align:left;vertical-align:top}
thead th{border-bottom:1.5px solid var(--ink);font-weight:600;font-size:12.5px;letter-spacing:.02em}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
tbody tr:hover{background:#fafbfc}
.callout{border-left:3px solid var(--navy);background:var(--navy-soft);padding:12px 16px;margin:16px 0;border-radius:0 4px 4px 0}
.callout.warn{border-color:var(--warm);background:var(--warm-soft)}
.callout p:first-child{margin-top:0}.callout p:last-child{margin-bottom:0}
figure{margin:22px 0;border:1px solid var(--rule-soft);border-radius:4px;padding:14px 14px 8px}
figure svg{display:block;width:100%;height:auto}
figcaption{font-size:12.5px;color:var(--muted);margin-top:8px;line-height:1.6}
.toc{columns:2;column-gap:40px;font-size:13.5px;margin:14px 0}
.toc a{color:var(--ink);text-decoration:none;border-bottom:1px dotted var(--rule)}
.toc a:hover{color:var(--navy)}
.tag{display:inline-block;font-size:11.5px;border-radius:3px;padding:1px 7px;letter-spacing:.03em}
.tag.ok{background:#e9f3ec;color:#1d5c34;border:1px solid #c4ddcd}
.tag.part{background:#fdf3e4;color:#7a5217;border:1px solid #ecd6ad}
.tag.new{background:var(--navy-soft);color:var(--navy);border:1px solid #c9dcee}
.num{white-space:nowrap}
.rule{margin:34px 0;border:0;border-top:1px solid var(--rule-soft)}
footer.doc{margin-top:56px;padding-top:18px;border-top:1px solid var(--rule);font-size:12.5px;color:var(--muted)}
@media print{.wrap{max-width:none;padding:0 6mm}h2{break-after:avoid}figure,table{break-inside:avoid}a{color:inherit;text-decoration:none}}
"""

# ---------------------------------------------------------------- SVG 图表

def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

def line_chart(series, xs, *, w=880, h=300, x_label="", y_unit="", log_x=True,
               y_min=None, y_max=None, pad_l=64, pad_r=18, pad_t=16, pad_b=46):
    """series: [{"name","values","color","dashed"?}]; xs: x 值（与 values 等长）"""
    ys = [v for s in series for v in s["values"] if v is not None]
    lo = y_min if y_min is not None else 0.0
    hi = y_max if y_max is not None else max(ys) * 1.12
    import math
    if log_x:
        lx = [math.log10(x) for x in xs]
        x0, x1 = min(lx), max(lx)
        fx = lambda x: pad_l + (math.log10(x) - x0) / (x1 - x0) * (w - pad_l - pad_r)
    else:
        x0, x1 = min(xs), max(xs)
        fx = lambda x: pad_l + (x - x0) / (x1 - x0) * (w - pad_l - pad_r)
    fy = lambda v: h - pad_b - (v - lo) / (hi - lo) * (h - pad_t - pad_b)
    out = [f'<svg viewBox="0 0 {w} {h}" role="img">']
    # y 网格 + 刻度
    for i in range(5):
        v = lo + (hi - lo) * i / 4
        y = fy(v)
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{w-pad_r}" y2="{y:.1f}" stroke="#e8ecf0" stroke-width="1"/>')
        out.append(f'<text x="{pad_l-8}" y="{y+4:.1f}" text-anchor="end" font-size="11" fill="#5a6570">{v:,.0f}</text>')
    # x 刻度
    for x in xs:
        gx = fx(x)
        out.append(f'<line x1="{gx:.1f}" y1="{h-pad_b}" x2="{gx:.1f}" y2="{h-pad_b+4}" stroke="#9aa4ad"/>')
        lab = f"{x//1000}k" if x >= 1000 and x % 1000 == 0 else str(x)
        out.append(f'<text x="{gx:.1f}" y="{h-pad_b+18}" text-anchor="middle" font-size="11" fill="#5a6570">{lab}</text>')
    # 轴
    out.append(f'<line x1="{pad_l}" y1="{h-pad_b}" x2="{w-pad_r}" y2="{h-pad_b}" stroke="#1a1d21" stroke-width="1"/>')
    out.append(f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{h-pad_b}" stroke="#1a1d21" stroke-width="1"/>')
    # 折线
    for s in series:
        pts = " ".join(
            f"{fx(x):.1f},{fy(v):.1f}" for x, v in zip(xs, s["values"]) if v is not None)
        dash = ' stroke-dasharray="5 4"' if s.get("dashed") else ""
        out.append(f'<polyline points="{pts}" fill="none" stroke="{s["color"]}" stroke-width="2"{dash}/>')
        for x, v in zip(xs, s["values"]):
            if v is not None:
                out.append(f'<circle cx="{fx(x):.1f}" cy="{fy(v):.1f}" r="2.6" fill="{s["color"]}"/>')
    # 图例
    lx0 = pad_l + 6
    for s in series:
        out.append(f'<rect x="{lx0}" y="{pad_t+2}" width="14" height="3" fill="{s["color"]}"/>')
        out.append(f'<text x="{lx0+20}" y="{pad_t+9}" font-size="11.5" fill="#1a1d21">{esc(s["name"])}</text>')
        lx0 += 24 + 8 * len(s["name"]) + 26
    out.append(f'<text x="{pad_l-52}" y="{pad_t+10}" font-size="11" fill="#5a6570">{esc(y_unit)}</text>')
    if x_label:
        out.append(f'<text x="{w-pad_r}" y="{h-pad_b+34}" text-anchor="end" font-size="11" fill="#5a6570">{esc(x_label)}</text>')
    out.append("</svg>")
    return "".join(out)

def bar_chart(groups, series, *, w=880, h=300, y_unit="", pad_l=64, pad_r=18, pad_t=16, pad_b=46, fmt="{:.0f}"):
    """groups: x 轴组标签；series: [{"name","values","color"}]（每个 series 在每个组一根柱）"""
    vals = [v for s in series for v in s["values"]]
    hi = max(vals) * 1.15
    n_g, n_s = len(groups), len(series)
    gw = (w - pad_l - pad_r) / n_g
    bw = min(26.0, (gw - 18) / n_s)
    fy = lambda v: h - pad_b - v / hi * (h - pad_t - pad_b)
    out = [f'<svg viewBox="0 0 {w} {h}" role="img">']
    for i in range(5):
        v = hi * i / 4
        y = fy(v)
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{w-pad_r}" y2="{y:.1f}" stroke="#e8ecf0"/>')
        out.append(f'<text x="{pad_l-8}" y="{y+4:.1f}" text-anchor="end" font-size="11" fill="#5a6570">{v:,.0f}</text>')
    for gi, g in enumerate(groups):
        cx = pad_l + gw * (gi + 0.5)
        x = cx - (n_s * bw) / 2
        for si, s in enumerate(series):
            v = s["values"][gi]
            y = fy(v)
            out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw-2:.1f}" height="{h-pad_b-y:.1f}" fill="{s["color"]}"/>')
            out.append(f'<text x="{x+(bw-2)/2:.1f}" y="{y-5:.1f}" text-anchor="middle" font-size="10.5" fill="#1a1d21">{fmt.format(v)}</text>')
            x += bw
        out.append(f'<text x="{cx:.1f}" y="{h-pad_b+18}" text-anchor="middle" font-size="11.5" fill="#1a1d21">{esc(g)}</text>')
    out.append(f'<line x1="{pad_l}" y1="{h-pad_b}" x2="{w-pad_r}" y2="{h-pad_b}" stroke="#1a1d21"/>')
    lx0 = pad_l + 6
    for s in series:
        out.append(f'<rect x="{lx0}" y="{pad_t+2}" width="12" height="10" fill="{s["color"]}"/>')
        out.append(f'<text x="{lx0+18}" y="{pad_t+11}" font-size="11.5" fill="#1a1d21">{esc(s["name"])}</text>')
        lx0 += 20 + 8 * len(s["name"]) + 22
    out.append(f'<text x="{pad_l-52}" y="{pad_t+10}" font-size="11" fill="#5a6570">{esc(y_unit)}</text>')
    out.append("</svg>")
    return "".join(out)

def table(headers, rows, *, num_from=1, note=None):
    """headers: list[str]；rows: list[list[str]]；num_from: 从该列起右对齐"""
    th = "".join(
        f'<th{" class=\"num\"" if i >= num_from else ""}>{h}</th>' for i, h in enumerate(headers))
    trs = []
    for r in rows:
        tds = "".join(
            f'<td{" class=\"num num\"" if i >= num_from else ""}>{c}</td>' for i, c in enumerate(r))
        trs.append(f"<tr>{tds}</tr>")
    n = f'<p class="small">{note}</p>' if note else ""
    return f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>{n}"

def fig(svg, caption, n):
    return f'<figure>{svg}<figcaption>图 {n} · {caption}</figcaption></figure>'

# ---------------------------------------------------------------- 数据（全部为实测）

D = datetime.date(2026, 10, 6)

# ---- A. 四方吞吐（perf-report v2 口径，2026-10-04，5 轮中位）----
A_IMPLS = ["sodama", "dae v2.1.1", "sing-box 1.14.2", "v2ray 5.52.0"]
A_DIRECT = [24319, 24200, 22566, 13522]
A_DIRECT_P50 = [16, 16, 27, 34]
A_DIRECT_CPU = [0, 0, 80, 650]
A_SS = [9487, 9357, 10615, 6289]
A_SS_P50 = [46, 43, 47, 53]
A_SS_CPU = [590, 460, 500, 700]
A_RSS = [28.6, 54.2, 66.8, 72.2]
A_THREADS = [11, 20, 18, 26]
A_VLESS = [12225, 12689, 16588, 10739]
A_VLESS_P50 = [40, 42, 42, 52]
A_VLESS_CPU = [380, 410, 80, 710]
A_VTLS = [11624, 11453, 12003, 7529]
A_VTLS_P50 = [46, 55, 53, 58]
A_VTLS_CPU = [420, 450, 450, 800]

# ---- B. 并发扩展（scaling.sh，Gbps）----
B_STREAMS = ["1×64MB", "2×64MB", "4×64MB", "8×64MB", "64×1MB"]
B_DIRECT = [8.8, 17.5, 24.5, 21.9, 35.2]
B_SS = [4.12, 6.57, 9.91, 10.90, 9.38]
B_RELAY = [9.0, 15.8, 16.2, 15.0, 16.5]
B_SS_CPU = [180, 410, 850, 1690, 260]
B_RELAY_CPU = [30, 80, 490, 1100, 110]

# ---- C. M1/M2 优化前后 ----
C_M1 = [("vless 48MB×4（5 轮中位）", "12 225 Mbps / 380 ms / p50 40 µs", "16 926 Mbps / 60 ms / p50 36 µs"),
        ("vless 8×64MB（scaling）", "11 678 Mbps / 1 100 ms", "16 177 Mbps / 190 ms"),
        ("relay 8×64MB（scaling）", "14 864 Mbps / 1 100 ms", "21 580 Mbps / 150 ms（4 流 23 147）"),
        ("vless-tls（回归）", "11 624 Mbps / 420 ms", "11 670 Mbps / 420 ms（加密路径自动跳过 splice）"),
        ("perf 热点（vless 明文）", "rep_movs 46.8% + 建页 18.8%", "内核 splice 管线（skb_splice_from_iter 8.4% 居首）")]
C_M2 = [("vless-tls 48MB×4（5 轮中位）", "11 670 Mbps / 420 ms / p50 39 µs", "12 318 Mbps / 400 ms / p50 43 µs", "+5.6% 吞吐；解密错误 0；splice 4/4 命中"),
        ("vless-tls 8×64MB（scaling）", "11 253 Mbps / 1 450 ms", "11 147 Mbps / 1 510 ms（A/B 中位）", "夹具封顶：四方客户端均 10.7–12.5 Gbps"),
        ("perf 热点", "rep_movs 30.2% + ring AES 16.6% + 建页 10.8%", "内核 AES 48.0% + 建页 7.8% + memcpy 1.6%", "memcpy 目标 ≤3% ✓")]

# ---- D. 内存四层模型（v2.1，2026-10-05）----
N_POINTS = [1000, 2000, 5000, 10000, 20000]
M_RSS_SODAMA = [13.0, 14.0, 16.2, 19.7, 30.4]
M_RSS_DAE = [175.6, 306.0, 696.6, 1104.6, 1662.0]
M_SLAB_SODAMA = [47.9, 103.3, 282.4, 575.7, 1171.7]
M_SLAB_DAE = [32.2, 69.1, 167.6, 390.8, 810.3]
M_SLAB_CTL = [4.5, 11.2, 32.6, 67.1, 150.4]
M_NET_SODAMA = [44.4, 47.1, 51.2, 52.1, 52.5]
M_NET_DAE = [28.4, 29.6, 27.7, 33.2, 34.0]
M_SLAB_ATTR = [("TCP+", "+284.3 MB", "120 k socket（6/连接）× struct tcp_sock ≈ 2.4 KB"),
               ("sock_inode_cache", "+94.3 MB", "每 socket 一个 inode"),
               ("proc_inode_cache + dentry + inode_cache", "+118.7 MB", "socket/协议栈伴生 inode 与目录项（建连期产生，释放后大部分回收）"),
               ("filp", "+36.3 MB", "每 fd 一个 struct file（80 087 fd）"),
               ("eventpoll_epi", "+12.8 MB", "reactor epoll 每 fd 条目"),
               ("kmalloc-512 / cg-192 / cg-96 / LSM / file_lock 等", "≈ +33 MB", "协议栈小块与 socket 附属"),
               ("其余（页账/碎片/未命名）", "≈ +589 MB", "SLUB 页账与未归命名 cache；见 §10 局限")]

# ---- E. 五方 RSS（v1 存档口径，2026-10-05）----
E_IMPLS = ["sodama", "dae v2.1.1", "sing-box 1.14.2", "v2ray 5.52.0", "mihomo 1.19.32"]
E_PHASES = ["idle", "load（512MB 代理）", "hold 2000", "churn 10s", "recovery（30s）"]
E_RSS = [["27.0 / 28.5", "27.4 / 28.9", "29.0 / 30.5", "29.7 / 31.2", "12.4 / 12.5"],
         ["50.3 / 50.5", "50.6 / 50.7", "297 / 299", "406 / 419", "83.3 / 81.7"],
         ["60.2 / 58.7", "61.1 / 61.5", "94.5 / 90.6", "94.5 / 92.7", "78.4 / 76.8"],
         ["45.7 / 43.4", "70.4 / 68.3", "144 / 139", "495 / 463", "190 / 318"],
         ["50.5 / 51.4", "51.9 / 52.5", "168 / 174", "191 / 233", "68.4 / 72.3"]]
E_THREADS = ["29", "24", "22–23", "24", "23–24"]
E_FD = ["16 087", "4 095", "12 008", "4 006", "8 008"]
E_HOLD_MB = [29.8, 298.1, 92.6, 141.5, 171.1]

# ---- F. 本轮（2026-10-06）本机 5 万并发压测 ----
F_N = [1000, 5000, 10000, 20000, 35000, 50000]
F_RSS = [11.9, 15.1, 18.5, 26.9, 32.3, 32.9]          # 引擎 RSS（MB，active）
F_RSS_FC = [1.5, 0.6, 0.4, 0.4, 0.1, 0.0]             # ΔRSS/连接（KB）
F_KERN = [55.9, 57.6, 58.6, 59.6, 42.7, 42.4]         # 内核总Δ/连接（KB，系统总增量）
F_FD = [4.09, 4.02, 4.01, 4.00, 2.06, 2.03]           # fd/连接（active）
F_THR = [28, 28, 28, 28, 28, 28]
F_PEAK_FD = {20000: 80087, 35000: 140087, 50000: 200087}

# ---- G. 转发原语（v2.1 §3.7）----
G_PRIMS = [("splice（pipe）", "vs 用户态泵：+31% 吞吐 / −80% CPU（M1 历史：+38% / −84%）", "默认（零拷贝、批量搬运）"),
           ("userspace copy pump", "每连接 fd 4 → 2，吞吐下降约 24%", "fd ≥80% 时自动降级"),
           ("io_uring（IORING_OP_SPLICE）", "中位 8.15 GB/s vs epoll+splice 8.08 GB/s（+0.9%，噪声内）；SQPOLL 8.50 GB/s（忙等占核）；64 KB 管道 4.26 GB/s（明显更差）", "不引入（ADR-0058）"),
           ("MSG_ZEROCOPY", "面向「用户页→TCP 发送」；代理字节不在用户页，recv+send 无净收益", "不适用（记录边界）")]

# ---- H. 长稳（v2.1 §3.8，60 min）----
H_SOAK = [("RSS", "12.8 MB", "13.1 MB", "+3.1%", "≤5%"),
          ("fd", "74", "33", "−53.8%（回落为期望）", "无增长"),
          ("Slab", "944.1 MB", "939.0 MB", "−0.5%", "≤5%"),
          ("SUnreclaim", "312.1 MB", "307.6 MB", "−1.4%", "≤5%"),
          ("RTT p50 / p99", "34–93 µs", "229–904 µs", "—", "无劣化"),
          ("失败轮次", "0", "0", "—", "零失败")]

# ---------------------------------------------------------------- 正文

def build() -> str:
    P = []            # 段落收集
    add = P.append

    # ---------- 头部 ----------
    add(f"""<header class="doc">
  <div class="kicker">SODAMA · 技术报告 · 合并版 v3.0</div>
  <h1>性能与资源边界报告<span class="badge">BENCHMARK &amp; BOUNDS</span></h1>
  <p class="subtitle">吞吐四方对拍 · 四层内存模型（Process → Kernel → Total → per-connection）·
  FD 架构治理 · 转发原语对照 · <b>五万并发压测（新增）</b> · 长稳与有界性</p>
  <div class="meta">
    <div><b>日期</b>：{D.isoformat()}</div>
    <div><b>对象</b>：sodama（Rust 重写 dae；全 Rust 数据面 + eBPF）</div>
    <div><b>测试机</b>：Arch / Linux 6.18.54-lts / i9-9900KF 8C16T / 31 GB</div>
    <div><b>对照</b>：dae v2.1.1 · sing-box 1.14.2 · v2ray 5.52.0 · mihomo 1.19.32</div>
    <div><b>工具链</b>：lab/perf/{{run.sh, scaling.sh, mem.sh, mem-system.sh, soak-curve.sh}}</div>
    <div><b>合并来源</b>：perf-report.md + memory-report.html(v1) + memory-report-v2.html(v2.1) + 本轮压测</div>
  </div>
</header>""")

    # ---------- 摘要 ----------
    add("""<h2 id="s0">摘要</h2>
<p>本报告把此前的三份实测文档（吞吐对拍、五方 RSS 终测、系统内存与资源边界终测）合并为一份，
并补上 <b>2026-10-06 的本机并发压测（1 000 → 50 000 连接，VLESS + splice 路径）</b>。一句话结论：
<b>sodama 以个位数到两位数 MB 的用户态内存与恒定线程数承载高并发连接，代价集中在按连接的内核对象；
真实上限由内核内存与 CPU（加密协议）决定，而不是线程或用户态分配器。</b></p>""")

    add(table(["维度", "结论（实测）", "出处"], [
        ["吞吐 · direct", "24 319 Mbps / p50 16 µs / CPU≈0（受夹具 ~24.5 Gbps 限制；64×1MB 口径 35.2 Gbps）", "§3.1"],
        ["吞吐 · VLESS 明文", "splice 落地后 <b>16 926 Mbps</b>（M1 前 12 225）/ p50 36 µs / CPU 60 ms", "§3.3"],
        ["吞吐 · VLESS+TLS", "11 624 → <b>12 318 Mbps</b>（kTLS 实验，+5.6%）；默认 rustls", "§3.3"],
        ["用户态内存", "20 000 连接 <b>30.4 MB</b>（净增 0.9 KB/连接）；5 万连接 32.9 MB；dae 同口径 1 662 MB", "§4.1 / §7"],
        ["内核侧内存", "≈<b>52.5 KB/连接</b>（扣除对照；命名 cache ≈21 KB），1k→20k 近似线性", "§4.2 / §4.4"],
        ["系统总量 @20k", "sodama ≈<b>1.20 GB</b> vs dae ≈2.47 GB（内核侧为大头）", "§4.3"],
        ["FD 拓扑", "每连接 <b>2（空闲）/ 4（活跃）/ 4（建立峰值）</b>；治理前 8.3", "§5"],
        ["并发上限", "50 000 连接零失败、零泄漏；fd 硬限修复后 4096 → <b>262144</b>（1 000 → 6.5 万连接）", "§7"],
        ["长稳 60 min", "RSS +3.1% / Slab −0.5% / fd 无增长 / 零失败", "§8"],
    ], num_from=9))

    add("""<div class="callout"><p><b>口径声明（沿用 v2.1）</b>：用户态优势 ≠ 系统优势——内核侧远大于用户态（约 30×）。
本报告不以 RSS 单指标下结论；所有结论都给「用户态 / 内核 / 总量 / 每连接」四层，
并注明夹具共享链路的影响。所有数字均为本机实测，未做外推。</p></div>""")

    # ---------- 目录 ----------
    toc = [("s1", "1 · 范围、口径与不变式"), ("s2", "2 · 方法学"), ("s3", "3 · 吞吐与延迟（四方对拍）"),
           ("s4", "4 · 内存四层模型（1k→20k）"), ("s5", "5 · FD 拓扑与治理（I2）"),
           ("s6", "6 · 五方 RSS 对照（存档口径）"), ("s7", "7 · 五万并发压测（本轮新增）"),
           ("s8", "8 · 长稳与有界性"), ("s9", "9 · 转发原语对照"), ("s10", "10 · 局限与边界"),
           ("s11", "11 · 复现与工件"), ("s12", "12 · 结论"), ("sa", "附录 A · 历史数据"),
           ("sb", "附录 B · 版本沿革")]
    add('<h2 id="toc">目录</h2><div class="toc">' +
        "".join(f'<a href="#{i}">{t}</a><br>' for i, t in toc) + "</div>")

    # ---------- §1 范围与口径 ----------
    add("""<h2 id="s1">1 · 范围、口径与不变式</h2>
<table><thead><tr><th>层</th><th>指标</th></tr></thead><tbody>
<tr><td><b>Process</b>（用户态）</td><td>VmRSS、Threads、fd 分类计数（socket/pipe）、smaps_rollup Private_Dirty</td></tr>
<tr><td><b>Kernel</b>（内核侧）</td><td>/proc/meminfo Slab / SReclaimable / SUnreclaim / PageTables；/proc/slabinfo 归因；sockstat；conntrack；bpftool map（eBPF 内存）</td></tr>
<tr><td><b>Total</b>（总量）</td><td>用户态增量 + 内核侧增量（同点邻近采样；对照组扣除夹具后给出净增）</td></tr>
<tr><td><b>per-connection</b></td><td>增量 ÷ 连接数；同时给原始值与扣除对照后的净增，避免口径歧义</td></tr>
</tbody></table>
<p class="small">不在口径内：共享测试链路（sing-box VLESS 服务端、echo 夹具）的进程 RSS；页面缓存；NIC/DMA 侧。均在设计对照与文字中显式处理。</p>""")

    # ---------- §2 方法学 ----------
    add("""<h2 id="s2">2 · 方法学</h2>
<h3>2.1 拓扑与夹具</h3>
<p>三个网络命名空间隔离：<code>client ns</code>（压测端）— 被测网关（sodama / dae）— <code>WAN ns</code>
（<code>echo_server</code> 回显 + sing-box VLESS 服务端）。客户端经 eBPF 重定向进入网关，网关以 VLESS（明文 TCP）
拨号至 WAN 侧上游，上游回环至回显端，形成完整的 <b>6-socket 链</b>（这也是内核侧每连接开销的来源）。</p>
<ul>
<li><b>连接夹具</b>：<code>conn_scale hold</code>（单进程 poll 模型逐条连接 + 32 B ping + 回显校验，全部成功才计入）；<code>churn</code> 为限时建连风暴。</li>
<li><b>回显端</b>：<code>echo_server</code>（epoll 单线程）。<b>刻意不用</b> <code>bench_io</code> 作 WAN 侧回显：其每连接 1–2 线程，10 k 连接即 2 万线程，既污染 task_struct 观测，也会撞 systemd scope 的 TasksMax。</li>
<li><b>端口</b>：client/WAN 两命名空间放宽 <code>ip_local_port_range=10000-65000</code> 且 <code>tcp_tw_reuse=1</code>。
<b>单目的 IP 的端口空间是夹具侧上限（≈5.5 万）</b>，不是实现特性。</li>
</ul>
<h3>2.2 采样与增量</h3>
<p>每个扫描点取三个快照：<code>pre</code>（起压前 1 s）、<code>active</code>（全部连接建立后 1 s）、
<code>after</code>（释放后 2 s）。所有增量均为<b>同点邻近</b>的 active − pre；早期以 N=0 为基线会把数分钟扫描期的背景漂移计入增量，已修正。</p>
<h3>2.3 对照扣除</h3>
<p>对照组同拓扑、同夹具、不放任何实现（连接直接经内核到回显端），其每连接增量代表夹具与内核直连路径开销
（20 k 点 7.1 KB/连接）。实现净增 = 实现每连接 − 对照每连接。由于实现路径含共享的 sing-box/echo 链路，
净增仍包含该部分（两实现同口径可比，不能当作纯实现值）。</p>
<div class="callout warn"><p><b>方法学修正记录（透明性）</b>：① 早期以 N=0 为基线的内核增量受背景漂移污染（20 k 点虚高约 0.6 GB），已改为同点 pre/active 并全量重采；
② 早期「2 万线程」曾疑为 sodama 问题，实为 <code>bench_io</code> 夹具线程（cgroup.threads 聚合证实），已更换夹具并固化口径；
③ 本轮又修掉两个扫描脚本误判（建连超时 60 s 硬编码、失败点夹具未杀干净），见 §7.5。</p></div>""")

    # ---------- §3 吞吐 ----------
    add('<h2 id="s3">3 · 吞吐与延迟（四方对拍）</h2>')
    add("<h3>3.1 四方对比（5 轮中位数，2026-10-04）</h3>")
    add(table(["实现", "direct", "direct p50", "direct CPU", "ss", "ss p50", "ss CPU", "RSS", "线程"],
              [[A_IMPLS[i], f"{A_DIRECT[i]:,}", f"{A_DIRECT_P50[i]} µs", f"{A_DIRECT_CPU[i]} ms",
                f"{A_SS[i]:,}", f"{A_SS_P50[i]} µs", f"{A_SS_CPU[i]} ms", f"<b>{A_RSS[i]} MB</b>",
                f"<b>{A_THREADS[i]}</b>"] for i in range(4)],
              note="单位 Mbps；口径：单工方向（每流发 48MB 并原样收回）；CPU = 该路径搬运 512MB 的进程 CPU；RSS/线程 = 负载期中位值。"))
    add(fig(bar_chart(["direct", "ss"], [
        {"name": "sodama", "values": [A_DIRECT[0] / 1000, A_SS[0] / 1000], "color": "#1f4e79"},
        {"name": "dae", "values": [A_DIRECT[1] / 1000, A_SS[1] / 1000], "color": "#6b8fb0"},
        {"name": "sing-box", "values": [A_DIRECT[2] / 1000, A_SS[2] / 1000], "color": "#a0522d"},
        {"name": "v2ray", "values": [A_DIRECT[3] / 1000, A_SS[3] / 1000], "color": "#b9a08e"},
    ], y_unit="Gbps", h=260, fmt="{:.1f}"), "direct 与 ss 路径四方吞吐（Gbps）。direct 受夹具 ≈24.5 Gbps 限制；ss 路径由同一 ssserver 上游提供（共同天花板）。", 1))
    add("""<div class="callout"><p><b>夹具边界</b>：4 流 48MB 时夹具环回自身上限 ≈24.5 Gbps，因此 sodama/dae 的 direct 数字是<b>夹具受限</b>的下界（§3.4 中 64×1MB 达 35.2 Gbps）。ss 路径（&lt;24.5 Gbps）不受此限。</p></div>""")

    add("<h3>3.2 VLESS 明文 / TLS（四方，2026-10-04 加测）</h3>")
    add(table(["实现", "vless 明文", "p50", "CPU", "vless-tls", "p50", "CPU", "RSS", "线程"],
              [[A_IMPLS[i], f"{A_VLESS[i]:,}", f"{A_VLESS_P50[i]} µs", f"{A_VLESS_CPU[i]} ms",
                f"{A_VTLS[i]:,}", f"{A_VTLS_P50[i]} µs", f"{A_VTLS_CPU[i]} ms",
                f"<b>{A_RSS[i]} MB</b>", f"<b>{A_THREADS[i]}</b>"] for i in range(4)]))
    add("""<p>要点：① VLESS+TLS 下 sodama 综合第一梯队（吞吐 ≈ sing-box 的 97%，CPU/延迟/内存最优）；
② 明文路径当时落后 sing-box 是<b>零拷贝（splice）差距</b>（其 CPU 80 ms vs 380 ms）——该差距已由 M1 消除（§3.3）；
③ TLS（AES-NI GCM）比 ss 的 chacha20-poly1305 更快更省（11.6 G/420 ms vs 9.5 G/590 ms）。</p>""")

    add("<h3>3.3 零拷贝（M1）与 kTLS（M2）落地前后</h3>")
    add(table(["场景", "M1 前", "M1 后"], C_M1))
    add(table(["场景", "M1（rustls）", "M2（kTLS）", "备注"], C_M2))
    add(fig(bar_chart(["M1 前\n(2026-10-04 早)", "M1 后", "M2 kTLS"], [
        {"name": "vless 48MB×4", "values": [12225, 16926, 16926], "color": "#1f4e79"},
        {"name": "vless-tls 48MB×4", "values": [11624, 11670, 12318], "color": "#a0522d"},
    ], y_unit="Mbps", h=260, fmt="{:,.0f}"), "splice 零拷贝（M1）与 kTLS（M2）落地前后的吞吐（Mbps）。kTLS 为实验开关（默认关）：本机是「拷贝换引擎」的等价交换，默认仍用 rustls。", 2))

    add("<h3>3.4 并发扩展（sodama，scaling.sh）</h3>")
    add(table(["路径"] + B_STREAMS,
              [["direct"] + [f"{v} Gbps" for v in B_DIRECT],
               ["ss（CPU ms）"] + [f"{v} Gbps（{c}）" for v, c in zip(B_SS, B_SS_CPU)],
               ["relay 无加密（CPU ms）"] + [f"{v} Gbps（{c}）" for v, c in zip(B_RELAY, B_RELAY_CPU)]],
              note="每行 = MB×流数 单工下行；CPU 为 sodama 进程增量。M1 后 relay 8×64MB 16.2 → 21.6 Gbps（4 流 23.1）。"))
    add(fig(bar_chart(B_STREAMS, [
        {"name": "direct", "values": B_DIRECT, "color": "#1f4e79"},
        {"name": "ss", "values": B_SS, "color": "#a0522d"},
        {"name": "relay", "values": B_RELAY, "color": "#2e7d4f"},
    ], y_unit="Gbps", h=280, fmt="{:.1f}"), "并发扩展（Gbps）。direct 在 64 流小包达 35.2；ss 在 ~10.9 饱和且 4→8 流 CPU 翻倍只换 +10% 吞吐（用户态加密环路单点效率，见 §3.5）。", 3))

    add("<h3>3.5 perf 热点剖面（8×64MB）</h3>")
    add(table(["路径", "热点", "占比/明细"], [
        ["ss（9.5 Gbps）", "AEAD chacha20-poly1305", "~38–41%（chacha20 AVX2 21.3% + poly1305 12.5%）"],
        ["ss", "内核 socket 拷贝", "~18%（rep_movs 13.8%）"],
        ["ss", "skb 建页/分配 + libc memcpy", "~5% + ~3.4%"],
        ["relay（13.8 Gbps）", "内核 socket 拷贝 + 建页", "<b>49.4%</b> + 18.5%"],
        ["direct", "系统级热点几乎全在客户端夹具", "eBPF 数据面无 ≥0.4% 符号（bpf_printk 0.3–0.45%，已门控默认关）"],
    ]))
    add("""<p class="small">结论：明文/relay 路径的成本几乎全是拷贝与建页——这正是 M1 用 splice 消掉的部分；
加密路径的成本是 AEAD 本身（下一阶段优化的主战场）。</p>""")

    sections_rest(P)
    return "\n".join(P)


def sections_rest(P):
    """§4 起（内存四层 / FD / 五方 RSS / 本轮压测 / 长稳 / 原语 / 局限 / 复现 / 结论 / 附录）。"""
    add = P.append

    # ---------- §4 内存四层 ----------
    add('<h2 id="s4">4 · 内存四层模型（1 000 → 20 000 连接）</h2>')
    add("<h3>4.1 用户态（VmRSS / 线程 / fd）</h3>")
    add(table(["实现", "N=1 000", "N=2 000", "N=5 000", "N=10 000", "N=20 000", "线程", "fd/连接"],
              [["<b>sodama</b>"] + [f"{v} MB" for v in M_RSS_SODAMA] + ["<b>28</b>", "<b>4.00</b>"],
               ["dae（对照）"] + [f"{v} MB" for v in M_RSS_DAE] + ["26", "2.00"]]))
    add(fig(line_chart([
        {"name": "sodama RSS", "values": M_RSS_SODAMA, "color": "#1f4e79"},
        {"name": "dae RSS（对照）", "values": M_RSS_DAE, "color": "#a0522d", "dashed": True},
    ], N_POINTS, y_unit="MB", x_label="并发连接数（对数轴）", h=280),
        "进程 RSS 随并发连接数。sodama 在 N≥2 000 后由主动回收进入 12–24 MB 平台；dae 随连接线性增长至 1.66 GB。", 4))
    add("""<p class="small">sodama 净增（以 N=1000 的 13.0 MB 为基线）：(30.4−13.0) MB ÷ 19 000 ≈ <b>0.9 KB/连接</b>；
启动即回收后空闲常驻 11.9 MB（I6，ADR-0059）。dae 同法 ≈ 82.7 KB/连接。两实现线程数均保持 O(核数)。</p>""")

    add("<h3>4.2 内核侧（Slab 增量，含夹具与共享链路）</h3>")
    add(table(["N", "sodama ΔSlab", "dae ΔSlab", "对照 ΔSlab", "sodama 净增/连接", "dae 净增/连接"],
              [[f"{n:,}", f"{s} MB", f"{d} MB", f"{c} MB", f"<b>{ns} KB</b>", f"{nd} KB"]
               for n, s, d, c, ns, nd in zip(N_POINTS, M_SLAB_SODAMA, M_SLAB_DAE, M_SLAB_CTL, M_NET_SODAMA, M_NET_DAE)],
              note="净增/连接 = (实现 Δ − 对照 Δ) ÷ N；三条线均近似线性——这是 TCP/socket 等按连接内核对象的预期行为。"))
    add(fig(line_chart([
        {"name": "sodama ΔSlab", "values": M_SLAB_SODAMA, "color": "#1f4e79"},
        {"name": "dae ΔSlab", "values": M_SLAB_DAE, "color": "#a0522d", "dashed": True},
        {"name": "对照（无实现）", "values": M_SLAB_CTL, "color": "#9aa4ad", "dashed": True},
    ], N_POINTS, y_unit="MB", x_label="并发连接数（对数轴）", h=280),
        "Slab 增量（pre→active，含夹具与共享链路）。对照斜率即夹具自身开销（20 k 点 7.1 KB/连接）。", 5))

    add("<h3>4.3 每连接与总量（20 000 连接）</h3>")
    add(fig(bar_chart(["用户态 net（KB/连接）", "内核侧 net（KB/连接）"], [
        {"name": "sodama", "values": [0.9, 52.5], "color": "#1f4e79"},
        {"name": "dae", "values": [82.7, 34.0], "color": "#a0522d"},
    ], y_unit="KB/连接", h=260, fmt="{:.1f}"),
        "每连接内存（20 000 连接）：sodama 的用户态优势约 120×，内核侧高约 1.5×（差额来自 splice 管道与对照口径下共享链路的分配方式）。", 6))
    add(table(["实现", "用户态", "内核侧（全系统 Δ）", "总计", "每连接总计"], [
        ["sodama", "30.4 MB", "≈1 171.7 MB", "<b>≈1.20 GB</b>", "≈53.4 KB"],
        ["dae（对照）", "1 662.0 MB", "≈810.3 MB", "≈2.47 GB", "≈116.7 KB"],
    ], note="内核侧为全系统增量，含共享测试链路（6 socket/连接）。"))

    add("<h3>4.4 Slab 归因（20 000 连接，干净快照）</h3>")
    add(table(["cache", "Δ", "解释"], [[a, b, c] for a, b, c in M_SLAB_ATTR],
              num_from=9, note="命名 cache 合计 579 MB（约占 meminfo ΔSlab 的一半）；其余为 SLUB 页账/partial slab/对齐碎片与未命名 socket 附属分配。释放后 3 s：TCP、sock_inode、filp 全部回落至基线 ±1 MB，无结构性泄漏。"))

    add("<h3>4.5 管道容量 ≠ 常驻（对「64 KB × pipe 推算数百 MB」的实测回应）</h3>")
    add("""<ul>
<li>本项目 <code>F_SETPIPE_SZ = 1 MiB</code>；20 000 连接同时持有 20 000 条 pipe（status <code>pipe_created=20000</code>），容量上界 <b>20 GiB</b>；</li>
<li>实测该内核 <code>slabinfo</code> 中<b>不存在任何 pipe 命名 cache</b>（管道结构走 kmalloc/伴随分配，缓冲页由页分配器按需供给）；</li>
<li>整个 hold 的系统 Slab 总增量为 1.17 GiB（含全部 socket 链）——比容量推算低一个数量级以上。</li>
</ul>
<p><b>结论</b>：以「pipe capacity × 数量」估算常驻内存不成立；以实测为准。</p>""")

    # ---------- §5 FD ----------
    add("""<h2 id="s5">5 · FD 拓扑与治理（I2）</h2>""")
    add(table(["状态", "socket fd/连接", "pipe fd/连接", "合计 fd/连接", "说明"], [
        ["治理前", "4.03", "4.00", "<b>8.29</b>", "RelayHandle 克隆 2 socket + 每 session 2×pipe（4 fd）"],
        ["治理后（活跃）", "2.00", "2.00", "<b>4.00</b>", "去克隆；pipe 懒建 + worker 本地复用 + 空闲释放（10 s 阈值）"],
        ["治理后（空闲）", "2.00", "≈1.1", "<b>≈3.1</b>", "空闲会话释放管道"],
    ], num_from=1))
    add("""<ul>
<li>20 000 连接实测 80 087 fd（2 socket + 2 pipe/连接 + 87 常量），建立期峰值与结束态一致（无限时性额外 fd）。</li>
<li>启动自提升 <code>RLIMIT_NOFILE</code>；fd 使用率 ≥80% 时新会话<b>自动降级用户态泵</b>（吞吐换可用性），回退计数可观测。</li>
<li>管道复用实测：跨先后会话 <code>pipe_reused</code> 持续增长，消 <code>pipe()/close()</code> 系统调用与 slab 抖动。</li>
<li>50 000 连接空闲态实测 fd 降到 <b>2.03/连接</b>（管道仅剩 1 448 条 = 1.4%）——见 §7.3。</li>
</ul>
<p class="small">方法学注：早期「2 万线程 / TasksMax 撞限」已定位为 <code>bench_io</code> 夹具的每连接线程模型（cgroup.threads 聚合：20 007 线程全部来自夹具），sodama 自身线程恒为 28。</p>""")

    # ---------- §6 五方 RSS（存档） ----------
    add("""<h2 id="s6">6 · 五方 RSS 对照（存档口径，2026-10-05）</h2>
<p class="small">本章为 v1 终测的进程 RSS 口径数据（含 mihomo），<b>不含内核侧</b>；作为「用户态视角」的历史对照保留。
系统级结论以 §4 四层模型为准。</p>""")
    add(table(["实现"] + E_PHASES + ["hold 线程", "hold fd"],
              [[f"<b>{E_IMPLS[i]}</b>"] + E_RSS[i] + [E_THREADS[i], E_FD[i]] for i in range(5)],
              note="单位 MB（两遍独立全程，格式 第一遍 / 第二遍）；fd 为 hold 阶段峰值（2 000 连接）。"))
    add(fig(bar_chart(["sodama", "sing-box", "v2ray", "mihomo", "dae"], [
        {"name": "hold 2000 RSS（MB）", "values": E_HOLD_MB, "color": "#1f4e79"},
    ], y_unit="MB", h=240, fmt="{:.1f}"),
        "hold 2 000 连接时的 RSS（MB）：sodama 每条 ≈15 KB；dae ≈153 KB、mihomo ≈88 KB、sing-box ≈47 KB、v2ray ≈72 KB。", 7))
    add(table(["阶段", "sodama", "备注"], [
        ["UDP 20k pps（40 000 包）", "29.2 MB / CPU <b>580 ms</b>", "五方最低（dae 2 100 / sing-box 1 620 / v2ray 1 770 / mihomo 2 425 ms）"],
        ["churn 10 s 极限", "26 026 conn/s（260 336 条，fail=0）", "峰值 35.2 MB / 42 线程"],
        ["10 000 连接（direct relay）", "34.8 MB / 29 线程 / 4 950 建立/s", "0 线程/连接"],
        ["线程模型单变量对照（SODAMA_NO_REACTOR=1）", "527.4 MB / 20 012 线程 / 3 534 建立/s", "reactor：34.8 MB / 29 线程 → <b>15× 内存 / 690× 线程</b>"],
        ["静置回收（30 s）", "峰值 31.2 → <b>12.4/12.5 MB</b>", "低于启动期 27–28.5 MB 的一次性高水位；对手 68.4–317.7 MB"],
    ]))

    # ---------- §7 本轮：五万并发 ----------
    add("""<h2 id="s7">7 · 五万并发压测 <span class="tag new">本轮新增 · 2026-10-06</span></h2>
<p>目的：在<b>同一套四层口径</b>下把并发推到夹具上限，找真实的「设计瓶颈」在哪一层。
路径：VLESS（明文）+ splice 零拷贝，与 §4 同拓扑；每点保持 6 s，取 active − pre 增量。</p>""")

    add("<h3>7.1 现场准备（测量可信度前提）</h3>")
    add(table(["项", "前", "后", "动作"], [
        ["可用内存", "607 MB（swap 已用 18/19 GB）", "<b>19 GB</b>（swap 5.1 GB）", "停 rust-analyzer（10.7 GB，可重启）+ 清 page cache；<b>未动</b>用户浏览器与 docker 容器"],
    ], num_from=9, note="内存濒临耗尽时跑高并发会触发 swap 抖动甚至 OOM——此前「进程被内核杀掉」即此因，故先清理再测。"))

    add("<h3>7.2 结果（1 000 → 50 000 连接）</h3>")
    add(table(["N", "引擎 RSS", "ΔRSS/连接", "内核总Δ/连接", "fd/连接（active）", "线程", "建立耗时"],
              [["1 000", "11.9 MB", "1.5 KB", "55.9 KB", "4.09", "28", "—"],
               ["5 000", "15.1 MB", "0.6 KB", "57.6 KB", "4.02", "28", "—"],
               ["10 000", "18.5 MB", "0.4 KB", "58.6 KB", "4.01", "28", "—"],
               ["20 000", "26.9 MB", "0.4 KB", "59.6 KB", "4.00（socket 2 + pipe 2）", "28", "≈45 s"],
               ["35 000", "32.3 MB", "0.1 KB", "42.7 KB", "<b>2.06</b>（pipe 已由 I2 空闲释放）", "28", "78.8 s（444 conn/s）"],
               ["<b>50 000</b>", "<b>32.9 MB</b>", "~0.0 KB", "<b>42.4 KB</b>", "<b>2.03</b>", "28", "270.4 s（185 conn/s）"]],
              note='内核总Δ/连接为<b>系统总增量</b>（4 个 socket：客户端夹具 1 + 引擎 2 + WAN 回显 1）；引擎自身约占一半（同 v2.1 的对照扣除口径）。'))
    add(fig(line_chart([
        {"name": "引擎 RSS（MB）", "values": F_RSS, "color": "#1f4e79"},
        {"name": "ΔRSS/连接（KB）", "values": F_RSS_FC, "color": "#2e7d4f"},
    ], F_N, y_unit="RSS MB / Δ KB", x_label="并发连接数（对数轴）", h=280),
        "本轮压测：引擎 RSS 与每连接增量。5 万连接下总 RSS 仅 32.9 MB，边际增量趋近 0——bounded-memory 在 2.5× 历史最大值下依然成立。", 8))
    add(fig(line_chart([
        {"name": "fd/连接", "values": F_FD, "color": "#a0522d"},
    ], F_N, y_unit="fd/连接", x_label="并发连接数（对数轴）", h=220, y_max=4.6),
        "fd/连接：建立期 4（2 socket + 2 pipe），空闲稳态回落到 2（I2 管道空闲释放；35k/50k 两个点建立慢，早期连接已释放管道）。", 9))
    add(fig(line_chart([
        {"name": "内核总Δ/连接（KB）", "values": F_KERN, "color": "#5a6570"},
    ], F_N, y_unit="KB/连接", x_label="并发连接数（对数轴）", h=220, y_max=70),
        "内核侧每连接开销（系统总增量）：稳定在 42–60 KB，不随规模恶化；上限由内存容量而非结构决定。", 10))

    add("<h3>7.3 fd 硬限：从 4 096 到 262 144（本轮修复）</h3>")
    add("""<p>每连接「建立期 4 fd」意味着 <b>fd 上限就是并发天花板</b>。此前引擎只把 <code>RLIMIT_NOFILE</code> 的
soft 提到 hard，而 OpenWrt/procd 给的 hard 只有 <b>4096</b> → 实测上限 <b>≈1 000 条并发连接</b>
（几个浏览器标签页就能吃掉百级）。修复：以 root（CAP_SYS_RESOURCE）运行时把 hard 一并抬到
<code>min(/proc/sys/fs/nr_open, 262144)</code>。</p>""")
    add(table(["项", "修复前", "修复后", "验证"], [
        ["路由器 /proc/&lt;pid&gt;/limits", "4096 / 4096", "<b>262144 / 262144</b>", "重启引擎后实测"],
        ["状态面 relay.fds_soft_limit", "4096", "262144", "面板/状态面读数"],
        ["推算并发上限（4 fd/连接）", "≈1 000 条", "≈65 000 条", "网通验证：google 200 / 0.59 s"],
    ], num_from=9))
    add("""<div class="callout"><p><b>本轮引擎自述（扫描全程）</b>：<code>conns_total=105 000</code>（20k+35k+50k 三点合计）、
<code>dial_errors=0</code>、<code>evicted=0</code>；释放后 <code>fds_used=346</code>（回基线，<b>无泄漏</b>）；
<code>splice_total=105 000 / fallbacks=0</code>——<b>全程走 reactor 零线程 + splice 零拷贝路径</b>。</p></div>""")

    add("<h3>7.4 瓶颈排序（按「先撞到」的顺序）</h3>")
    add(table(["#", "瓶颈", "实测证据", "现状/对策"], [
        ["1", "<b>fd（建立期）</b>", "50 000 连接建立峰值 200 087 fd = 4/连接", "已修：hard 提到 262 144（≈6.5 万连接）"],
        ["2", "<b>内核内存</b>", "42–60 KB/连接（系统总增量；引擎约一半）", "软路由 4 GB → <b>5–6.5 万连接</b>先撞内存；进一步只能减少 socket/pipe 或换拓扑"],
        ["3", "<b>CPU（加密协议）</b>", "明文 splice ≈0 CPU；ss 路径 4→8 流 CPU 翻倍只换 +10% 吞吐", "vless/vmess/tuic 每字节要 AEAD；2 核软路由会更早到顶"],
        ["4", "单 worker 事件循环", "worker = 核数（路由器 2）；codec 会话 CPU 密集", "可用 MAX_WORKERS 上调；极端场景按 CPU 分片"],
        ["—", "夹具侧限制（非引擎）", "单目的 IP 端口空间 ≈5.5 万；建连速率 444→185 conn/s", "换多目的 IP/多源可继续上量；建连退化疑在夹具单线程 poll 侧"],
    ], num_from=9))

    add("<h3>7.5 本轮踩到并修掉的两个脚本误判（方法学）</h3>")
    add("""<ul>
<li><b>建连超时硬编码 60 s</b>：35 000 连接实测建连 <b>78.8 s</b>，被误判成「建立失败」而跳过采样。
改为 <code>SETUP_MAX</code>（×0.2 s）可配。</li>
<li><b>失败点夹具未杀干净</b>：<code>kill $hpid</code> 只杀到 <code>in_client</code> 的函数壳，
netns 里的夹具继续占着 3 万+ 连接 → 下一个点端口耗尽（ECONNRESET errno=104），数据被污染。
改为按进程名在 ns 内清理（<code>in_client pkill -x conn_scale</code>）。</li>
</ul>""")

    # ---------- §8 长稳 ----------
    add('<h2 id="s8">8 · 长稳与有界性</h2>')
    add("""<p>负载：常驻 200 条长连接（全链路回显）+ 每 5 s 一波 0.1 s 微量 churn + 每 60 s 一次 8 MB×2 流全双工校验 + 每 15 s 一次 RTT 采样；
每 15 s 采样 RSS/线程/fd/slab/SUnreclaim/TCP mem/conntrack/eBPF map/CPU/RTT（<code>lab/perf/soak-curve.sh</code>）。</p>""")
    add(table(["指标", "基线（t≥120 s，带载）", "结束（停机 + 15 s 静置）", "漂移", "判据"], H_SOAK))
    add("""<div class="callout"><p><b>bounded-memory 判据</b>：60 分钟 soak（233 个采样点，I6 版本）：RSS +3.1%、Slab −0.5%、SUnreclaim −1.4%，
fd 无增长且零失败 → <span class="tag ok">PASS</span>。<b>72 小时</b>正式 soak（24/48/72 h 三档、漂移 ≤5% 且失败不增长方可对外使用「bounded-memory」表述）
为机时型任务，判据/脚本/采样已固化（<code>SOAK_SECS=259200</code>），本轮以 60 分钟数据先行。</p></div>""")
    add("""<p><b>O9 泵线程泄漏修复（2026-10-06）</b>：线程泵路径下，两个方向各一个泵线程，
旧行为是「先结束的泵」就摘注册表——半开连接（上游先关 + 客户端保持）时另一个卡在 recv 的泵
既不被 janitor 看见也无法退出，线程/64KB 缓冲/fd 永久泄漏（路由器现场实测 54+ 泵线程）。
改为<b>泵引用计数，最后一个泵结束时才收尾</b>；回归用例 <code>test-relay-thread-leak</code>
双向验证（修复版 PASS：16 条半开连接全部被回收、线程回落基线；回退旧语义 FAIL：残留 16 线程、evicted 增量 0）。</p>""")

    # ---------- §9 转发原语 ----------
    add('<h2 id="s9">9 · 转发原语对照</h2>')
    add(table(["原语", "实测/结论", "决策"], [[a, b, c] for a, b, c in G_PRIMS]))

    # ---------- §10 局限 ----------
    add("""<h2 id="s10">10 · 局限与边界</h2>
<ol>
<li><b>对照扣除是近似</b>：对照路径每连接 2 个 socket，实现路径 6 个 socket + pipe；「实现净增」仍含共享 sing-box/echo 链路的部分（两实现同口径可比，不可视为纯实现独占值）。</li>
<li><b>命名 cache 归因覆盖约一半</b>：20 k 点 meminfo ΔSlab 1 168.6 MB 中，命名 cache ≈579 MB；其余为 SLUB 页账/partial slab/对齐碎片与未命名分配，本报告不做强行拆分。</li>
<li><b>瞬时采样</b>：数值为快照，不是峰值积分；建连窗口内的瞬时更接近「活跃」，稳态更接近「after」。</li>
<li><b>环境边界</b>：单机环回拓扑，无真实 NIC 中断/DMA；内核 6.18 的 pipe 实现（按需页）结论在其他内核上应以复测为准；绝对吞吐数字不可外推到公网。</li>
<li><b>夹具边界</b>：direct 4×48MB 受夹具 ≈24.5 Gbps 限制；VLESS-TLS 8 流受 ≈12.5 Gbps 限制（四方客户端同受）；单目的 IP 端口空间 ≈5.5 万是并发扫描的夹具上限。</li>
<li><b>长稳时长</b>：60 min ≠ 72 h；在完成 72 h 前不使用「bounded-memory」的绝对表述。</li>
<li><b>表述口径</b>：不使用「唯一解 / 遥遥领先 / 顶级」等评估性措辞；对外定位为 <b>predictable resource consumption</b>。</li>
</ol>""")

    # ---------- §11 复现 ----------
    add("""<h2 id="s11">11 · 复现与工件</h2>
<pre># 吞吐四方对拍（vless 默认协议；ss 口径对照）
lab/perf/run.sh build
sudo ROUNDS=5 PROXY_PROTO=vless lab/perf/run.sh all
sudo ROUNDS=5 PROXY_PROTO=ss SS_UPSTREAM=ssserver lab/perf/run.sh all
sudo PROXY_PROTO=vless lab/perf/scaling.sh all        # 并发扩展

# 系统内存四层扫描（sodama / 对照组 / dae 对照）
sudo lab/perf/mem-system.sh prepare
sudo env POINTS="100 500 1000 2000 5000 10000 20000" HOLD_SECS=6 \\
  RESULTS=/tmp/mem-system-sodama.tsv lab/perf/mem-system.sh run
sudo env POINTS="..." RESULTS=/tmp/mem-system-ctl.tsv lab/perf/mem-system.sh run-control
sudo env IMPL=dae POINTS="..." RESULTS=/tmp/mem-system-dae.tsv lab/perf/mem-system.sh run
# 本轮五万并发（建连慢，需放宽等待：SETUP_MAX=1500 → 300 s）
sudo env POINTS="20000 35000 50000" SETUP_MAX=1500 HOLD_SECS=6 \\
  RESULTS=/tmp/mem-system-hi.tsv lab/perf/mem-system.sh run

# 长稳曲线（60 min；72 h 用 SOAK_SECS=259200）
sudo lab/perf/soak-curve.sh run 3600</pre>
<table><thead><tr><th>工件</th><th>说明</th></tr></thead><tbody>
<tr><td><code>lab/perf/{run.sh, scaling.sh, mem.sh, mem-system.sh, soak-curve.sh}</code></td><td>压测与扫描脚本（含本轮 SETUP_MAX/夹具清理修复）</td></tr>
<tr><td><code>lab/perf/{bench_io.c, ../scale/conn_scale.c, ../scale/echo_server.c}</code></td><td>全双工 echo / 并发夹具（poll 单线程）</td></tr>
<tr><td><code>lab/perf/gen-benchmark-report.py</code></td><td><b>本报告的生成器</b>（数据内嵌，可复算重建）</td></tr>
<tr><td><code>docs/adr/ADR-0058</code> · <code>ADR-0059</code></td><td>reactor/io_uring 结论 · I6 零线程握手与启动水位</td></tr>
<tr><td><code>docs/reviews/</code></td><td>第三方评审原文 + 采纳提案（A/B、I1–I5）</td></tr>
</tbody></table>""")

    # ---------- §12 结论 ----------
    add("""<h2 id="s12">12 · 结论</h2>
<ol>
<li><b>用户态内存优势是真实的，但不是全部事实。</b> sodama 以 ≈0.9 KB/连接的用户态净增承载 2 万连接
（5 万连接 32.9 MB）；内核侧 ≈42–60 KB/连接（含共享链路），远大于用户态。任何以 RSS 单独下结论的表述都不成立，
本报告统一采用四层模型。</li>
<li><b>同口径下系统总量仍显著低于 dae 对照</b>（20 k：≈1.20 GB vs ≈2.47 GB），差值几乎全部来自 dae 的用户态线性增长；
sodama 的增量集中在按连接的内核对象与 splice 管道结构（可回收、无泄漏）。</li>
<li><b>FD 架构隐患已消除一个数量级。</b> 每连接 fd 8.3 → 4.0（活跃）/ 2.0（空闲）；本轮又把
<code>RLIMIT_NOFILE</code> hard 限从 4 096 抬到 262 144——并发天花板从 ≈1 000 提到 ≈6.5 万。</li>
<li><b>5 万并发实测：无天花板、无泄漏、零拨号错误</b>，全部走 reactor 零线程 + splice；
真正的下一个瓶颈是<b>内核内存</b>（4 GB 路由器 ≈5–6.5 万连接）与<b>加密协议的 CPU</b>。</li>
<li><b>数据面原语选择经受住对照。</b> splice 默认（+31% 吞吐 / −80% CPU）、fd 高压降级、io_uring 不引入、MSG_ZEROCOPY 不适用——
每条结论都有 A/B 或语义分析支撑。</li>
<li><b>下一步</b>：72 h 全量 soak（判据/脚本就绪）；TLS 路径的 AEAD 成本优化（当前 CPU 大头）；
多目的 IP/多源夹具以突破 5.5 万端口的夹具上限。对外定位继续使用「predictable resource consumption」。</li>
</ol>""")

    # ---------- 附录 A ----------
    add("""<h2 id="sa">附录 A · 历史数据</h2>
<h3>A.1 第一轮（python ss 上游，方法演进记录）</h3>
<p class="small">python 上游 GIL ≈2.4 Gbps，把 ss 路径全部压平；保留作为夹具演进记录。</p>""")
    add(table(["实现", "direct", "ss", "ss CPU"],
              [["sodama", "30.0 Gbps", "2.20 Gbps", "610 ms"],
               ["dae v2.1.1", "29.7", "1.93", "600 ms"],
               ["sing-box", "26.9", "2.73", "480 ms"],
               ["v2ray", "17.6", "0.54", "1 730 ms"]]))
    add("""<h3>A.2 夹具校准（v2 全双工 echo 环回）</h3>""")
    add(table(["负载", "吞吐", "备注"],
              [["48MB×4 环回", "22.7 / 24.5 / 24.8 Gbps", "3 次；客户端 pattern 填充+校验为极限"],
               ["500 RTT 环回", "p50 10–11 µs", "夹具地面延迟"],
               ["48MB×4 环回（旧半双工夹具）", "<b>偶发 60 s 假死</b>", "与上游实现形成环形依赖，已改为预分配 ring 的全双工 echo"]],
              num_from=9))
    add("""<h3>A.3 生命周期与回收</h3>
<ul>
<li>静置回落：load/hold/churn 后静置 30 s，RSS 由峰值 31.2 → <b>12.4–12.5 MB</b>（低于启动期 27–28.5 MB 的一次性高水位）。</li>
<li>缓冲池封顶（O8）：转发缓冲池 64/128 KB 两档、按字节封顶 8 MB；UDP 槽按需增长；无增长趋势。</li>
<li>周期 trim：30 s 一次 <code>malloc_trim</code>，把 allocator 空闲页还给内核。</li>
<li>优雅退出：SIGTERM 有界退出——50 条在途连接整机 462 ms（内部有界 302 ms），退出后 TC 钩子/管道无残留。</li>
</ul>""")

    # ---------- 附录 B ----------
    add("""<h2 id="sb">附录 B · 版本沿革</h2>
<table><thead><tr><th>版本</th><th>日期</th><th>范围</th><th>状态</th></tr></thead><tbody>
<tr><td>内存终测 v1.0（五方 RSS）</td><td>2026-10-05</td><td>idle/load/hold/churn/recovery 五阶段 RSS 峰值、UDP 专项、规模与线程专项</td><td>并入本报告 §6 + 附录 A</td></tr>
<tr><td>系统内存与资源边界 v2.1</td><td>2026-10-05</td><td>四层模型、FD 治理（I2）、转发原语、I6 零线程、60 min soak</td><td>并入本报告 §4/§5/§8/§9</td></tr>
<tr><td>性能对比报告（perf-report.md）</td><td>2026-10-04</td><td>四方吞吐/延迟、并发扩展、perf 剖面、M1/M2 优化前后、夹具校准</td><td>并入本报告 §3 + 附录 A</td></tr>
<tr><td><b>本报告 v3.0（合并版）</b></td><td>2026-10-06</td><td>上述全部 + <b>五万并发压测</b> + fd 硬限修复 + 脚本误判修正</td><td>现行版本（旧文件保留于 git 历史）</td></tr>
</tbody></table>
<p class="small">不再单独维护的文档：<code>memory-report.html</code>（v1）、<code>memory-report-v2.html</code>（v2.1）、
<code>perf-report.md</code>。保留的相邻文档：<code>vless-proposal.html</code>（VLESS 优化提案/验收）、
<code>optimization-roadmap.md</code>（优化路线）、<code>project-summary.html</code>（工程总结）、
<code>architecture-decision.html</code>（决策档案）、<code>reviews/</code>（评审原文与回应）。</p>""")

    add(f"""<footer class="doc">
  <p>sodama 性能与资源边界报告 v3.0（合并版）· {D.isoformat()} · 自包含 HTML（无外部依赖）· 由
  <code>lab/perf/gen-benchmark-report.py</code> 生成。</p>
  <p>全部数字为本机实测；口径、对照扣除与边界见 §1/§2/§10。旧版报告（v1 / v2.1 / perf-report.md）已并入本文，
  原文保留于 git 历史。</p>
</footer>""")


def main():
    html = build()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                "<title>sodama · 性能与资源边界报告 v3.0（合并版）</title>\n"
                f"<style>{CSS}</style>\n</head>\n<body>\n<div class=\"wrap\">\n"
                + html + "\n</div>\n</body>\n</html>\n")
    print(f"已生成 {OUT}（{os.path.getsize(OUT):,} 字节）")


if __name__ == "__main__":
    main()

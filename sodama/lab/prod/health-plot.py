#!/usr/bin/env python3
"""把 sodama 健康曲线 TSV 画成自包含 SVG（只用标准库，无第三方依赖）。

输入：`sh sodama/lab/prod/health-track.sh pull` 拉下来的 `sodama-health.tsv`
输出：默认 `docs/notes/health-curve.svg`

判据（画在图上，便于一眼判断回归）：
  · stragglers 应恒为 0 —— 一旦抬升说明「握手墙钟看门狗」失效或有新卡死路径
  · rss_kb 应在 40 MB 附近波动、不单调上升 —— 单调上升即泄漏回归
  · thr 应在 20–50 波动 —— 持续抬升说明线程又累积了

用法：python3 sodama/lab/prod/health-plot.py [tsv] [out.svg]
"""

import math
import os
import sys

W, H = 1180, 940
PAD_L, PAD_R = 86, 210
PANEL_H, GAP, TOP0 = 178, 56, 76

C = {
    "rss": "#1f4e79",
    "vmsize": "#8fb4d1",
    "thr": "#a0522d",
    "probe": "#8a6d3b",
    "stragglers": "#7a1f1f",
}


def read_tsv(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        head = f.readline().rstrip("\n").split("\t")
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) != len(head):
                continue
            rows.append(dict(zip(head, p)))
    return rows


def vals(rows, key):
    out = []
    for r in rows:
        try:
            out.append(float(r.get(key) or 0))
        except ValueError:
            out.append(0.0)
    return out


def nice_max(v, floor=1.0):
    m = max(list(v) + [floor])
    step = 10 ** max(0, len(str(int(m))) - 1)
    return max(step, int(math.ceil(m / step) * step))


def panel(y0, title, series, n, unit):
    """series: [(values, color, label)]"""
    s = [
        f'<text x="{PAD_L}" y="{y0 - 10}" font-size="13" font-weight="600" '
        f'fill="#151515">{title}</text>',
        f'<rect x="{PAD_L}" y="{y0}" width="{W - PAD_L - PAD_R}" height="{PANEL_H}" '
        f'fill="#fffff8" stroke="#ddd8c8"/>',
    ]
    allv = [x for vs, _, _ in series for x in vs]
    top = nice_max(allv)
    for k in (0, 0.25, 0.5, 0.75, 1.0):
        yy = y0 + PANEL_H - k * PANEL_H
        s.append(f'<line x1="{PAD_L}" y1="{yy:.1f}" x2="{W - PAD_R}" y2="{yy:.1f}" stroke="#eee8d8"/>')
        s.append(f'<text x="{PAD_L - 8}" y="{yy + 4:.1f}" text-anchor="end" font-size="10.5" '
                 f'fill="#6f6a5c">{top * k:,.0f}</text>')
    s.append(f'<text x="{PAD_L - 8}" y="{y0 - 2}" text-anchor="end" font-size="10" '
             f'fill="#6f6a5c">{unit}</text>')
    span = W - PAD_L - PAD_R
    for i, (vs, color, label) in enumerate(series):
        if n < 2 or not vs:
            continue
        pts = " ".join(
            f"{PAD_L + span * j / (n - 1):.1f},{y0 + PANEL_H - (v / top) * PANEL_H:.1f}"
            for j, v in enumerate(vs)
        )
        s.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="1.6"/>')
        ly = y0 + 16 + i * 16
        s.append(f'<rect x="{W - PAD_R + 12}" y="{ly - 9}" width="10" height="10" fill="{color}"/>')
        s.append(f'<text x="{W - PAD_R + 28}" y="{ly}" font-size="11" fill="#3d3a33">'
                 f'{label} = {vs[-1]:,.0f}</text>')
    return "\n".join(s)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "sodama-health.tsv"
    dst = sys.argv[2] if len(sys.argv) > 2 else "docs/notes/health-curve.svg"
    if not os.path.exists(src):
        print(f"找不到 {src}；先跑 `sh sodama/lab/prod/health-track.sh pull`")
        return 2
    rows = read_tsv(src)
    if not rows:
        print("TSV 无有效数据行")
        return 2
    n = len(rows)

    rss = [v / 1024 for v in vals(rows, "rss_kb")]
    vmsize = [v / 1024 for v in vals(rows, "vmsize_kb")]
    thr = vals(rows, "thr")
    probe = vals(rows, "probe_thr")
    stragglers = vals(rows, "stragglers")

    body = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
        f'font-family="Palatino, \'Source Han Serif SC\', \'Noto Serif CJK SC\', Georgia, serif">',
        f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
        f'<text x="{PAD_L}" y="26" font-size="16" font-weight="600" fill="#151515">'
        f'sodama 生产健康曲线</text>',
        f'<text x="{PAD_L}" y="42" font-size="11.5" fill="#6f6a5c">'
        f'{rows[0].get("time","?")} → {rows[-1].get("time","?")} · {n} 个采样点（每 60s）</text>',
        panel(TOP0, "内存（MB）· 判据：40 MB 附近波动，不单调上升", 
              [(rss, C["rss"], "RSS"), (vmsize, C["vmsize"], "VmSize")], n, "MB"),
        panel(TOP0 + PANEL_H + GAP, "线程数 · 判据：20–50 波动，不持续抬升",
              [(thr, C["thr"], "总线程"), (probe, C["probe"], "probe")], n, "个"),
        panel(TOP0 + 2 * (PANEL_H + GAP),
              "探测超时被放弃数 · 判据：恒为 0（非 0 即墙钟看门狗失效或有新卡死路径）",
              [(stragglers, C["stragglers"], "stragglers")], n, "个"),
        "</svg>",
    ]
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "w", encoding="utf-8") as f:
        f.write("\n".join(body))
    print(f"已写出 {dst}（{n} 点）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

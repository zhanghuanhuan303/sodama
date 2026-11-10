#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""I1：mem-system.sh TSV 分析器——四层模型净增量。

口径：
  - within-run 增量：同一次 run 内 active(N) − N=0（消除跨 run 系统漂移）；
  - 对照扣除：对照组（无实现、同夹具同拓扑）同样取 within-run 增量，折算“夹具自身
    每连接内核开销”，用于把实现路径中属于夹具的部分扣掉（近似、上界，见报告方法学）；
  - per-conn：增量 / N。

用法：
  python3 mem-analyze.py sodama.tsv dae.tsv --control ctl.tsv \
      --out-md /tmp/mem-analysis.md --out-json /tmp/mem-analysis.json
"""
import argparse
import json


def parse(path):
    rows = {}
    header = None
    with open(path) as f:
        for line in f:
            if line.startswith("#label"):
                header = line.rstrip("\n").split("\t")
                continue
            parts = line.rstrip("\n").split("\t")
            if header is None or len(parts) < len(header):
                continue
            label = parts[0]
            ncols = len(header) - 1  # 数据列数（不含 label）
            vals = dict(zip(header[1:ncols], parts[1:1 + ncols - 1]))
            subset_field = parts[ncols] if len(parts) > ncols else ""
            subset = {}
            for pair in subset_field.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    try:
                        subset[k] = int(v)
                    except ValueError:
                        pass
            for k in list(vals):
                try:
                    vals[k] = int(vals.get(k, 0) or 0)
                except ValueError:
                    vals[k] = 0
            vals["slab_subset"] = subset
            rows[label] = vals
    return rows


def strip_prefix(rows):
    out = {}
    for label, row in rows.items():
        out[label.split(":", 1)[1] if ":" in label else label] = row
    return out


def split_label(label):
    rest = label.split(":", 1)[1] if ":" in label else label
    if rest.startswith("N="):
        body = rest[2:]
        if "/" in body:
            n, phase = body.split("/", 1)
        else:
            n, phase = body, "idle"
        try:
            return int(n), phase
        except ValueError:
            return None, phase
    return None, rest


def subset_total(row):
    return sum(row["slab_subset"].values())


def delta(rows, n, key):
    """同点邻近增量：active(N) − pre(N)（无 pre 时回退 N=0）。"""
    b = rows.get(f"N={n}/pre") or rows.get("N=0")
    a = rows.get(f"N={n}/active")
    if not b or not a:
        return None
    return a[key] - b[key]


def delta_subset(rows, n, cache):
    b = rows.get(f"N={n}/pre") or rows.get("N=0")
    a = rows.get(f"N={n}/active")
    if not b or not a:
        return None
    return a["slab_subset"].get(cache, 0) - b["slab_subset"].get(cache, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("impl_tsvs", nargs="+")
    ap.add_argument("--control", required=True)
    ap.add_argument("--out-md", default="/tmp/mem-analysis.md")
    ap.add_argument("--out-json", default="/tmp/mem-analysis.json")
    args = ap.parse_args()

    ctl = strip_prefix(parse(args.control))
    groups = {}
    for path in args.impl_tsvs:
        name = path.rsplit("/", 1)[-1].replace("mem-system-", "").replace(".tsv", "")
        groups[name] = strip_prefix(parse(path))

    points = sorted({n for n, _ in (split_label(l) for l in ctl) if n})
    result = {"points": points, "groups": {}}
    md = ["# I1 系统内存基准 · 分析\n",
          f"对照组：`{args.control}`；实现组：{', '.join('`%s`' % p for p in args.impl_tsvs)}。",
          "所有增量为**同点邻近（pre → active）**；`每连接` = 增量/N。\n"]

    md.append("## 1. 用户态（进程）\n")
    md.append("| 组 | N | RSS(MB) | ΔRSS(MB) | RSS/连接(KB) | Threads | fd/连接 | priv_dirty(MB) |")
    md.append("|---|---|---|---|---|---|---|---|")
    for name, rows in groups.items():
        for n in points:
            a, b = rows.get(f"N={n}/active"), (rows.get(f"N={n}/pre") or rows.get("N=0"))
            if not a:
                continue
            drss = (a["rss_kb"] - b["rss_kb"]) / 1024 if b else None
            md.append(f"| {name} | {n} | {a['rss_kb']/1024:.1f} | {drss:+.1f} | {a['rss_kb']/n:.1f} | "
                      f"{a['threads']} | {a['fds']/n:.2f} | {a['priv_dirty_kb']/1024:.1f} |")
    md.append("")

    md.append("## 2. 内核（pre→active 邻近增量，含夹具）\n")
    md.append("| 组 | N | ΔSlab(MB) | ΔSUnreclaim(MB) | ΔTCP mem(MB) | Δsum(cache)(MB) | Δbpf(MB) |")
    md.append("|---|---|---|---|---|---|---|")
    for name, rows in groups.items():
        for n in points:
            ds, du, dt = (delta(rows, n, k) for k in ("slab_kb", "sunrec_kb", "tcp_mem"))
            a, b = rows.get(f"N={n}/active"), (rows.get(f"N={n}/pre") or rows.get("N=0"))
            dsub = subset_total(a) - subset_total(b) if (a and b) else None
            dbpf = delta(rows, n, "bpf_map_kb")
            md.append(f"| {name} | {n} | {ds/1024:.1f} | {du/1024:.1f} | {dt*4/1024:.1f} | "
                      f"{dsub/1024:.1f} | {dbpf/1024:.1f} |")
    md.append("")

    md.append("## 3. 对照组（夹具+内核，无实现）每连接内核开销\n")
    md.append("| N | ΔSlab/连接(KB) | ΔSUnreclaim/连接(KB) | ΔTCP mem/连接(KB) |")
    md.append("|---|---|---|---|")
    ctl_per = {}
    for n in points:
        ds, du, dt = (delta(ctl, n, k) for k in ("slab_kb", "sunrec_kb", "tcp_mem"))
        if ds is None:
            continue
        ctl_per[n] = {"slab_kb": ds / n, "sunrec_kb": du / n, "tcp_mem_kb": dt * 4 / n}
        md.append(f"| {n} | {ds/n:.2f} | {du/n:.2f} | {dt*4/n:.2f} |")
    md.append("")

    md.append("## 4. 内核每连接（扣除对照组夹具与内核路径后的实现净增）\n")
    md.append("| 组 | N | Slab/连接(KB) | SUnreclaim/连接(KB) | TCP mem/连接(KB) |")
    md.append("|---|---|---|---|---|")
    result["kernel_net_per_conn"] = {}
    for name, rows in groups.items():
        result["kernel_net_per_conn"][name] = {}
        for n in points:
            ds, du, dt = (delta(rows, n, k) for k in ("slab_kb", "sunrec_kb", "tcp_mem"))
            if ds is None:
                continue
            c = ctl_per.get(n, {"slab_kb": 0, "sunrec_kb": 0, "tcp_mem_kb": 0})
            v = {"slab_kb": ds / n - c["slab_kb"], "sunrec_kb": du / n - c["sunrec_kb"],
                 "tcp_mem_kb": dt * 4 / n - c["tcp_mem_kb"]}
            result["kernel_net_per_conn"][name][n] = v
            md.append(f"| {name} | {n} | {v['slab_kb']:.2f} | {v['sunrec_kb']:.2f} | {v['tcp_mem_kb']:.2f} |")
    md.append("")

    # 用户态：以“稳态低点”为基线（malloc_trim 后）的净每连接，避免启动高水位
    md.append("## 5. 用户态净每连接（稳态基线：各 run 的最小 active RSS）\n")
    md.append("| 组 | 基线RSS(MB) | N=20000 RSS(MB) | 净增/连接(KB) |")
    md.append("|---|---|---|---|")
    result["userspace_net"] = {}
    for name, rows in groups.items():
        acts = [(split_label(l)[0], r["rss_kb"]) for l, r in rows.items()
                if l.endswith("/active") and split_label(l)[0]]
        if not acts:
            continue
        base_n, base_rss = min(acts, key=lambda t: t[1])
        top = max(acts, key=lambda t: t[0])
        net = (top[1] - base_rss) / (top[0] - base_n) if top[0] > base_n else 0
        result["userspace_net"][name] = {"base_n": base_n, "base_rss_mb": base_rss / 1024,
                                         "top_n": top[0], "top_rss_mb": top[1] / 1024,
                                         "net_per_conn_kb": net}
        md.append(f"| {name} | {base_rss/1024:.1f}（N={base_n}） | {top[1]/1024:.1f}（N={top[0]}） | {net:.1f} |")
    md.append("")

    at_n = 20000 if 20000 in points else max(points)
    md.append(f"## 6. N={at_n} 活跃期 slab cache 归因（within-run 增量，KB，>32KB 才列出）\n")
    md.append("| cache | " + " | ".join(groups) + " | control |")
    md.append("|---|" + "---|" * (len(groups) + 1))
    caches = set()
    for rows in list(groups.values()) + [ctl]:
        a, b = rows.get(f"N={at_n}/active"), rows.get("N=0")
        if a and b:
            caches |= set(a["slab_subset"]) | set(b["slab_subset"])
    cache_rows = []
    for k in sorted(caches):
        row = {"cache": k}
        for name, rows in groups.items():
            row[name] = delta_subset(rows, at_n, k)
        row["control"] = delta_subset(ctl, at_n, k)
        if any(v is not None and v > 32 for k2, v in row.items() if k2 != "cache"):
            cache_rows.append(row)
    for row in sorted(cache_rows, key=lambda r: -(max((v for k2, v in r.items() if k2 != "cache" and v is not None), default=0))):
        cells = [row["cache"]] + [("-" if row.get(x) is None else f"{row[x]:+d}") for x in list(groups) + ["control"]]
        md.append("| " + " | ".join(cells) + " |")
    result["slab_attribution_n"] = at_n

    with open(args.out_md, "w") as f:
        f.write("\n".join(md) + "\n")
    with open(args.out_json, "w") as f:
        json.dump(result, f, ensure_ascii=False, indent=1, sort_keys=True)
    print("\n".join(md))
    print(f"\n== 写出：{args.out_md} / {args.out_json} ==")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""从本机 Go module 缓存生成 hysteria2 认证所需的常量表：

1) HPACK Huffman 表（golang.org/x/net/http2/hpack/tables.go，RFC 7541 附录 B）
2) QPACK 静态表（olicesx/qpack static_table.go，RFC 9204 附录 A）

用法： python3 lab/gen-huffman-table.py > loader/src/huffman_table.rs
"""
import glob
import os
import re
import sys


def find(pattern):
    hits = sorted(glob.glob(pattern))
    if not hits:
        sys.exit(f"找不到源码：{pattern}")
    return open(hits[-1]).read()


# ---- HPACK Huffman ----
net = find(os.path.expanduser("~/go/pkg/mod/golang.org/x/net@*/http2/hpack/tables.go"))


def go_array(name, n):
    m = re.search(r"var\s+%s\s*=\s*\[%d\][^{]*\{(.*?)\}" % (name, n), net, re.S)
    if not m:
        sys.exit(f"找不到数组 {name}")
    body = re.sub(r"//.*", "", m.group(1))
    vals = [v.strip() for v in body.split(",") if v.strip()]
    if len(vals) != n:
        sys.exit(f"{name} 元素数 {len(vals)} != {n}")
    return vals


codes = go_array("huffmanCodes", 256)
lens = go_array("huffmanCodeLen", 256)

# ---- QPACK 静态表 ----
qpack = find(os.path.expanduser("~/go/pkg/mod/github.com/olicesx/qpack@*/static_table.go"))
entries = re.findall(r'\{(?:Name:\s*"((?:[^"\\]|\\.)*)")(?:,\s*Value:\s*"((?:[^"\\]|\\.)*)")?\}', qpack)
if len(entries) != 99:
    sys.exit(f"QPACK 静态表条目数 {len(entries)} != 99")


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


out = []
out.append("// SPDX-License-Identifier: GPL-2.0")
out.append("// 由 lab/gen-huffman-table.py 生成：")
out.append("//   - HUFFMAN_* 来自 golang.org/x/net/http2/hpack/tables.go（HPACK/RFC 7541 附录 B）")
out.append("//   - QPACK_STATIC 来自 olicesx/qpack static_table.go（QPACK/RFC 9204 附录 A）")
out.append("// 勿手改；重新生成：lab/gen-huffman-table.py > loader/src/huffman_table.rs")
out.append("")
out.append("/// 每个字节的 Huffman 码字（低位对齐）。")
out.append("pub const HUFFMAN_CODES: [u32; 256] = [")
for i in range(0, 256, 8):
    out.append("    " + ", ".join(codes[i : i + 8]) + ",")
out.append("];")
out.append("")
out.append("/// 每个字节的码长（bit）。")
out.append("pub const HUFFMAN_CODE_LEN: [u8; 256] = [")
for i in range(0, 256, 16):
    out.append("    " + ", ".join(lens[i : i + 16]) + ",")
out.append("];")
out.append("")
out.append("/// QPACK 静态表 (name, value)，索引即数组下标（0..=98）。")
out.append("pub const QPACK_STATIC: [(&str, &str); 99] = [")
for name, value in entries:
    out.append(f"    ({rust_str(name)}, {rust_str(value)}),")
out.append("];")
out.append("")
sys.stdout.write("\n".join(out))

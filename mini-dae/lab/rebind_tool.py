#!/usr/bin/env python3
"""redirect_track / mini_stats_map 的读写工具（rebind 测试用）。

bpftool -j 输出形态（v7.8）：
  {"key": ["0x0a",...], "value": ["0x04",...], "formatted": {...}}
key/value 原始字节数组是权威来源，formatted 只是 BTF 解码视图；本工具以
原始字节为准（不依赖 BTF）。

子命令：
  dump   打印 redirect_track 条目：
           sip:sport -> dip:dport proto … ifindex/smac/dmac/from_wan/last_seen_ns
  stats  汇总 mini_stats_map（PERCPU_ARRAY）各 key 的总计数
  set    伪造一条 redirect_track 条目（模拟竞争发布者 / 陈旧条目），时间戳
         用 /proc/uptime 近似 CLOCK_MONOTONIC（2s 窗口，误差 ms 级）
"""
import argparse
import json
import socket
import struct
import subprocess
import sys

# struct mini_tuple: sip4 + dip4 + sport2 + dport2 + l4proto1 + pad3
KEY_LEN = 16
# struct mini_redirect_entry: ifindex4 + smac6 + dmac6 + from_wan1 + pad3
#                             + 对齐 4B + last_seen8
VAL_LEN = 32


def bpftool(*args):
    r = subprocess.run(["bpftool", "-j", *args], capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        sys.exit(r.returncode)
    if not r.stdout.strip():
        return []
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return []  # map update 等命令没有结构化输出


def raw_bytes(x):
    if x is None:
        return None
    if isinstance(x, list):
        out = b""
        for v in x:
            if isinstance(v, str):
                out += bytes([int(v, 16)])
            elif isinstance(v, int):
                out += bytes([v & 0xFF])
            else:
                return None
        return out
    if isinstance(x, str):
        try:
            return bytes.fromhex(x.removeprefix("0x"))
        except ValueError:
            return None
    return None


def ip4(b):
    return socket.inet_ntoa(b)


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def fmt_entry(key, value):
    sip, dip = ip4(key[0:4]), ip4(key[4:8])
    sport, dport = struct.unpack("!HH", key[8:12])
    ifindex = struct.unpack("<I", value[0:4])[0]
    return (
        f"{sip}:{sport} -> {dip}:{dport} proto={key[12]} "
        f"ifindex={ifindex} smac={mac(value[4:10])} dmac={mac(value[10:16])} "
        f"from_wan={value[16]} last_seen_ns={struct.unpack('<Q', value[24:32])[0]}"
    )


def cmd_dump(_):
    entries = bpftool("map", "dump", "name", "redirect_track")
    shown = 0
    for e in entries:
        key, value = raw_bytes(e.get("key")), raw_bytes(e.get("value"))
        if key is None or value is None:
            continue
        if len(key) != KEY_LEN or len(value) != VAL_LEN:
            continue
        print(fmt_entry(key, value))
        shown += 1
    if shown == 0:
        print("(empty)")
    return 0


def _sum_numbers(x):
    """递归求和一个 JSON 子树的全部数值。"""
    if isinstance(x, dict):
        return sum(_sum_numbers(v) for v in x.values())
    if isinstance(x, list):
        return sum(_sum_numbers(v) for v in x)
    if isinstance(x, bool):
        return 0
    if isinstance(x, (int, float)):
        return int(x)
    return 0


def cmd_stats(_):
    names = {0: "rebind_rejected", 1: "redirect_update_failed"}
    for e in bpftool("map", "dump", "name", "mini_stats_map"):
        key_raw = raw_bytes(e.get("key")) or b"\x00\x00\x00\x00"
        key = struct.unpack("<I", key_raw[:4].ljust(4, b"\x00"))[0]
        vals = e.get("formatted", {}).get("values", e.get("values", 0))
        print(f"stat {key} ({names.get(key, '?')}) = {_sum_numbers(vals)}")
    return 0


def cmd_set(a):
    uptime_ns = int(float(open("/proc/uptime").read().split()[0]) * 1e9)
    import time

    last_seen = uptime_ns - int(a.age_sec * 1e9)
    key = (
        bytes(int(x) for x in a.sip.split("."))
        + bytes(int(x) for x in a.dip.split("."))
        + struct.pack("!H", a.sport)
        + struct.pack("!H", a.dport)
        + bytes([a.proto, 0, 0, 0])
    )
    smac = bytes(int(x, 16) for x in a.smac.split(":"))
    dmac = bytes(int(x, 16) for x in a.dmac.split(":"))
    value = (
        struct.pack("<I", a.ifindex)
        + smac
        + dmac
        + bytes([a.from_wan, 0, 0, 0, 0, 0, 0, 0])
        + struct.pack("<Q", last_seen)
    )
    assert len(key) == KEY_LEN and len(value) == VAL_LEN, (len(key), len(value))
    bpftool(
        "map",
        "update",
        "name",
        "redirect_track",
        "key",
        "hex",
        *(f"{b:02x}" for b in key),
        "value",
        "hex",
        *(f"{b:02x}" for b in value),
    )
    print(
        f"set ok: sport={a.sport} ifindex={a.ifindex} smac={a.smac} "
        f"age_sec={a.age_sec} (uptime_ns={uptime_ns}, wall_ns≈{time.time_ns()})"
    )
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("dump")
    sub.add_parser("stats")
    s = sub.add_parser("set")
    s.add_argument("--sip", required=True)
    s.add_argument("--dip", required=True)
    s.add_argument("--sport", type=int, required=True)
    s.add_argument("--dport", type=int, default=8080)
    s.add_argument("--proto", type=int, default=6)
    s.add_argument("--ifindex", type=int, required=True)
    s.add_argument("--smac", required=True)
    s.add_argument("--dmac", required=True)
    s.add_argument("--from-wan", type=int, default=0, dest="from_wan")
    s.add_argument("--age-sec", type=float, default=0.0, dest="age_sec")
    a = p.parse_args()
    return {"dump": cmd_dump, "stats": cmd_stats, "set": cmd_set}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())

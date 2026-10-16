#!/usr/bin/env python3
"""redirect_track / sodama_stats_map 的读写工具（rebind 测试用）。

bpftool -j 输出形态（v7.8）：
  {"key": ["0x0a",...], "value": ["0x04",...], "formatted": {...}}
key/value 原始字节数组是权威来源，formatted 只是 BTF 解码视图；本工具以
原始字节为准（不依赖 BTF）。

子命令：
  dump   打印 redirect_track 条目：
           sip:sport -> dip:dport proto … ifindex/smac/dmac/from_wan/last_seen_ns
  stats  汇总 sodama_stats_map（PERCPU_ARRAY）各 key 的总计数
  set    伪造一条 redirect_track 条目（模拟竞争发布者 / 陈旧条目），时间戳
         用 /proc/uptime 近似 CLOCK_MONOTONIC（2s 窗口，误差 ms 级）

多实例（lab + 真网关同时运行）时 map 名字会重复：默认从 /tmp/sodama.pid
的 loader 进程 fdinfo 反查 map_id 精确锁定本条实例；如需指定其它实例，
用环境变量 SODAMA_DAE_PID_FILE（如 /tmp/sodama-gw.pid）。
"""
import argparse
import glob
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys

from map_id import resolve_map_ids

# struct sodama_tuple: sip16 + dip16 + sport2 + dport2 + l4proto1 + is_v6 1 + pad2
# （P16 起地址统一 16 字节：IPv4 = v4-mapped ::ffff:a.b.c.d）
KEY_LEN = 40
# struct sodama_redirect_entry: ifindex4 + smac6 + dmac6 + from_wan1 + pad3
#                             + 对齐 4B + last_seen8
VAL_LEN = 32

_MAP_IDS = {}
_RESOLVED = False


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


def _resolve_map_ids():
    """一次读完本实例的 name→map_id（实现见 map_id.py：fdinfo ∩ map list）。

    必须很快（rebind 测试只有 2s 陈旧窗口）：早期版本逐 fd 调用 map show，
    16 个子进程直接吃满窗口，导致误报「改绑被改掉」。
    """
    global _RESOLVED
    if _RESOLVED:
        return
    _RESOLVED = True
    pid_file = os.environ.get("SODAMA_DAE_PID_FILE", "/tmp/sodama.pid")
    _MAP_IDS.update(resolve_map_ids(pid_file))


def map_id(name):
    """精确定位本条实例的 map id；解析失败返回 None（回退按名字）。"""
    _resolve_map_ids()
    return _MAP_IDS.get(name[:15])  # map_id.py 的键是内核截断后的 15 字符名


def map_dump(name):
    mid = map_id(name)
    if mid is not None:
        return bpftool("map", "dump", "id", str(mid))
    return bpftool("map", "dump", "name", name)


def map_update(name, key, value):
    mid = map_id(name)
    tail = (
        "key",
        "hex",
        *(f"{b:02x}" for b in key),
        "value",
        "hex",
        *(f"{b:02x}" for b in value),
    )
    if mid is not None:
        return bpftool("map", "update", "id", str(mid), *tail)
    return bpftool("map", "update", "name", name, *tail)


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


def fmt_addr(b):
    """16 字节地址 → 文本：v4-mapped 显示点分，其余显示 IPv6。"""
    a = ipaddress.IPv6Address(bytes(b))
    if a.ipv4_mapped is not None:
        return str(a.ipv4_mapped)
    return str(a)


def addr_bytes(s):
    """点分 IPv4 或 IPv6 文本 → 16 字节（v4 走 v4-mapped）。"""
    a = ipaddress.ip_address(s)
    if a.version == 4:
        return b"\x00" * 10 + b"\xff\xff" + a.packed
    return a.packed


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def fmt_entry(key, value):
    sip, dip = fmt_addr(key[0:16]), fmt_addr(key[16:32])
    sport, dport = struct.unpack("!HH", key[32:36])
    ifindex = struct.unpack("<I", value[0:4])[0]
    return (
        f"{sip}:{sport} -> {dip}:{dport} proto={key[36]} "
        f"ifindex={ifindex} smac={mac(value[4:10])} dmac={mac(value[10:16])} "
        f"from_wan={value[16]} last_seen_ns={struct.unpack('<Q', value[24:32])[0]}"
    )


def cmd_dump(_):
    entries = map_dump("redirect_track")
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


def _counter_sum(vals):
    """PERCPU 值求和：兼容 [{"cpu":N,"value":M}]（BTF 解码）与原始字节列表。"""
    if not isinstance(vals, list):
        return _sum_numbers(vals)
    total = 0
    for v in vals:
        if isinstance(v, dict):
            total += _counter_sum(v.get("value"))
        elif isinstance(v, int):
            total += v
        elif isinstance(v, str):
            b = raw_bytes([v])
            if b is not None:
                total += struct.unpack("<Q", b[:8].ljust(8, b"\x00"))[0]
        elif isinstance(v, list):
            total += _counter_sum(v)
    return total


def cmd_stats(_):
    # 键域对齐 dae `enum bpf_stats_key`（0..=12）+ sodama 自有（13+）
    names = {
        0: "udp_conn_overflow",
        1: "tcp_conn_overflow",
        2: "redirect_overflow",
        3: "redirect_update_failed",
        4: "redirect_rebind_rejected",
        5: "syn_rebind_rejected",
        6: "stateless_tcp_passthrough",
        7: "frag_tail_passed",
        8: "parse_unsupported_l4",
        9: "unsolicited_udp_seen",
        10: "sockmark_fallback",
        11: "event_drops",
        12: "rebind_rerouted",
        13: "offload_redirects",
        14: "offload_verdicts",
        15: "pname_hits",
        16: "offload_sent_bytes",
        17: "account_drops",
        18: "probe_calls",
        19: "probe_parse_fail",
        20: "probe_guard_miss",
        21: "offload_pause_passes",
    }
    for e in map_dump("sodama_stats_map"):
        key_raw = raw_bytes(e.get("key")) or b"\x00\x00\x00\x00"
        key = struct.unpack("<I", key_raw[:4].ljust(4, b"\x00"))[0]
        vals = e.get("formatted", {}).get("values", e.get("values", 0))
        print(f"stat {key} ({names.get(key, '?')}) = {_counter_sum(vals)}")
    return 0


def cmd_set(a):
    uptime_ns = int(float(open("/proc/uptime").read().split()[0]) * 1e9)
    import time

    last_seen = uptime_ns - int(a.age_sec * 1e9)
    key = (
        addr_bytes(a.sip)
        + addr_bytes(a.dip)
        + struct.pack("!H", a.sport)
        + struct.pack("!H", a.dport)
        + bytes([a.proto])
        + bytes([1 if ":" in a.sip or ":" in a.dip else 0])
        + b"\x00\x00"
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
    map_update("redirect_track", key, value)
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

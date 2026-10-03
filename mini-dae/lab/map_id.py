#!/usr/bin/env python3
"""多实例下按 loader pid 精确定位 eBPF map id。

lab（mini_daens）与真网关（gwdae）可以同时运行，两者 map 名字完全相同；
按名字 `bpftool map list | head -1` 会抓到另一个实例的 map（rebind/DNS
位图测试都踩过）。本工具用 loader 进程的 fdinfo 反查 map_id（只对本进程
打开的 map 生效），再与 bpftool map list 的名字求交。

用法：
  python3 lab/map_id.py <map_name> [--pid-file /tmp/mini-dae.pid]
环境变量 MINI_DAE_PID_FILE 可覆盖默认 pid 文件（如 /tmp/mini-dae-gw.pid）。
"""
import argparse
import glob
import json
import os
import subprocess
import sys


def resolve_map_ids(pid_file="/tmp/mini-dae.pid"):
    """loader 进程 fdinfo ∩ bpftool map list → {name: id}（找不到时为空）。"""
    try:
        with open(pid_file) as f:
            pid = f.read().strip()
    except OSError:
        pid = ""
    ids = set()
    if pid.isdigit():
        for fdinfo in glob.glob(f"/proc/{pid}/fdinfo/*"):
            try:
                with open(fdinfo) as f:
                    for line in f:
                        if line.startswith("map_id:"):
                            ids.add(int(line.split(":")[1]))
            except OSError:
                continue
    names = {}
    if not ids:
        return names
    r = subprocess.run(
        ["bpftool", "-j", "map", "list"], capture_output=True, text=True
    )
    if r.returncode != 0:
        return names
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return names
    for info in data:
        mid, name = info.get("id"), info.get("name")
        if mid in ids and name:
            # 内核把 map 名截断到 15 字符，按截断后匹配。
            names.setdefault(name[:15], mid)
    return names


def map_id(name, pid_file="/tmp/mini-dae.pid"):
    return resolve_map_ids(pid_file).get(name[:15])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument(
        "--pid-file",
        default=os.environ.get("MINI_DAE_PID_FILE", "/tmp/mini-dae.pid"),
    )
    a = ap.parse_args()
    mid = map_id(a.name, a.pid_file)
    if mid is None:
        sys.stderr.write(f"map {a.name} not found (pid-file={a.pid_file})\n")
        return 1
    print(mid)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""极简 expect：spawn 一个命令（通常是 qemu -nographic）并按其控制台交互。

用法：
  qemu-console.py <脚本文件> -- <命令...>
脚本文件每行一条指令（空行/`#` 开头忽略）：
  EXPECT <子串或正则>      # 等待输出中出现
  SEND   <文本>            # 发送文本 + 回车（支持 \\n 转义）
  SLEEP  <秒>
  MARK   <名字>            # 打印标记到自己的 stdout（供调用方 grep）
  QUIT                     # 结束（发 ctrl-a x 给 qemu，再 kill）
全部控制台输出会原样转发到 stdout。

无第三方依赖（pty + select）。
"""
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time


def main():
    if "--" not in sys.argv:
        print(__doc__)
        sys.exit(2)
    i = sys.argv.index("--")
    script = sys.argv[1:i]
    cmd = sys.argv[i + 1 :]
    if not script or not cmd:
        print(__doc__)
        sys.exit(2)
    steps = []
    for line in open(script[0]):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        op, _, arg = line.partition(" ")
        steps.append((op.strip().upper(), arg))

    master, slave = pty.openpty()
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    buf = b""
    deadline = time.time() + 1200

    def pump(timeout):
        nonlocal buf
        r, _, _ = select.select([master], [], [], timeout)
        if master in r:
            try:
                data = os.read(master, 4096)
            except OSError:
                return False
            if not data:
                return False
            buf += data
            sys.stdout.write(data.decode(errors="replace"))
            sys.stdout.flush()
            return True
        return False

    try:
        for op, arg in steps:
            if op == "EXPECT":
                pat = arg
                ok = False
                while time.time() < deadline:
                    if re.search(pat, buf.decode(errors="replace")):
                        ok = True
                        break
                    if not pump(1.0) and proc.poll() is not None:
                        break
                # 消费已匹配部分，避免重复匹配
                m = re.search(pat, buf.decode(errors="replace"))
                if m:
                    buf = buf[m.end():]
                if not ok:
                    print(f"\n[expect] TIMEOUT/EXITED waiting: {pat}", file=sys.stderr)
                    return_code = 3
                    break
            elif op == "SEND":
                text = arg.replace("\\n", "\n")
                os.write(master, (text + "\n").encode())
                time.sleep(0.3)
            elif op == "SLEEP":
                end = time.time() + float(arg)
                while time.time() < end:
                    pump(0.5)
            elif op == "MARK":
                print(f"\n### {arg} ###", flush=True)
            elif op == "QUIT":
                try:
                    os.write(master, b"\x01x")  # qemu: ctrl-a x
                except OSError:
                    pass
                time.sleep(1.0)
                break
        else:
            return_code = 0
            # 脚本走完：留一点时间排空输出
            end = time.time() + 3
            while time.time() < end:
                pump(0.5)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()

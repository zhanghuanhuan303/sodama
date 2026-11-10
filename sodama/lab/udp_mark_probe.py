#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""临时调试：对比 marked UDP socket 的 sendto/recvfrom 与 connect/send/recv 在 sodama 下的行为。"""
import socket

MARK = getattr(socket, "SO_MARK", 36)


def mk():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, MARK, 0x233)
    s.settimeout(2)
    return s


a = mk()
a.sendto(b"A", ("2.2.2.2", 9998))
try:
    print("A(unconnected) got:", a.recvfrom(2048))
except Exception as e:  # noqa: BLE001
    print("A(unconnected) fail:", e)

b = mk()
b.connect(("2.2.2.2", 9998))
b.send(b"B")
try:
    print("B(connected) got:", b.recv(2048))
except Exception as e:  # noqa: BLE001
    print("B(connected) fail:", e)

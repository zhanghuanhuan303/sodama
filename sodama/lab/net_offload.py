#!/usr/bin/env python3
"""关闭网卡的校验和/分段 offload —— 不依赖 ethtool（lab 机器不一定装）。

为什么需要（踩坑记录，2026-10-16 VM 实测）：
veth/ipip 这类虚拟设备在「隧道 + 卸载」链路上会把**内层** TCP 校验和以
CHECKSUM_PARTIAL 交给对端设备完成，而 veth 并不真正计算它 —— 结果是对端收到的
内层报文校验和恒错，TCP 栈直接静默丢包。现象极具迷惑性：**包都到了、握手不完成**
（抓包可见 `cksum … (incorrect …)`，两侧收发包计数都在涨）。

经典处置是 `ethtool -K <dev> tx off rx off`；本脚本用 SIOCETHTOOL +
传统 ETHTOOL_S{RX,TX}CSUM / S{TSO,GSO,GRO} ioctl 达到同样效果，纯 stdlib。

实现要点：ifr_ifru 里的 ifr_data 是**内核要解引用的用户态指针**，必须指向一块
真实缓冲区。做法：bytearray 当 struct ifreq（可变缓冲，fcntl 以 mutate 语义直接
下传），再用 `struct.pack_into("@P", …)` 把 ethtool_value 的地址写进指针槽位；
`ctypes.addressof` 仅用于取地址。严禁用 `id(buf)` 之类的 CPython 对象头地址当
指针——那是 2026-10-16 段错误的来源（内核往解释器堆里写回）。
"""

import ctypes
import fcntl
import socket
import struct
import sys

SIOCETHTOOL = 0x8946
_IFREQ_SIZE = 40  # x86_64：16B ifr_name + 24B ifr_ifru 联合体
_IFR_DATA_OFF = 16


class EthtoolValue(ctypes.Structure):
    _fields_ = [
        ("cmd", ctypes.c_uint32),
        ("data", ctypes.c_uint32),
    ]


def _ioctl_value(sock: socket.socket, ifname: str, cmd: int, value: int = 0) -> int:
    """一条 ethtool_value ioctl；返回内核写回的 data。"""
    ev = EthtoolValue(cmd, value)
    raw = bytearray(_IFREQ_SIZE)
    struct.pack_into("@16s", raw, 0, ifname.encode()[:15])
    struct.pack_into("@P", raw, _IFR_DATA_OFF, ctypes.addressof(ev))
    fcntl.ioctl(sock.fileno(), SIOCETHTOOL, raw, True)
    return ev.data


# (名称, GET, SET)：号值见 /usr/include/linux/ethtool.h
FEATURES = [
    ("rx-csum", 0x14, 0x15),  # ETHTOOL_G/SRXCSUM
    ("tx-csum", 0x16, 0x17),  # ETHTOOL_G/STXCSUM
    ("tso", 0x1E, 0x1F),      # ETHTOOL_G/STSO
    ("gso", 0x23, 0x24),      # ETHTOOL_G/SGSO
    ("gro", 0x2B, 0x2C),      # ETHTOOL_G/SGRO
]


def main() -> int:
    """用法：net_offload.py [--on] <dev>…

    默认关闭五类 offload（校验和/TSO/GSO/GRO）；`--on` 恢复开启
    （用于 L3 用例的“治完即还”，避免污染同一拓扑上的后续压测）。
    """
    args = sys.argv[1:]
    enable = False
    if args and args[0] in ("--on", "--enable", "on"):
        enable = True
        args = args[1:]
    if not args:
        print(main.__doc__)
        return 2
    failed = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for dev in args:
            states = []
            for name, gcmd, scmd in FEATURES:
                try:
                    _ioctl_value(sock, dev, scmd, 1 if enable else 0)
                except OSError as e:
                    failed += 1
                    states.append(f"{name}=set失败({e.strerror})")
                    continue
                try:
                    cur = _ioctl_value(sock, dev, gcmd)
                    states.append(f"{name}={'on' if cur else 'off'}")
                except OSError as e:
                    states.append(f"{name}=?({e.strerror})")
            print(f"net_offload: {dev} " + " ".join(states))
    finally:
        sock.close()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

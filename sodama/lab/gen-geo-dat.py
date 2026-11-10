#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""生成 P17a 测试用的小型 geoip.dat / geosite.dat（v2ray protobuf 格式）。

用法： gen-geo-dat.py <输出目录>

内容（确定性，供 lab 会话与 parity 对拍共用）：
  geoip.dat:
    CN: 10.9.10.0/24, 2001:db8:aa::1/128      （lab 中 10.9.10.0/24 由 WAN echo 服务）
    US: 1.2.3.0/24
  geosite.dat:
    CN: suffix geo.test / .sub.geo.test（仅子域）、full full.geo.test、
        keyword kwgeo、regex ^re[0-9]+\\.geo\\.test$、带 attr(ads) 的 suffix ads.geo.test
    US: full us.geo.test

字段号对照 dae/pkg/geodata/common.pb.go：
  GeoIPList.entry=1; GeoIP{country_code=1, cidr=2, inverse_match=3}
  CIDR{ip=1, prefix=2}; GeoSiteList.entry=1; GeoSite{country_code=1, domain=2}
  Domain{type=1, value=2, attribute=3}; Attribute.key=1
  Domain.Type: Plain=0 / Regex=1 / RootDomain=2 / Full=3
"""
import os
import sys


def varint(v, out):
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return


def tag(num, wire, out):
    varint((num << 3) | wire, out)


def len_field(num, payload, out):
    tag(num, 2, out)
    varint(len(payload), out)
    out.extend(payload)


def cidr(ip_bytes, plen):
    b = bytearray()
    len_field(1, ip_bytes, b)
    tag(2, 0, b)
    varint(plen, b)
    return bytes(b)


def geoip_entry(code, cidrs, inverse=False):
    b = bytearray()
    len_field(1, code.encode(), b)
    for c in cidrs:
        len_field(2, c, b)
    if inverse:
        tag(3, 0, b)
        varint(1, b)
    return bytes(b)


def attr(key):
    b = bytearray()
    len_field(1, key.encode(), b)
    return bytes(b)


def domain(dtype, value, attrs=()):
    b = bytearray()
    tag(1, 0, b)
    varint(dtype, b)
    len_field(2, value.encode(), b)
    for a in attrs:
        len_field(3, attr(a), b)
    return bytes(b)


def geosite_entry(code, domains):
    b = bytearray()
    len_field(1, code.encode(), b)
    for d in domains:
        len_field(2, d, b)
    return bytes(b)


def pb_list(entries):
    b = bytearray()
    for e in entries:
        len_field(1, e, b)
    return bytes(b)


def main():
    if len(sys.argv) != 2:
        print("usage: gen-geo-dat.py <dir>", file=sys.stderr)
        return 2
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    v6 = bytes([0x20, 0x01, 0x0D, 0xB8, 0x00, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    geoip = pb_list(
        [
            geoip_entry(
                "CN",
                [
                    cidr(bytes([10, 9, 10, 0]), 24),
                    cidr(v6, 128),
                ],
            ),
            geoip_entry("US", [cidr(bytes([1, 2, 3, 0]), 24)]),
        ]
    )
    geosite = pb_list(
        [
            geosite_entry(
                "CN",
                [
                    domain(2, "geo.test"),
                    domain(2, ".sub.geo.test"),  # 前导点 = 仅子域
                    domain(3, "full.geo.test"),
                    domain(0, "kwgeo"),
                    domain(1, r"^re[0-9]+\.geo\.test$"),
                    domain(2, "ads.geo.test", ["ads"]),
                ],
            ),
            geosite_entry("US", [domain(3, "us.geo.test")]),
        ]
    )
    with open(os.path.join(out_dir, "geoip.dat"), "wb") as f:
        f.write(geoip)
    with open(os.path.join(out_dir, "geosite.dat"), "wb") as f:
        f.write(geosite)
    print(f"geo-dat: wrote {out_dir}/geoip.dat ({len(geoip)}B), geosite.dat ({len(geosite)}B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""P20：QUIC Initial 探针（lab 夹具）——按 RFC 9001 手工构造带 SNI 的客户端 Initial。

与 Rust 侧 `quicsniff` 的互操作是「跨实现」验证：本文件用 Python `cryptography`
独立实现初始密钥派生（HKDF-SHA256）、头部保护（AES-ECB 采样）与 AEAD（AES-128-GCM），
不复用 Rust 侧任何代码。

用法： quic_probe.py <host> <port> <sni>
输出： "quic-sniff-sent sni=<sni> bytes=<n>"
"""
import hashlib
import hmac
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# RFC 9001 §5.2 固定盐（QUIC v1）
SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def expand_label(secret: bytes, label: str, length: int) -> bytes:
    """HKDF-Expand-Label（RFC 8446 §7.1；QUIC v1 标签带 "tls13 " 前缀）。"""
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def client_hello(sni: str) -> bytes:
    """最小 ClientHello（含 SNI 扩展即可）。"""
    name = sni.encode()
    sni_ext = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    exts = b"\x00\x00" + struct.pack("!H", len(sni_ext)) + sni_ext
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def varint(n: int) -> bytes:
    """RFC 9000 §16（本夹具只需到 2 字节与 4 字节形式）。"""
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack("!H", 0x4000 | n)
    return struct.pack("!I", 0x80000000 | n)


def main() -> None:
    host, port, sni = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    dcid = os.urandom(8)
    # 初始密钥（RFC 9001 §5.2）
    initial_secret = hmac.new(SALT_V1, dcid, hashlib.sha256).digest()
    client_secret = expand_label(initial_secret, "client in", 32)
    key = expand_label(client_secret, "quic key", 16)
    iv = expand_label(client_secret, "quic iv", 12)
    hp = expand_label(client_secret, "quic hp", 16)

    hs = client_hello(sni)
    frames = b"\x06" + varint(0) + varint(len(hs)) + hs  # CRYPTO 帧

    # 头部（PN 长度 4）：1 + 4 + 1 + dcid + 1(scid_len) + 1(token_len) + 2(plen) + 4(pn)
    header_len = 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 + 4
    # 整包 >= 1200（明文 PADDING 填充）
    min_pt = max(1200 - header_len - 16, len(frames))
    if len(frames) < min_pt:
        frames += b"\x00" * (min_pt - len(frames))
    plen = 4 + len(frames) + 16  # PN + 密文 + tag

    header = (
        b"\xc3"  # long + fixed + Initial(v1) + pn_len=4
        + b"\x00\x00\x00\x01"  # version
        + bytes([len(dcid)])
        + dcid
        + b"\x00"  # scid_len
        + varint(0)  # token
        + varint(plen)
        + b"\x00\x00\x00\x00"  # pn=0
    )
    assert len(header) == header_len, (len(header), header_len)
    # AEAD：nonce = iv XOR pn（pn=0 → 即 iv）
    ct = AESGCM(key).encrypt(iv, frames, bytes(header))
    pkt = bytearray(header + ct)

    # 头部保护：sample 从 pn 字段起第 4 字节处取 16B
    pn_offset = header_len - 4
    sample = bytes(pkt[pn_offset + 4 : pn_offset + 20])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    pkt[0] ^= mask[0] & 0x0F
    for i in range(4):
        pkt[pn_offset + i] ^= mask[1 + i]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(bytes(pkt), (host, port))
    print(f"quic-sniff-sent sni={sni} bytes={len(pkt)}")


if __name__ == "__main__":
    main()

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! P20：QUIC Initial SNI 嗅探（RFC 9001）。
//!
//! 用途：UDP 侧域名观测——UDP 数据面（`udp_nat_handle` 新会话）识别 QUIC Initial 并解出
//! TLS ClientHello 的 SNI（日志 + `sniffing.quic_sni` 计数），补齐「TLS/HTTP/h2c/QUIC」
//! 嗅探组合的最后一块（对照 dae 内核侧 QUIC 嗅探）。
//!
//! 范围与边界（如实）：
//! - **QUIC v1** 长头 Initial（客户端首包）；v2（RFC 9369 标签不同）与 Retry/0-RTT 不解；
//! - 客户端首飞包号即截断值（首包 pn=0/1，成立）；重放/迁移的后续 Initial 不回看；
//! - **只看单包**：ClientHello 跨多包时（首包只含部分 CRYPTO）返回 No；
//! - 解出 SNI 仅作观测：UDP 拨号仍按目标地址（UDP 域名拨号未做，见 ADR-0044）。

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit as _};
use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::Aes128Gcm;
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};

use crate::sniffer::{self, Sniff};

#[derive(Debug, PartialEq, Eq)]
pub enum QuicSniff {
    Found(String),
    /// 不是可解的 QUIC v1 Initial（或首包不含完整 ClientHello）
    No,
}

/// RFC 9001 §5.2 固定盐（QUIC v1）。
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V1: u32 = 0x0000_0001;

struct OutLen(usize);
impl KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label（RFC 8446 §7.1；QUIC v1 的标签带 "tls13 " 前缀）。
fn expand_label(prk: &ring::hkdf::Prk, label: &str, out_len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 6 + label.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0); // context 长度 0
    let info_parts: [&[u8]; 1] = [info.as_slice()];
    let okm = prk
        .expand(&info_parts, OutLen(out_len))
        .expect("hkdf 参数合法");
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).expect("输出长度合法");
    out
}

/// 客户端 Initial 密钥（RFC 9001 §5.2）。
struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_initial_keys(dcid: &[u8]) -> InitialKeys {
    let prk = Salt::new(HKDF_SHA256, &QUIC_V1_SALT).extract(dcid);
    let client = expand_label(&prk, "client in", 32);
    let client_prk = ring::hkdf::Prk::new_less_safe(HKDF_SHA256, &client);
    let mut key = [0u8; 16];
    key.copy_from_slice(&expand_label(&client_prk, "quic key", 16));
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&expand_label(&client_prk, "quic iv", 12));
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&expand_label(&client_prk, "quic hp", 16));
    InitialKeys { key, iv, hp }
}

/// RFC 9000 §16 可变长整数。
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &x in &b[1..len] {
        v = (v << 8) | x as u64;
    }
    Some((v, len))
}

/// 解出 Initial 包明文（CRYPTO/PADDING 帧）。失败（非 v1 Initial/保护错/AEAD 失败）None。
/// 测试可见：RFC 9001 A.2 黄金向量直接验证本函数。
pub(crate) fn decrypt_initial(datagram: &[u8]) -> Option<Vec<u8>> {
    let d = datagram;
    if d.len() < 7 {
        return None;
    }
    // 长头 + fixed bit
    if d[0] & 0x80 == 0 || d[0] & 0x40 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
    if version != QUIC_V1 {
        return None; // v2/协商包不解（标签不同）
    }
    if (d[0] & 0x30) >> 4 != 0 {
        return None; // v1：0=Initial
    }
    let dcid_len = d[5] as usize;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let mut off = 6usize;
    let dcid = d.get(off..off + dcid_len)?;
    off += dcid_len;
    let scid_len = *d.get(off)? as usize;
    if scid_len > 20 {
        return None;
    }
    off += 1 + scid_len;
    // Initial 有 token 字段
    let (tok_len, n) = varint(d.get(off..)?)?;
    off += n + tok_len as usize;
    // Packet Payload Length 含 pn_len + 密文 + 16B tag
    let (plen, n) = varint(d.get(off..)?)?;
    off += n;
    let pn_offset = off;
    if plen < 4 + 16 {
        return None;
    }
    let end = pn_offset.checked_add(usize::try_from(plen).ok()?)?;
    if end > d.len() || d.len() < pn_offset + 4 + 16 {
        return None;
    }

    let keys = derive_initial_keys(dcid);
    // 头部保护：sample 从 pn 字段起第 4 字节处取 16B（RFC 9001 §5.4.2）
    let sample = &d[pn_offset + 4..pn_offset + 20];
    let mut blk = GenericArray::clone_from_slice(sample);
    let hp = aes::Aes128::new(GenericArray::from_slice(&keys.hp));
    hp.encrypt_block(&mut blk);
    let mask = &blk[..];
    // 解除首字节低 4 位 → pn_len
    let pn_len = ((d[0] ^ (mask[0] & 0x0f)) & 0x03) as usize + 1;
    if pn_offset + pn_len + 16 > end {
        return None;
    }
    let mut header = d[..pn_offset + pn_len].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }
    // nonce = iv XOR pn（右对齐）
    let mut nonce = keys.iv;
    for i in 0..8 {
        nonce[11 - i] ^= ((pn >> (8 * i)) & 0xff) as u8;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let ct = &d[pn_offset + pn_len..end];
    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ct,
                aad: &header,
            },
        )
        .ok()
}

/// 从明文里取 CRYPTO 帧（offset 0 起拼接；跨帧不重排）。
fn crypto_frame(pt: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let mut data = Vec::new();
    while pos < pt.len() {
        let (ftype, n) = varint(&pt[pos..])?;
        pos += n;
        match ftype {
            0x00 => break, // PADDING 起，其后全为 0
            0x06 => {
                let (offset, n) = varint(&pt[pos..])?;
                pos += n;
                if offset != 0 {
                    return None; // 首见帧即非 0 偏移：不回看重传包
                }
                let (len, n) = varint(&pt[pos..])?;
                pos += n;
                let end = pos.checked_add(usize::try_from(len).ok()?)?;
                data.extend_from_slice(pt.get(pos..end)?);
                pos = end;
            }
            0x01 => {} // PING
            _ => return None,
        }
    }
    if data.is_empty() {
        None
    } else {
        Some(data)
    }
}

/// handshake 消息（CRYPTO 内容）→ ClientHello SNI。
fn handshake_sni(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data[0] != 0x01 {
        return None; // 非 ClientHello
    }
    let len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    let body = data.get(4..4 + len)?;
    match sniffer::parse_client_hello_body(body) {
        Sniff::Found(n) => Some(n),
        _ => None,
    }
}

/// QUIC Initial 数据报 → SNI（纯函数）。
pub fn sniff(datagram: &[u8]) -> QuicSniff {
    let Some(pt) = decrypt_initial(datagram) else {
        return QuicSniff::No;
    };
    let Some(crypto) = crypto_frame(&pt) else {
        return QuicSniff::No;
    };
    match handshake_sni(&crypto) {
        Some(name) => QuicSniff::Found(name),
        None => QuicSniff::No,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        clean
            .as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// RFC 9001 A.1：由 DCID 派生的客户端 Initial 密钥必须逐字节一致。
    #[test]
    fn rfc9001_a1_client_initial_keys() {
        let dcid = unhex("8394c8f03e515708");
        let k = derive_initial_keys(&dcid);
        assert_eq!(
            k.key.to_vec(),
            unhex("1f369613dd76d5467730efcbe3b1a22d"),
            "key"
        );
        assert_eq!(k.iv.to_vec(), unhex("fa044b2f42a3fd3b46fb255c"), "iv");
        assert_eq!(
            k.hp.to_vec(),
            unhex("9f50449e04a0e810283a1e9933adedd2"),
            "hp"
        );
    }

    /// RFC 9001 A.2：官方保护后 Client Initial 包（含 SNI example.com）——
    /// 全链路（密钥派生→头部保护解除→AEAD→CRYPTO→ClientHello）黄金向量。
    #[test]
    fn rfc9001_a2_client_initial_sni() {
        let pkt = unhex(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
             d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
             1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
             8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
             30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
             457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
             4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
             4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
             485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
             059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
             7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
             9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
             be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
             68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
             c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
             f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
             291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
             25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
             14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
             ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
             e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
             c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
             203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
             cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
             fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
             a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
             90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
             162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
             40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
             6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
             8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
             be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
             54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
             760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
             f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
             056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
             7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
             e221af44860018ab0856972e194cd934",
        );
        assert_eq!(
            sniff(&pkt),
            QuicSniff::Found("example.com".into()),
            "RFC 9001 A.2 黄金向量应解出 example.com"
        );
    }

    /// 非 Initial / 截断 / 短头：一律 No（不误报）。
    #[test]
    fn non_initial_is_no() {
        assert_eq!(sniff(&[]), QuicSniff::No);
        assert_eq!(sniff(&[0x40, 0, 0, 0, 0]), QuicSniff::No); // 短头
        assert_eq!(
            sniff(&[0xc3, 0, 0, 0, 2, 8, 1, 2, 3, 4, 5, 6, 7, 8]),
            QuicSniff::No
        ); // v2
        let pkt = unhex("c300000001088394c8f03e5157080000449e7b9aec34");
        assert_eq!(sniff(&pkt), QuicSniff::No); // 截断
    }

    #[test]
    fn varint_decoding() {
        assert_eq!(varint(&[0x00]), Some((0, 1)));
        assert_eq!(varint(&[0x25]), Some((0x25, 1)));
        assert_eq!(varint(&[0x40, 0x25]), Some((0x25, 2)));
        assert_eq!(varint(&[0x80, 0, 0, 0x25]), Some((0x25, 4)));
        assert_eq!(varint(&[0x40]), None);
    }

    /// 真实 QUIC 栈（quinn）在环回口产出的客户端首包 Initial——跨实现验证
    /// （不是我们自造的包，能抓住「只与自己的加密实现自洽」的类错）。
    #[test]
    fn sniff_real_quinn_client_initial() {
        use std::sync::Arc;
        let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rustls_cfg = crate::tls::build_rustls_config(true, &[b"h3".to_vec()]);
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg).unwrap();
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(quinn::TransportConfig::default()));
        let mut ep = crate::tuic::runtime()
            .block_on(async {
                quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    None,
                    client_sock,
                    Arc::new(quinn::TokioRuntime),
                )
            })
            .unwrap();
        ep.set_default_client_config(client_cfg);
        let addr = server_sock.local_addr().unwrap();
        // connect 会在运行时 spawn 连接 driver，必须在 tokio 上下文里调用
        let connecting = crate::tuic::runtime()
            .block_on(async { ep.connect(addr, "quic.sniff.test") })
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = server_sock
            .recv(&mut buf)
            .expect("5s 内应收到 quinn 客户端 Initial");
        assert_eq!(sniff(&buf[..n]), QuicSniff::Found("quic.sniff.test".into()));
        // 收尾也回到运行时上下文（driver/连接状态与 runtime 交互）
        crate::tuic::runtime().block_on(async {
            drop(connecting);
            ep.close(0u32.into(), b"done");
        });
    }
}

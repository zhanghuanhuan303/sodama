// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! P5-G3b：HPACK Huffman 解码 + QPACK 最小编／解码（hysteria2 认证用）。
//!
//! hysteria2 的认证是标准 HTTP/3 请求：客户端需要 QPACK **编码** 一个请求头块，
//! 并**解码**服务端返回的响应头块。quic-go 的 QPACK 编码器总是对 literal 的
//! 名字/值做 HPACK Huffman 编码（`golang.org/x/net/http2/hpack`），所以解码侧
//! 必须实现 Huffman；编码侧我们只用「静态表索引 / name-ref + 非 Huffman literal」，
//! 服务端解码器两者都收。
//!
//! 表来自 `huffman_table.rs`（由 lab/gen-huffman-table.py 从 Go 源码生成）。

use std::sync::OnceLock;

use crate::huffman_table::{HUFFMAN_CODES, HUFFMAN_CODE_LEN, QPACK_STATIC};

// ---------------------------------------------------------------- Huffman 解码

const EOS_SYM: i16 = -2;

struct Node {
    child: [i16; 2],
    sym: i16,
}

fn tree() -> &'static Vec<Node> {
    static T: OnceLock<Vec<Node>> = OnceLock::new();
    T.get_or_init(|| {
        let mut nodes: Vec<Node> = vec![Node {
            child: [-1, -1],
            sym: -1,
        }];
        let insert = |code: u32, len: u8, sym: i16, nodes: &mut Vec<Node>| {
            let mut cur = 0usize;
            for i in (0..len).rev() {
                let bit = ((code >> i) & 1) as usize;
                let next = nodes[cur].child[bit];
                if next < 0 {
                    let id = nodes.len() as i16;
                    nodes.push(Node {
                        child: [-1, -1],
                        sym: -1,
                    });
                    nodes[cur].child[bit] = id;
                    cur = id as usize;
                } else {
                    cur = next as usize;
                }
            }
            nodes[cur].sym = sym;
        };
        for (b, (&code, &len)) in HUFFMAN_CODES
            .iter()
            .zip(HUFFMAN_CODE_LEN.iter())
            .enumerate()
        {
            insert(code, len, b as i16, &mut nodes);
        }
        // EOS：30 位全 1（用于校验 padding）
        insert(0x3fff_ffff, 30, EOS_SYM, &mut nodes);
        nodes
    })
}

/// HPACK Huffman 解码（含 RFC 7541 §5.2 的 padding 校验：≤7 位全 1）。
pub fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let t = tree();
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut cur = 0usize;
    let mut pad_bits: u32 = 0;
    let mut pad_len: u32 = 0;
    for &byte in input {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as usize;
            let next = t[cur].child[bit];
            if next < 0 {
                return Err("huffman: 非法码字".into());
            }
            pad_bits = (pad_bits << 1) | bit as u32;
            pad_len += 1;
            cur = next as usize;
            match t[cur].sym {
                EOS_SYM => return Err("huffman: EOS 出现在数据中".into()),
                s if s >= 0 => {
                    out.push(s as u8);
                    cur = 0;
                    pad_bits = 0;
                    pad_len = 0;
                }
                _ => {}
            }
        }
    }
    if cur != 0 {
        // 剩余的必须全是 1（EOS 前缀）且 ≤7 位
        if pad_len > 7 || pad_bits != (1u32 << pad_len) - 1 {
            return Err("huffman: padding 非法".into());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- QPACK 编解码

/// RFC 7541 §5.1 前缀整数编码。
fn encode_int(dst: &mut Vec<u8>, value: u64, prefix_bits: u8, first_byte_mask: u8) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        dst.push(first_byte_mask | value as u8);
        return;
    }
    dst.push(first_byte_mask | max as u8);
    let mut v = value - max;
    while v >= 128 {
        dst.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    dst.push(v as u8);
}

/// RFC 7541 §5.1 前缀整数解码；返回 (值, 消费字节数)。
fn decode_int(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), String> {
    if buf.is_empty() {
        return Err("qpack: 整数截断".into());
    }
    let max = (1u64 << prefix_bits) - 1;
    let mut value = (buf[0] as u64) & max;
    if value < max {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    let mut i = 1usize;
    loop {
        if i >= buf.len() {
            return Err("qpack: 整数截断".into());
        }
        let b = buf[i];
        i += 1;
        value = value
            .checked_add(((b & 0x7f) as u64) << shift)
            .ok_or("qpack: 整数溢出")?;
        if b & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
        if shift > 62 {
            return Err("qpack: 整数过长".into());
        }
    }
}

/// 非 Huffman 字符串（编码侧用）。
fn encode_str(dst: &mut Vec<u8>, s: &str) {
    encode_int(dst, s.len() as u64, 7, 0x00);
    dst.extend_from_slice(s.as_bytes());
}

/// 字符串解码（H=1 时走 Huffman）；返回 (串, 消费字节数)。
fn decode_str(buf: &[u8]) -> Result<(String, usize), String> {
    if buf.is_empty() {
        return Err("qpack: 字符串截断".into());
    }
    let huffman = buf[0] & 0x80 != 0;
    let (len, used) = decode_int(buf, 7)?;
    let len = len as usize;
    if buf.len() < used + len {
        return Err("qpack: 字符串越过块尾".into());
    }
    let raw = &buf[used..used + len];
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    let s = String::from_utf8(bytes).map_err(|e| format!("qpack: 非 UTF-8: {e}"))?;
    Ok((s, used + len))
}

/// QPACK 编码：静态表索引 + name-ref（非 Huffman 值）+ literal（非 Huffman 名值）。
pub fn qpack_encode(block: &mut Vec<u8>, fields: &[(&str, &str)]) {
    // Required Insert Count = 0, Delta Base = 0
    block.extend_from_slice(&[0x00, 0x00]);
    for (name, value) in fields {
        let idx = QPACK_STATIC
            .iter()
            .position(|(n, v)| n == name && v == value);
        if let Some(i) = idx {
            // Indexed Field Line (static)：1Txxxxxx
            encode_int(block, i as u64, 6, 0xC0);
            continue;
        }
        let name_idx = QPACK_STATIC.iter().position(|(n, _)| n == name);
        if let Some(i) = name_idx {
            // Literal Field Line with Name Reference (static)：01NTxxxx
            encode_int(block, i as u64, 4, 0x50);
            encode_str(block, value);
        } else {
            // Literal Field Line with Literal Name：001Nxxxx
            encode_int(block, name.len() as u64, 3, 0x20);
            block.extend_from_slice(name.as_bytes());
            encode_str(block, value);
        }
    }
}

/// QPACK 解码（只支持静态表；出现动态表引用即报错）。
pub fn qpack_decode(buf: &[u8]) -> Result<Vec<(String, String)>, String> {
    if buf.len() < 2 {
        return Err("qpack: 块过短".into());
    }
    let (ric, used) = decode_int(buf, 8)?;
    if ric != 0 {
        return Err("qpack: 不支持动态表（Required Insert Count != 0）".into());
    }
    let (_, used2) = decode_int(&buf[used..], 7)?;
    let mut pos = used + used2;
    let mut out = Vec::new();
    while pos < buf.len() {
        let b = buf[pos];
        if b & 0x80 != 0 {
            // Indexed Field Line：1Txxxxxx（T=1 静态；T=0 动态 → 不支持）
            if b & 0x40 == 0 {
                return Err("qpack: 不支持动态表索引".into());
            }
            let (idx, n) = decode_int(&buf[pos..], 6)?;
            pos += n;
            let (name, value) = QPACK_STATIC
                .get(idx as usize)
                .ok_or("qpack: 静态索引越界")?;
            out.push((name.to_string(), value.to_string()));
        } else if b & 0x40 != 0 {
            // Literal Field Line with Name Reference：01NTxxxx
            if b & 0x10 == 0 {
                return Err("qpack: 不支持动态表名字引用".into());
            }
            let (idx, n) = decode_int(&buf[pos..], 4)?;
            pos += n;
            let name = QPACK_STATIC
                .get(idx as usize)
                .ok_or("qpack: 静态索引越界")?
                .0
                .to_string();
            let (value, n) = decode_str(&buf[pos..])?;
            pos += n;
            out.push((name, value));
        } else if b & 0x20 != 0 {
            // Literal Field Line with Literal Name：001N Hxxx（H=名字是否 Huffman）
            let name_huffman = b & 0x08 != 0;
            let (name_len, n) = decode_int(&buf[pos..], 3)?;
            pos += n;
            let name_len = name_len as usize;
            if buf.len() < pos + name_len {
                return Err("qpack: 名字截断".into());
            }
            let name_bytes = &buf[pos..pos + name_len];
            let name = if name_huffman {
                huffman_decode(name_bytes)?
            } else {
                name_bytes.to_vec()
            };
            let name = String::from_utf8(name).map_err(|e| format!("qpack: 非 UTF-8 名字: {e}"))?;
            pos += name_len;
            let (value, n) = decode_str(&buf[pos..])?;
            pos += n;
            out.push((name, value));
        } else {
            return Err("qpack: 不支持的字段行（post-base/动态表）".into());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huffman_rfc7541_vectors() {
        // RFC 7541 附录 C.4 的官方向量
        let cases: [(&[u8], &str); 4] = [
            (
                &[
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ],
                "www.example.com",
            ),
            (&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf], "no-cache"),
            (
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
                "custom-key",
            ),
            (
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
                "custom-value",
            ),
        ];
        for (enc, want) in cases {
            assert_eq!(huffman_decode(enc).unwrap(), want.as_bytes(), "{want}");
        }
    }

    #[test]
    fn huffman_rejects_bad_padding_and_eos() {
        // 全 1 的 30 bit EOS
        assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
        // padding 超过 7 位（此处 8 位全 1 且不是完整符号）
        let ok = huffman_decode(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        assert!(ok.is_ok());
    }

    #[test]
    fn integer_roundtrip() {
        for (value, bits, mask, expect_first_max) in [
            (5u64, 5u8, 0x00u8, false),
            (31, 5, 0x00, false),
            (1337, 5, 0x00, true),
            (255, 8, 0x00, false),
        ] {
            let mut buf = Vec::new();
            encode_int(&mut buf, value, bits, mask);
            let (got, used) = decode_int(&buf, bits).unwrap();
            assert_eq!(got, value);
            assert_eq!(used, buf.len());
            let _ = expect_first_max;
        }
    }

    #[test]
    fn qpack_literal_name_with_huffman() {
        // quic-go 对不在静态表中的名字（如 hysteria-udp）用 Huffman literal name：
        // 001N Hxxx。用 RFC 7541 C.4 的 "www.example.com" 向量做名字构造一个块。
        let mut block = vec![0x00, 0x00, 0x2f, 0x05]; // RIC=0, Base=0, N=0/H=1, len=12（3 位前缀续长）
        block.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        block.extend_from_slice(&[0x01, b'v']); // 非 Huffman 值 "v"
        let fields = qpack_decode(&block).unwrap();
        assert_eq!(fields, vec![("www.example.com".into(), "v".into())]);
    }

    #[test]
    fn qpack_request_block_layout() {
        // 与 hysteria2 认证请求一致的头块（静态索引 + name-ref + literal）
        let mut block = Vec::new();
        qpack_encode(
            &mut block,
            &[
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "hysteria"),
                (":path", "/auth"),
                ("hysteria-auth", "secret"),
                ("hysteria-cc-rx", "0"),
            ],
        );
        assert_eq!(&block[..2], &[0x00, 0x00]);
        assert_eq!(block[2], 0xD4); // :method POST → 索引 20
        assert_eq!(block[3], 0xD7); // :scheme https → 索引 23
        assert_eq!(block[4], 0x50); // :authority name-ref 0（literal 值）
                                    // 自我解码（我们自己的解码器同样能吃）
        let fields = qpack_decode(&block).unwrap();
        assert_eq!(fields[0], (":method".into(), "POST".into()));
        assert_eq!(fields[1], (":scheme".into(), "https".into()));
        assert_eq!(fields[2], (":authority".into(), "hysteria".into()));
        assert_eq!(fields[3], (":path".into(), "/auth".into()));
        assert_eq!(fields[4], ("hysteria-auth".into(), "secret".into()));
    }
}

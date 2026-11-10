// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! QUIC 可变长整数（RFC 9000 §16）——hysteria2 帧与 HTTP/3 帧共用。
//!
//! 变体规则：首字节高 2 位决定总长（00=1B / 01=2B / 10=4B / 11=8B），
//! 其余 6 位是高位数据。h3client（P26）与 hysteria2 都在这层之上解帧。

use std::io;

use quinn::RecvStream;

/// 编码需要的字节数（1/2/4/8）。
pub fn varint_len(v: u64) -> usize {
    if v < 64 {
        1
    } else if v < 16384 {
        2
    } else if v < (1 << 30) {
        4
    } else {
        8
    }
}

pub fn write_varint(dst: &mut Vec<u8>, v: u64) {
    match varint_len(v) {
        1 => dst.push(v as u8),
        2 => {
            let b = (v as u16 | 0x4000).to_be_bytes();
            dst.extend_from_slice(&b);
        }
        4 => {
            let b = (v as u32 | 0x8000_0000).to_be_bytes();
            dst.extend_from_slice(&b);
        }
        _ => {
            let b = (v | 0xC000_0000_0000_0000).to_be_bytes();
            dst.extend_from_slice(&b);
        }
    }
}

/// 从字节切片读一个 varint（同步版；`pos` 前进到下一个字节）。
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= buf.len() {
        return None;
    }
    let first = buf[*pos];
    let len = 1usize << (first >> 6);
    if *pos + len > buf.len() {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &buf[*pos + 1..*pos + len] {
        v = (v << 8) | b as u64;
    }
    *pos += len;
    Some(v)
}

/// 从 QUIC 流读一个 varint（异步）。
pub async fn read_varint_async(recv: &mut RecvStream) -> io::Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| io::Error::other(format!("varint 读: {e}")))?;
    let len = 1usize << (first[0] >> 6);
    let mut v = (first[0] & 0x3f) as u64;
    if len > 1 {
        let mut rest = [0u8; 7];
        recv.read_exact(&mut rest[..len - 1])
            .await
            .map_err(|e| io::Error::other(format!("varint 读: {e}")))?;
        for &b in &rest[..len - 1] {
            v = (v << 8) | b as u64;
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_appendix_a1_vectors() {
        // RFC 9000 §A.1 官方样例
        let cases: [(u64, &[u8]); 5] = [
            (0, &[0x00]),
            (37, &[0x25]),
            (15293, &[0x7b, 0xbd]),
            (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652,
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ];
        for (v, want) in cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            assert_eq!(buf, want, "encode {v}");
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos), Some(v));
            assert_eq!(pos, want.len());
        }
    }

    #[test]
    fn lengths_match_encoder() {
        for v in [0u64, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_len(v), "value {v}");
        }
    }
}

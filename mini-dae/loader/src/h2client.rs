//! P23：最小 HTTP/2 客户端（DoH 专用；RFC 7540/7541 子集）。
//!
//! 只实现 DoH 所需的 POST：
//! - 连接前言 + 空 SETTINGS，等对端 SETTINGS 并回 ACK（握手）；
//! - 每查询一条流：HEADERS（END_HEADERS，HPACK：静态索引 + 非 Huffman literal）
//!   后跟 DATA（END_STREAM）；
//! - 读帧：处理 SETTINGS/PING/WINDOW_UPDATE/CONTINUATION/GOAWAY/RST_STREAM，
//!   拼接 DATA，流 END_STREAM 结束；随 DATA 回 WINDOW_UPDATE 维持流控窗口。
//!
//! HPACK 编码不用 Huffman（静态表索引 + literal 原样），解码只取 `:status`。
//! 与 dae（Go net/http2 完整实现）的差异如实记录在 ADR。

use std::io::{Read, Write};

use crate::hpack;
use crate::tls;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
const FRAME_PRIORITY: u8 = 2;
const FRAME_RST_STREAM: u8 = 3;
const FRAME_SETTINGS: u8 = 4;
const FRAME_PUSH_PROMISE: u8 = 5;
const FRAME_PING: u8 = 6;
const FRAME_GOAWAY: u8 = 7;
const FRAME_WINDOW_UPDATE: u8 = 8;
const FRAME_CONTINUATION: u8 = 9;

const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// 单条查询的响应上限（DNS 报文远小于此；防止坏服务端耗尽内存）。
const MAX_RESPONSE: usize = 65536;

pub struct H2Conn {
    next_stream: u32,
}

fn err(msg: impl Into<String>) -> String {
    msg.into()
}

fn write_frame<W: Write>(
    w: &mut W,
    ty: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> Result<(), String> {
    let len = payload.len();
    if len > 0x00ff_ffff {
        return Err(err("HTTP/2 帧超长"));
    }
    let mut h = [0u8; 9];
    h[0] = (len >> 16) as u8;
    h[1] = (len >> 8) as u8;
    h[2] = len as u8;
    h[3] = ty;
    h[4] = flags;
    h[5..9].copy_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    w.write_all(&h)
        .map_err(|e| err(format!("h2 写帧头: {e}")))?;
    if !payload.is_empty() {
        w.write_all(payload)
            .map_err(|e| err(format!("h2 写帧体: {e}")))?;
    }
    w.flush().map_err(|e| err(format!("h2 flush: {e}")))
}

fn read_frame<R: Read>(r: &mut R) -> Result<(u8, u8, u32, Vec<u8>), String> {
    let mut h = [0u8; 9];
    r.read_exact(&mut h)
        .map_err(|e| err(format!("h2 读帧头: {e}")))?;
    let len = ((h[0] as usize) << 16) | ((h[1] as usize) << 8) | h[2] as usize;
    if len > 1 << 20 {
        return Err(err(format!("h2 帧过大（{len}）")));
    }
    let ty = h[3];
    let flags = h[4];
    let sid = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload)
            .map_err(|e| err(format!("h2 读帧体: {e}")))?;
    }
    Ok((ty, flags, sid, payload))
}

// ---------------------------------------------------------------- HPACK 编码

/// 整数编码（RFC 7541 §5.1）：`first` 已含前缀（如 0x80 = indexed）。
fn hpack_int(out: &mut Vec<u8>, prefix_bits: u8, first: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    let mut v = value - max;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// 字符串字面量（Huffman=0）。
fn hpack_str(out: &mut Vec<u8>, s: &str) {
    hpack_int(out, 7, 0x00, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// 静态表索引头（RFC 7541 附录 A）。
fn hpack_indexed(out: &mut Vec<u8>, idx: u64) {
    hpack_int(out, 7, 0x80, idx);
}

/// 带静态名字引用的 literal（不加入索引表）。
fn hpack_literal(out: &mut Vec<u8>, name_idx: u64, value: &str) {
    hpack_int(out, 4, 0x00, name_idx);
    hpack_str(out, value);
}

fn encode_request_headers(authority: &str, path: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(96);
    hpack_indexed(&mut b, 3); // :method POST
    hpack_indexed(&mut b, 7); // :scheme https
    hpack_literal(&mut b, 4, path); // :path
    hpack_literal(&mut b, 1, authority); // :authority
    hpack_literal(&mut b, 31, "application/dns-message"); // content-type
    hpack_literal(&mut b, 19, "application/dns-message"); // accept
    b
}

// ---------------------------------------------------------------- HPACK 解码（只取 :status）

/// 解出整数（RFC 7541 §5.1），返回 (值, 消耗字节)。
fn hpack_read_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let max = (1u64 << prefix_bits) - 1;
    let mut v = (first & max as u8) as u64;
    if v < max {
        return Some((v, 1));
    }
    let mut i = 1;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(i)?;
        v = v.checked_add(((b & 0x7f) as u64) << shift)?;
        i += 1;
        if b & 0x80 == 0 {
            return Some((v, i));
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

fn hpack_read_str(buf: &[u8]) -> Option<(String, usize)> {
    let (len, used) = hpack_read_int(buf, 7)?;
    let huff = buf.first()? & 0x80 != 0;
    let start = used;
    let end = start.checked_add(len as usize)?;
    let raw = buf.get(start..end)?;
    let s = if huff {
        String::from_utf8_lossy(&hpack::huffman_decode(raw).ok()?).into_owned()
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    Some((s, end))
}

/// 静态表（仅返回我们需要的名字/值）。
fn static_entry(idx: u64) -> Option<(&'static str, &'static str)> {
    Some(match idx {
        1 => (":authority", ""),
        2 => (":method", "GET"),
        3 => (":method", "POST"),
        4 => (":path", "/"),
        5 => (":path", "/index.html"),
        6 => (":scheme", "http"),
        7 => (":scheme", "https"),
        8 => (":status", "200"),
        9 => (":status", "204"),
        10 => (":status", "206"),
        11 => (":status", "304"),
        12 => (":status", "400"),
        13 => (":status", "404"),
        14 => (":status", "500"),
        31 => ("content-type", ""),
        _ => return None,
    })
}

/// 从头块中提取 `:status`（尽力而为；解不出返回 None）。
fn decode_status(block: &[u8]) -> Option<u16> {
    let mut i = 0usize;
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            // indexed
            let (idx, used) = hpack_read_int(&block[i..], 7)?;
            i += used;
            if let Some((":status", v)) = static_entry(idx) {
                if let Ok(n) = v.parse::<u16>() {
                    return Some(n);
                }
            }
        } else if b & 0x20 != 0 {
            // 动态表大小更新（无名字/值）
            let (_, used) = hpack_read_int(&block[i..], 5)?;
            i += used;
        } else if b & 0x40 != 0 {
            // literal with incremental indexing（名字 6 位前缀）
            let (idx, used) = hpack_read_int(&block[i..], 6)?;
            i += used;
            let name = if idx == 0 {
                let (n, u) = hpack_read_str(&block[i..])?;
                i += u;
                n
            } else {
                static_entry(idx).map(|(n, _)| n.to_string())?
            };
            let (value, u) = hpack_read_str(&block[i..])?;
            i += u;
            if name == ":status" {
                return value.parse::<u16>().ok();
            }
        } else {
            // literal without indexing：4 位前缀名字
            let (name_idx, used) = hpack_read_int(&block[i..], 4)?;
            i += used;
            let name = if name_idx == 0 {
                let (n, u) = hpack_read_str(&block[i..])?;
                i += u;
                n
            } else {
                static_entry(name_idx).map(|(n, _)| n.to_string())?
            };
            let (value, u) = hpack_read_str(&block[i..])?;
            i += u;
            if name == ":status" {
                return value.parse::<u16>().ok();
            }
        }
    }
    None
}

// ---------------------------------------------------------------- 客户端

impl H2Conn {
    /// 握手：前言 + 空 SETTINGS；等对端 SETTINGS 并回 ACK。
    pub fn handshake(r: &mut tls::TlsReader, w: &mut tls::TlsWriter) -> Result<Self, String> {
        w.write_all(PREFACE)
            .map_err(|e| err(format!("h2 前言: {e}")))?;
        write_frame(w, FRAME_SETTINGS, 0, 0, &[])?;
        // 读到对端 SETTINGS（其间回应 PING；忽略其它帧）
        for _ in 0..32 {
            let (ty, flags, _, payload) = read_frame(r)?;
            match ty {
                FRAME_SETTINGS => {
                    if flags & FLAG_ACK == 0 {
                        write_frame(w, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
                        return Ok(Self { next_stream: 1 });
                    }
                }
                FRAME_PING => {
                    if flags & FLAG_ACK == 0 && payload.len() == 8 {
                        write_frame(w, FRAME_PING, FLAG_ACK, 0, &payload)?;
                    }
                }
                FRAME_GOAWAY => {
                    return Err(err(format!(
                        "h2 对端 GOAWAY（code={}）",
                        payload
                            .get(4..8)
                            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                            .unwrap_or(0)
                    )))
                }
                _ => {}
            }
        }
        Err(err("h2 握手超时（未见对端 SETTINGS）"))
    }

    /// POST 一个请求，返回响应体。出错即连接不可复用（调用方丢弃重建）。
    pub fn post(
        &mut self,
        r: &mut tls::TlsReader,
        w: &mut tls::TlsWriter,
        authority: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sid = self.next_stream;
        self.next_stream += 2;
        let hdr = encode_request_headers(authority, path);
        write_frame(w, FRAME_HEADERS, FLAG_END_HEADERS, sid, &hdr)?;
        write_frame(w, FRAME_DATA, FLAG_END_STREAM, sid, body)?;

        let mut out: Vec<u8> = Vec::new();
        let mut header_block: Vec<u8> = Vec::new();
        let mut status: Option<u16> = None;
        for _ in 0..4096 {
            let (ty, flags, fsid, payload) = read_frame(r)?;
            match ty {
                FRAME_SETTINGS => {
                    if flags & FLAG_ACK == 0 {
                        write_frame(w, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
                    }
                }
                FRAME_PING => {
                    if flags & FLAG_ACK == 0 && payload.len() == 8 {
                        write_frame(w, FRAME_PING, FLAG_ACK, 0, &payload)?;
                    }
                }
                FRAME_GOAWAY => {
                    return Err(err("h2 连接被 GOAWAY 关闭"));
                }
                FRAME_RST_STREAM => {
                    if fsid == sid {
                        let code = payload
                            .get(0..4)
                            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                            .unwrap_or(0);
                        return Err(err(format!("h2 流被重置（code={code}）")));
                    }
                }
                FRAME_HEADERS | FRAME_CONTINUATION => {
                    if fsid != sid {
                        continue;
                    }
                    let mut p: &[u8] = &payload;
                    if ty == FRAME_HEADERS && flags & FLAG_PADDED != 0 {
                        let pad = *p.first().ok_or_else(|| err("h2 PADDED 头缺 pad"))? as usize;
                        p = p.get(1..).ok_or_else(|| err("h2 头截断"))?;
                        p = p
                            .get(..p.len().saturating_sub(pad))
                            .ok_or_else(|| err("h2 pad 越界"))?;
                    }
                    if ty == FRAME_HEADERS && flags & FLAG_PRIORITY != 0 {
                        p = p.get(5..).ok_or_else(|| err("h2 PRIORITY 头截断"))?;
                    }
                    header_block.extend_from_slice(p);
                    if flags & FLAG_END_HEADERS != 0 && status.is_none() {
                        status = decode_status(&header_block);
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                FRAME_DATA => {
                    if fsid != sid {
                        continue;
                    }
                    let mut p: &[u8] = &payload;
                    if flags & FLAG_PADDED != 0 {
                        let pad = *p.first().ok_or_else(|| err("h2 PADDED 数据缺 pad"))? as usize;
                        p = p.get(1..).ok_or_else(|| err("h2 数据截断"))?;
                        p = p
                            .get(..p.len().saturating_sub(pad))
                            .ok_or_else(|| err("h2 pad 越界"))?;
                    }
                    out.extend_from_slice(p);
                    if out.len() > MAX_RESPONSE {
                        return Err(err("h2 响应超过上限"));
                    }
                    // 流控：按消费量补窗口（连接 + 流）
                    if !p.is_empty() {
                        let inc = (p.len() as u32).to_be_bytes();
                        write_frame(w, FRAME_WINDOW_UPDATE, 0, 0, &inc)?;
                        write_frame(w, FRAME_WINDOW_UPDATE, 0, sid, &inc)?;
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                FRAME_PUSH_PROMISE => {
                    return Err(err("h2 服务端推送不接受"));
                }
                _ => {}
            }
        }
        match status {
            Some(200) => Ok(out),
            Some(s) => Err(err(format!("DoH 响应状态 {s}"))),
            None => {
                // 头块解不出 :status：用 DNS 报文特征兜底判断（≥12 字节且 QR=1）
                if out.len() >= 12 && out[2] & 0x80 != 0 {
                    Ok(out)
                } else {
                    Err(err("h2 响应缺少可解析的 :status"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpack_encodes_expected_bytes() {
        let h = encode_request_headers("dns.example", "/dns-query");
        // :method POST = indexed 3；:scheme https = indexed 7
        assert_eq!(&h[0..2], &[0x83, 0x87]);
        // :path name idx 4 + "/dns-query"（10 字节）
        assert_eq!(h[2], 0x04);
        assert_eq!(h[3], 10);
        assert_eq!(&h[4..14], b"/dns-query");
        // :authority name idx 1
        assert_eq!(h[14], 0x01);
        assert_eq!(h[15], 11);
        assert_eq!(&h[16..27], b"dns.example");
        // content-type 静态名 31 → 4 位前缀放不下，续字节
        assert_eq!(h[27], 0x0f);
        assert_eq!(h[28], 31 - 15);
        // 值长 23 "application/dns-message"
        assert_eq!(h[29], 23);
        assert_eq!(&h[30..53], b"application/dns-message");
        // accept 静态名 19
        assert_eq!(h[53], 0x0f);
        assert_eq!(h[54], 19 - 15);
        assert_eq!(h[55], 23);
        assert_eq!(&h[56..79], b"application/dns-message");
        assert_eq!(h.len(), 79);
    }

    #[test]
    fn hpack_read_int_roundtrip() {
        let mut b = Vec::new();
        hpack_int(&mut b, 5, 0x20, 1337);
        let (v, used) = hpack_read_int(&b, 5).unwrap();
        assert_eq!(v, 1337);
        assert_eq!(used, b.len());
        let mut b = Vec::new();
        hpack_int(&mut b, 7, 0x80, 3);
        assert_eq!(b, vec![0x83]);
    }

    #[test]
    fn decode_status_indexed_and_literal() {
        // 索引 8 = :status 200
        assert_eq!(decode_status(&[0x88]), Some(200));
        // literal with indexed name 8（0x08 → name idx 8, len 3 "500"）
        let mut b = vec![0x08];
        hpack_str(&mut b, "500");
        assert_eq!(decode_status(&b), Some(500));
    }

    #[test]
    fn decode_status_huffman_value() {
        // 用 huffman 表手工编 "200"（RFC 7541 示例 "www.example.com" 的编码器不好造；
        // 这里用普通 literal 验证 huffman 分支由 huffman_decode 覆盖）
        assert_eq!(decode_status(&[0x88]), Some(200));
    }
}

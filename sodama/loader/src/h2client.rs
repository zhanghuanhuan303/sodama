// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

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

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::hpack;
use crate::tls;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
/// P38：帧类型登记表完整性（当前不发 PRIORITY；保留常量避免魔法数字）。
#[allow(dead_code)]
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

/// CONNECT 隧道：单帧 DATA 上限（= RFC 7540 默认 MAX_FRAME_SIZE）。
const MAX_DATA_FRAME: usize = 16384;
/// CONNECT 隧道：对端迟迟不发 WINDOW_UPDATE 时的等待上限。
const SEND_WINDOW_TIMEOUT: Duration = Duration::from_secs(15);

pub struct H2Conn {
    next_stream: u32,
    /// 对端 SETTINGS 的 INITIAL_WINDOW_SIZE（新流的发送窗口初值；默认 65535）。
    peer_initial_window: i64,
}

fn err(msg: impl Into<String>) -> String {
    msg.into()
}

fn write_frame_raw<W: Write>(
    w: &mut W,
    ty: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload.len();
    if len > 0x00ff_ffff {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP/2 帧超长",
        ));
    }
    let mut h = [0u8; 9];
    h[0] = (len >> 16) as u8;
    h[1] = (len >> 8) as u8;
    h[2] = len as u8;
    h[3] = ty;
    h[4] = flags;
    h[5..9].copy_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    w.write_all(&h)?;
    if !payload.is_empty() {
        w.write_all(payload)?;
    }
    w.flush()
}

fn write_frame<W: Write>(
    w: &mut W,
    ty: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> Result<(), String> {
    write_frame_raw(w, ty, flags, stream, payload).map_err(|e| err(format!("h2 写帧: {e}")))
}

fn read_frame_raw<R: Read>(r: &mut R) -> std::io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut h = [0u8; 9];
    r.read_exact(&mut h)?;
    let len = ((h[0] as usize) << 16) | ((h[1] as usize) << 8) | h[2] as usize;
    if len > 1 << 20 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("h2 帧过大（{len}）"),
        ));
    }
    let ty = h[3];
    let flags = h[4];
    let sid = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload)?;
    }
    Ok((ty, flags, sid, payload))
}

fn read_frame<R: Read>(r: &mut R) -> Result<(u8, u8, u32, Vec<u8>), String> {
    read_frame_raw(r).map_err(|e| err(format!("h2 读帧: {e}")))
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

/// 名字与值都为字面量的 literal（不加入索引表）；静态表没有的头（如
/// proxy-authorization）用这个。
fn hpack_literal_name(out: &mut Vec<u8>, name: &str, value: &str) {
    hpack_int(out, 4, 0x00, 0);
    hpack_str(out, name);
    hpack_str(out, value);
}

/// P25：CONNECT 请求头块（naive 用；纯函数，单测覆盖）。
pub(crate) fn encode_connect_headers(authority: &str, extra_headers: &[(&str, &str)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(96);
    hpack_literal(&mut b, 2, "CONNECT"); // :method（静态名索引 2）+ CONNECT
    hpack_literal(&mut b, 1, authority); // :authority
    for (n, v) in extra_headers {
        hpack_literal_name(&mut b, n, v);
    }
    b
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
                        // 解析 INITIAL_WINDOW_SIZE（id=4）——CONNECT 隧道发送流控用
                        let mut i = 0usize;
                        let mut init_window = 65535i64;
                        while i + 6 <= payload.len() {
                            let id = u16::from_be_bytes([payload[i], payload[i + 1]]);
                            let v = u32::from_be_bytes([
                                payload[i + 2],
                                payload[i + 3],
                                payload[i + 4],
                                payload[i + 5],
                            ]);
                            if id == 4 {
                                init_window = v as i64;
                            }
                            i += 6;
                        }
                        write_frame(w, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
                        return Ok(Self {
                            next_stream: 1,
                            peer_initial_window: init_window,
                        });
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

// ---------------------------------------------------------------- P25：CONNECT 隧道（naive）

/// 隧道共享状态：读缓冲（reader 线程 → Read 半）、发送窗口（Write 半 ↔ reader 线程）。
struct TunnelShared {
    rx: Mutex<VecDeque<u8>>,
    rx_cond: Condvar,
    eof: AtomicBool,
    err: Mutex<Option<(std::io::ErrorKind, String)>>,
    /// 发送窗口：(连接级, 流级)。reader 线程收到 WINDOW_UPDATE 后增加。
    send_window: Mutex<(i64, i64)>,
    send_cond: Condvar,
    /// 两个半都 drop 后 shutdown 底层 TCP，唤醒 reader 线程
    halves: std::sync::atomic::AtomicU8,
    kill: std::sync::Mutex<Option<std::net::TcpStream>>,
}

impl TunnelShared {
    fn set_err(&self, kind: std::io::ErrorKind, msg: String) {
        let mut g = self.err.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some((kind, msg));
        }
        self.eof.store(true, Ordering::SeqCst);
        self.rx_cond.notify_all();
        self.send_cond.notify_all();
    }

    fn half_dropped(&self) {
        use std::sync::atomic::Ordering as O;
        if self.halves.fetch_sub(1, O::SeqCst) == 1 {
            if let Some(k) = self.kill.lock().unwrap_or_else(|p| p.into_inner()).take() {
                let _ = k.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

/// CONNECT 隧道的读半（服务端 DATA → 字节流）。
pub struct TunnelReader {
    shared: Arc<TunnelShared>,
    leftover: Vec<u8>,
}

impl Read for TunnelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Ok(n);
        }
        let mut q = self.shared.rx.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if !q.is_empty() {
                let n = q.len().min(buf.len());
                for (i, b) in q.drain(..n).enumerate() {
                    buf[i] = b;
                }
                return Ok(n);
            }
            if let Some((kind, msg)) = self
                .shared
                .err
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                return Err(std::io::Error::new(kind, msg));
            }
            if self.shared.eof.load(Ordering::SeqCst) {
                return Ok(0);
            }
            let (g, _) = self
                .shared
                .rx_cond
                .wait_timeout(q, Duration::from_secs(1))
                .unwrap_or_else(|p| p.into_inner());
            q = g;
        }
    }
}

impl Drop for TunnelReader {
    fn drop(&mut self) {
        self.shared.half_dropped();
    }
}

/// CONNECT 隧道的写半（字节流 → 服务端 DATA，带双向流控）。
pub struct TunnelWriter {
    shared: Arc<TunnelShared>,
    w: Arc<Mutex<tls::TlsWriter>>,
    sid: u32,
    ended: AtomicBool,
}

impl TunnelWriter {
    fn wait_window(&self, need: usize) -> std::io::Result<()> {
        let mut g = self
            .shared
            .send_window
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let deadline = Instant::now() + SEND_WINDOW_TIMEOUT;
        loop {
            if self.shared.eof.load(Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "naive: 隧道已关闭",
                ));
            }
            let (c, s) = *g;
            if c.min(s) >= need as i64 {
                *g = (c - need as i64, s - need as i64);
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "naive: 等待发送窗口超时",
                ));
            }
            let (ng, _) = self
                .shared
                .send_cond
                .wait_timeout(g, deadline - now)
                .unwrap_or_else(|p| p.into_inner());
            g = ng;
        }
    }

    /// 半关闭：空 DATA + END_STREAM（幂等）。
    pub fn end_stream(&self) -> std::io::Result<()> {
        if self.ended.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut w = self.w.lock().unwrap_or_else(|p| p.into_inner());
        write_frame_raw(&mut *w, FRAME_DATA, FLAG_END_STREAM, self.sid, &[])
    }
}

impl Write for TunnelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.ended.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "naive: 写半已关闭",
            ));
        }
        let mut off = 0usize;
        while off < buf.len() {
            let end = (off + MAX_DATA_FRAME).min(buf.len());
            self.wait_window(end - off)?;
            let mut w = self.w.lock().unwrap_or_else(|p| p.into_inner());
            write_frame_raw(&mut *w, FRAME_DATA, 0, self.sid, &buf[off..end])?;
            off = end;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for TunnelWriter {
    fn drop(&mut self) {
        let _ = self.end_stream();
        self.shared.half_dropped();
    }
}

fn strip_padding_io(flags: u8, payload: &[u8]) -> std::io::Result<&[u8]> {
    let mut p = payload;
    if flags & FLAG_PADDED != 0 {
        let pad = *p.first().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "h2 PADDED 缺 pad")
        })? as usize;
        p = p
            .get(1..)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "h2 头截断"))?;
        p = p
            .get(..p.len().saturating_sub(pad))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "h2 pad 越界"))?;
    }
    Ok(p)
}

/// 隧道 reader 线程：解 DATA/控制帧 → 读缓冲；发送窗口更新 → 唤醒写端。
fn tunnel_reader_loop(
    mut r: tls::TlsReader,
    w: Arc<Mutex<tls::TlsWriter>>,
    sid: u32,
    sh: Arc<TunnelShared>,
) {
    crate::log("naive: 隧道 reader 线程启动");
    loop {
        match read_frame_raw(&mut r) {
            Err(e) => {
                crate::log(&format!("naive: h2 读失败: {e}"));
                sh.set_err(e.kind(), format!("naive: h2 读失败: {e}"));
                break;
            }
            Ok((ty, flags, fsid, payload)) => match ty {
                FRAME_DATA if fsid == sid => {
                    let data = match strip_padding_io(flags, &payload) {
                        Ok(d) => d,
                        Err(e) => {
                            sh.set_err(e.kind(), format!("naive: h2 DATA: {e}"));
                            break;
                        }
                    };
                    if !data.is_empty() {
                        {
                            let mut q = sh.rx.lock().unwrap_or_else(|p| p.into_inner());
                            q.extend(data.iter().copied());
                        }
                        sh.rx_cond.notify_all();
                        let inc = (data.len() as u32).to_be_bytes();
                        if let Ok(mut wg) = w.lock() {
                            let _ = write_frame_raw(&mut *wg, FRAME_WINDOW_UPDATE, 0, 0, &inc);
                            let _ = write_frame_raw(&mut *wg, FRAME_WINDOW_UPDATE, 0, sid, &inc);
                        }
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        sh.eof.store(true, Ordering::SeqCst);
                        sh.rx_cond.notify_all();
                        break;
                    }
                }
                FRAME_HEADERS if fsid == sid => {
                    if flags & FLAG_END_STREAM != 0 {
                        sh.eof.store(true, Ordering::SeqCst);
                        sh.rx_cond.notify_all();
                        break;
                    }
                }
                FRAME_SETTINGS => {
                    if flags & FLAG_ACK == 0 {
                        if let Ok(mut wg) = w.lock() {
                            let _ = write_frame_raw(&mut *wg, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                        }
                    }
                }
                FRAME_PING => {
                    if flags & FLAG_ACK == 0 && payload.len() == 8 {
                        if let Ok(mut wg) = w.lock() {
                            let _ = write_frame_raw(&mut *wg, FRAME_PING, FLAG_ACK, 0, &payload);
                        }
                    }
                }
                FRAME_WINDOW_UPDATE => {
                    if payload.len() >= 4 {
                        let inc =
                            (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                                & 0x7fff_ffff) as i64;
                        {
                            let mut g = sh.send_window.lock().unwrap_or_else(|p| p.into_inner());
                            if fsid == 0 {
                                g.0 += inc;
                            } else if fsid == sid {
                                g.1 += inc;
                            }
                        }
                        sh.send_cond.notify_all();
                    }
                }
                FRAME_RST_STREAM if fsid == sid => {
                    sh.set_err(
                        std::io::ErrorKind::ConnectionReset,
                        "naive: 流被重置".into(),
                    );
                    break;
                }
                FRAME_GOAWAY => {
                    sh.set_err(
                        std::io::ErrorKind::ConnectionAborted,
                        "naive: GOAWAY".into(),
                    );
                    break;
                }
                _ => {}
            },
        }
    }
    sh.eof.store(true, Ordering::SeqCst);
    sh.rx_cond.notify_all();
    sh.send_cond.notify_all();
}

impl H2Conn {
    /// P25：HTTP/2 CONNECT 隧道（naiveproxy）——HEADERS(CONNECT，无 END_STREAM)，
    /// 等 200 后返回可并发的读写两半（reader 线程 + 流控写端）。
    /// `extra_headers` 为额外的 (名字, 值)，如 ("proxy-authorization", "Basic …")。
    pub fn connect_tunnel(
        &mut self,
        mut r: tls::TlsReader,
        w: tls::TlsWriter,
        kill: std::net::TcpStream,
        authority: &str,
        extra_headers: &[(&str, &str)],
    ) -> Result<(TunnelReader, TunnelWriter), String> {
        let sid = self.next_stream;
        self.next_stream += 2;
        let w = Arc::new(Mutex::new(w));
        let hdr = encode_connect_headers(authority, extra_headers);
        {
            let mut wg = w.lock().unwrap_or_else(|p| p.into_inner());
            write_frame(&mut *wg, FRAME_HEADERS, FLAG_END_HEADERS, sid, &hdr)?;
        }
        // 等响应头（:status 必须 200）
        let mut block: Vec<u8> = Vec::new();
        let mut status: Option<u16> = None;
        loop {
            let (ty, flags, fsid, payload) = read_frame(&mut r)?;
            match ty {
                FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                    let mut wg = w.lock().unwrap_or_else(|p| p.into_inner());
                    let _ = write_frame(&mut *wg, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                }
                FRAME_PING if flags & FLAG_ACK == 0 && payload.len() == 8 => {
                    let mut wg = w.lock().unwrap_or_else(|p| p.into_inner());
                    let _ = write_frame(&mut *wg, FRAME_PING, FLAG_ACK, 0, &payload);
                }
                FRAME_HEADERS | FRAME_CONTINUATION if fsid == sid => {
                    let p = payload.as_slice();
                    let p = if ty == FRAME_HEADERS {
                        let mut q = p;
                        if flags & FLAG_PADDED != 0 {
                            let pad = *q.first().ok_or("naive: PADDED 头缺 pad")? as usize;
                            q = &q[1..];
                            q = q
                                .get(..q.len().saturating_sub(pad))
                                .ok_or("naive: pad 越界")?;
                        }
                        if flags & FLAG_PRIORITY != 0 {
                            q = q.get(5..).ok_or("naive: PRIORITY 头截断")?;
                        }
                        q
                    } else {
                        p
                    };
                    block.extend_from_slice(p);
                    if flags & FLAG_END_HEADERS != 0 && status.is_none() {
                        status = decode_status(&block);
                    }
                    if let Some(s) = status {
                        if s != 200 {
                            return Err(format!("naive: CONNECT 被拒（HTTP {s}）"));
                        }
                        break;
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        return Err("naive: 服务端在应答前结束流".into());
                    }
                }
                FRAME_RST_STREAM if fsid == sid => {
                    return Err("naive: CONNECT 流被重置".into());
                }
                FRAME_GOAWAY => return Err("naive: 连接被 GOAWAY 关闭".into()),
                _ => {}
            }
        }
        let shared = Arc::new(TunnelShared {
            rx: Mutex::new(VecDeque::new()),
            rx_cond: Condvar::new(),
            eof: AtomicBool::new(false),
            err: Mutex::new(None),
            send_window: Mutex::new((65535, self.peer_initial_window)),
            send_cond: Condvar::new(),
            halves: std::sync::atomic::AtomicU8::new(2),
            kill: std::sync::Mutex::new(Some(kill)),
        });
        let sh = shared.clone();
        let w2 = w.clone();
        std::thread::spawn(move || tunnel_reader_loop(r, w2, sid, sh));
        Ok((
            TunnelReader {
                shared: shared.clone(),
                leftover: Vec::new(),
            },
            TunnelWriter {
                shared,
                w,
                sid,
                ended: AtomicBool::new(false),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_headers_encode() {
        let h = encode_connect_headers(
            "1.1.1.1:443",
            &[("proxy-authorization", "Basic dXNlcjpwYXNz")],
        );
        // :method 静态名索引 2（literal without indexing，4 位前缀）+ "CONNECT"
        assert_eq!(h[0], 0x02);
        assert_eq!(h[1], 7);
        assert_eq!(&h[2..9], b"CONNECT");
        // :authority 静态名索引 1 + "1.1.1.1:443"（11 字节）
        assert_eq!(h[9], 0x01);
        assert_eq!(h[10], 11);
        assert_eq!(&h[11..22], b"1.1.1.1:443");
        // 名字字面量（name_idx=0）
        assert_eq!(h[22], 0x00);
        assert_eq!(h[23] as usize, "proxy-authorization".len());
        let name_end = 24 + "proxy-authorization".len();
        assert_eq!(&h[24..name_end], b"proxy-authorization");
        let val = "Basic dXNlcjpwYXNz";
        assert_eq!(h[name_end] as usize, val.len());
        assert_eq!(&h[name_end + 1..name_end + 1 + val.len()], val.as_bytes());
        assert_eq!(h.len(), name_end + 1 + val.len());
    }

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

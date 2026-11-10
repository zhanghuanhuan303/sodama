// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! P26：最小 HTTP/3 客户端（RFC 9114）——DoH over H3 与 `naive+quic://` CONNECT 共用。
//!
//! 分层（与 `h2client.rs` 对称）：
//! - 控制流：type 0x00 + SETTINGS(0x04, len 0)（保持打开）；
//! - 请求流：HEADERS(0x01) + QPACK 块（静态表/字面量，见 `hpack::qpack_encode`）；
//! - `request()`：普通请求（HEADERS + DATA + FIN → 读 HEADERS/DATA 直到 FIN），DoH 用；
//! - `connect_tunnel()`：CONNECT（` :method` + `:authority`，无 `:scheme`/`:path`），
//!   2xx 后返回隧道读写半——DATA 帧承载隧道字节（RFC 9114 §4.4），流控由 QUIC 负责。
//!
//! 边界：响应头只解静态表（动态表引用报错，与 QPACK 编码器同源）；不开 QPACK
//! encoder/decoder 单向流；不做 0-RTT/服务端推送/GOAWAY 重试。

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::{RecvStream, SendStream};

use crate::hpack::{qpack_decode, qpack_encode};
use crate::quicvarint::{read_varint_async, write_varint};

const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;
/// 写出时的 DATA 帧切块上限（与 h2 隧道一致）
const MAX_DATA_FRAME: usize = 16384;
/// `request()` 响应体上限（DoH 查询很小；上限防跑飞）
const MAX_BODY: usize = 256 * 1024;

fn rt() -> &'static tokio::runtime::Runtime {
    crate::tuic::runtime()
}

fn map_err(ctx: &str, e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("h3 {ctx}: {e}"))
}

fn encode_data_frame(dst: &mut Vec<u8>, payload: &[u8]) {
    write_varint(dst, FRAME_DATA);
    write_varint(dst, payload.len() as u64);
    dst.extend_from_slice(payload);
}

async fn skip_frame(recv: &mut RecvStream, len: u64) -> io::Result<()> {
    let mut left = len;
    let mut buf = [0u8; 4096];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        recv.read_exact(&mut buf[..want])
            .await
            .map_err(|e| map_err("帧跳过", e))?;
        left -= want as u64;
    }
    Ok(())
}

struct H3Shared {
    conn: quinn::Connection,
    /// 控制流：SETTINGS 后保持打开（关闭会被服务端视为关键流关闭）。
    _control: Mutex<Option<SendStream>>,
    /// 持有 endpoint 句柄，保证隧道两半存活期间连接不被驱动回收。
    _ep: quinn::Endpoint,
}

/// 一条 HTTP/3 连接（调用方负责 QUIC 建连与 ALPN=h3）。
pub struct H3Conn {
    shared: Arc<H3Shared>,
}

impl H3Conn {
    /// 开控制流并发送空 SETTINGS。
    pub fn new(conn: quinn::Connection, ep: quinn::Endpoint) -> io::Result<Self> {
        let shared = rt().block_on(async {
            let mut uni = conn
                .open_uni()
                .await
                .map_err(|e| map_err("control 流", e))?;
            uni.write_all(&[0x00, FRAME_SETTINGS as u8, 0x00])
                .await
                .map_err(|e| map_err("SETTINGS 写", e))?;
            Ok::<_, io::Error>(H3Shared {
                conn,
                _control: Mutex::new(Some(uni)),
                _ep: ep,
            })
        })?;
        Ok(Self {
            shared: Arc::new(shared),
        })
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.shared.conn
    }

    /// 单次请求：HEADERS + DATA(body) + FIN，读响应直到流结束。
    /// 返回 `(status, 响应头, 响应体)`。
    pub fn request(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        let conn = self.shared.conn.clone();
        rt().block_on(async {
            let fut = async {
                let (mut send, mut recv) =
                    conn.open_bi().await.map_err(|e| map_err("请求流", e))?;
                let mut block = Vec::new();
                {
                    let mut fields: Vec<(&str, &str)> = Vec::with_capacity(4 + headers.len());
                    fields.push((":method", method));
                    fields.push((":scheme", scheme));
                    fields.push((":authority", authority));
                    fields.push((":path", path));
                    fields.extend_from_slice(headers);
                    qpack_encode(&mut block, &fields);
                }
                let mut out = Vec::with_capacity(block.len() + body.len() + 20);
                write_varint(&mut out, FRAME_HEADERS);
                write_varint(&mut out, block.len() as u64);
                out.extend_from_slice(&block);
                encode_data_frame(&mut out, body);
                send.write_all(&out)
                    .await
                    .map_err(|e| map_err("请求写", e))?;
                send.finish().map_err(|e| map_err("请求 FIN", e))?;

                let mut status: Option<u16> = None;
                let mut fields_out: Vec<(String, String)> = Vec::new();
                let mut body_out: Vec<u8> = Vec::new();
                loop {
                    // 流 FIN 时首字节读失败 → 正常结束（由 status 判定成败）
                    let ty = match read_varint_async(&mut recv).await {
                        Ok(t) => t,
                        Err(_) => break,
                    };
                    let len = read_varint_async(&mut recv).await?;
                    match ty {
                        FRAME_HEADERS => {
                            let mut buf = vec![0u8; len as usize];
                            recv.read_exact(&mut buf)
                                .await
                                .map_err(|e| map_err("响应头读", e))?;
                            let fs = qpack_decode(&buf).map_err(|e| map_err("QPACK 解码", e))?;
                            if status.is_none() {
                                for (k, v) in &fs {
                                    if k == ":status" {
                                        status = v.parse().ok();
                                    }
                                }
                                fields_out = fs;
                            }
                            // 尾部 HEADERS 忽略
                        }
                        FRAME_DATA => {
                            if len as usize > MAX_BODY.saturating_sub(body_out.len()) {
                                return Err(io::Error::other("h3: 响应体超限"));
                            }
                            let mut buf = vec![0u8; len as usize];
                            recv.read_exact(&mut buf)
                                .await
                                .map_err(|e| map_err("响应体读", e))?;
                            body_out.extend_from_slice(&buf);
                        }
                        _ => skip_frame(&mut recv, len).await?,
                    }
                }
                let status = status.ok_or_else(|| io::Error::other("h3: 响应无 :status"))?;
                Ok((status, fields_out, body_out))
            };
            match tokio::time::timeout(timeout, fut).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::other("h3: 请求超时")),
            }
        })
    }

    /// CONNECT 隧道（RFC 9114 §4.4）：HEADERS(`:method`=CONNECT + `:authority`) 后等
    /// 2xx；成功后 DATA 帧即隧道字节。返回可并发的读写两半。
    pub fn connect_tunnel(
        &self,
        authority: &str,
        extra_headers: &[(&str, &str)],
        timeout: Duration,
    ) -> io::Result<(H3TunnelReader, H3TunnelWriter)> {
        let conn = self.shared.conn.clone();
        rt().block_on(async {
            let fut = async {
                let (mut send, mut recv) =
                    conn.open_bi().await.map_err(|e| map_err("CONNECT 流", e))?;
                let mut fields: Vec<(&str, &str)> = Vec::with_capacity(2 + extra_headers.len());
                fields.push((":method", "CONNECT"));
                fields.push((":authority", authority));
                fields.extend_from_slice(extra_headers);
                let mut block = Vec::new();
                qpack_encode(&mut block, &fields);
                let mut out = Vec::with_capacity(block.len() + 10);
                write_varint(&mut out, FRAME_HEADERS);
                write_varint(&mut out, block.len() as u64);
                out.extend_from_slice(&block);
                send.write_all(&out)
                    .await
                    .map_err(|e| map_err("CONNECT 写", e))?;

                let status = loop {
                    let ty = read_varint_async(&mut recv).await?;
                    let len = read_varint_async(&mut recv).await?;
                    match ty {
                        FRAME_HEADERS => {
                            let mut buf = vec![0u8; len as usize];
                            recv.read_exact(&mut buf)
                                .await
                                .map_err(|e| map_err("CONNECT 响应读", e))?;
                            let fs = qpack_decode(&buf).map_err(|e| map_err("QPACK 解码", e))?;
                            let st = fs
                                .iter()
                                .find(|(k, _)| k == ":status")
                                .and_then(|(_, v)| v.parse::<u16>().ok());
                            break st
                                .ok_or_else(|| io::Error::other("h3: CONNECT 响应无 :status"))?;
                        }
                        _ => skip_frame(&mut recv, len).await?,
                    }
                };
                if !(200..300).contains(&status) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("h3: CONNECT 被拒（:status {status}）"),
                    ));
                }
                Ok((
                    H3TunnelReader {
                        _shared: self.shared.clone(),
                        recv,
                        remaining: 0,
                        eof: false,
                    },
                    H3TunnelWriter {
                        _shared: self.shared.clone(),
                        send: Mutex::new(send),
                        ended: AtomicBool::new(false),
                    },
                ))
            };
            match tokio::time::timeout(timeout, fut).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::other("h3: CONNECT 超时")),
            }
        })
    }
}

/// 隧道读半：把 DATA 帧载荷吐成字节流。
pub struct H3TunnelReader {
    _shared: Arc<H3Shared>,
    recv: RecvStream,
    /// 当前 DATA 帧未消费字节数
    remaining: u64,
    eof: bool,
}

impl Read for H3TunnelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof || buf.is_empty() {
            return Ok(0);
        }
        rt().block_on(async {
            loop {
                if self.remaining > 0 {
                    let want = buf.len().min(self.remaining as usize);
                    return match self.recv.read(&mut buf[..want]).await {
                        Ok(Some(n)) => {
                            self.remaining -= n as u64;
                            Ok(n)
                        }
                        // DATA 帧中途 FIN：截断（按流结束处理）
                        Ok(None) => {
                            self.eof = true;
                            Ok(0)
                        }
                        Err(e) => Err(map_err("隧道读", e)),
                    };
                }
                // 下一帧
                let ty = match read_varint_async(&mut self.recv).await {
                    Ok(t) => t,
                    Err(_) => {
                        self.eof = true;
                        return Ok(0);
                    }
                };
                let len = read_varint_async(&mut self.recv).await?;
                match ty {
                    FRAME_DATA => self.remaining = len,
                    _ => skip_frame(&mut self.recv, len).await?,
                }
            }
        })
    }
}

/// 隧道写半：每次写入切成 DATA 帧（≤16KB/帧）。
pub struct H3TunnelWriter {
    _shared: Arc<H3Shared>,
    send: Mutex<SendStream>,
    ended: AtomicBool,
}

impl H3TunnelWriter {
    /// 半关闭（幂等）：发 QUIC 流的 FIN。
    pub fn end_stream(&self) -> io::Result<()> {
        if self.ended.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut send = self.send.lock().unwrap_or_else(|e| e.into_inner());
        send.finish().map_err(|e| map_err("隧道 FIN", e))
    }
}

impl Write for H3TunnelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.ended.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "h3: 隧道已关闭"));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        rt().block_on(async {
            let mut send = self.send.lock().unwrap_or_else(|e| e.into_inner());
            for chunk in buf.chunks(MAX_DATA_FRAME) {
                let mut frame = Vec::with_capacity(chunk.len() + 10);
                encode_data_frame(&mut frame, chunk);
                send.write_all(&frame)
                    .await
                    .map_err(|e| map_err("隧道写", e))?;
            }
            Ok(buf.len())
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for H3TunnelWriter {
    fn drop(&mut self) {
        let _ = self.end_stream();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_header_block_layout() {
        // CONNECT：无 :scheme/:path（RFC 9114 §4.4）；Basic 头以字面量名字编码
        let mut block = Vec::new();
        qpack_encode(
            &mut block,
            &[
                (":method", "CONNECT"),
                (":authority", "1.1.1.1:443"),
                ("proxy-authorization", "Basic dTpw"),
            ],
        );
        assert_eq!(&block[..2], &[0x00, 0x00]); // RIC=0, Delta Base=0
        assert_eq!(block[2], 0xCF); // :method CONNECT → QPACK 静态索引 15（1Txxxxxx）
        assert_eq!(block[3], 0x50); // :authority name-ref 0（literal 值）
        let fields = qpack_decode(&block).unwrap();
        assert_eq!(fields[0], (":method".into(), "CONNECT".into()));
        assert_eq!(fields[1], (":authority".into(), "1.1.1.1:443".into()));
        assert_eq!(
            fields[2],
            ("proxy-authorization".into(), "Basic dTpw".into())
        );
    }

    #[test]
    fn data_frame_encoding() {
        let mut buf = Vec::new();
        encode_data_frame(&mut buf, b"hello");
        assert_eq!(buf, b"\x00\x05hello");
        let mut big = Vec::new();
        encode_data_frame(&mut big, &[0xAA; 20000]);
        // type 0x00 + varint 长度 20000（4 字节：0x80 00 4E 20）
        assert_eq!(&big[..6], &[0x00, 0x80, 0x00, 0x4e, 0x20, 0xAA]);
        assert_eq!(big.len(), 1 + 4 + 20000);
    }
}

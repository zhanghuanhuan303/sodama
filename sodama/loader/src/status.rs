// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! 状态面 + 主循环消息通道（K3/P3a；P6 起含控制命令）。
//!
//! 协议：客户端发一行命令，服务端回一行（JSON，metrics 为 Prometheus 文本）后关闭连接。
//! 查询命令：`status` / `config` / `rules` / `maps` / `metrics`；
//! 控制命令：`reload`（等价 SIGHUP）/ `suspend`（no-load）/ `resume`（P6，dae 靠 reload 恢复）。
//!
//! 服务线程本身**不碰 eBPF map**：`Query` 与 DNS 线程的 `DnsPublish` 都经 mpsc
//! 交给主循环（唯一持有 `Ebpf` 与全部 map 的地方）处理，因此控制命令与数据面写入
//! 天然串行，不存在并发读写 map 的问题。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::Duration;

/// 一次 DNS 位图发布：把 `bits` OR 进 `domain_routing_map[(slot, addr)]`。
#[derive(Debug, Clone)]
pub struct DnsUpdate {
    pub slot: u32,
    /// IPv4-mapped 16 字节（与数据面 lpm key 一致）
    pub addr: [u8; 16],
    pub bits: Vec<u32>,
}

/// 交给主循环处理的消息。
pub enum MainMsg {
    Query { cmd: String, reply: Sender<String> },
    DnsPublish { updates: Vec<DnsUpdate> },
}

/// 绑定 socket 并后台 accept（read-only；不返回错误即已启动）。
pub fn serve(path: &Path, tx: Sender<MainMsg>) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || handle_conn(stream, tx));
        }
    });
    Ok(())
}

fn handle_conn(stream: UnixStream, tx: Sender<MainMsg>) {
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let cmd = line.trim().to_string();
    let (rtx, rrx) = std::sync::mpsc::channel();
    if tx.send(MainMsg::Query { cmd, reply: rtx }).is_err() {
        return;
    }
    let resp = match rrx.recv_timeout(Duration::from_secs(5)) {
        Ok(r) => r,
        Err(_) => "{\"error\":\"status timeout\"}".to_string(),
    };
    let mut w = stream;
    let _ = w.write_all(resp.as_bytes());
    let _ = w.write_all(b"\n");
}

/// 客户端：发一条命令，读到 EOF（JSON 单行 / metrics 为多行文本）。
pub fn client(sock: &Path, cmd: &str) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut stream = UnixStream::connect(sock)?;
    stream.write_all(cmd.as_bytes())?;
    stream.write_all(b"\n")?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out.trim_end().to_string())
}

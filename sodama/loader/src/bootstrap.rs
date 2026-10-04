//! P23：bootstrap resolver（对照 dae `global.bootstrap_resolver`）。
//!
//! 用于解析「解析本身可能被数据面接管」的域名：DNS 上游主机名、订阅/节点服务器
//! 主机名。直连指定解析器、绕开本机 DNS（P19 前用 IP 字面量规避启动期自阻塞）。
//!
//! 配置：`global { bootstrap_resolver: 'tcp+udp://9.9.9.9:53' }`（可逗号分隔多个；
//! 未配置时不启用——sodama 与 dae 的差异：dae 未配置时回退 119.29.29.29/223.5.5.5）。
//! 查 A + AAAA，任一有结果即返回；UDP 截断自动走 TCP。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE: usize = 4096;

fn servers() -> &'static Mutex<Vec<SocketAddr>> {
    static S: OnceLock<Mutex<Vec<SocketAddr>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// 配置 bootstrap 解析器（None/空 = 不启用）。可在每次 reload 时重调。
pub fn configure(raw: Option<&str>) -> Result<(), String> {
    let mut out = Vec::new();
    if let Some(raw) = raw {
        for item in raw.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            let item = item.trim();
            // 允许带 scheme（tcp+udp:// / udp:// / tcp://——本实现统一先 UDP 后 TCP）
            let hp = item.split_once("://").map(|(_, r)| r).unwrap_or(item);
            let (host, port) = match hp.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => (
                    h.to_string(),
                    p.parse::<u16>()
                        .map_err(|e| format!("bootstrap 端口非法: {e}"))?,
                ),
                _ => (hp.to_string(), 53),
            };
            // bootstrap 服务器自身按 IP 字面量（域名会引入自举循环；dae 同默认）
            let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
                vec![SocketAddr::new(ip, port)]
            } else {
                (host.as_str(), port)
                    .to_socket_addrs()
                    .map_err(|e| format!("解析 bootstrap 服务器 {host} 失败: {e}"))?
                    .collect()
            };
            let addr = addrs
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| addrs.first())
                .copied()
                .ok_or_else(|| format!("bootstrap 服务器 {host} 无地址"))?;
            out.push(addr);
        }
    }
    let mut g = match servers().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    *g = out;
    Ok(())
}

pub fn enabled() -> bool {
    match servers().lock() {
        Ok(g) => !g.is_empty(),
        Err(p) => !p.into_inner().is_empty(),
    }
}

fn next_id() -> u16 {
    static N: AtomicU16 = AtomicU16::new(0);
    let base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    base.wrapping_add(N.fetch_add(1, Ordering::Relaxed))
}

/// 构造最小查询报文（RD=1；EDNS 不参与——bootstrap 只关心基础应答）。
fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

fn parse_addrs(resp: &[u8]) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let (a, aaaa) = crate::dns::answer_a_and_aaaa_records(resp);
    (
        a.into_iter().map(Ipv4Addr::from).collect(),
        aaaa.into_iter().map(Ipv6Addr::from).collect(),
    )
}

/// 单服务器解析：A + AAAA，UDP 截断回退 TCP。
fn query_server(server: SocketAddr, qname: &str) -> Result<Vec<IpAddr>, String> {
    let udp = crate::outbound::new_marked_udp_for(server)
        .map_err(|e| format!("bootstrap 建 UDP socket 失败: {e}"))?;
    udp.set_read_timeout(Some(QUERY_TIMEOUT)).ok();
    let mut out: Vec<IpAddr> = Vec::new();
    let mut buf = vec![0u8; MAX_RESPONSE];
    for qtype in [1u16, 28u16] {
        let id = next_id();
        let query = build_query(id, qname, qtype);
        udp.send_to(&query, server)
            .map_err(|e| format!("bootstrap 发送失败: {e}"))?;
        let mut resp = None;
        for _ in 0..4 {
            let n = match udp.recv(&mut buf) {
                Ok(n) => n,
                Err(e) => return Err(format!("bootstrap 接收失败: {e}")),
            };
            if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                resp = Some(buf[..n].to_vec());
                break;
            }
        }
        let Some(resp) = resp else {
            return Err("bootstrap 应答与查询 ID 不匹配".into());
        };
        if resp.len() >= 4 && resp[2] & 0x02 != 0 {
            // TC=1：走 TCP 重查
            let tcp = crate::outbound::marked_tcp_connect(server, QUERY_TIMEOUT)
                .map_err(|e| format!("bootstrap TCP 连接失败: {e}"))?;
            tcp.set_read_timeout(Some(QUERY_TIMEOUT)).ok();
            let mut t = tcp;
            use std::io::{Read, Write};
            t.write_all(&(query.len() as u16).to_be_bytes())
                .and_then(|_| t.write_all(&query))
                .map_err(|e| format!("bootstrap TCP 写失败: {e}"))?;
            let mut lb = [0u8; 2];
            t.read_exact(&mut lb)
                .map_err(|e| format!("bootstrap TCP 读失败: {e}"))?;
            let mut rb = vec![0u8; u16::from_be_bytes(lb) as usize];
            t.read_exact(&mut rb)
                .map_err(|e| format!("bootstrap TCP 读失败: {e}"))?;
            let (a, aaaa) = parse_addrs(&rb);
            out.extend(a.into_iter().map(IpAddr::V4));
            out.extend(aaaa.into_iter().map(IpAddr::V6));
            continue;
        }
        let (a, aaaa) = parse_addrs(&resp);
        out.extend(a.into_iter().map(IpAddr::V4));
        out.extend(aaaa.into_iter().map(IpAddr::V6));
    }
    Ok(out)
}

/// 解析主机名（IP 字面量直通）。多个 bootstrap 服务器按序尝试。
pub fn resolve_host(host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let list: Vec<SocketAddr> = match servers().lock() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    };
    if list.is_empty() {
        return Err("bootstrap resolver 未配置".into());
    }
    let mut last = String::from("bootstrap 无可用服务器");
    for s in &list {
        match query_server(*s, host) {
            Ok(v) if !v.is_empty() => {
                crate::log(&format!("bootstrap: {host} → {v:?}（{s}）"));
                return Ok(v);
            }
            Ok(_) => last = format!("bootstrap {s} 无 {host} 的记录"),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_shape() {
        let q = build_query(0x1234, "a.bc", 1);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[4..6], &[0, 1]);
        assert_eq!(q[12], 1);
        assert_eq!(&q[13..14], b"a");
        assert_eq!(q[14], 2);
        assert_eq!(&q[15..17], b"bc");
        assert_eq!(q[17], 0);
        assert_eq!(&q[18..20], &[0, 1]);
        assert_eq!(&q[20..22], &[0, 1]);
    }

    #[test]
    fn configure_parses_lists_and_schemes() {
        configure(Some("udp://9.9.9.9:5353, 1.1.1.1")).unwrap();
        let list = servers().lock().unwrap().clone();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], "9.9.9.9:5353".parse().unwrap());
        assert_eq!(list[1], "1.1.1.1:53".parse().unwrap());
        assert!(enabled());
        configure(None).unwrap();
        assert!(!enabled());
        let v = resolve_host("1.2.3.4").unwrap();
        assert_eq!(v, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn resolve_host_roundtrip_against_local_server() {
        // 本地 UDP DNS：A 1.2.3.4 / AAAA ::1（独立实现最小应答）
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let jh = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::Relaxed) {
                sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let q = &buf[..n];
                if n < 12 {
                    continue;
                }
                let qtype = u16::from_be_bytes([q[n - 4], q[n - 3]]);
                let mut resp = Vec::new();
                resp.extend_from_slice(&q[0..2]);
                resp.extend_from_slice(&0x8180u16.to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&0u16.to_be_bytes());
                resp.extend_from_slice(&0u16.to_be_bytes());
                resp.extend_from_slice(&q[12..n]);
                resp.extend_from_slice(&[0xc0, 0x0c]); // name ptr
                resp.extend_from_slice(&qtype.to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&60u32.to_be_bytes());
                if qtype == 1 {
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&[1, 2, 3, 4]);
                } else {
                    resp.extend_from_slice(&16u16.to_be_bytes());
                    resp.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                }
                let _ = sock.send_to(&resp, peer);
            }
        });
        configure(Some(&format!("udp://{addr}"))).unwrap();
        let v = resolve_host("boot.test").unwrap();
        stop.store(true, Ordering::Relaxed);
        jh.join().unwrap();
        configure(None).unwrap();
        assert!(v.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()), "{v:?}");
        assert!(v.contains(&"::1".parse::<IpAddr>().unwrap()), "{v:?}");
    }
}

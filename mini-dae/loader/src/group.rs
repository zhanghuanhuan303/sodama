//! P15：节点组——filter（`name`/`subtag`/`keyword`/`regex`/取反/OR）、
//! policy（`min` / `min_moving_avg` / `min_avg10` / `random` / `fixed(i)`）、
//! 健康检查（经节点的 TCP/HTTP 探测）与拨号失败切换。
//!
//! 对照 dae `component/outbound`：数据面仍把全部用户组映射到 proxy（K3 边界），
//! 本模块在**拨号层**替用户组做节点选择；按规则分派到不同组需要数据面携带
//! outbound id（后续，见 ADR-0031）。

use std::collections::VecDeque;
use std::io::{Read as _, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config;
use crate::outbound::{self, DialedStream};
use crate::subscribe::ParsedNode;
use crate::target::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Random,
    Fixed(usize),
    Min,
    MinMovingAvg,
    MinAvg10,
}

pub fn parse_policy(s: Option<&str>) -> Policy {
    let Some(s) = s.map(str::trim) else {
        return Policy::MinMovingAvg;
    };
    match s {
        "random" => Policy::Random,
        "min" => Policy::Min,
        "min_moving_avg" => Policy::MinMovingAvg,
        "min_avg10" => Policy::MinAvg10,
        other if other.starts_with("fixed(") => {
            let inner = other
                .trim_start_matches("fixed(")
                .trim_end_matches(')')
                .trim();
            inner
                .parse()
                .map(Policy::Fixed)
                .unwrap_or(Policy::MinMovingAvg)
        }
        _ => Policy::MinMovingAvg,
    }
}

fn name_param_match(p: &config::Param, name: &str) -> bool {
    match p.key.as_deref() {
        None | Some("") => p.val.as_deref() == Some(name),
        Some("keyword") => p
            .val
            .as_deref()
            .map(|v| !v.is_empty() && name.contains(v))
            .unwrap_or(false),
        Some("regex") => p
            .val
            .as_deref()
            .and_then(|v| regex::Regex::new(v).ok())
            .map(|r| r.is_match(name))
            .unwrap_or(false),
        _ => false,
    }
}

fn func_match(f: &config::Function, name: &str, tag: &str) -> bool {
    let hit = match f.name.as_str() {
        "name" => f.params.iter().any(|p| name_param_match(p, name)),
        "subtag" => f.params.iter().any(|p| match p.key.as_deref() {
            Some("regex") => p
                .val
                .as_deref()
                .and_then(|v| regex::Regex::new(v).ok())
                .map(|r| r.is_match(tag))
                .unwrap_or(false),
            _ => p.val.as_deref() == Some(tag),
        }),
        _ => false,
    };
    if f.not {
        !hit
    } else {
        hit
    }
}

/// filter 语义（对照 dae）：多行 filter 之间为 OR；一行内为 AND；函数可带 `!`。
pub fn filter_match(filters: &[Vec<config::Function>], name: &str, tag: &str) -> bool {
    if filters.is_empty() {
        return true;
    }
    filters
        .iter()
        .any(|line| line.iter().all(|f| func_match(f, name, tag)))
}

#[derive(Debug, Clone)]
pub struct Health {
    pub alive: bool,
    pub fails: u32,
    pub last_ms: Option<u64>,
    pub ema_ms: Option<f64>,
    pub hist: VecDeque<u64>,
}

impl Default for Health {
    /// 未探测前乐观上活（否则组在首轮探测完成前会把所有节点当 dead）。
    fn default() -> Self {
        Self {
            alive: true,
            fails: 0,
            last_ms: None,
            ema_ms: None,
            hist: VecDeque::new(),
        }
    }
}

impl Health {
    fn note_probe(&mut self, ok: bool, ms: u64, tolerance: u32) {
        if ok {
            self.alive = true;
            self.fails = 0;
            self.last_ms = Some(ms);
            self.ema_ms = Some(match self.ema_ms {
                Some(prev) => prev * 0.7 + ms as f64 * 0.3,
                None => ms as f64,
            });
            self.hist.push_back(ms);
            while self.hist.len() > 10 {
                self.hist.pop_front();
            }
        } else {
            self.fails = self.fails.saturating_add(1);
            if self.fails > tolerance {
                self.alive = false;
            }
        }
    }
}

#[derive(Debug)]
pub struct Member {
    pub name: String,
    pub tag: String,
    pub outbound: outbound::Outbound,
}

#[derive(Default)]
pub struct GroupStats {
    pub dials: AtomicU64,
    pub failovers: AtomicU64,
    pub probes_ok: AtomicU64,
    pub probes_fail: AtomicU64,
}

pub struct GroupRuntime {
    pub name: String,
    pub policy: Policy,
    pub members: Vec<Member>,
    health: Mutex<Vec<Health>>,
    pub check_targets: Vec<(String, u16)>,
    pub check_interval_secs: u64,
    pub check_tolerance: u32,
    pub stats: GroupStats,
}

impl std::fmt::Debug for GroupRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GroupRuntime({}, {:?}, {} members)",
            self.name,
            self.policy,
            self.members.len()
        )
    }
}

impl GroupRuntime {
    pub fn new(
        name: String,
        policy: Policy,
        members: Vec<Member>,
        check_targets: Vec<(String, u16)>,
        check_interval_secs: u64,
        check_tolerance: u32,
    ) -> Arc<Self> {
        let n = members.len();
        Arc::new(Self {
            name,
            policy,
            members,
            health: Mutex::new(vec![Health::default(); n]),
            check_targets,
            check_interval_secs,
            check_tolerance,
            stats: GroupStats::default(),
        })
    }

    fn health_lock(&self) -> std::sync::MutexGuard<'_, Vec<Health>> {
        match self.health.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn metric(&self, h: &Health) -> Option<f64> {
        match self.policy {
            Policy::Min => h.last_ms.map(|v| v as f64),
            Policy::MinMovingAvg => h.ema_ms,
            Policy::MinAvg10 => {
                if h.hist.is_empty() {
                    None
                } else {
                    Some(h.hist.iter().sum::<u64>() as f64 / h.hist.len() as f64)
                }
            }
            _ => None,
        }
    }

    /// 按 policy + 健康状态给出尝试顺序（alive/已知延迟优先，其后未探测，最后 dead）。
    pub fn select_order(&self) -> Vec<usize> {
        let hs = self.health_lock();
        let n = self.members.len();
        match self.policy {
            Policy::Random => {
                let mut idx: Vec<usize> = (0..n).collect();
                // Fisher–Yates
                for i in (1..idx.len()).rev() {
                    let j = (rand::random::<u64>() % (i as u64 + 1)) as usize;
                    idx.swap(i, j);
                }
                // alive 排在 dead 前
                idx.sort_by_key(|&i| !hs[i].alive);
                idx
            }
            Policy::Fixed(k) => {
                let mut idx = Vec::with_capacity(n);
                if k < n {
                    idx.push(k);
                }
                idx.extend((0..n).filter(|&i| i != k));
                idx.sort_by_key(|&i| {
                    if i == k {
                        0
                    } else if hs[i].alive {
                        1
                    } else {
                        2
                    }
                });
                idx
            }
            _ => {
                let mut idx: Vec<usize> = (0..n).collect();
                idx.sort_by(|&a, &b| {
                    let ca = if !hs[a].alive {
                        2
                    } else if self.metric(&hs[a]).is_some() {
                        0
                    } else {
                        1
                    };
                    let cb = if !hs[b].alive {
                        2
                    } else if self.metric(&hs[b]).is_some() {
                        0
                    } else {
                        1
                    };
                    ca.cmp(&cb).then_with(|| {
                        let ma = self.metric(&hs[a]).unwrap_or(f64::INFINITY);
                        let mb = self.metric(&hs[b]).unwrap_or(f64::INFINITY);
                        ma.partial_cmp(&mb).unwrap_or(std::cmp::Ordering::Equal)
                    })
                });
                idx
            }
        }
    }

    fn note_dial(&self, i: usize, ok: bool) {
        let tolerance = self.check_tolerance;
        let mut hs = self.health_lock();
        if let Some(h) = hs.get_mut(i) {
            if ok {
                h.fails = 0;
                h.alive = true;
            } else {
                h.fails = h.fails.saturating_add(1);
                if h.fails > tolerance {
                    h.alive = false;
                }
            }
        }
    }

    /// 拨号：按顺序最多尝试 3 个成员；失败自动切换下一个。
    pub fn dial_tcp(&self, target: &Target, timeout: Duration) -> std::io::Result<DialedStream> {
        let order = self.select_order();
        let mut last_err: Option<std::io::Error> = None;
        let mut tried = 0usize;
        for &i in order.iter().take(3.max(1)) {
            self.stats.dials.fetch_add(1, Ordering::Relaxed);
            match self.members[i].outbound.dial_tcp(target, timeout) {
                Ok(d) => {
                    self.note_dial(i, true);
                    return Ok(d);
                }
                Err(e) => {
                    self.note_dial(i, false);
                    if tried > 0 {
                        self.stats.failovers.fetch_add(1, Ordering::Relaxed);
                    }
                    tried += 1;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| std::io::Error::other("组内无可用节点")))
    }

    /// 选一个支持 UDP 的成员（按同一顺序），失败切换至多 3 个。
    pub fn dial_udp(
        &self,
        target: std::net::SocketAddr,
        timeout: Duration,
    ) -> std::io::Result<Option<outbound::UdpRelay>> {
        let order = self.select_order();
        let mut last_err: Option<std::io::Error> = None;
        let mut tried = 0usize;
        for &i in order.iter().take(3.max(1)) {
            if !self.members[i].outbound.supports_udp() {
                continue;
            }
            match self.members[i].outbound.dial_udp(target, timeout) {
                Ok(Some(r)) => {
                    self.note_dial(i, true);
                    return Ok(Some(r));
                }
                Ok(None) => continue,
                Err(e) => {
                    self.note_dial(i, false);
                    if tried > 0 {
                        self.stats.failovers.fetch_add(1, Ordering::Relaxed);
                    }
                    tried += 1;
                    last_err = Some(e);
                }
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(None),
        }
    }

    pub fn supports_udp(&self) -> bool {
        self.members.iter().any(|m| m.outbound.supports_udp())
    }

    /// 健康快照（状态面用）。
    pub fn snapshot(&self) -> Vec<(String, String, bool, Option<u64>, Option<f64>)> {
        let hs = self.health_lock();
        self.members
            .iter()
            .zip(hs.iter())
            .map(|(m, h)| (m.name.clone(), m.tag.clone(), h.alive, h.last_ms, h.ema_ms))
            .collect()
    }

    /// 启动健康探测线程：周期性经每个成员连接 check 目标，成功即更新延迟/存活。
    pub fn spawn_health_loop(self: &Arc<Self>) {
        if self.check_targets.is_empty() || self.members.is_empty() {
            return;
        }
        let g = self.clone();
        std::thread::spawn(move || loop {
            let n = g.members.len();
            let mut i = 0;
            while i < n {
                let end = (i + 8).min(n);
                std::thread::scope(|s| {
                    for j in i..end {
                        let g = &g;
                        s.spawn(move || {
                            let _ = g.probe(j);
                        });
                    }
                });
                i = end;
            }
            std::thread::sleep(Duration::from_secs(g.check_interval_secs.max(1)));
        });
    }

    fn probe(&self, i: usize) -> std::io::Result<()> {
        let Some((host, port)) = self.check_targets.first().cloned() else {
            return Ok(());
        };
        let target: Target = format!("{host}:{port}")
            .parse()
            .map_err(|e| std::io::Error::other(format!("check 目标非法: {e}")))?;
        let t0 = Instant::now();
        let d = match self.members[i]
            .outbound
            .dial_tcp(&target, Duration::from_secs(5))
        {
            Ok(d) => d,
            Err(e) => {
                // 拨号失败必须计入健康状态（否则死节点永远不会被标死）
                self.stats.probes_fail.fetch_add(1, Ordering::Relaxed);
                let tol = self.check_tolerance;
                self.health_lock()[i].note_probe(false, 0, tol);
                return Err(e);
            }
        };
        // 发一个 HTTP/1.0 请求并等任意响应（echo 型目标也会回；QUIC 无底层 socket 时仅计拨号成功）
        let mut ok = true;
        if let Some(sock) = d.socket.as_ref() {
            let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
            let mut d = d;
            let req = format!("GET /generate_204 HTTP/1.0\r\nHost: {host}\r\n\r\n");
            let mut ok_write = d.to_remote.write_all(req.as_bytes()).is_ok();
            ok_write &= d.to_remote.flush().is_ok();
            let mut buf = [0u8; 64];
            let read_ok = matches!(d.from_remote.read(&mut buf), Ok(n) if n > 0);
            ok = ok_write && read_ok;
        }
        let ms = t0.elapsed().as_millis() as u64;
        if ok {
            self.stats.probes_ok.fetch_add(1, Ordering::Relaxed);
            let tol = self.check_tolerance;
            self.health_lock()[i].note_probe(true, ms, tol);
            Ok(())
        } else {
            self.stats.probes_fail.fetch_add(1, Ordering::Relaxed);
            let tol = self.check_tolerance;
            self.health_lock()[i].note_probe(false, 0, tol);
            Err(std::io::Error::other("check 无响应"))
        }
    }
}

/// 从已解析节点 + 组配置构建成员（filter 命中；空 filter = 全部）。
pub fn build_members(nodes: &[ParsedNode], filters: &[Vec<config::Function>]) -> Vec<Member> {
    nodes
        .iter()
        .filter(|n| filter_match(filters, &n.name, &n.tag))
        .map(|n| Member {
            name: n.name.clone(),
            tag: n.tag.clone(),
            outbound: n.outbound.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Function, Param};

    fn f(name: &str, not: bool, params: Vec<(&str, &str)>) -> Function {
        Function {
            name: name.into(),
            not,
            params: params
                .into_iter()
                .map(|(k, v)| Param {
                    key: if k.is_empty() { None } else { Some(k.into()) },
                    val: Some(v.into()),
                    funcs: None,
                    annotation: Vec::new(),
                    loc: None,
                })
                .collect(),
            loc: crate::config::Loc { file: 0, line: 0 },
        }
    }

    #[test]
    fn filter_or_and_not() {
        let filters = vec![
            vec![f("subtag", false, vec![("", "sub1")])],
            vec![
                f("subtag", false, vec![("", "sub2")]),
                f("name", true, vec![("keyword", "ExpireAt:")]),
            ],
        ];
        assert!(filter_match(&filters, "node-a", "sub1"));
        assert!(filter_match(&filters, "node-b", "sub2"));
        assert!(!filter_match(&filters, "ExpireAt: x", "sub2"));
        assert!(!filter_match(&filters, "node", "other"));
        assert!(filter_match(&[], "any", "any"));
    }

    #[test]
    fn filter_name_forms() {
        let exact = vec![vec![f("name", false, vec![("", "HK-01"), ("", "US-01")])]];
        assert!(filter_match(&exact, "HK-01", "t"));
        assert!(!filter_match(&exact, "HK-02", "t"));
        let kw = vec![vec![f("name", false, vec![("keyword", "香港")])]];
        assert!(filter_match(&kw, "香港 IEPL 01", "t"));
        let re = vec![vec![f("name", false, vec![("regex", "^HK-\\d+$")])]];
        assert!(filter_match(&re, "HK-12", "t"));
        assert!(!filter_match(&re, "HK-12x", "t"));
    }

    #[test]
    fn health_tolerance_and_recovery() {
        let mut h = Health::default();
        // tolerance=1：连续 2 次失败才 dead
        h.note_probe(false, 0, 1);
        assert!(h.alive || h.fails == 1);
        assert!(h.alive); // 首次失败仍在容忍内
        h.note_probe(false, 0, 1);
        assert!(!h.alive);
        h.note_probe(true, 42, 1);
        assert!(h.alive);
        assert_eq!(h.last_ms, Some(42));
        assert!(!h.hist.is_empty());
    }

    #[test]
    fn policy_parse() {
        assert_eq!(parse_policy(Some("random")), Policy::Random);
        assert_eq!(parse_policy(Some("min")), Policy::Min);
        assert_eq!(parse_policy(Some("min_avg10")), Policy::MinAvg10);
        assert_eq!(parse_policy(Some("fixed(2)")), Policy::Fixed(2));
        assert_eq!(parse_policy(None), Policy::MinMovingAvg);
        assert_eq!(parse_policy(Some("nonsense")), Policy::MinMovingAvg);
    }

    #[test]
    fn select_order_min_prefers_low_latency_alive() {
        let dummy = crate::outbound::Outbound::Direct;
        let members = vec![
            Member {
                name: "slow".into(),
                tag: "t".into(),
                outbound: dummy.clone(),
            },
            Member {
                name: "fast".into(),
                tag: "t".into(),
                outbound: dummy.clone(),
            },
            Member {
                name: "dead".into(),
                tag: "t".into(),
                outbound: dummy,
            },
        ];
        let g = GroupRuntime::new("g".into(), Policy::Min, members, vec![], 30, 1);
        {
            let mut hs = g.health_lock();
            hs[0].note_probe(true, 200, 1);
            hs[1].note_probe(true, 20, 1);
            hs[2].alive = false;
        }
        let order = g.select_order();
        assert_eq!(order[0], 1, "fast first");
        assert_eq!(order[1], 0, "slow second");
        assert_eq!(order[2], 2, "dead last");
    }

    #[test]
    fn probe_records_failure_on_dial_error() {
        // 回归：dial 失败必须计失败（曾因 `?` 提前返回导致死节点永不标死）
        let link = "ss://chacha20-ietf-poly1305:testpass@127.0.0.1:1#dead";
        let (nodes, _) = crate::subscribe::parse_subscription(link, "t");
        let members = build_members(&nodes, &[]);
        let g = GroupRuntime::new(
            "g".into(),
            Policy::MinMovingAvg,
            members,
            vec![("127.0.0.1".into(), 1)],
            1,
            0,
        );
        assert!(g.probe(0).is_err());
        assert_eq!(g.stats.probes_fail.load(Ordering::Relaxed), 1);
        assert_eq!(g.stats.probes_ok.load(Ordering::Relaxed), 0);
        assert!(!g.snapshot()[0].2, "一次失败 + tolerance=0 应标死");
    }

    #[test]
    fn build_members_applies_filter() {
        // 用 lab 的 ss 链接构造（parse 不联网）
        let link = "ss://chacha20-ietf-poly1305:testpass@127.0.0.1:18388#%E9%A6%99%E6%B8%AF";
        let (nodes, errors) = crate::subscribe::parse_subscription(link, "sub1");
        assert!(errors.is_empty());
        let all = build_members(&nodes, &[]);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "香港");
        let hit = build_members(&nodes, &[vec![f("subtag", false, vec![("", "sub1")])]]);
        assert_eq!(hit.len(), 1);
        let miss = build_members(&nodes, &[vec![f("subtag", false, vec![("", "other")])]]);
        assert_eq!(miss.len(), 0);
    }
}

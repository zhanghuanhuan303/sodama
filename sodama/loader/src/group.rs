//! P15：节点组——filter（`name`/`subtag`/`keyword`/`regex`/取反/OR）、
//! policy（`min` / `min_moving_avg` / `min_avg10` / `random` / `fixed(i)`）、
//! 健康检查（经节点的 TCP/HTTP 探测）与拨号失败切换。
//!
//! 对照 dae `component/outbound`：数据面仍把全部用户组映射到 proxy（K3 边界），
//! 本模块在**拨号层**替用户组做节点选择；按规则分派到不同组需要数据面携带
//! outbound id（后续，见 ADR-0031）。

use std::collections::VecDeque;
use std::io::{Read as _, Write as _};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config;
use crate::outbound::{self, DialedStream};
use crate::subscribe::ParsedNode;
use crate::target::Target;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Random,
    Fixed(usize),
    /// 按**节点名**点名（`fixed('日本02')`）：订阅刷新会重排成员索引，
    /// 名字比索引稳定；找不到时退化为全池 policy 排序（不影响兜底）。
    FixedName(String),
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
            if inner.is_empty() {
                return Policy::MinMovingAvg;
            }
            if let Ok(k) = inner.parse::<usize>() {
                return Policy::Fixed(k);
            }
            // `fixed('名称')` / "fixed(名称)" → 名字点名
            let name = inner.trim_matches(['\'', '"']).trim().to_string();
            if name.is_empty() {
                Policy::MinMovingAvg
            } else {
                Policy::FixedName(name)
            }
        }
        _ => Policy::MinMovingAvg,
    }
}

/// `policy` 的可读名（状态面/日志用；解决 `format!("{:?}")` 不能表达引号名的问题）。
pub fn policy_name(p: &Policy) -> String {
    match p {
        Policy::Random => "random".into(),
        Policy::Fixed(k) => format!("fixed({k})"),
        Policy::FixedName(n) => format!("fixed('{n}')"),
        Policy::Min => "min".into(),
        Policy::MinMovingAvg => "min_moving_avg".into(),
        Policy::MinAvg10 => "min_avg10".into(),
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

#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub tag: String,
    /// P34：来源顺序（0 = 最高优先；`subscription_failover` 按此分层回退）。
    pub rank: u32,
    pub outbound: outbound::Outbound,
}

#[derive(Default)]
pub struct GroupStats {
    pub dials: AtomicU64,
    pub failovers: AtomicU64,
    pub probes_ok: AtomicU64,
    pub probes_fail: AtomicU64,
    /// 健康探测中「超时未回、被放弃等待」的成员数累计。
    /// 生产事故（2026-10-09）：`thread::scope` 等待全部子线程，任一个探测卡死在
    /// 无超时的 socket 读上即拖垮整轮探测 → 全网零延迟数据。此计数用于持续可见性。
    pub probes_stragglers: AtomicU64,
    /// P34：活动订阅层（rank+1 编码；0 = 尚未选出/未启用顺序回退）。
    pub active_rank: AtomicU64,
    /// 当前健康探测节奏（秒；空闲退避时变大）——状态面展示用。
    pub probe_interval: AtomicU64,
    /// 本轮是否处于「活跃探测」（有人看状态或有流量）。
    pub probe_active: AtomicU64,
}

/// 单个探测批次的等待上限：超时即放弃等待（迟到结果仍会被 `record_probe` 记入）。
/// 单次探测最坏耗时 = 拨号 5s + 读 3s；整批 24 并发正常远小于该值。
const PROBE_BATCH_DEADLINE: Duration = Duration::from_secs(30);
/// 探测线程栈：探测只做小分配，无需默认 8 MiB（大批量时省内存）。
const PROBE_STACK: usize = 512 * 1024;
/// **在跑的探测线程上限**（安全网）。
///
/// 背景（2026-10-09 生产事故，第二阶段 §9）：探测改为「独立 spawn + 超时收集」后，
/// 被放弃的线程若因握手读无超时而**永不退出**，就会永久累积——20 小时攒到 553 个
/// probe 线程 / VmSize 432 MB / RSS 105 MB。
/// 这里用「存活计数 + 上限」把最坏情况封死：一旦撞顶就跳过本轮并告警，
/// 线程数不再无界增长（真正的根因已在 `outbound.rs` 的握手硬超时里修掉）。
static PROBE_LIVE: AtomicU64 = AtomicU64::new(0);
const PROBE_MAX_LIVE: u64 = 96;

/// 探测线程存活计数守卫（无论正常结束还是被放弃，只要线程真的退出就会 −1）。
struct ProbeLiveGuard;
impl Drop for ProbeLiveGuard {
    fn drop(&mut self) {
        PROBE_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 状态面用的节点快照（含可公开协议事实，供控制面板列展示）。
#[derive(Clone)]
pub struct NodeSnap {
    pub name: String,
    pub tag: String,
    pub alive: bool,
    pub last_ms: Option<u64>,
    pub ema_ms: Option<f64>,
    pub facts: outbound::NodeFacts,
}

/// 探测节奏决策（纯函数，便于测试）：
/// 有人看/有流量 → 基准间隔并清零退避；两者皆无 → 指数退避（×2 到 `cap`）。
/// `cap = 0` = 不退避（保持旧行为）。
pub fn probe_interval_for(
    base: u64,
    cap: u64,
    watched: bool,
    busy: bool,
    idle_rounds: &mut u32,
) -> u64 {
    if cap == 0 || watched || busy {
        *idle_rounds = 0;
        base
    } else {
        *idle_rounds = (*idle_rounds + 1).min(5);
        (base << *idle_rounds).min(cap)
    }
}

pub struct GroupRuntime {
    pub name: String,
    /// policy 热可替换（控制面板“手动切节点”/config 编辑都靠 reload 即时生效；
    /// `Arc` 包一层让热路径取用只是引用计数自增，不拷贝名字串）。
    policy: std::sync::RwLock<std::sync::Arc<Policy>>,
    /// P18e：成员集可热替换（订阅热更新）；Arc 快照读，拨号不持锁。
    inner: std::sync::RwLock<std::sync::Arc<GroupInner>>,
    pub check_targets: Vec<(String, u16)>,
    /// P18e：UDP 健康检查目标（解析后的 IP:port）；None = 不启用。
    pub udp_check_dns: Option<(String, u16)>,
    pub check_interval_secs: u64,
    pub check_tolerance: u32,
    pub stats: GroupStats,
    /// P34：订阅顺序回退开关（config global `subscription_failover`，默认开）。
    sub_failover: AtomicBool,
    /// 空闲探测退避上限（秒；0 = 不退避，保持旧行为）；config global `probe_idle_cap`。
    idle_cap_secs: AtomicU64,
}

/// 成员 + 健康（整体替换以实现“生成代”隔离）。
struct GroupInner {
    members: Vec<Member>,
    health: Mutex<Vec<Health>>,
}

impl std::fmt::Debug for GroupRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GroupRuntime({}, {:?}, {} members)",
            self.name,
            *self.policy(),
            self.member_count()
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
        udp_check_dns: Option<(String, u16)>,
    ) -> Arc<Self> {
        let n = members.len();
        Arc::new(Self {
            name,
            policy: std::sync::RwLock::new(std::sync::Arc::new(policy)),
            inner: std::sync::RwLock::new(std::sync::Arc::new(GroupInner {
                members,
                health: Mutex::new(vec![Health::default(); n]),
            })),
            check_targets,
            udp_check_dns,
            check_interval_secs,
            check_tolerance,
            stats: GroupStats::default(),
            sub_failover: AtomicBool::new(true),
            idle_cap_secs: AtomicU64::new(600),
        })
    }

    fn inner(&self) -> std::sync::Arc<GroupInner> {
        match self.inner.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    pub fn member_count(&self) -> usize {
        self.inner().members.len()
    }

    /// 组内**全部**成员是否都支持 reactor 的 codec 会话（每连接 0 线程）。
    ///
    /// 用于 `Outbound::Group` 的 `codec_reactor_capable()`：组的成员是动态的
    ///（订阅热更新），因此这里**逐成员实算**而不是缓存。
    ///
    /// 语义是**保守放行**：只要有一个成员不跑 reactor 路径（tuic/hysteria2/
    /// juicity/naive/QUIC，或带 shadow-tls 的 ss），整组就不进 reactor，
    /// 退回双泵线程路径——慢但正确。真实订阅下组内通常是同质协议
    ///（如 vless + anytls），因此生产能吃到这个优化。
    ///
    /// 空组返回 false（启动早期还没成员时不冒险）。
    pub fn codec_reactor_capable_all(&self) -> bool {
        let inner = self.inner();
        !inner.members.is_empty()
            && inner
                .members
                .iter()
                .all(|m| m.outbound.codec_reactor_capable())
    }

    /// 空闲探测退避上限（秒；0 = 不退避）。
    pub fn set_idle_cap(&self, secs: u64) {
        self.idle_cap_secs.store(secs, Ordering::Relaxed);
    }

    /// 当前策略（Arc 快照；热路径用，不拷贝名字）。
    pub fn policy(&self) -> std::sync::Arc<Policy> {
        match self.policy.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// 热替换 policy（reload 时由 config 重算；splice 重排成员不影响）。
    pub fn set_policy(&self, p: Policy) {
        match self.policy.write() {
            Ok(mut g) => *g = std::sync::Arc::new(p),
            Err(e) => *e.into_inner() = std::sync::Arc::new(p),
        }
    }

    /// 当前优选 = `select_order()` 首位（**新连接优先走它**，失败再依次兜底）；
    /// 同时给出「点名锁定」的名字 + 是否命中当前成员（未命中＝订阅变更/节点下线，已兜底自动）。
    pub fn current_and_pinned(&self) -> (Option<usize>, Option<String>, bool) {
        let current = self.select_order().first().copied();
        let inner = self.inner();
        let n = inner.members.len();
        let (pinned, ok) = match &*self.policy() {
            Policy::FixedName(nm) => {
                let hit = (0..n).any(|i| &inner.members[i].name == nm);
                (Some(nm.clone()), hit)
            }
            Policy::Fixed(k) => (inner.members.get(*k).map(|m| m.name.clone()), *k < n),
            _ => (None, true),
        };
        (current, pinned, ok)
    }

    /// P34：订阅顺序回退开关（config global `subscription_failover`，默认开）。
    pub fn set_sub_failover(&self, on: bool) {
        self.sub_failover.store(on, Ordering::Relaxed);
    }

    pub fn sub_failover_enabled(&self) -> bool {
        self.sub_failover.load(Ordering::Relaxed)
    }

    /// P34：当前活动订阅层来源 tag（未启用顺序回退或全 dead 时为 None）。
    pub fn active_tag(&self) -> Option<String> {
        if !self.sub_failover.load(Ordering::Relaxed) {
            return None;
        }
        let inner = self.inner();
        let hs = Self::health_lock(&inner);
        let a = (0..inner.members.len())
            .filter(|&i| hs[i].alive)
            .map(|i| inner.members[i].rank)
            .min()?;
        inner
            .members
            .iter()
            .find(|m| m.rank == a)
            .map(|m| m.tag.clone())
    }

    /// P18e：订阅热更新——整体替换成员（同 name+tag 的成员继承健康/延迟）。
    /// 返回（新成员数, 继承数）。
    pub fn replace_members(&self, members: Vec<Member>) -> (usize, usize) {
        let old = self.inner();
        let old_hs = match old.health.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        let mut health = Vec::with_capacity(members.len());
        let mut inherited = 0usize;
        for m in &members {
            let mut h = Health::default();
            if let Some((i, _)) = old
                .members
                .iter()
                .enumerate()
                .find(|(_, o)| o.name == m.name && o.tag == m.tag)
            {
                if let Some(oh) = old_hs.get(i) {
                    h = oh.clone();
                    inherited += 1;
                }
            }
            health.push(h);
        }
        let n = members.len();
        let new_inner = std::sync::Arc::new(GroupInner {
            members,
            health: Mutex::new(health),
        });
        match self.inner.write() {
            Ok(mut g) => *g = new_inner,
            Err(p) => *p.into_inner() = new_inner,
        }
        (n, inherited)
    }

    /// P0（2026-10-11）：按 tag 克隆组内成员（订阅热更新的「按源保留」用：
    /// 拉取失败的来源沿用旧成员，成功的来源整体替换）。
    pub fn clone_members_by_tag(&self, tags: &[String]) -> Vec<Member> {
        self.inner()
            .members
            .iter()
            .filter(|m| tags.iter().any(|t| t == &m.tag))
            .cloned()
            .collect()
    }

    fn health_lock(inner: &GroupInner) -> std::sync::MutexGuard<'_, Vec<Health>> {
        match inner.health.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn metric_with(pol: &Policy, h: &Health) -> Option<f64> {
        match pol {
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

    /// P34：计算活动订阅层（alive 成员中 rank 最小）并在变化时记日志；
    /// select_order 与健康探测轮共用（探测周期内即可发现切换，不必等下一次拨号）。
    fn note_active_layer(&self, inner: &GroupInner, hs: &[Health]) -> Option<u32> {
        if !self.sub_failover.load(Ordering::Relaxed) {
            return None;
        }
        let a = (0..inner.members.len())
            .filter(|&i| hs[i].alive)
            .map(|i| inner.members[i].rank)
            .min()?;
        let enc = a as u64 + 1;
        if self.stats.active_rank.swap(enc, Ordering::Relaxed) != enc {
            if let Some(m) = inner.members.iter().find(|m| m.rank == a) {
                crate::log(&format!(
                    "组 {}: 活动订阅 -> {}（顺序回退 rank {a}）",
                    self.name, m.tag
                ));
            }
        }
        Some(a)
    }

    /// 按 policy + 健康状态给出尝试顺序（alive/已知延迟优先，其后未探测，最后 dead）。
    pub fn select_order(&self) -> Vec<usize> {
        let inner = self.inner();
        let hs = Self::health_lock(&inner);
        let n = inner.members.len();
        // P34：订阅顺序回退（pacman 风格）——alive 成员中 rank 最小者为「活动层」，
        // 层内按 policy 排序；其余来源作兜底（层键在健康之后、延迟之前）。
        // `subscription_failover` 关闭时为 None → 与旧行为（全池按 policy）一致。
        let pol = self.policy();
        let active = self.note_active_layer(&inner, &hs);
        let layer = |i: usize| -> u8 {
            match active {
                Some(a) if inner.members[i].rank != a => 1,
                _ => 0,
            }
        };
        match &*pol {
            Policy::Random => {
                let mut idx: Vec<usize> = (0..n).collect();
                // Fisher–Yates
                for i in (1..idx.len()).rev() {
                    let j = (rand::random::<u64>() % (i as u64 + 1)) as usize;
                    idx.swap(i, j);
                }
                // 活动订阅层在前（仅对 alive 有意义），dead 一律最后
                idx.sort_by_key(|&i| (if hs[i].alive { layer(i) } else { 0 }, !hs[i].alive));
                idx
            }
            Policy::Fixed(_) | Policy::FixedName(_) => {
                // fixed 是显式点名：不做订阅分层（避免层逻辑抢走用户指定的成员）。
                // 名字点名在每次排序时**重新解析**，订阅刷新重排成员后仍指向同一节点。
                let k = match &*pol {
                    Policy::Fixed(k) => (*k < n).then_some(*k),
                    Policy::FixedName(nm) => (0..n).find(|&i| &inner.members[i].name == nm),
                    _ => None,
                };
                let mut idx = Vec::with_capacity(n);
                if let Some(k) = k {
                    idx.push(k);
                }
                idx.extend((0..n).filter(|&i| Some(i) != k));
                idx.sort_by(|&a, &b| {
                    let ca = if Some(a) == k {
                        0
                    } else if hs[a].alive {
                        1
                    } else {
                        2
                    };
                    let cb = if Some(b) == k {
                        0
                    } else if hs[b].alive {
                        1
                    } else {
                        2
                    };
                    // O6：同健康类别内优先 AES-GCM（AES-NI 平台）。
                    ca.cmp(&cb).then_with(|| {
                        inner.members[a]
                            .outbound
                            .crypto_pref()
                            .cmp(&inner.members[b].outbound.crypto_pref())
                    })
                });
                idx
            }
            _ => {
                let mut idx: Vec<usize> = (0..n).collect();
                // 键 =（dead, 层, 是否有延迟）：dead 最后；活动订阅层优先；
                // 同层内已知延迟先于未探测，再按 metric/crypto 排序。
                let key = |i: usize| -> (u8, u8, u8) {
                    if !hs[i].alive {
                        (1, 0, 2)
                    } else if Self::metric_with(&pol, &hs[i]).is_some() {
                        (0, layer(i), 0)
                    } else {
                        (0, layer(i), 1)
                    }
                };
                idx.sort_by(|&a, &b| {
                    key(a)
                        .cmp(&key(b))
                        .then_with(|| {
                            let ma = Self::metric_with(&pol, &hs[a]).unwrap_or(f64::INFINITY);
                            let mb = Self::metric_with(&pol, &hs[b]).unwrap_or(f64::INFINITY);
                            ma.partial_cmp(&mb).unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .then_with(|| {
                            // O6：同健康/同延迟时优先 AES-GCM（AES-NI 平台）。
                            inner.members[a]
                                .outbound
                                .crypto_pref()
                                .cmp(&inner.members[b].outbound.crypto_pref())
                        })
                });
                idx
            }
        }
    }

    fn note_dial(inner: &GroupInner, i: usize, ok: bool, tolerance: u32) {
        let mut hs = Self::health_lock(inner);
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
        let inner = self.inner();
        let tol = self.check_tolerance;
        let mut last_err: Option<std::io::Error> = None;
        let mut tried = 0usize;
        for &i in order.iter().take(3.max(1)) {
            self.stats.dials.fetch_add(1, Ordering::Relaxed);
            match inner.members[i].outbound.dial_tcp(target, timeout) {
                Ok(d) => {
                    Self::note_dial(&inner, i, true, tol);
                    return Ok(d);
                }
                Err(e) => {
                    Self::note_dial(&inner, i, false, tol);
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

    /// 选一个支持 UDP 的成员（按延迟顺序遍历；不支持的成员免费跳过，
    /// 真实拨号失败至多重试 3 个）。
    ///
    /// 修复（2026-10-08）：旧实现 `order.iter().take(3)` 只看延迟榜前 3 名——
    /// 真实订阅里 anytls/reality 常占据前列（前者无 UDP、后者协商不支持），
    /// 导致即使组内有上百个可用 vless 成员，UDP 也永远回退直连。
    /// 本遍历成本极低：不支持的成员仅一次能力判定位；`Ok(None)`（如 reality）
    /// 不产生任何 IO。
    pub fn dial_udp(
        &self,
        target: std::net::SocketAddr,
        timeout: Duration,
    ) -> std::io::Result<Option<outbound::UdpRelay>> {
        let order = self.select_order();
        let inner = self.inner();
        let tol = self.check_tolerance;
        let mut last_err: Option<std::io::Error> = None;
        let mut tried = 0usize;
        for &i in order.iter() {
            if tried >= 3 {
                break;
            }
            if !inner.members[i].outbound.supports_udp() {
                continue;
            }
            match inner.members[i].outbound.dial_udp(target, timeout) {
                Ok(Some(r)) => {
                    Self::note_dial(&inner, i, true, tol);
                    return Ok(Some(r));
                }
                Ok(None) => continue,
                Err(e) => {
                    Self::note_dial(&inner, i, false, tol);
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
        self.inner()
            .members
            .iter()
            .any(|m| m.outbound.supports_udp())
    }

    /// 健康快照（状态面用）。
    pub fn snapshot(&self) -> Vec<NodeSnap> {
        let inner = self.inner();
        let hs = Self::health_lock(&inner);
        inner
            .members
            .iter()
            .zip(hs.iter())
            .map(|(m, h)| NodeSnap {
                name: m.name.clone(),
                tag: m.tag.clone(),
                alive: h.alive,
                last_ms: h.last_ms,
                ema_ms: h.ema_ms,
                facts: m.outbound.facts(),
            })
            .collect()
    }

    /// 启动健康探测线程：周期性经每个成员连接 check 目标，成功即更新延迟/存活。
    /// P19：成员为空也启动（订阅热更新可能后续替换进成员）。
    pub fn spawn_health_loop(self: &Arc<Self>) {
        if self.check_targets.is_empty() && self.udp_check_dns.is_none() {
            return;
        }
        let g = self.clone();
        std::thread::spawn(move || {
            // 优雅空闲：探测频率跟随「有没有人用」——有人看状态（面板/CLI）或有流量时按
            // `check_interval`；两者都无则指数退避到 `probe_idle_cap`（默认 600s）。
            // 退避期间分片睡眠（每秒醒一次），一旦有人看/有流量立刻恢复活跃探测。
            let base = g.check_interval_secs.max(1);
            let active_window = base.max(30);
            let mut idle_rounds: u32 = 0;
            let mut last_logged: u64 = 0;
            loop {
                let watched = crate::watched_recently(20);
                let busy = crate::traffic_active(active_window);
                let cap = g.idle_cap_secs.load(Ordering::Relaxed);
                let interval = probe_interval_for(base, cap, watched, busy, &mut idle_rounds);
                if interval != last_logged {
                    crate::log(&format!(
                        "健康探测节奏 {}s（{}；{}）",
                        interval,
                        if watched || busy {
                            "活跃"
                        } else {
                            "空闲退避"
                        },
                        if watched {
                            "有人在看状态"
                        } else if busy {
                            "最近有流量"
                        } else {
                            "无人看且无流量"
                        }
                    ));
                    last_logged = interval;
                }
                g.stats.probe_interval.store(interval, Ordering::Relaxed);
                g.stats
                    .probe_active
                    .store(u64::from(watched || busy), Ordering::Relaxed);

                let n = g.member_count();
                let mut i = 0;
                // P19：并发 24（原 8）——大订阅（66+ 节点）首轮收敛从 ~70s 降到 ~20s，
                // 缩短网关启动后「健康数据空窗期」的浏览卡顿。
                //
                // ⚠ 这里**不用** `std::thread::scope`：scope 会等待批内全部线程结束，
                // 任一探测卡死在无超时的 socket 读上即拖垮整轮探测。生产实测
                //（2026-10-09）：探测循环停摆数小时 → `ema_ms` 全空 → MinMovingAvg
                // 无值可排 → 组退化按索引取成员 → 命中失效入口，拨号失败率 40%。
                // 改为独立 spawn + 带超时的收集：超时未回的线程被放弃（其迟到结果
                // 仍经 `record_probe` 记入，不丢），主循环必定继续。
                while i < n {
                    // 安全网：在跑的探测线程撞顶说明大量探测卡死未退，本轮跳过。
                    let live = PROBE_LIVE.load(Ordering::Relaxed);
                    if live >= PROBE_MAX_LIVE {
                        crate::log(&format!(
                            "健康探测: 存活探测线程 {live} 已达上限 {PROBE_MAX_LIVE}（大量探测未退出），\
                             本轮跳过；若持续出现请上报（根因见标记为 dial 的握手超时）"
                        ));
                        break;
                    }
                    let end = (i + 24).min(n);
                    let (tx, rx) = std::sync::mpsc::channel::<()>();
                    for j in i..end {
                        let g = g.clone();
                        let tx = tx.clone();
                        PROBE_LIVE.fetch_add(1, Ordering::Relaxed);
                        let b = std::thread::Builder::new()
                            .name("probe".into())
                            .stack_size(PROBE_STACK);
                        if b.spawn(move || {
                            let _guard = ProbeLiveGuard;
                            let _ = g.probe(j);
                            let _ = tx.send(());
                        })
                        .is_err()
                        {
                            PROBE_LIVE.fetch_sub(1, Ordering::Relaxed);
                            crate::log("健康探测: 线程创建失败，跳过该成员本轮");
                        }
                    }
                    drop(tx);
                    let deadline = Instant::now() + PROBE_BATCH_DEADLINE;
                    let mut done = 0usize;
                    while done < end - i {
                        let left = deadline.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            let lost = (end - i) - done;
                            g.stats
                                .probes_stragglers
                                .fetch_add(lost as u64, Ordering::Relaxed);
                            crate::log(&format!(
                                "健康探测: 本批 {lost} 个成员超过 {}s 未回，放弃等待（探测可能被无超时的读阻塞）",
                                PROBE_BATCH_DEADLINE.as_secs()
                            ));
                            break;
                        }
                        // 超时或通道关闭都回到循环重算剩余额度；额度耗尽即 break。
                        if rx.recv_timeout(left).is_ok() {
                            done += 1;
                        }
                    }
                    i = end;
                    // 撞顶就中断本轮剩余批次（不再继续攒线程）
                    if PROBE_LIVE.load(Ordering::Relaxed) >= PROBE_MAX_LIVE {
                        crate::log(&format!(
                            "健康探测: 本轮提前结束（存活探测线程达上限 {PROBE_MAX_LIVE}）"
                        ));
                        break;
                    }
                }
                // P34：探测一轮后刷新活动订阅层（切换在探测周期内记日志，空闲期也可见）
                {
                    let inner = g.inner();
                    let hs = Self::health_lock(&inner);
                    g.note_active_layer(&inner, &hs);
                }
                // 分片睡眠：退避期间被「叫醒」时不等待剩余时间
                let mut slept = 0u64;
                while slept < interval {
                    std::thread::sleep(Duration::from_secs(1));
                    slept += 1;
                    if slept < interval
                        && (crate::watched_recently(20) || crate::traffic_active(active_window))
                    {
                        break;
                    }
                }
            }
        });
    }

    /// 记录一次探测结果（UDP/TCP 共用）。
    fn record_probe(&self, inner: &GroupInner, i: usize, ok: bool, ms: u64) {
        let tol = self.check_tolerance;
        if ok {
            self.stats.probes_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.probes_fail.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(h) = Self::health_lock(inner).get_mut(i) {
            h.note_probe(ok, ms, tol);
        }
    }

    /// UDP DNS 探测：经该节点向 udp_check_dns 发一条最小 DNS 查询并等应答。
    /// （dae `udp_check_dns` 语义；目标需在构建时解析为 IP:port。）
    fn udp_probe(out: &outbound::Outbound, dns: &(String, u16)) -> std::io::Result<()> {
        let target: std::net::SocketAddr = format!("{}:{}", dns.0, dns.1)
            .parse()
            .map_err(|e| std::io::Error::other(format!("udp_check_dns 目标非法: {e}")))?;
        let relay = out
            .dial_udp(target, Duration::from_secs(5))?
            .ok_or_else(|| std::io::Error::other("outbound 不支持 UDP"))?;
        relay.set_read_timeout(Some(Duration::from_secs(3)))?;
        relay.send_payload(&dns_query())?;
        let mut buf = [0u8; 512];
        let r = relay.recv_payload(&mut buf)?;
        if r.is_empty() {
            return Err(std::io::Error::other("UDP check 空响应"));
        }
        Ok(())
    }

    fn probe(&self, i: usize) -> std::io::Result<()> {
        let inner = self.inner();
        let Some(member) = inner.members.get(i) else {
            return Ok(());
        };
        let t0 = Instant::now();
        // P18e：配置 udp_check_dns 且成员支持 UDP 时，优先 UDP DNS 探测；
        // 失败回退 TCP（dae health check：UDP 能力节点以 UDP 检查为主）。
        if let Some(dns) = self.udp_check_dns.as_ref() {
            if member.outbound.supports_udp() {
                if let Ok(()) = Self::udp_probe(&member.outbound, dns) {
                    self.record_probe(&inner, i, true, t0.elapsed().as_millis() as u64);
                    return Ok(());
                }
            }
        }
        let Some((host, port)) = self.check_targets.first().cloned() else {
            return Ok(());
        };
        let target: Target = format!("{host}:{port}")
            .parse()
            .map_err(|e| std::io::Error::other(format!("check 目标非法: {e}")))?;
        let d = match member.outbound.dial_tcp(&target, Duration::from_secs(5)) {
            Ok(d) => d,
            Err(e) => {
                // 拨号失败必须计入健康状态（否则死节点永远不会被标死）
                self.record_probe(&inner, i, false, 0);
                return Err(e);
            }
        };
        // 发一个 HTTP/1.0 请求并等任意响应（echo 型目标也会回；QUIC 无底层 socket 时仅计拨号成功）
        let mut ok = true;
        if let Some(sock) = d.socket.as_ref() {
            // 硬超时：**失败即判探测失败**。旧行为是 `let _ = set_read_timeout(..)`
            // 丢弃返回值，超时未生效时后面的 read 可永久阻塞（生产事故根因之一）。
            if let Err(e) = sock.set_read_timeout(Some(Duration::from_secs(3))) {
                self.record_probe(&inner, i, false, 0);
                return Err(std::io::Error::other(format!(
                    "check: 设置读超时失败（{e}），拒绝无限期等待"
                )));
            }
            let _ = sock.set_write_timeout(Some(Duration::from_secs(3)));
            let mut d = d;
            let req = format!("GET /generate_204 HTTP/1.0\r\nHost: {host}\r\n\r\n");
            let mut ok_write = d.to_remote.write_all(req.as_bytes()).is_ok();
            ok_write &= d.to_remote.flush().is_ok();
            let mut buf = [0u8; 64];
            let read_ok = matches!(d.from_remote.read(&mut buf), Ok(n) if n > 0);
            ok = ok_write && read_ok;
        }
        let ms = t0.elapsed().as_millis() as u64;
        self.record_probe(&inner, i, ok, ms);
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::other("check 无响应"))
        }
    }
}

/// 最小 DNS A 查询（ID 固定；健康探测只需任意应答）。
fn dns_query() -> Vec<u8> {
    let mut q = Vec::with_capacity(29);
    q.extend_from_slice(&0x1234u16.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in [b"a" as &[u8], b"com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label);
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    q
}

/// 从已解析节点 + 组配置构建成员（filter 命中；空 filter = 全部）。
pub fn build_members(nodes: &[ParsedNode], filters: &[Vec<config::Function>]) -> Vec<Member> {
    nodes
        .iter()
        .filter(|n| filter_match(filters, &n.name, &n.tag))
        .map(|n| Member {
            name: n.name.clone(),
            tag: n.tag.clone(),
            rank: n.rank,
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
    fn select_order_prefers_chacha_on_tie() {
        // O6：延迟/健康相同时，chacha 节点排在 AES 前面（本客户端 RustCrypto
        // 实测 chacha 1.73 GB/s > aes-256-gcm 1.57 GB/s @16KB）。
        let mk = |url: &str, name: &str| Member {
            name: name.into(),
            tag: "t".into(),
            rank: 0,
            outbound: crate::outbound::parse(url).unwrap(),
        };
        let g = GroupRuntime::new(
            "g".into(),
            Policy::Min,
            vec![
                mk("ss://aes-256-gcm:pw@127.0.0.1:8389", "aes"),
                mk("ss://chacha20-ietf-poly1305:pw@127.0.0.1:8388", "chacha"),
            ],
            vec![],
            30,
            1,
            None,
        );
        {
            let inner = g.inner();
            let mut hs = GroupRuntime::health_lock(&inner);
            for h in hs.iter_mut() {
                h.alive = true;
                h.last_ms = Some(10);
                h.ema_ms = Some(10.0);
            }
        }
        let order = g.select_order();
        assert_eq!(order[0], 1, "同延迟时应优先 chacha 节点（实测更快）");
    }

    #[test]
    fn replace_members_inherits_health_by_name_tag() {
        // P18e：订阅热更新——同名+tag 成员继承健康/延迟，新成员默认健康。
        let dummy = crate::outbound::Outbound::Direct;
        let mk = |name: &str| Member {
            name: name.into(),
            tag: "t".into(),
            rank: 0,
            outbound: dummy.clone(),
        };
        let g = GroupRuntime::new(
            "g".into(),
            Policy::Min,
            vec![mk("a"), mk("b")],
            vec![],
            30,
            1,
            None,
        );
        {
            let inner = g.inner();
            let mut hs = GroupRuntime::health_lock(&inner);
            hs[0].note_probe(true, 33, 0);
            hs[1].alive = false;
        }
        let (n, inherited) = g.replace_members(vec![mk("a"), mk("c")]);
        assert_eq!(n, 2);
        assert_eq!(inherited, 1, "a 应继承");
        let snap = g.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].name, "a");
        assert!(snap[0].alive, "a 继承 alive");
        assert_eq!(snap[0].last_ms, Some(33), "a 继承 last_ms");
        assert_eq!(snap[1].name, "c");
        assert!(snap[1].alive, "新成员默认 alive");
        assert_eq!(snap[1].last_ms, None);
        assert_eq!(g.member_count(), 2);
    }

    #[test]
    fn policy_parse() {
        assert_eq!(parse_policy(Some("random")), Policy::Random);
        assert_eq!(parse_policy(Some("min")), Policy::Min);
        assert_eq!(parse_policy(Some("min_avg10")), Policy::MinAvg10);
        assert_eq!(parse_policy(Some("fixed(2)")), Policy::Fixed(2));
        // 名字点名（引号可省）
        assert_eq!(
            parse_policy(Some("fixed('日本02')")),
            Policy::FixedName("日本02".into())
        );
        assert_eq!(
            parse_policy(Some("fixed(\"HK-01\")")),
            Policy::FixedName("HK-01".into())
        );
        assert_eq!(
            parse_policy(Some("fixed(HK-01)")),
            Policy::FixedName("HK-01".into())
        );
        assert_eq!(parse_policy(Some("fixed()")), Policy::MinMovingAvg);
        assert_eq!(parse_policy(None), Policy::MinMovingAvg);
        assert_eq!(parse_policy(Some("nonsense")), Policy::MinMovingAvg);
        // 状态面可读名
        assert_eq!(policy_name(&Policy::FixedName("x".into())), "fixed('x')");
        assert_eq!(policy_name(&Policy::MinMovingAvg), "min_moving_avg");
    }

    #[test]
    fn fixed_name_survives_member_reorder() {
        // 订阅刷新会重排成员索引；名字点名必须仍指向同一节点（索引点名会指错）。
        let dummy = crate::outbound::Outbound::Direct;
        let mk = |name: &str| Member {
            name: name.into(),
            tag: "t".into(),
            rank: 0,
            outbound: dummy.clone(),
        };
        let g = GroupRuntime::new(
            "g".into(),
            Policy::FixedName("b".into()),
            vec![mk("a"), mk("b"), mk("c")],
            vec![],
            30,
            1,
            None,
        );
        assert_eq!(g.select_order()[0], 1, "b 在索引 1");
        // 重排：c, b, a → 名字点名的“b”应变成索引 1 仍是 b（这个顺序下巧合），
        // 关键是**名字**不变；再用 a 在末位的顺序验证。
        g.replace_members(vec![mk("b"), mk("c"), mk("a")]);
        let order = g.select_order();
        assert_eq!(order[0], 0, "b 现在在索引 0");
        let snap = g.snapshot();
        assert_eq!(snap[order[0]].name, "b", "首位仍是名字 b");
        let (cur, pinned, ok) = g.current_and_pinned();
        assert_eq!(cur, Some(0));
        assert_eq!(pinned.as_deref(), Some("b"));
        assert!(ok);
    }

    #[test]
    fn probe_interval_backs_off_when_idle() {
        let mut n = 0u32;
        // 有人看 / 有流量：保持基准节奏
        assert_eq!(probe_interval_for(30, 600, true, false, &mut n), 30);
        assert_eq!(n, 0, "活跃时清零退避");
        assert_eq!(probe_interval_for(30, 600, false, true, &mut n), 30);
        // 空闲：30 → 60 → 120 → 240 → 480 → 600（封顶）
        let seq: Vec<u64> = (0..7)
            .map(|_| probe_interval_for(30, 600, false, false, &mut n))
            .collect();
        assert_eq!(seq, vec![60, 120, 240, 480, 600, 600, 600]);
        // 被叫醒：立刻回到基准
        assert_eq!(probe_interval_for(30, 600, true, false, &mut n), 30);
        assert_eq!(n, 0);
        // cap = 0：明确不退避
        let mut z = 0u32;
        assert_eq!(probe_interval_for(30, 0, false, false, &mut z), 30);
        assert_eq!(probe_interval_for(30, 0, false, false, &mut z), 30);
        assert_eq!(z, 0);
    }

    #[test]
    fn policy_hot_swap() {
        // reload 时热替换策略（控制面板“锁定/恢复自动”依赖它即时生效）。
        let dummy = crate::outbound::Outbound::Direct;
        let mk = |name: &str| Member {
            name: name.into(),
            tag: "t".into(),
            rank: 0,
            outbound: dummy.clone(),
        };
        let g = GroupRuntime::new(
            "g".into(),
            Policy::MinMovingAvg,
            vec![mk("a"), mk("b")],
            vec![],
            30,
            1,
            None,
        );
        assert!(matches!(*g.policy(), Policy::MinMovingAvg));
        g.set_policy(Policy::FixedName("b".into()));
        assert_eq!(g.select_order()[0], 1);
        assert_eq!(g.current_and_pinned().1.as_deref(), Some("b"));
        assert!(g.current_and_pinned().2, "命中成员");
        g.set_policy(Policy::FixedName("missing".into()));
        let (_, name, ok) = g.current_and_pinned();
        assert_eq!(name.as_deref(), Some("missing"), "仍报点名（UI 可提示）");
        assert!(!ok, "未命中成员");
        g.set_policy(Policy::MinMovingAvg);
        assert!(matches!(*g.policy(), Policy::MinMovingAvg));
    }

    #[test]
    fn fixed_name_unknown_falls_back_to_pool() {
        // 点名的节点不在池里（订阅被删/改名）：不死锁，按池内顺序兜底。
        let dummy = crate::outbound::Outbound::Direct;
        let members = vec![Member {
            name: "a".into(),
            tag: "t".into(),
            rank: 0,
            outbound: dummy,
        }];
        let g = GroupRuntime::new(
            "g".into(),
            Policy::FixedName("missing".into()),
            members,
            vec![],
            30,
            1,
            None,
        );
        assert_eq!(g.select_order().len(), 1);
        let (cur, pinned, ok) = g.current_and_pinned();
        assert_eq!(cur, Some(0), "兜底到池内");
        assert_eq!(pinned.as_deref(), Some("missing"));
        assert!(!ok);
    }

    #[test]
    fn group_codec_reactor_capable_requires_all_members() {
        // 生产实测（2026-10-08）：旧实现漏了 Group，`codec_reactor_capable()` 落
        // `_ => false`，而生产 dialer 正是 `group:proxy` ⟹ 所有代理连接退回双泵
        // 线程路径（现场拟合 `线程 = 15.9 + 2.39 × 活跃连接`，Reactor 池空转）。
        let mk = |o: crate::outbound::Outbound, n: &str| Member {
            name: n.into(),
            tag: "t".into(),
            rank: 0,
            outbound: o,
        };
        // Trojan 代表「已审计 WouldBlock 可重入」的一族（vless/anytls/vmess/ss/ssr/trojan）
        let capable = || crate::outbound::Outbound::Trojan {
            server: "1.2.3.4:443".parse().unwrap(),
            password: "p".into(),
            sni: "s.example".into(),
            insecure: false,
        };
        // 空组：不放行（订阅尚未到达时不冒险）
        let empty = GroupRuntime::new("g".into(), Policy::Min, vec![], vec![], 30, 1, None);
        assert!(!empty.codec_reactor_capable_all(), "空组不放行");
        // 全为 capable → 放行
        let all_ok = GroupRuntime::new(
            "g".into(),
            Policy::Min,
            vec![mk(capable(), "a"), mk(capable(), "b")],
            vec![],
            30,
            1,
            None,
        );
        assert!(all_ok.codec_reactor_capable_all(), "全 capable 应放行");
        // 混入一个不支持的（Direct 代表 tuic/hy2/juicity/naive/QUIC 一族）→ 整组不放行
        let mixed = GroupRuntime::new(
            "g".into(),
            Policy::Min,
            vec![
                mk(capable(), "a"),
                mk(crate::outbound::Outbound::Direct, "b"),
            ],
            vec![],
            30,
            1,
            None,
        );
        assert!(!mixed.codec_reactor_capable_all(), "混协议应保守不放行");
        // 订阅热更新把成员换掉后，结论应随之改变（不做缓存）
        mixed.replace_members(vec![mk(capable(), "a")]);
        assert!(mixed.codec_reactor_capable_all(), "换成员后应重新判定");
    }

    #[test]
    fn select_order_min_prefers_low_latency_alive() {
        let dummy = crate::outbound::Outbound::Direct;
        let members = vec![
            Member {
                name: "slow".into(),
                tag: "t".into(),
                rank: 0,
                outbound: dummy.clone(),
            },
            Member {
                name: "fast".into(),
                tag: "t".into(),
                rank: 0,
                outbound: dummy.clone(),
            },
            Member {
                name: "dead".into(),
                tag: "t".into(),
                rank: 0,
                outbound: dummy,
            },
        ];
        let g = GroupRuntime::new("g".into(), Policy::Min, members, vec![], 30, 1, None);
        {
            let inner = g.inner();
            let mut hs = GroupRuntime::health_lock(&inner);
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
    fn select_order_prefers_earlier_subscription_rank() {
        // P34：订阅顺序回退——同 rank 内按 policy；跨 rank 时活动层优先（即使延迟更差），
        // 主源全部标死才切下一源；`subscription_failover=false` 恢复池化。
        let dummy = crate::outbound::Outbound::Direct;
        let mk = |name: &str, rank: u32| Member {
            name: name.into(),
            tag: format!("s{rank}"),
            rank,
            outbound: dummy.clone(),
        };
        let members = vec![mk("primary", 0), mk("backup", 1)];
        let g = GroupRuntime::new(
            "g".into(),
            Policy::MinMovingAvg,
            members,
            vec![],
            30,
            1,
            None,
        );
        {
            let inner = g.inner();
            let mut hs = GroupRuntime::health_lock(&inner);
            hs[0].note_probe(true, 200, 1); // 主源延迟更差也不动摇顺序
            hs[1].note_probe(true, 20, 1);
        }
        assert_eq!(g.select_order()[0], 0, "rank 小的在前");
        assert_eq!(g.active_tag().as_deref(), Some("s0"));

        // 主源标死 → 活动层切到下一源
        {
            let inner = g.inner();
            let mut hs = GroupRuntime::health_lock(&inner);
            hs[0].alive = false;
        }
        assert_eq!(g.select_order()[0], 1, "主源死后切备用源");
        assert_eq!(g.active_tag().as_deref(), Some("s1"));

        // 关闭顺序回退 → 恢复池化：按延迟挑（备用源更快）
        g.set_sub_failover(false);
        {
            let inner = g.inner();
            let mut hs = GroupRuntime::health_lock(&inner);
            hs[0].alive = true;
        }
        assert_eq!(g.select_order()[0], 1, "池化模式按延迟");
        assert_eq!(g.active_tag(), None);
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
            None,
        );
        assert!(g.probe(0).is_err());
        assert_eq!(g.stats.probes_fail.load(Ordering::Relaxed), 1);
        assert_eq!(g.stats.probes_ok.load(Ordering::Relaxed), 0);
        assert!(!g.snapshot()[0].alive, "一次失败 + tolerance=0 应标死");
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

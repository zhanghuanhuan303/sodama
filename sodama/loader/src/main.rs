// SPDX-License-Identifier: GPL-2.0
/*
 * sodama 加载器：用 Rust + aya 复现 dae 控制面里与数据面相关的最小职责。
 *
 * 对照 dae（Go 侧）：
 *   - pkg/ebpf_internal + control/bpf_utils.go  : 加载 ELF、建 map、配 rodata
 *   - control/control_plane_core_bind.go        : 挂 tc 钩子（含 dae netns 里的 dae0peer）
 *   - control/tcp.go / dns_listener.go          : 创建 tproxy 监听 socket 并放进 sockmap
 *   - control/routing_matcher_builder.go        : 把路由规则编译进 BPF map（双 epoch 槽）
 *   - control/conn_state_janitor.go             : 清理 conn_state 过期条目
 *
 * K0–K3 已实现：
 *   - 规则下发走「非活跃槽 → 切 active」的热重载（SIGHUP 触发，不重挂钩子）；
 *   - LAN ingress / WAN egress / WAN ingress / dae0 / dae0peer 五种钩子角色
 *     + 单臂 dual-role 合用程序；
 *   - conn_state 过期清扫（用户态 janitor）；
 *   - K3：`--config <file.dae>` 全量配置解析（loader/src/config.rs）、只读状态面
 *     （`--status-socket`，Unix socket JSON）、可选「过渡一跳」（`--forward socks5://…`）。
 *
 * 与 dae 的差异：
 *   - 监听 socket 由本进程直接 accept（dae 交给 session manager/relay）；
 *   - 规则是 dae 路由语法的子集（见 rules.rs）；无法编译的能力显式列入 deferred
 *     （不静默丢弃，见 config.rs extract_routing）；P17a/P17b 后 dae 现有
 *     routing 函数已全部覆盖；
 *   - pname 由 cgroup2 钩子采集（comm，非 argv basename；见 cgroup.rs / ADR-0033）。
 */
// status_json 的 json! 对象随功能增长逼近宏默认递归上限（P23 起）。
#![recursion_limit = "512"]

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aya::maps::lpm_trie::Key;
use aya::maps::{
    Array, ArrayOfMaps, HashMap, LpmTrie, MapData, PerCpuHashMap, RingBuf, SockHash, SockMap,
};
use aya::programs::tc::{self, TcAttachType};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SchedClassifier, SkSkb};
use aya::programs::{CgroupSockAddrAttachType, CgroupSockAttachType};
use aya::programs::{FEntry, KProbe, Xdp, XdpMode};
use aya::{Btf, Ebpf};
use serde_json::json;

mod anytls;
mod bootstrap;
mod brutal;
mod btfoff;
mod bufpool;
mod config;
mod dns;
mod dns_pref_wait;
mod dnsroute;
mod dnsup;
mod dump;
#[cfg(test)]
mod fuzz_smoke;
mod geodata;
mod group;
mod h2client;
mod h3client;
mod hpack;
mod huffman_table;
mod hysteria2;
mod ifwatch;
mod juicity;
mod outbound;
mod quicsniff;
mod quicsock;
mod quicvarint;
mod reactor;
mod real_domain;
mod reality;
mod rules;
mod ruleset;
mod shadowtls;
mod sniffer;
mod socks5;
mod socksin;
mod ss;
mod ssr;
mod ssr_cipher;
mod status;
mod sticky;
mod subscribe;
mod sysctl;
mod target;
mod tls;
mod tls13;
mod trojan;
mod tuic;
mod vision;
mod vless;
mod vmess;
mod watch;
mod ws;

/// dae 给控制面自己的 socket 打的内部 mark（对照 so_mark_from_dae / dae_socket_mark）。
/// 副作用：避免监听 socket 的 sk_mark 为 0 时新连接继承 SYN 上的 TPROXY_MARK
/// （内核 net.ipv4.tcp_fwmark_accept=1 时的 inet_request_mark 行为）。
const DAE_SOCKET_MARK: libc::c_int = 0x233;

/// musl 的 `recvmmsg` flags 为 `c_uint`，gnu 为 `c_int`——按目标环境对齐类型，
/// 保证同一源码在 glibc / musl（OpenWrt 等）都能编。
#[cfg(target_env = "musl")]
pub(crate) const MSG_WAITFORONE: libc::c_uint = libc::MSG_WAITFORONE as libc::c_uint;
#[cfg(not(target_env = "musl"))]
pub(crate) const MSG_WAITFORONE: libc::c_int = libc::MSG_WAITFORONE;

/// 与 ebpf-rs/src/common.rs 的 SODAMA_MAX_MATCH_SET_LEN 保持一致。
const MAX_MATCH_SET_LEN: u32 = rules::MAX_MATCH_SET_LEN;
const EPOCH_SLOT_NUM: u32 = 2;
/// conn_state janitor 扫描间隔
const JANITOR_INTERVAL: Duration = Duration::from_secs(5);

static RELOAD: AtomicBool = AtomicBool::new(false);
/// P38：日志时间戳开关（`--disable-timestamp` / config global.disable_timestamp）。
static LOG_TS_OFF: AtomicBool = AtomicBool::new(false);
static ACTIVE_SLOT: AtomicU32 = AtomicU32::new(0);
/// P6：SIGUSR2（`dae suspend` 同义）/ 状态面 suspend → 主循环置位 control_flags_map；
/// SIGHUP/reload 清除（对照 dae 「suspend 后用 reload 恢复」）。
static SUSPEND_REQ: AtomicBool = AtomicBool::new(false);
static SUSPENDED: AtomicBool = AtomicBool::new(false);
/// P6：最近一次 reload 的结果（状态面/CLI 可查）。
static LAST_RELOAD: Mutex<Option<ReloadOutcome>> = Mutex::new(None);
#[derive(Clone)]
struct ReloadOutcome {
    ok: bool,
    match_sets: usize,
    slot: u32,
    error: Option<String>,
    at_sec: u64,
}
/// P6：`--log-file`（轮转友好：SIGHUP reload 时 reopen）。
static LOG_PATH: OnceLock<String> = OnceLock::new();
static LOG_SINK: Mutex<Option<std::fs::File>> = Mutex::new(None);
/// A2 #2：内建日志轮转参数（MB / 保留份数；0 = 关轮转 / 不保留，对照 dae lumberjack 的
/// `--logfile-maxsize`/`--logfile-maxbackups`）。
static LOG_MAX_SIZE_MB: AtomicU64 = AtomicU64::new(0);
static LOG_MAX_BACKUPS: AtomicU64 = AtomicU64::new(3);
/// 当前日志文件已写入字节数（轮转判定用；开文件时以文件大小为初值）。
static LOG_WRITTEN: AtomicU64 = AtomicU64::new(0);
/// A2 #6：日志级别（0=off 1=error 2=warn 3=info 4=debug；默认 info）。
static LOG_LEVEL: AtomicU32 = AtomicU32::new(3);
/// CLI 子命令：日志改走 stderr，保持 stdout 只有机器可读输出（JSON/文本）。
static LOG_STDERR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// 只读状态面：进程启动时间 / 监听端口 / 钩子列表 / 最近编译结果 / 配置解析结果
static STARTED: OnceLock<Instant> = OnceLock::new();
static TPROXY_PORT: AtomicU32 = AtomicU32::new(0);
static HOOKS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static LAST_RULES: Mutex<Option<rules::CompiledRules>> = Mutex::new(None);
static CONFIG_STATE: Mutex<Option<(config::Config, config::RoutingExtract)>> = Mutex::new(None);
/// P4/P5：代理出口（Dialer）——direct / socks5 / shadowsocks / trojan（G1）。
/// None = 保留实验回显行为（lab 的回归用例）。
static OUTBOUND: OnceLock<outbound::Outbound> = OnceLock::new();
/// P4a：accept 线程（daens）→ relay 线程池（host ns）的连接转交通道
static TCP_RELAY_TX: OnceLock<std::sync::mpsc::Sender<TcpStream>> = OnceLock::new();
/// P19：全部用户组（顺序 = config `group` 段顺序；outbound 索引 = GROUP_INDEX_BASE + i）。
static GROUP_SET: OnceLock<std::sync::RwLock<GroupSet>> = OnceLock::new();
/// P19：conn_state_map 的 fd（dup；relay/UDP 线程按 5 元组回读该连接选中的组）。
static CONN_STATE_MAP_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
/// routing_handoff_map 的 dup fd（首包路由兜底读取用；模式同上）。
static HANDOFF_MAP_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// P19：组集合与默认组（`--group` 指定 > proxy > 第一个）。
#[derive(Default)]
struct GroupSet {
    groups: Vec<std::sync::Arc<group::GroupRuntime>>,
    default_idx: usize,
}

impl GroupSet {
    fn by_outbound(&self, outbound: u8) -> Option<&std::sync::Arc<group::GroupRuntime>> {
        if !(rules::GROUP_INDEX_BASE..rules::OUTBOUND_MUST_RULES).contains(&outbound) {
            return None; // direct/block/must_rules/control_plane/逻辑编码 → 不是用户组
        }
        self.groups
            .get((outbound - rules::GROUP_INDEX_BASE) as usize)
    }

    fn default_group(&self) -> Option<&std::sync::Arc<group::GroupRuntime>> {
        self.groups.get(self.default_idx)
    }
}

/// P19：组名 → outbound 索引（与 build_groups 的构建顺序严格一致）。
fn group_index_map(cfg: Option<&config::Config>) -> std::collections::HashMap<String, u8> {
    let specs = cfg.map(config::groups).unwrap_or_default();
    let mut m = std::collections::HashMap::new();
    if specs.is_empty() {
        m.insert("proxy".to_string(), rules::GROUP_INDEX_BASE);
    }
    for (i, s) in specs.iter().enumerate() {
        m.insert(s.name.clone(), rules::GROUP_INDEX_BASE + i as u8);
    }
    m
}
/// relay 连接空闲回收阈值（秒）；janitor 每 5s 扫描一次。
static RELAY_IDLE_SECS: AtomicU64 = AtomicU64::new(300);
/// M1：relay splice 零拷贝开关（默认开；`--no-splice` 关闭）。
static RELAY_SPLICE: AtomicBool = AtomicBool::new(true);
/// I6：会话建立/relay 入口线程栈（默认 8 MiB 对万级瞬时建立意味着可观的虚拟内存；
/// 实际调用深度远低于 1 MiB，全量回归覆盖）。
const RELAY_HANDLER_STACK: usize = 1 << 20;
/// M1：splice 不可用回退日志（只打一次，避免刷屏）。
static SPLICE_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);
/// P11：relay 拨号超时（毫秒，默认 5000；真实节点首连可能较慢）
static RELAY_DIAL_TIMEOUT_MS: AtomicU64 = AtomicU64::new(5000);
/// P4b：UDP NAT 会话空闲阈值（秒）。
static UDP_IDLE_SECS: AtomicU64 = AtomicU64::new(60);
/// P33/P35：配置热驱动——`--watch-config`/`watch_config` 的值：inotify 不可用时的
/// 兜底扫描秒数（0=关）；inotify 事件驱动本身是毫秒级（见 `watch` 模块）。
static CONFIG_WATCH_INTERVAL: AtomicU64 = AtomicU64::new(0);
/// P35：热驱动传输方式（true=inotify 已启用，false=纯兜底轮询）。
static CONFIG_WATCH_INOTIFY: AtomicBool = AtomicBool::new(false);
/// P35：订阅节点缓存 TTL（秒；watch 触发的 fast reload 复用，0=关）。
/// P37（B1）：默认 60 → 1800——未变源在配置热重载时 0 请求（对齐 dae 语义：
/// 订阅拉取不随配置热重载发生；内容更新交给周期刷新/手动 reload）。
static SUB_CACHE_TTL_SECS: AtomicU64 = AtomicU64::new(1800);
/// P37（B2）：失败源负缓存窗口（秒；fast 重载对窗口内失败源不打网，0=关）。
/// 与自愈退避（300s·2^n）/429 冷却（15min）互补：这里管「配置热重载别去敲失败源」。
static SUB_FAIL_TTL_SECS: AtomicU64 = AtomicU64::new(600);
/// P35：订阅节点缓存（url → (抓取时刻, 节点)）——「改订阅顺序」这类 reload 不再重走网络。
static SUB_NODE_CACHE: OnceLock<
    Mutex<std::collections::HashMap<String, (Instant, std::sync::Arc<Vec<subscribe::ParsedNode>>)>>,
> = OnceLock::new();
/// P36：规则集仓库（`rule_set` 段加载结果；状态面可查）。
static RULESET_STORE: OnceLock<Mutex<ruleset::RuleSetStore>> = OnceLock::new();
/// P36：本地规则集文件（加入 inotify 监听——编辑用户名单文件即热生效）。
static RULESET_FILES: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());

// ---- P14：嗅探 / dial_mode（远端域名解析）----
/// 0=ip（默认，不嗅探）| 1=domain | 2=domain+（当前同 domain）。
static DIAL_MODE: AtomicU8 = AtomicU8::new(0);
/// 嗅探等待上限（毫秒）；只在 dial_mode != ip 时生效。
static SNIFF_TIMEOUT_MS: AtomicU64 = AtomicU64::new(100);
/// P21：嗅探重判开关（`--sniff-punt` 或 config `global.auto_sniff_punt: true`）。
static SNIFF_PUNT: AtomicBool = AtomicBool::new(false);

struct SniffStats {
    attempts: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    /// P18e：识别到的 QUIC Initial 包（长头 + ≥1200B；仅识别，不含解密结果）。
    quic_initial: AtomicU64,
    /// P20：Initial 解密后成功解出 SNI 的计数。
    quic_sni: AtomicU64,
    /// P21：重判尝试 / 判为 direct / 判为 block / 判为用户组 / 保持原决策。
    punt_attempts: AtomicU64,
    punt_direct: AtomicU64,
    punt_block: AtomicU64,
    punt_group: AtomicU64,
    punt_keep: AtomicU64,
}
impl SniffStats {
    const fn new() -> Self {
        Self {
            attempts: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            quic_initial: AtomicU64::new(0),
            quic_sni: AtomicU64::new(0),
            punt_attempts: AtomicU64::new(0),
            punt_direct: AtomicU64::new(0),
            punt_block: AtomicU64::new(0),
            punt_group: AtomicU64::new(0),
            punt_keep: AtomicU64::new(0),
        }
    }
}
static SNIFF_STATS: SniffStats = SniffStats::new();

fn dial_mode_name(mode: u8) -> &'static str {
    match mode {
        1 => "domain",
        2 => "domain+",
        _ => "ip",
    }
}

/// A2 #10：`dial_mode: domain` 的「真实域名」判定（对照 dae `ChooseDialTarget`）：
/// 1. DNS 控制器已知（我们的 DNS 缓存在任意作用域有 A/AAAA 新鲜记录）→ 确认 + 域名拨号；
/// 2. 确认集命中 → 域名拨号；
/// 3. 负缓存命中 → 按 IP 拨号（不再探测）；
/// 4. 未知 → 异步探测 + **本连接按 IP 拨号**（不阻塞首屏路径；与 dae 同）。
fn real_domain_ok(domain: &str) -> bool {
    if real_domain::is_ip_like(domain) {
        return false;
    }
    // 1) DNS 已知（任一 IP 版本的新鲜记录都算「像真实域名」）。
    let now = Instant::now();
    let dns_known = DNS_CACHE.lock().ok().is_some_and(|c| {
        c.has_fresh_any_scope(domain, 1, now) || c.has_fresh_any_scope(domain, 28, now)
    });
    if dns_known {
        real_domain::remember(domain);
        return true;
    }
    match real_domain::lookup(domain, now) {
        Some(true) => true,
        Some(false) => false,
        None => {
            // 异步探测（单飞近似）；本次按 IP 拨号。
            real_domain::trigger_probe(domain);
            false
        }
    }
}

#[derive(Default)]
struct RelayStats {
    conns_total: AtomicU64,
    conns_active: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    dial_errors: AtomicU64,
    evicted: AtomicU64,
    offloaded_total: AtomicU64,
    offload_failures: AtomicU64,
    /// M1：splice 零拷贝连接数 / 不可用回退次数。
    splice_total: AtomicU64,
    splice_fallbacks: AtomicU64,
    /// I2：fd 预算压力导致的 splice 降级次数。
    splice_fd_budget: AtomicU64,
    /// I2：pipe 懒建/复用/释放计数（worker 本地缓存）。
    pipe_created: AtomicU64,
    pipe_reused: AtomicU64,
    pipe_released: AtomicU64,
    /// H1：带残留字节而被丢弃（不入缓存）的 pipe 数——应为个位数（RST/异常收尾时）。
    pipe_discarded: AtomicU64,
    /// P18e：并发上限拒绝数（--max-conns）。
    limit_rejected: AtomicU64,
    /// M4：交给 Reactor 的 codec 会话数（每连接 0 线程）。
    /// 生产实测（2026-10-08）旧实现下恒为 0：组拨号未声明 reactor 能力。
    reactor_codec_sessions: AtomicU64,
    /// 对标批：offload 会话在内核路径真实推送的字节（`skb_send_sock` fentry/kprobe
    /// 记账，per-CPU 分桶；用户态在键摘除时汇总 `offload_sent` 得到）。
    offload_sent_bytes: AtomicU64,
    /// 背压 fuse（对照 dae `fuseStep`/`tcp_offload_pause`）：engage / lift / 失败计数。
    fuse_engages: AtomicU64,
    fuse_lifts: AtomicU64,
    fuse_failures: AtomicU64,
}
static RELAY_STATS: RelayStats = RelayStats {
    conns_total: AtomicU64::new(0),
    conns_active: AtomicU64::new(0),
    bytes_up: AtomicU64::new(0),
    bytes_down: AtomicU64::new(0),
    dial_errors: AtomicU64::new(0),
    evicted: AtomicU64::new(0),
    offloaded_total: AtomicU64::new(0),
    offload_failures: AtomicU64::new(0),
    splice_total: AtomicU64::new(0),
    splice_fallbacks: AtomicU64::new(0),
    splice_fd_budget: AtomicU64::new(0),
    pipe_created: AtomicU64::new(0),
    pipe_reused: AtomicU64::new(0),
    pipe_released: AtomicU64::new(0),
    pipe_discarded: AtomicU64::new(0),
    limit_rejected: AtomicU64::new(0),
    reactor_codec_sessions: AtomicU64::new(0),
    offload_sent_bytes: AtomicU64::new(0),
    fuse_engages: AtomicU64::new(0),
    fuse_lifts: AtomicU64::new(0),
    fuse_failures: AtomicU64::new(0),
};

// ---- P-AI：按域名统计（面板「AI 流量」卡片的数据源） ------------------------
/// 每域名累计（仅在连接打开/收尾各取一次锁；数据路径零查表）。
#[derive(Default)]
struct DomainStat {
    conns: AtomicU64,
    active: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    last_ns: AtomicU64,
}

/// 域名表上限：超出后不再为新域名建条目（已有域名照常累计），保持有界。
const DOMAIN_STATS_MAX: usize = 512;

/// AI 服务域名后缀表（对齐 docs/examples/ai-low-latency.dae；status 读时判定）。
const AI_DOMAIN_SUFFIXES: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "oaiusercontent.com",
    "sora.com",
    "anthropic.com",
    "claude.ai",
    "claudeusercontent.com",
    "generativelanguage.googleapis.com",
    "aistudio.google.com",
    "gemini.google.com",
    "x.ai",
    "grok.com",
    "cursor.com",
    "cursor.sh",
    "windsurf.com",
    "codeium.com",
    "githubcopilot.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "poe.com",
    "openrouter.ai",
    "groq.com",
    "replicate.com",
    "together.ai",
    "together.xyz",
    "fireworks.ai",
    "fal.ai",
    "deepinfra.com",
    "cerebras.ai",
    "mistral.ai",
    "cohere.com",
    "cohere.ai",
    "lambdalabs.com",
    "sambanova.ai",
    "midjourney.com",
    "suno.com",
    "suno.ai",
    "elevenlabs.io",
    "runwayml.com",
    "pika.art",
    "lumalabs.ai",
    "character.ai",
    "huggingface.co",
];

fn is_ai_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    AI_DOMAIN_SUFFIXES.iter().any(|s| {
        d == *s
            || (d.len() > s.len() && d.ends_with(s) && d.as_bytes()[d.len() - s.len() - 1] == b'.')
    })
}

static DOMAIN_STATS: OnceLock<Mutex<std::collections::HashMap<Box<str>, Arc<DomainStat>>>> =
    OnceLock::new();

fn domain_stats() -> &'static Mutex<std::collections::HashMap<Box<str>, Arc<DomainStat>>> {
    DOMAIN_STATS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// 连接建立（dial 成功后）计入域名统计。
fn domain_stat_open(domain: &str) {
    let Ok(mut m) = domain_stats().lock() else {
        return;
    };
    let st = match m.get(domain) {
        Some(s) => s.clone(),
        None => {
            if m.len() >= DOMAIN_STATS_MAX {
                return; // 有界：不为新域名建条目
            }
            let s = Arc::new(DomainStat::default());
            m.insert(domain.into(), s.clone());
            s
        }
    };
    st.conns.fetch_add(1, Ordering::Relaxed);
    st.active.fetch_add(1, Ordering::Relaxed);
    st.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
}

/// 连接收尾：活跃 -1，累计本连接字节。
fn domain_stat_close(domain: &str, bytes_up: u64, bytes_down: u64) {
    let Ok(m) = domain_stats().lock() else {
        return;
    };
    let Some(st) = m.get(domain).cloned() else {
        return;
    };
    let _ = st
        .active
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    st.bytes_up.fetch_add(bytes_up, Ordering::Relaxed);
    st.bytes_down.fetch_add(bytes_down, Ordering::Relaxed);
    st.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
}

/// status 用：Top 域名（按累计字节降序，最多 30 条）。
fn snapshot_domain_stats() -> serde_json::Value {
    let mut rows: Vec<(Box<str>, Arc<DomainStat>, u64, u64)> = Vec::new();
    if let Some(map) = DOMAIN_STATS.get() {
        if let Ok(m) = map.lock() {
            for (d, st) in m.iter() {
                let up = st.bytes_up.load(Ordering::Relaxed);
                let down = st.bytes_down.load(Ordering::Relaxed);
                rows.push((d.clone(), st.clone(), up, down));
            }
        }
    }
    rows.sort_by_key(|(_, _, up, down)| std::cmp::Reverse(up + down));
    rows.truncate(30);
    serde_json::Value::Array(
        rows.iter()
            .map(|(d, st, up, down)| {
                serde_json::json!({
                    "domain": d.as_ref(),
                    "ai": is_ai_domain(d),
                    "conns": st.conns.load(Ordering::Relaxed),
                    "active": st.active.load(Ordering::Relaxed),
                    "bytes_up": up,
                    "bytes_down": down,
                    "last_seen_secs_ago": monotonic_now_ns()
                        .saturating_sub(st.last_ns.load(Ordering::Relaxed))
                        / 1_000_000_000,
                })
            })
            .collect(),
    )
}

/// P18e：relay 并发上限（0 = 不限；对照 dae relay 的并发上限）。
static RELAY_MAX_CONNS: AtomicU64 = AtomicU64::new(0);

// ---- I2：fd 预算治理 ----

static NOFILE_SOFT: AtomicU64 = AtomicU64::new(0);
static FD_HIGH: AtomicBool = AtomicBool::new(false);
static FD_LAST_CHECK_NS: AtomicU64 = AtomicU64::new(0);

/// 启动时提升 RLIMIT_NOFILE。
///
/// 历史行为只把 soft 提到 hard —— 在 procd/OpenWrt 下 hard 默认 4096，于是
/// 并发上限被卡在 ~1000 连接（每连接 2 socket + 活跃时 2 pipe ≈ 4 fd）。
/// root（CAP_SYS_RESOURCE）可以一并抬高 hard：目标 `min(/proc/sys/fs/nr_open, 262144)`，
/// 失败（非 root / 内核不允）则退回原行为，仅记日志。
fn raise_nofile_limit() {
    const CAP: u64 = 1 << 18; // 262144：够 6 万+ 连接，避免无意义地放大 fd 表
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return;
        }
        let (old_soft, old_hard) = (rl.rlim_cur, rl.rlim_max);
        let nr_open = std::fs::read_to_string("/proc/sys/fs/nr_open")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(CAP);
        let want = nr_open.min(CAP);
        if rl.rlim_max < want {
            rl.rlim_max = want; // 无权限则下面的 setrlimit 整体失败，保持原值
        }
        if rl.rlim_cur < rl.rlim_max {
            rl.rlim_cur = rl.rlim_max;
        }
        let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        let mut now = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::getrlimit(libc::RLIMIT_NOFILE, &mut now);
        NOFILE_SOFT.store(now.rlim_cur, Ordering::Relaxed);
        log(&format!(
            "nofile: soft {old_soft} -> {}，hard {old_hard} -> {}（I2）",
            now.rlim_cur, now.rlim_max
        ));
    }
}

fn fd_used() -> u64 {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count() as u64)
        .unwrap_or(0)
}

/// I2：fd 高压判定（使用率 ≥80%；1s 采样缓存，避免每连接 readdir）。
fn fd_pressure() -> bool {
    let now = monotonic_now_ns();
    let last = FD_LAST_CHECK_NS.load(Ordering::Relaxed);
    if now.saturating_sub(last) > 1_000_000_000 {
        let soft = NOFILE_SOFT.load(Ordering::Relaxed).max(1);
        FD_HIGH.store(fd_used() * 100 / soft >= 80, Ordering::Relaxed);
        FD_LAST_CHECK_NS.store(now, Ordering::Relaxed);
    }
    FD_HIGH.load(Ordering::Relaxed)
}

/// P4c：offload 用的 fast_sock SOCKHASH（从 Ebpf 中取出后由 relay 线程共享写入）。
static RELAY_OFFLOAD: OnceLock<Mutex<SockHash<MapData, SodaTuple>>> = OnceLock::new();
/// P8：Rust/aya-ebpf offload 对象的预检镜像（HASH map，与 fast_sock 同步双写）。
static RELAY_OFFLOAD_GUARD: OnceLock<Mutex<HashMap<MapData, SodaTuple, u8>>> = OnceLock::new();
/// 对标批：`offload_sent` 记账表（key = fast_sock 键，value = 该键方向被内核推送的
/// 字节，per-CPU）。键摘除时汇总并删除；对照 dae `control/kern/tproxy.c:276-287`
/// 的 `tcp_offload_sent`（记账在 `tproxy.c:4324-4393`；其 per-key 背压 fuse 未实现，
/// 本表只做归因计量）。
static OFFLOAD_SENT: OnceLock<Mutex<PerCpuHashMap<MapData, SodaTuple, u64>>> = OnceLock::new();

/// offload 背压 fuse 的 pause 表（键在 = verdict 改回 SK_PASS，数据交用户态泵）。
/// 对照 dae `tcp_offload_pause`（`control/tcp_offload_linux.go` 的 fuseStep）。
/// 数据面是 LRU_HASH；用户态用 `HashMap` 承载（aya 的 `TryFrom` 支持 LruHashMap 变体）。
static OFFLOAD_PAUSE: OnceLock<Mutex<HashMap<MapData, SodaTuple, u8>>> = OnceLock::new();

/// 出口连通性投影句柄（Array；每 2s 由 `connectivity_loop` 从组健康刷新）。
/// 对照 dae `outbound_connectivity_map` + `resumeOutboundConnectivityUpdates`。
static OUTBOUND_CONNECTIVITY: OnceLock<Mutex<Array<MapData, u32>>> = OnceLock::new();
/// `outbound_connectivity_map` 项数（256 出口 × 3 domain × 2 IP 版本）。
/// 与 `ebpf-rs/src/common.rs` 的 `SODAMA_CONNECTIVITY_MAP_SIZE` 保持一致。
const CONNECTIVITY_MAP_SIZE: u32 = 1536;
/// 上次投影的 dead 组数（status 用；0 = 全部存活）。
static CONNECTIVITY_DEAD_GROUPS: AtomicU64 = AtomicU64::new(0);

/// 出口连通性投影（对照 dae `control/connectivity.go:135-186`）：
/// 仅 `dial_mode=ip` 且策略非 random/fixed 时把真实健康写入数据面；否则恒写 1
/// （保留用户态选择/回退）。键域：outbound*6 + domain*2 + ipver（3 domain × 2 版本）。
///
/// P38 修复（实测）：**全键域投影**（`GROUP_INDEX_BASE..OUTBOUND_MUST_RULES`），
/// 未被组覆盖的索引写 1。旧实现只遍历组，而 map 是零初始化 Array（0 = dead）——
/// 「无 group 段」的配置里路由给隐式 proxy 索引（即 `GROUP_INDEX_BASE`），该索引
/// 永远不被组覆盖 → 恒为 0 → 新流**首包**被 `flow.rs::outbound_is_alive` 门禁 SHOT
/// （debug 实测：`route outbound=0x2` 打出后 `udp_nat.sessions_total` 不增长）。
/// 每 tick 全量写（250 索引 × 6 = 1500 次 map set，µs 级）同时覆盖 reload 后
/// 组集缩小留下的陈旧槽（旧代某组标死 → 新代无该组 → 槽位滞留 0 的隐患）。
fn publish_outbound_connectivity() {
    let Some(gs_lock) = GROUP_SET.get() else {
        return;
    };
    let Some(map_lock) = OUTBOUND_CONNECTIVITY.get() else {
        return;
    };
    let mode = DIAL_MODE.load(Ordering::Relaxed);
    let gs = match gs_lock.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let Ok(mut map) = map_lock.lock() else {
        return;
    };
    let mut dead = 0u64;
    for outbound in rules::GROUP_INDEX_BASE..rules::OUTBOUND_MUST_RULES {
        let g = gs.groups.get((outbound - rules::GROUP_INDEX_BASE) as usize);
        let alive: u32 = match g {
            // 无组覆盖（无 group 段 / 组数少于索引）→ 乐观默认为存活。
            None => 1,
            Some(g) => {
                let publish_health = mode == 0
                    && g.member_count() > 0
                    && !matches!(
                        &*g.policy(),
                        group::Policy::Random
                            | group::Policy::Fixed(_)
                            | group::Policy::FixedName(_)
                    );
                if publish_health && !g.snapshot().iter().any(|n| n.alive) {
                    0
                } else {
                    1
                }
            }
        };
        if alive == 0 {
            dead += 1;
        }
        for domain in 0..3u32 {
            for ipv in 0..2u32 {
                let key = (outbound as u32) * 6 + domain * 2 + ipv;
                let _ = map.set(key, alive, 0);
            }
        }
    }
    CONNECTIVITY_DEAD_GROUPS.store(dead, Ordering::Relaxed);
}

/// 投影循环（2s tick；幂等写，开销 = 250 索引 × 6 次 map set）。
/// 首次启动晚于组构建：循环内部容忍 GROUP_SET/句柄未就绪（early return；
/// 该窗口内 map 的乐观初值由 main 取图时的一次性全量置 1 保底）。
///
/// P38 修复（实测）：旧行为是「先 sleep 2s 再首次投影」，而 `outbound_connectivity_map`
/// 是零初始化 Array——在首次投影前所有出口都是 0（dead），新流的**首包**会被
/// `flow.rs::outbound_is_alive` 门禁 SHOT。实测现象：启动后第一个 UDP 报文/第一个 TCP
/// 首连必失败（曾被记为「QEMU 首连抖动」，devlog §19）。改为**先投影再睡眠**，
/// 并在启动首次下发规则后立即再投影一次（见 main 主流程）。
fn connectivity_loop() {
    loop {
        publish_outbound_connectivity();
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ---- P4b：UDP NAT ----

#[derive(Default)]
struct UdpNatStats {
    sessions_total: AtomicU64,
    /// P5：经协议栈（G1=shadowsocks）代理的会话数
    sessions_proxied: AtomicU64,
    /// P5：协议不支持 UDP 时的直连回退数（有 dialer 但非 ss 时计数；无 dialer 不计数）
    direct_fallback: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    evicted: AtomicU64,
    errors: AtomicU64,
    /// M3 修复：回包 socket 表超限逐出的条目数。
    reply_sockets_evicted: AtomicU64,
    /// P38：full-cone 端点（按客户端 src 复用）创建数 / 负缓存命中数 / raw UDP 回退回数。
    cone_sessions: AtomicU64,
    negcache_hits: AtomicU64,
    raw_udp_fallbacks: AtomicU64,
}
static UDP_NAT_STATS: UdpNatStats = UdpNatStats {
    sessions_total: AtomicU64::new(0),
    sessions_proxied: AtomicU64::new(0),
    direct_fallback: AtomicU64::new(0),
    bytes_up: AtomicU64::new(0),
    bytes_down: AtomicU64::new(0),
    evicted: AtomicU64::new(0),
    errors: AtomicU64::new(0),
    reply_sockets_evicted: AtomicU64::new(0),
    cone_sessions: AtomicU64::new(0),
    negcache_hits: AtomicU64::new(0),
    raw_udp_fallbacks: AtomicU64::new(0),
};

/// P38：UDP 端点键（对照 dae `UdpEndpointKey`）：`dst=None` 即 **Full-Cone**——
/// 同一客户端 src 的任意目标共用一个出口（上行按包 `send_to`）；`dst=Some` 为
/// dest-affine（QUIC Initial / 嗅探到域名 / 代理型协议——会话即目标）。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct UdpFlowKey {
    client: SocketAddr,
    dst: Option<SocketAddr>,
}

/// 一条 UDP NAT 会话（端点）。full-cone 端点回包按每包来源选源地址（见 `reply_send`）。
struct UdpSession {
    /// P38：自己的键（退役摘表用；full-cone 的键不含 dst）。
    key: UdpFlowKey,
    client: SocketAddr,
    relay: outbound::UdpRelay,
    last_ns: AtomicU64,
    alive: AtomicBool,
    /// P38：创建时的数据面代次（`reload --abort` 只关旧代会话）。
    generation: u16,
    /// P38：端点 TTL（秒；dae 分类：DNS 17 / QUIC|域名 300 / 代理地板 300 / NAT 默认）。
    ttl_secs: u64,
    /// P38：full-cone 端点（dst=None）——上行按包目标发送，回包按来源选源。
    full_cone: bool,
}

static UDP_NAT: std::sync::LazyLock<Vec<UdpNatShard>> = std::sync::LazyLock::new(|| {
    (0..UDP_NAT_SHARDS)
        .map(|_| Mutex::new(std::collections::HashMap::new()))
        .collect()
});
type UdpNatShard = Mutex<std::collections::HashMap<UdpFlowKey, Arc<UdpSession>>>;

/// O7：会话表分片数（单锁在包速率下会成为竞争点；按 key hash 选片）。
const UDP_NAT_SHARDS: usize = 16;
/// O7：监听/回程一次 recvmmsg 最多收包数。
const UDP_RECV_BATCH: usize = 32;

/// P38：端点 TTL 分类（对照 dae `control/udp.go` 常量）：DNS 17s / QUIC|域名 5min /
/// 代理型 dialer 地板 5min。
const UDP_TTL_DNS_SECS: u64 = 17;
const UDP_TTL_QUIC_SECS: u64 = 300;
const UDP_TTL_PROXY_FLOOR_SECS: u64 = 300;

/// O7：批量路径开关（`SODAMA_UDP_BATCH=0` 回退逐包，供 A/B）。
static UDP_BATCH_ON: OnceLock<bool> = OnceLock::new();
fn udp_batch_on() -> bool {
    *UDP_BATCH_ON.get_or_init(|| std::env::var("SODAMA_UDP_BATCH").map_or(true, |v| v != "0"))
}

fn fnv_step(h: &mut u64, b: u8) {
    *h ^= b as u64;
    *h = h.wrapping_mul(0x0000_0100_0000_01b3);
}

/// 轻量会话 hash（FNV-1a；避免 SipHash 每包开销）。
fn udp_nat_shard(key: &UdpFlowKey) -> &'static UdpNatShard {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for ip in [
        key.client.ip(),
        key.dst.map(|d| d.ip()).unwrap_or(key.client.ip()),
    ] {
        match ip {
            std::net::IpAddr::V4(v4) => {
                for b in v4.octets() {
                    fnv_step(&mut h, b);
                }
            }
            std::net::IpAddr::V6(v6) => {
                for b in v6.octets() {
                    fnv_step(&mut h, b);
                }
            }
        }
    }
    for p in [
        key.client.port(),
        key.dst.map(|d| d.port()).unwrap_or_default(),
    ] {
        for b in p.to_be_bytes() {
            fnv_step(&mut h, b);
        }
    }
    &UDP_NAT[(h as usize) % UDP_NAT_SHARDS]
}

/// relay 活跃连接注册表（janitor 据此空闲回收）。
struct RelayHandle {
    last_ns: AtomicU64,
    /// P4c：已 offload 的连接由内核对拼，用户态看不到流量也不回收。
    offloaded: AtomicBool,
    /// P7：offload 看门狗（半关闭/终止检测）置位后，驻留的泵线程退出并回收 socket。
    stop: AtomicBool,
    /// I2：reactor 接管的会话不克隆 socket（看门狗改走 `reactor::kill(id)`），
    /// 仅 offload/传统线程泵路径保留可 shutdown 的 fd 句柄（各 −2 fd/连接）。
    reactor_managed: bool,
    client: Option<TcpStream>,
    /// QUIC 协议（tuic）没有底层 TCP，为 None。
    upstream: Option<TcpStream>,
    /// P-AI：本连接归属域名（收尾归入域名统计；IP 直连为 None）。
    domain: Option<Box<str>>,
    /// P38：创建时的数据面代次（`reload --abort` 只关闭旧代会话）。
    generation: u16,
    /// P38：(client, orig_dst) 五元组（abort 时清对应 conn_state）。
    conn_key: Option<(SocketAddr, SocketAddr)>,
    /// P-AI：本连接字节明细（泵双写：全局统计 + 本字段）。
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}
static RELAY_CONNS: std::sync::LazyLock<Mutex<std::collections::HashMap<u64, Arc<RelayHandle>>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
static NEXT_RELAY_ID: AtomicU64 = AtomicU64::new(1);

/// P3a/P6/P18a/P18c：DNS 上游集合（tag → Upstream）+ legacy 单上游。
/// P6 起支持热重载（`--config` 模式下重读 dns.upstream 并重建）；P18c 起多上游 + dns.routing。
struct UpstreamSet {
    by_tag: std::collections::HashMap<String, Arc<dnsup::Upstream>>,
    /// 无 dns.routing 时的默认上游（对照旧行为）。
    legacy: Arc<dnsup::Upstream>,
    /// `asis` 用的按目的地址缓存（每个地址一把 marked UDP socket）。
    asis: Mutex<std::collections::HashMap<SocketAddr, Arc<dnsup::Upstream>>>,
}

impl UpstreamSet {
    fn get(&self, tag: &str) -> Option<Arc<dnsup::Upstream>> {
        self.by_tag.get(tag).cloned()
    }

    /// 客户端原始目的地址（仅 UDP；对照 dae `AsIs` 语义）。
    fn asis(&self, orig: SocketAddr) -> Result<Arc<dnsup::Upstream>, String> {
        if let Ok(g) = self.asis.lock() {
            if let Some(u) = g.get(&orig) {
                return Ok(u.clone());
            }
        }
        let host = match orig.ip() {
            std::net::IpAddr::V4(a) => a.to_string(),
            std::net::IpAddr::V6(a) => format!("[{a}]"),
        };
        let u = dnsup::Upstream::new(&format!("udp://{host}:{}", orig.port()))
            .map_err(|e| format!("asis 上游 {orig}: {e}"))?;
        if let Ok(mut g) = self.asis.lock() {
            g.insert(orig, u.clone());
        }
        Ok(u)
    }
}

/// P18c：按出口统计的请求路由选路次数（tag/asis/legacy/reject）；
/// DNS 线程写、状态面读，Mutex 持有时间极短。
static DNS_TAG_HITS: std::sync::LazyLock<Mutex<std::collections::HashMap<String, u64>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

fn note_tag_hit(tag: &str) {
    if let Ok(mut g) = DNS_TAG_HITS.lock() {
        *g.entry(tag.to_string()).or_insert(0) += 1;
    }
}

static UPSTREAMS: Mutex<Option<Arc<UpstreamSet>>> = Mutex::new(None);
/// P18c：`dns.routing` 编译结果（None = 无该段，走 legacy 单上游）。
static DNS_ROUTER: Mutex<Option<Arc<dnsroute::DnsRouter>>> = Mutex::new(None);
/// P38：`dns.bind` 已启动的监听描述（status 面展示；None = 未配置/启动失败）。
static DNS_BIND: Mutex<Option<String>> = Mutex::new(None);

fn upstreams() -> Option<Arc<UpstreamSet>> {
    UPSTREAMS.lock().ok().and_then(|g| g.clone())
}

fn set_upstreams(u: Arc<UpstreamSet>) {
    if let Ok(mut g) = UPSTREAMS.lock() {
        *g = Some(u);
    }
}

fn dns_router() -> Option<Arc<dnsroute::DnsRouter>> {
    DNS_ROUTER.lock().ok().and_then(|g| g.clone())
}

fn set_dns_router(r: Option<Arc<dnsroute::DnsRouter>>) {
    if let Ok(mut g) = DNS_ROUTER.lock() {
        *g = r;
    }
}

/// 状态面/旧代码兼容：取 legacy 上游。
fn upstream() -> Option<Arc<dnsup::Upstream>> {
    upstreams().map(|s| s.legacy.clone())
}
static DOMAIN_SETS: Mutex<Vec<rules::DomainSetSpec>> = Mutex::new(Vec::new());
/// P23：dns 段选项（optimistic cache / fixed_domain_ttl / ipversion_prefer）。
#[derive(Default, Clone)]
struct DnsOpts {
    ipversion_prefer: u8,
    fixed_domain_ttl: std::collections::HashMap<String, u32>,
}
static DNS_OPTS: std::sync::LazyLock<Mutex<DnsOpts>> =
    std::sync::LazyLock::new(|| Mutex::new(DnsOpts::default()));

/// 域名归一化（fixed_domain_ttl 的键匹配）。
fn dns_key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// P23：从配置 dns 段读取选项并应用到缓存（启动/reload 均可）。
fn apply_dns_options(cfg: Option<&config::Config>) {
    let mut opts = DnsOpts::default();
    let mut optimistic = true;
    let mut optimistic_ttl = 60u32;
    let mut stale_ttl = 30u32;
    if let Some(cfg) = cfg {
        for sec in cfg.sections.iter().filter(|s| s.name == "dns") {
            for item in &sec.items {
                match item {
                    config::Item::Param(p) => {
                        let key = p.key.as_deref().unwrap_or("");
                        let val = p.val.as_deref().unwrap_or("").trim().to_string();
                        match key {
                            "ipversion_prefer" => {
                                opts.ipversion_prefer = match val.as_str() {
                                    "4" => 4,
                                    "6" => 6,
                                    _ => 0,
                                }
                            }
                            "optimistic_cache" => {
                                optimistic = matches!(val.as_str(), "true" | "1" | "yes" | "on")
                            }
                            "optimistic_cache_ttl" => optimistic_ttl = val.parse().unwrap_or(60),
                            "optimistic_stale_reply_ttl" => stale_ttl = val.parse().unwrap_or(30),
                            _ => {}
                        }
                    }
                    config::Item::Section(s) if s.name == "fixed_domain_ttl" => {
                        for it in &s.items {
                            if let config::Item::Param(p) = it {
                                if let (Some(k), Some(v)) = (&p.key, &p.val) {
                                    match v.trim().parse::<u32>() {
                                        Ok(t) => {
                                            opts.fixed_domain_ttl.insert(dns_key(k), t);
                                        }
                                        Err(e) => log(&format!(
                                            "dns.fixed_domain_ttl {k}: TTL 非法（{e}），忽略"
                                        )),
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if let Ok(mut c) = DNS_CACHE.lock() {
        c.set_options(optimistic, optimistic_ttl, stale_ttl);
    }
    let summary = format!(
        "dns 选项: ipversion_prefer={} optimistic_cache={optimistic} \
         optimistic_cache_ttl={optimistic_ttl} optimistic_stale_reply_ttl={stale_ttl} \
         fixed_domain_ttl={}",
        opts.ipversion_prefer,
        opts.fixed_domain_ttl.len()
    );
    let changed = opts.ipversion_prefer != 0 || !opts.fixed_domain_ttl.is_empty();
    *DNS_OPTS.lock().unwrap_or_else(|p| p.into_inner()) = opts;
    if changed {
        log(&summary);
    }
}

fn dns_opts() -> DnsOpts {
    DNS_OPTS.lock().map(|g| g.clone()).unwrap_or_default()
}
/// P3b-1：DNS 应答缓存（UDP/TCP 共用；锁仅短暂持有）
static DNS_CACHE: std::sync::LazyLock<Mutex<dns::DnsCache>> =
    std::sync::LazyLock::new(|| Mutex::new(dns::DnsCache::default()));
/// P3b-1：accept 线程（daens）→ TCP DNS 处理线程（host ns）的连接转交通道
static TCP_DNS_TX: OnceLock<std::sync::mpsc::Sender<TcpStream>> = OnceLock::new();

#[derive(Default)]
struct DnsStats {
    queries: AtomicU64,
    responses: AtomicU64,
    published_ips: AtomicU64,
    upstream_errors: AtomicU64,
    aaaa_published: AtomicU64,
    tcp_unsupported: AtomicU64,
    tcp_queries: AtomicU64,
    tcp_responses: AtomicU64,
    bitmap_matched: AtomicU64,
    /// P18c：请求路由 reject 数
    rejects: AtomicU64,
    /// P18c：应答路由 reject 数
    response_rejects: AtomicU64,
    /// P18c：应答路由换上游重查数
    relookups: AtomicU64,
    /// P23：ipversion_prefer 过滤（非首选族回空 NOERROR）数
    ipversion_filtered: AtomicU64,
    /// P28：上游应答带 ECS 回显（回填 scope）的次数
    ecs_echo: AtomicU64,
    /// P29：后台刷新：发起（实际执行）次数 / 合并（已有在飞）次数 / 失败
    refresh_spawned: AtomicU64,
    refresh_coalesced: AtomicU64,
    refresh_err: AtomicU64,
    /// P38：`dns.bind` 明文监听收到的查询数
    bind_queries: AtomicU64,
}
static DNS_STATS: DnsStats = DnsStats {
    queries: AtomicU64::new(0),
    responses: AtomicU64::new(0),
    published_ips: AtomicU64::new(0),
    upstream_errors: AtomicU64::new(0),
    aaaa_published: AtomicU64::new(0),
    tcp_unsupported: AtomicU64::new(0),
    tcp_queries: AtomicU64::new(0),
    tcp_responses: AtomicU64::new(0),
    bitmap_matched: AtomicU64::new(0),
    rejects: AtomicU64::new(0),
    response_rejects: AtomicU64::new(0),
    relookups: AtomicU64::new(0),
    ipversion_filtered: AtomicU64::new(0),
    ecs_echo: AtomicU64::new(0),
    refresh_spawned: AtomicU64::new(0),
    refresh_coalesced: AtomicU64::new(0),
    refresh_err: AtomicU64::new(0),
    bind_queries: AtomicU64::new(0),
};

/// P28：最近一次 ECS 回填 scope（状态面展示，如 `10.9.10.0/16` / `0.0.0.0/0`）。
static ECS_SCOPE_LAST: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

extern "C" fn on_sighup(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

/// O8：SIGTERM/SIGINT = 优雅退出（有界等待；见 `graceful_shutdown`）。
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_shutdown(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// P6：SIGUSR2 = suspend（对照 dae `dae suspend`），由主循环写 control_flags_map。
extern "C" fn on_sigusr2(_sig: libc::c_int) {
    SUSPEND_REQ.store(true, Ordering::SeqCst);
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SodaConfig {
    tproxy_port: u32,
    dae0_ifindex: u32,
    datapath_generation: u16,
    dae0peer_mac: [u8; 6],
    /// A2 #6：控制面 socket 的 SO_MARK（`so_mark_from_dae`；数据面据此跳过自环）。
    so_mark: u32,
}
unsafe impl aya::Pod for SodaConfig {}

/// 数据面代次（u16，非 0）：启动时由时间种子随机、每次 reload 递增。
/// 数据面把写时的代次+epoch 槽记进 conn_state；纯 SYN 按「同代拒改 / 异代重路由」
/// 分流（对照 dae `nextDatapathGeneration`，`control/datapath_generation.go:20-27`；
/// sodama 的冷启动代次必与上一次不同——跨重启保留的 pinned 条目因此不会误判同代）。
static DATAPATH_GENERATION: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn init_datapath_generation() -> u16 {
    let cur = DATAPATH_GENERATION.load(Ordering::SeqCst);
    if cur != 0 {
        return cur;
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() ^ d.as_secs() as u32) as u16)
        .unwrap_or(1)
        | 1;
    DATAPATH_GENERATION.store(seed, Ordering::SeqCst);
    seed
}

fn next_datapath_generation() -> u16 {
    loop {
        let cur = DATAPATH_GENERATION.load(Ordering::SeqCst);
        let mut next = cur.wrapping_add(1);
        if next == 0 {
            next = 1;
        }
        if DATAPATH_GENERATION
            .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return next;
        }
    }
}

/// reload 时递增代次并回写 config_map（生效于数据面纯 SYN 重绑判定）。
/// 对照 dae：每次换代重建 datapath 时写新 `PARAM.datapath_generation`。
fn bump_datapath_generation(ebpf: &mut Ebpf) {
    let gen = next_datapath_generation();
    let Some(map) = ebpf.map_mut("config_map") else {
        return;
    };
    let Ok(mut arr) = Array::<_, SodaConfig>::try_from(map) else {
        return;
    };
    if let Ok(cur) = arr.get(&0, 0) {
        let next = SodaConfig {
            datapath_generation: gen,
            ..cur
        };
        if arr.set(0, next, 0).is_ok() {
            log(&format!("datapath generation -> {gen}"));
        }
    }
}

fn current_datapath_generation() -> u16 {
    let v = DATAPATH_GENERATION.load(Ordering::SeqCst);
    if v == 0 {
        1
    } else {
        v
    }
}

/// conn_state_map 的 pin 路径（对照 dae `LIBBPF_PIN_BY_NAME` + `/sys/fs/bpf/dae`；
/// sodama 用 `/sys/fs/bpf/sodama/conn_state_map`）。
const CONN_STATE_PIN_DIR: &str = "/sys/fs/bpf/sodama";
fn conn_state_pin_path() -> std::path::PathBuf {
    std::path::Path::new(CONN_STATE_PIN_DIR).join("conn_state_map")
}

/// 把 pinned 旧 conn_state_map 的条目迁移进新表，然后 pin 新表。
/// 对照 dae：`LIBBPF_PIN_BY_NAME`（跨重启保留）+「Loader may override pinning on
/// cold start」；sodama 用一次性搬迁替代 libbpf 的 pinned map 复用——旧条目的
/// `datapath_generation` 与新进程不同，纯 SYN 会按「异代重路由」处理（语义正确）。
/// 尽力而为：/sys/fs/bpf 不可写、旧表不兼容等都只告警不阻断启动。
fn migrate_pinned_conn_state(ebpf: &mut Ebpf, capacity: u32) {
    let path = conn_state_pin_path();
    let mut migrated: u64 = 0;
    let mut dropped: u64 = 0;
    if path.exists() {
        match aya::maps::MapData::from_pin(&path) {
            Ok(old_data) => {
                let mut entries: Vec<(SodaTuple, SodaConnState)> = Vec::new();
                if let Ok(old) = HashMap::<MapData, SodaTuple, SodaConnState>::try_from(
                    aya::maps::Map::HashMap(old_data),
                ) {
                    // 容量上限防御：旧表可能来自更大的配置。
                    for kv in old.iter().take(capacity as usize).flatten() {
                        entries.push(kv);
                    }
                }
                if let Some(map) = ebpf.map_mut("conn_state_map") {
                    if let Ok(mut new_map) = HashMap::<_, SodaTuple, SodaConnState>::try_from(map) {
                        for (k, v) in &entries {
                            match new_map.insert(k, v, 0) {
                                Ok(()) => migrated += 1,
                                Err(_) => dropped += 1,
                            }
                        }
                    }
                }
            }
            Err(e) => log(&format!("conn_state pin: 读旧表失败（{e}），跳过迁移")),
        }
        // 旧 pin 必须先摘掉（pin 新表会 EEXIST）。
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log(&format!("conn_state pin: 摘除旧 pin 失败（{e}）"));
            }
        }
    }
    // pin 新表（失败降级：无 pinning = 重启后状态不保留，靠无状态放行兜底）。
    match std::fs::create_dir_all(CONN_STATE_PIN_DIR) {
        Ok(()) => {
            if let Some(aya::maps::Map::HashMap(md)) = ebpf.map("conn_state_map") {
                if let Err(e) = md.pin(&path) {
                    log_warn(&format!("conn_state pin: 失败（{e}），重启后状态不保留"));
                }
            }
        }
        Err(e) => log_warn(&format!(
            "conn_state pin: 目录不可用（{e}），重启后状态不保留"
        )),
    }
    if migrated > 0 || dropped > 0 {
        log(&format!(
            "conn_state pin: 迁移 {migrated} 条（容量外丢弃 {dropped}）"
        ));
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct SodaTuple {
    /// 与 ebpf-rs 同位：16 字节地址（IPv4 为 v4-mapped），is_v6 区分家族。
    sip: [u8; 16],
    dip: [u8; 16],
    sport: u16,
    dport: u16,
    l4proto: u8,
    is_v6: u8,
    pad: [u8; 2],
}
unsafe impl aya::Pod for SodaTuple {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SodaConnState {
    last_seen_ns: u64,
    mark: u32,
    outbound: u8,
    must: u8,
    has_routing: u8,
    l4proto: u8,
    is_wan_ingress_direction: u8,
    routing_epoch_slot: u8,
    pad: [u8; 2],
    datapath_generation: u16,
}
unsafe impl aya::Pod for SodaConnState {}

/// 首包路由结果交接（兜底；与 ebpf-rs/src/common.rs 的 `SodaRoutingHandoffEntry` 同位）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SodaRoutingHandoffEntry {
    last_seen_ns: u64,
    result: u64,
    datapath_generation: u16,
    dscp: u8,
    pad: u8,
    mac: [u8; 6],
}
unsafe impl aya::Pod for SodaRoutingHandoffEntry {}

/// handoff 条目陈旧阈值（sodama 侧；见 ebpf-rs/common.rs `SODAMA_HANDOFF_TTL_NS`）。
const SODAMA_HANDOFF_TTL_NS: u64 = 30_000_000_000;

/// handoff 条目是否过期（读取侧与 janitor 共用同一判定）。
fn handoff_expired(now_ns: u64, last_seen_ns: u64, ttl_ns: u64) -> bool {
    last_seen_ns <= now_ns && now_ns - last_seen_ns > ttl_ns
}

/// 与 ebpf-rs/src/common.rs 的 `SodaTraceParam` 同位（16 字节）。
/// 字段= `struct sk_buff` 的字节偏移（用户态 BTF 解出后写入；a/k/a «CO-RE 替代»）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TraceParam {
    network_header: u32,
    transport_header: u32,
    tail: u32,
    head: u32,
}
unsafe impl aya::Pod for TraceParam {}

/// C3：与 ebpf-rs/src/common.rs 的 `SodaEvent` 同位（72 字节）。
/// 字段布局对照 dae `struct dae_event`（`kern/tproxy.c:694-703`）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SodaEvent {
    timestamp: u64,
    type_: u32,
    pid: u32,
    pname: [u8; 16],
    outbound: u8,
    l4proto: u8,
    pad: [u8; 2],
    sip: [u8; 16],
    dip: [u8; 16],
    sport: u16,
    dport: u16,
}
unsafe impl aya::Pod for SodaEvent {}

/// 事件类型常量（与 ebpf-rs/src/common.rs 逐位对齐）。
const EV_BLOCKED: u32 = 0;
const EV_UDP_CONN_OVERFLOW: u32 = 1;
const EV_TCP_CONN_OVERFLOW: u32 = 2;
const EV_BLOCKED_ALIVE: u32 = 3;
const EV_REDIRECT_REBIND_REJECTED: u32 = 4;
const EV_SYN_REBIND_REJECTED: u32 = 5;
const EV_REDIRECT_UPDATE_FAILED: u32 = 8;
const EV_SYN_REBIND_REROUTED: u32 = 9;
/// A2 #3：trace 事件（sodama 自有；判决在 `SodaEvent.pad[0]`）。
const EV_TRACE: u32 = 10;
/// trace 判决编码（与 ebpf-rs/src/common.rs 的 `SODAMA_VERDICT_*` 对齐）。
const VERDICT_OK: u8 = 0;
const VERDICT_SHOT: u8 = 1;
const VERDICT_REDIR: u8 = 2;

/// 事件类型名（日志/status 用；未实现的编号保留为 unknown）。
fn event_type_name(t: u32) -> &'static str {
    match t {
        EV_BLOCKED => "blocked",
        EV_UDP_CONN_OVERFLOW => "udp_conn_overflow",
        EV_TCP_CONN_OVERFLOW => "tcp_conn_overflow",
        EV_BLOCKED_ALIVE => "blocked_alive",
        EV_REDIRECT_REBIND_REJECTED => "redirect_rebind_rejected",
        EV_SYN_REBIND_REJECTED => "syn_rebind_rejected",
        EV_REDIRECT_UPDATE_FAILED => "redirect_update_failed",
        EV_SYN_REBIND_REROUTED => "syn_rebind_rerouted",
        EV_TRACE => "trace",
        _ => "unknown",
    }
}

/// C3：事件通道消费侧计数。5 个槽位对应 5 个已知类型（`EV_*` 是位标志而非连续序号，
/// 经 `event_type_slot` 归一）；未知类型与长度异常的记录单独归入 unknown——对照
/// dae `control/event_ringbuf.go` 的 default 分支：ABI 漂移不得被静默丢弃。
static EVENTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static EVENT_COUNTS: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static EVENT_SUPPRESSED: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// 每类型最近一条日志的 monotonic ns：用户态限速 1 条/秒/类型（未知类型更严），
/// 其余只计数——内核侧已限速，这里兜底 ABI 漂移/损坏数据打爆日志的可能。
static EVENT_LAST_LOG_NS: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static EVENT_UNKNOWN_TOTAL: AtomicU64 = AtomicU64::new(0);
static EVENT_UNKNOWN_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
static EVENT_UNKNOWN_LAST_LOG_NS: AtomicU64 = AtomicU64::new(0);

/// 已知事件类型 → 槽位（与 `events_json` 的列表顺序一致）。
fn event_type_slot(t: u32) -> Option<usize> {
    match t {
        EV_BLOCKED => Some(0),
        EV_UDP_CONN_OVERFLOW => Some(1),
        EV_TCP_CONN_OVERFLOW => Some(2),
        EV_BLOCKED_ALIVE => Some(3),
        EV_REDIRECT_REBIND_REJECTED => Some(4),
        EV_SYN_REBIND_REJECTED => Some(5),
        EV_REDIRECT_UPDATE_FAILED => Some(6),
        EV_SYN_REBIND_REROUTED => Some(7),
        _ => None,
    }
}

/// C3：打印事件地址（与 `tuple_hex` 同口径：IPv4 为 v4-mapped → 点分十进制；
/// 其余按 IPv6 RFC 5952 风格压缩——日志里可读优先）。
fn format_event_addr(a: &[u8; 16]) -> String {
    if a[..10].iter().all(|b| *b == 0) && a[10] == 0xff && a[11] == 0xff {
        return format!("{}.{}.{}.{}", a[12], a[13], a[14], a[15]);
    }
    let groups: [u16; 8] = std::array::from_fn(|i| u16::from_be_bytes([a[2 * i], a[2 * i + 1]]));
    // 最长全零段（RFC 5952：≥2 组才折叠；同长取最靠前）。
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut cur_start, mut cur_len) = (0usize, 0usize);
    for (i, g) in groups.iter().enumerate() {
        if *g == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if best_len >= 2 && i == best_start {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    out
}

/// C3：打印一条设备事件（tuple 形态对照 dae `control/event_ringbuf.go:228-235`
/// 的 reportDatapathEventAt；不打印 pid/pname——内核侧当前恒为 0/空，只会制造噪声）。
/// 限速在调用方完成。
fn log_soda_event(ev: &SodaEvent) {
    let slot = event_type_slot(ev.type_);
    let (last, suppressed, window_ns) = match slot {
        Some(i) => (
            &EVENT_LAST_LOG_NS[i],
            &EVENT_SUPPRESSED[i],
            1_000_000_000u64,
        ),
        // 未知类型：限速更严（1 条/10s），避免损坏数据/ABI 漂移洪泛。
        None => (
            &EVENT_UNKNOWN_LAST_LOG_NS,
            &EVENT_UNKNOWN_SUPPRESSED,
            10_000_000_000u64,
        ),
    };
    let now = monotonic_now_ns();
    if now.saturating_sub(last.load(Ordering::Relaxed)) < window_ns {
        suppressed.fetch_add(1, Ordering::Relaxed);
        return;
    }
    last.store(now, Ordering::Relaxed);
    let n = suppressed.swap(0, Ordering::Relaxed);
    let l4 = match ev.l4proto {
        6 => "tcp",
        17 => "udp",
        _ => "?",
    };
    let name = match slot {
        Some(_) => event_type_name(ev.type_).to_string(),
        None => format!("unknown type=0x{:x}", ev.type_),
    };
    let mut msg = format!(
        "event: {name} outbound=0x{:x} {l4} sip={} sport={} -> dip={} dport={}",
        ev.outbound,
        format_event_addr(&ev.sip),
        ev.sport,
        format_event_addr(&ev.dip),
        ev.dport
    );
    if n > 0 {
        msg.push_str(&format!("（本秒抑制 {n} 条）"));
    }
    log(&msg);
}

// ---------------------------------------------------------------- A2 #3：trace
/// 与 ebpf-rs/src/common.rs 的 `SodaTraceFilter` 同位（20 字节）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SodaTraceFilter {
    enabled: u32,
    l4proto: u32,
    port: u32,
    ipver: u32,
    drop_only: u32,
}
unsafe impl aya::Pod for SodaTraceFilter {}

/// trace 会话截止时刻（单调 ns；0 = 未激活）。
static TRACE_UNTIL_NS: AtomicU64 = AtomicU64::new(0);
/// trace 会话代次（每次 `trace` 命令 +1；事件线程据此新建/截断文件）。
static TRACE_GEN: AtomicU64 = AtomicU64::new(0);
/// trace 输出文件（daemon 写、CLI 读；`/run` 不可写时退 `/tmp`）。
static TRACE_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
/// 本次会话收到的 trace 事件数。
static TRACE_EVENTS: AtomicU64 = AtomicU64::new(0);
/// trace 写盘失败数（磁盘满/权限）。
static TRACE_WRITE_ERRS: AtomicU64 = AtomicU64::new(0);

/// trace 文件路径（首次调用时探测：优先 `/run/sodama-trace.log`，否则 `/tmp/sodama-trace.log`）。
fn trace_path() -> &'static std::path::Path {
    TRACE_PATH.get_or_init(|| {
        let run = std::path::PathBuf::from("/run/sodama-trace.log");
        let chosen = if std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&run)
            .is_ok()
        {
            run
        } else {
            std::path::PathBuf::from("/tmp/sodama-trace.log")
        };
        chosen
    })
}

/// 开启一次 trace 会话（对照 dae `trace` 子命令的过滤参数：IPv4/IPv6、L4 协议、端口、drop-only）。
/// 返回 (seconds, 文件路径)；由状态命令调用，过滤器同步写入数据面（内核侧过滤）。
fn arm_trace(
    ebpf: &mut Ebpf,
    seconds: u64,
    l4: Option<u32>,
    port: Option<u32>,
    ipver: u32,
    drop_only: bool,
) -> Result<(u64, String), String> {
    let seconds = seconds.clamp(1, 3600);
    let filter = SodaTraceFilter {
        enabled: 1,
        l4proto: l4.unwrap_or(0),
        port: port.unwrap_or(0),
        ipver,
        drop_only: u32::from(drop_only),
    };
    let map = ebpf
        .map_mut("trace_filter_map")
        .ok_or("对象不含 trace_filter_map（旧 eBPF 对象？请重建数据面）")?;
    let mut arr: Array<_, SodaTraceFilter> = Array::try_from(map).map_err(|e| e.to_string())?;
    arr.set(0, filter, 0).map_err(|e| e.to_string())?;
    TRACE_EVENTS.store(0, Ordering::Relaxed);
    TRACE_WRITE_ERRS.store(0, Ordering::Relaxed);
    TRACE_GEN.fetch_add(1, Ordering::Relaxed);
    TRACE_UNTIL_NS.store(
        monotonic_now_ns() + seconds.saturating_mul(1_000_000_000),
        Ordering::Relaxed,
    );
    let path = trace_path().display().to_string();
    log(&format!(
        "trace: 会话开始（{seconds}s；l4={:?} port={:?} ipver={ipver} drop_only={drop_only}）→ {path}",
        l4, port
    ));
    Ok((seconds, path))
}

/// 会话到期清位（主循环 tick 调用）；未激活时是单次原子读。
fn trace_maybe_expired(ebpf: &mut Ebpf) {
    let until = TRACE_UNTIL_NS.load(Ordering::Relaxed);
    if until == 0 || monotonic_now_ns() < until {
        return;
    }
    TRACE_UNTIL_NS.store(0, Ordering::Relaxed);
    if let Some(map) = ebpf.map_mut("trace_filter_map") {
        if let Ok(mut arr) = Array::<_, SodaTraceFilter>::try_from(map) {
            let _ = arr.set(0, SodaTraceFilter::default(), 0);
        }
    }
    log(&format!(
        "trace: 会话结束（{} 事件，{} 写失败）",
        TRACE_EVENTS.load(Ordering::Relaxed),
        TRACE_WRITE_ERRS.load(Ordering::Relaxed)
    ));
}

/// trace 行格式（CLI 按此解析过滤后展示）：一行一事件，键值对自描述。
/// 端口转 host 序（tuple 里是网络序原始值；对照 `pkt.h_sport/h_dport`）。
fn format_trace_line(ev: &SodaEvent) -> String {
    let v6 = !(ev.sip[..10].iter().all(|b| *b == 0) && ev.sip[10] == 0xff && ev.sip[11] == 0xff);
    let l4 = match ev.l4proto {
        6 => "tcp",
        17 => "udp",
        _ => "?",
    };
    let act = match ev.pad[0] {
        VERDICT_OK => "ok",
        VERDICT_SHOT => "shot",
        VERDICT_REDIR => "redir",
        _ => "?",
    };
    format!(
        "{} v={} l4={} sip={} sport={} dip={} dport={} outbound=0x{:x} act={}\n",
        now_hms(),
        if v6 { 6 } else { 4 },
        l4,
        format_event_addr(&ev.sip),
        u16::from_be(ev.sport),
        format_event_addr(&ev.dip),
        u16::from_be(ev.dport),
        ev.outbound,
        act
    )
}

/// A2 #3：收一条 trace 事件——写盘（按代次截断开新文件），超期/未激活不写。
/// 返回 `true` = 本次为 trace 事件（消费循环据此跳过普通事件日志）。
fn trace_sink_write(ev: &SodaEvent, sink: &mut Option<(u64, std::fs::File)>) -> bool {
    if ev.type_ != EV_TRACE {
        return false;
    }
    TRACE_EVENTS.fetch_add(1, Ordering::Relaxed);
    let until = TRACE_UNTIL_NS.load(Ordering::Relaxed);
    if until == 0 || monotonic_now_ns() >= until {
        // 到期与主循环清位之间的窗口：事件仍会到（数据面旗标未清），直接丢。
        return true;
    }
    let gen = TRACE_GEN.load(Ordering::Relaxed);
    if sink.as_ref().map(|(g, _)| *g) != Some(gen) {
        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(trace_path())
        {
            Ok(f) => *sink = Some((gen, f)),
            Err(_) => {
                TRACE_WRITE_ERRS.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }
    if let Some((_, f)) = sink.as_mut() {
        use std::io::Write as _;
        if f.write_all(format_trace_line(ev).as_bytes()).is_err() {
            TRACE_WRITE_ERRS.fetch_add(1, Ordering::Relaxed);
        }
    }
    true
}

/// C3：`event_ringbuf` 常驻消费者（专用线程；对照 dae `control/event_ringbuf.go`
/// 的消费循环）。逐事件只做计数与限速日志，不做任何阻塞/逐包输出。
/// A2 #3：trace 事件（`EV_TRACE`）单独走落盘路径（不限速；筛选已在数据面完成）。
fn ebpf_event_loop(mut rb: RingBuf<MapData>) -> ! {
    const POLL_TIMEOUT_MS: libc::c_int = 500;
    // trace 落盘 sink（单线程持有；代次变化时截断开新文件）。
    let mut trace_sink: Option<(u64, std::fs::File)> = None;
    loop {
        let mut pfd = libc::pollfd {
            fd: rb.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // poll 失败（EINTR/异常 fd）不退出：睡 100ms 防自旋后重试——
        // 消费线程静默消失比短暂重试更糟（事件全丢且无人知道）。
        if unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) } < 0 {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        while let Some(item) = rb.next() {
            let bytes: &[u8] = &item;
            if bytes.len() != std::mem::size_of::<SodaEvent>() {
                // 长度不符 = 两侧镜像漂移（或内核侧损坏数据）：计入 unknown，不 panic。
                EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);
                EVENT_UNKNOWN_TOTAL.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // ringbuf 记录按 8B 对齐、SodaEvent 为 #[repr(C)] 纯值类型（无内部指针），
            // 故 unaligned 读安全（与 aya Pod 的字节视图语义一致）。
            let ev = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const SodaEvent) };
            EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);
            // A2 #3：trace 事件（落盘，不参与普通事件的计数槽/限速日志）。
            if trace_sink_write(&ev, &mut trace_sink) {
                continue;
            }
            match event_type_slot(ev.type_) {
                Some(i) => {
                    EVENT_COUNTS[i].fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    EVENT_UNKNOWN_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
            }
            log_soda_event(&ev);
        }
    }
}

/// 与 ebpf-rs/src/common.rs 的 `SodaRoutingEpochIp` 同位（20 字节）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct SodaEpochIp {
    slot: u32,
    addr: [u8; 16],
}
unsafe impl aya::Pod for SodaEpochIp {}

/// 与 ebpf-rs/src/common.rs 的 `SodaDomainRouting` 同位（MAX_MATCH_SET_LEN/32 个 u32）。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SodaDomainRouting {
    bitmap: [u32; (MAX_MATCH_SET_LEN as usize).div_ceil(32)],
}
unsafe impl aya::Pod for SodaDomainRouting {}

impl Default for SodaDomainRouting {
    fn default() -> Self {
        Self {
            bitmap: [0; (MAX_MATCH_SET_LEN as usize).div_ceil(32)],
        }
    }
}

/// 与 ebpf-rs/src/common.rs 的 `SodaRedirectEntry` 同位（32 字节，含对齐填充）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SodaPidPname {
    /// P17b：cgroup 钩子采集的进程名（16B，NUL 补全）
    pname: [u8; 16],
    pid: u32,
    pad: [u8; 4],
    last_seen_ns: u64,
}
unsafe impl aya::Pod for SodaPidPname {}

/// P18c+：与 ebpf-rs 的 `SodaDnsSenderKey`/`SodaDnsSenderPname` 同位。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SodaDnsSenderKey {
    addr: [u8; 16],
    port: u16,
    pad: u16,
}
unsafe impl aya::Pod for SodaDnsSenderKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SodaDnsSenderPname {
    pname: [u8; 16],
    pad: u16,
    _pad2: [u8; 6],
    ts_ns: u64,
}
unsafe impl aya::Pod for SodaDnsSenderPname {}

/// P18c+：dns_sender_pname_map 的 fd（dup 自加载的 map；DNS 线程用它做
/// BPF_MAP_LOOKUP_ELEM syscall，不持有 Ebpf 借用）。-1 = 未就绪。
static DNS_PNAME_MAP_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// BPF_MAP_LOOKUP_ELEM（raw syscall；attr 为 bpf_attr 的 map_fd/key/value 前 32B）。
fn bpf_map_lookup_raw(fd: i32, key: &[u8], val: &mut [u8]) -> Result<(), i32> {
    bpf_map_op_raw(1, fd, Some(key), Some(val.as_mut_ptr()))
}

/// bpf_attr 的 map 操作公共前缀（lookup/delete/get_next_key 同布局）。
#[repr(C)]
struct BpfMapOpAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// raw bpf() syscall 的 map 操作（cmd：1=lookup，3=delete，4=get_next_key）。
fn bpf_map_op_raw(
    cmd: i64,
    fd: i32,
    key: Option<&[u8]>,
    value: Option<*mut u8>,
) -> Result<(), i32> {
    let attr = BpfMapOpAttr {
        map_fd: fd as u32,
        _pad: 0,
        key: key.map(|k| k.as_ptr() as u64).unwrap_or(0),
        value: value.map(|p| p as u64).unwrap_or(0),
        flags: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            &attr as *const BpfMapOpAttr as *const libc::c_void,
            core::mem::size_of::<BpfMapOpAttr>() as u64,
        )
    };
    if ret < 0 {
        Err(unsafe { *libc::__errno_location() })
    } else {
        Ok(())
    }
}

/// BPF_MAP_DELETE_ELEM。
fn bpf_map_delete_raw(fd: i32, key: &[u8]) -> Result<(), i32> {
    bpf_map_op_raw(3, fd, Some(key), None)
}

/// BPF_MAP_GET_NEXT_KEY；key=None 表示从第一个键开始。
fn bpf_map_get_next_key_raw(fd: i32, key: Option<&[u8]>, next: &mut [u8]) -> Result<(), i32> {
    bpf_map_op_raw(4, fd, key, Some(next.as_mut_ptr()))
}

/// 内核 ktime（ns，自启动），用于判断 dns_sender_pname_map 条目是否陈旧；
/// 读 /proc/uptime，结果缓存 5s（DNS 每查询一次调用，开销可忽略）。
fn ktime_ns_now() -> u64 {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(std::time::Instant, u64)>> = Mutex::new(None);
    if let Ok(g) = CACHE.lock() {
        if let Some((at, v)) = *g {
            if at.elapsed() < std::time::Duration::from_secs(5) {
                return v;
            }
        }
    }
    let v = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|x| x.parse::<f64>().ok())
        })
        .map(|secs| (secs * 1e9) as u64)
        .unwrap_or(0);
    if let Ok(mut g) = CACHE.lock() {
        *g = Some((std::time::Instant::now(), v));
    }
    v
}

/// P18c+：反查 DNS 查询发送方进程名（WAN egress 新 UDP DNS 流由 eBPF 写入）。
/// 条目超 120s 视为陈旧（端口重用防误判）；pname 空 = 未命中。
fn lookup_dns_pname(client: Option<std::net::IpAddr>, sport: u16) -> Option<String> {
    let fd = DNS_PNAME_MAP_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return None;
    }
    let ip = client?;
    let addr = match ip {
        std::net::IpAddr::V4(a) => dns::map_v4(a.octets()),
        std::net::IpAddr::V6(a) => a.octets(),
    };
    let key = SodaDnsSenderKey {
        addr,
        port: sport,
        pad: 0,
    };
    let mut val = SodaDnsSenderPname::default();
    let keyb = unsafe {
        core::slice::from_raw_parts(
            &key as *const _ as *const u8,
            core::mem::size_of::<SodaDnsSenderKey>(),
        )
    };
    let valb = unsafe {
        core::slice::from_raw_parts_mut(
            &mut val as *mut _ as *mut u8,
            core::mem::size_of::<SodaDnsSenderPname>(),
        )
    };
    if bpf_map_lookup_raw(fd, keyb, valb).is_err() {
        return None;
    }
    if val.pname.iter().all(|b| *b == 0) {
        return None;
    }
    if val.ts_ns != 0 {
        let now = ktime_ns_now();
        if now != 0 && now.saturating_sub(val.ts_ns) > 120_000_000_000 {
            return None;
        }
    }
    let end = val.pname.iter().position(|b| *b == 0).unwrap_or(16);
    Some(String::from_utf8_lossy(&val.pname[..end]).into_owned())
}

/// P18c+：dns_sender_pname_map 周期性回收。条目仅对「最近 120s 的查询」有意义；
/// 不回收会因客户端源端口轮换耗尽 4096 槽位，新查询的 pname 反查静默失败。
fn dns_pname_gc_loop(fd: i32) {
    const KEY_LEN: usize = 20; // SodaDnsSenderKey
    const VAL_LEN: usize = 32; // SodaDnsSenderPname
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        let now = ktime_ns_now();
        if now == 0 {
            continue;
        }
        let mut prev: Option<[u8; KEY_LEN]> = None;
        let mut scanned = 0u32;
        loop {
            let mut next = [0u8; KEY_LEN];
            if bpf_map_get_next_key_raw(fd, prev.as_ref().map(|p| p.as_slice()), &mut next).is_err()
            {
                break;
            }
            scanned += 1;
            if scanned > 1_000_000 {
                break; // 防御异常（get_next_key 不会回退，正常到不了）
            }
            let mut val = [0u8; VAL_LEN];
            if bpf_map_lookup_raw(fd, &next, &mut val).is_ok() {
                let ts = u64::from_le_bytes(val[24..32].try_into().unwrap());
                if ts != 0 && now.saturating_sub(ts) > 120_000_000_000 {
                    let _ = bpf_map_delete_raw(fd, &next);
                }
            }
            prev = Some(next);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SodaRedirectEntry {
    ifindex: u32,
    smac: [u8; 6],
    dmac: [u8; 6],
    from_wan: u8,
    pad: [u8; 3],
    pad2: [u8; 4],
    last_seen_ns: u64,
}
unsafe impl aya::Pod for SodaRedirectEntry {}

#[derive(Clone)]
struct Args {
    ebpf: String,
    /// LAN 侧接口（ingress 分流）；`--lan none` = 不挂 LAN 钩子（纯本机网关）
    lan: Vec<String>,
    /// 是否显式声明不挂 LAN 钩子（`--lan none`；阻止默认值 landae）
    no_lan: bool,
    /// WAN 侧接口（egress 分流 + ingress 状态刷新）
    wan: Vec<String>,
    /// 能力缺口 #3：CLI 是否显式给出过 --lan/--wan（决定 config `lan_interface`/`wan_interface`
    /// 是否回填；默认值 landae/wan 不算显式给出）。
    lan_given: bool,
    wan_given: bool,
    /// 单臂模式：同一接口同时挂 LAN/WAN 合用程序（sodama_wan_lan_ingress + sodama_lan_wan_egress）
    dual: Vec<String>,
    dae0: String,
    dae0peer: String,
    daens: String,
    tproxy_port: u16,
    /// 路由规则文件（sodama 语法，见 rules.rs）；缺省时用 --proxy 生成
    rules: Option<String>,
    /// K3：完整 dae `.dae` 配置（含 include）；与 --rules 互斥，优先生效
    config: Option<String>,
    /// K3：配置里有规则无法编译时直接报错（默认：列 deferred 后继续）
    strict_config: bool,
    /// K3：只读状态面 socket 路径（Unix socket，JSON）
    status_socket: Option<String>,
    /// P4：代理出口拨号器（`direct` 或 `socks5://host:port`）；缺省保留实验回显
    dialer: Option<String>,
    /// P4：relay 空闲回收秒数（默认 300）
    relay_idle_timeout: Option<u64>,
    /// P18e：relay 并发上限（0/未设 = 不限）
    max_conns: Option<u64>,
    /// P11：relay 拨号超时秒数（默认 5；真实节点慢首连可调大）
    dial_timeout: Option<u64>,
    /// P14：拨号模式 ip|domain|domain+（缺省 ip；config global.dial_mode 可提供）
    dial_mode: Option<String>,
    /// P14：嗅探等待上限（毫秒，默认 100；仅 dial_mode != ip 时生效）
    sniffing_timeout_ms: Option<u64>,
    /// P21：嗅探重判（sniff-punt）——嗅到域名后按规则在 relay 侧重选出口
    sniff_punt: bool,
    /// P15：订阅 URL（可重复；每次都拉取并解析为节点池）
    subscribe: Vec<String>,
    /// P17a：geodata 搜索目录（可重复；优先于 DAE_LOCATION_ASSET/系统目录）
    geodata_dir: Vec<String>,
    /// P15：选用的组名（默认优先 `proxy`，否则唯一/第一个非空组）
    group: Option<String>,
    /// P12：本地 SOCKS5 入口（如 127.0.0.1:11080）；开启后不加载 eBPF、不需要 root
    listen_socks: Option<String>,
    /// P4：UDP NAT 会话空闲秒数（默认 60）
    udp_idle_timeout: Option<u64>,
    /// K3 过渡一跳：等价的旧写法（`--forward socks5://…` = `--dialer socks5://…`）
    forward: Option<String>,
    /// P4c：启用 TCP relay offload（fast_sock + sk_skb）
    offload: bool,
    /// 对标批：链路头模式（auto=按接口 sysfs arphrd 类型逐接口判定，对照 dae `linkHdrLen()`）
    link_hdr: LinkHdrMode,
    /// C4：XDP 计量探针的接口（可重复；默认空 = 不挂。探针恒 XDP_PASS，只计数）
    xdp: Vec<String>,
    /// M1：relay splice 零拷贝（Direct / VLESS 明文；默认开，`--no-splice` 关）
    splice: bool,
    /// M1：eBPF 热路径调试打印（默认关；`--ebpf-debug` 置 control_flags 位）
    ebpf_debug: bool,
    /// M2：kTLS（内核 TLS，实验性；成功则加解密与拷贝下沉内核，支持 TLS 上再 splice）
    ktls: bool,
    /// P3a/P18a：DNS 上游 URL（无 scheme 或 udp://、tcp://、tcp+udp://、tls://(DoT)、
    /// https://(DoH)；缺省时用配置 dns.upstream 或 8.8.8.8:53）
    dns_upstream: Option<String>,
    /// 打印编译出的 match_set / LPM 内容（对拍用）
    dump: bool,
    /// 只编译规则并按下对拍格式打印（不加载 eBPF，不需要 root）
    compile_dump: Option<String>,
    /// 走代理的目的 IP（网络序），仅在无 --rules 时用于生成规则
    proxy_dsts: Vec<u32>,
    /// P6：日志文件（默认 stdout/stderr；SIGHUP 时 reopen，适合 logrotate）
    log_file: Option<String>,
    /// P33：轮询 --config/--rules 及其 include 文件，变更时自动 reload（秒；缺省关）
    watch_config: Option<u64>,
    /// P34：未给 --config/--rules 时自动采用 ~/.config/sodama/config.dae（仅用于日志明示）
    auto_config: bool,
    /// P38：关闭日志时间戳（对照 dae `--disable-timestamp`；也可 config global.disable_timestamp）
    disable_timestamp: bool,
    /// P38：不写 pid 文件（对照 dae `--disable-pidfile`；默认写 /var/run/sodama.pid）
    disable_pidfile: bool,
    /// A2 #2：日志轮转——单文件上限 MB（0/缺省 = 不轮转；对照 dae `--logfile-maxsize`）。
    logfile_maxsize: Option<u64>,
    /// A2 #2：保留旧日志份数（缺省 3；0 = 不保留；对照 dae `--logfile-maxbackups`）。
    logfile_maxbackups: Option<u64>,
}

/// 本地时间戳 `YYYY-MM-DD HH:MM:SS`。
/// 生产事故取证需要“哪一行是什么时候”，旧日志无时间戳只能靠行号推断。
///
/// 时区解析三级兜底（生产踩坑：OpenWrt/musl 上 `TZ` 未设时 `localtime_r` 直接回 UTC，
/// 日志比本地时间早 8 小时）：
/// 1. `TZ` 环境变量已设 → 交给 `localtime_r`（两端 libc 都尊重完整 TZ 库）；
/// 2. 否则读 `/etc/TZ` 的简单形式（OpenWrt 即 `CST-8`）自行算偏移；
/// 3. 都不可用 → `localtime_r` 兜底（glibc 会读 `/etc/localtime`）。
fn now_hms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tz_env = std::env::var("TZ").ok().filter(|s| !s.is_empty());
    if tz_env.is_none() {
        if let Some(off) = std::fs::read_to_string("/etc/TZ")
            .ok()
            .as_deref()
            .and_then(parse_posix_tz)
        {
            let (y, mo, d, h, mi, s) = epoch_to_civil(secs + off);
            return format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}");
        }
    }
    // 兜底：交给 libc（glibc 会读 /etc/localtime；musl 在 TZ 已设时也正确）
    let t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        let (y, mo, d, h, mi, s) = epoch_to_civil(secs);
        return format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}");
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// POSIX TZ 的「名字 + 偏移」简单形式 → 本地相对 UTC 的偏移（秒）。
/// 例：`CST-8` → +28800（POSIX 语义：值表示“加到本地得 UTC”，符号与直觉相反）；
/// `UTC0` → 0；`<+08>-8` → +28800；解析不出返回 None。
fn parse_posix_tz(tz: &str) -> Option<i64> {
    let tz = tz.trim();
    let bytes = tz.as_bytes();
    let mut i = 0;
    // 名字：字母，或 `<...>` 包起的形式
    if bytes.first() == Some(&b'<') {
        i = tz.find('>')? + 1;
    } else {
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
    }
    if i == 0 {
        return None;
    }
    if i >= bytes.len() {
        return Some(0); // 只有名字（如 `UTC`）
    }
    let rest = &tz[i..];
    let (sign, rest) = match rest.as_bytes().first()? {
        b'-' => (-1i64, &rest[1..]),
        b'+' => (1i64, &rest[1..]),
        _ => (1i64, rest),
    };
    let mut parts = rest.split(':');
    // 取开头的十进制整数：末段可能跟 DST 规则（如 `8CDT-7,M3.2.0,M11.1.0`）
    let h: i64 = leading_i64(parts.next()?)?;
    let m: i64 = parts.next().and_then(leading_i64).unwrap_or(0);
    let s: i64 = parts.next().and_then(leading_i64).unwrap_or(0);
    Some(-(sign * (h * 3600 + m * 60 + s)))
}

/// 取字符串开头的十进制整数（后面的 DST 规则等尾部内容忽略）。
fn leading_i64(s: &str) -> Option<i64> {
    let n = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    s[..n].parse().ok()
}

/// epoch 秒 → UTC 日历（Howard Hinnant 的 civil_from_days）。
fn epoch_to_civil(secs: i64) -> (i64, u32, u32, i64, i64, i64) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m as u32,
        d as u32,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
    )
}

fn log(msg: &str) {
    log_at(3, msg);
}

/// A2 #6：warn 级（`log_level: warning` 仍可见）。
fn log_warn(msg: &str) {
    log_at(2, msg);
}

/// A2 #6：debug 级（仅 `log_level: debug` 可见；对照 dae logrus Debug 行）。
fn log_debug(msg: &str) {
    log_at(4, msg);
}

/// A2 #6：解析 `min-max` / 单值区间（`50-100` → (50,100)；`64` → (64,64)；
/// 非法/倒置 → 默认值）。用于 `tls_fragment_length`/`tls_fragment_interval`。
fn parse_range(v: &str, dmin: usize, dmax: usize) -> (usize, usize) {
    let t = v.trim();
    let (a, b) = match t.split_once('-') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (t, t),
    };
    match (a.parse::<usize>(), b.parse::<usize>()) {
        (Ok(a), Ok(b)) if a > 0 && b >= a => (a, b),
        _ => (dmin, dmax),
    }
}

/// A2 #6：`pprof_port` 的等价形态——本机诊断端口（只读快照；对照 dae 用 Go
/// `net/http/pprof`，Rust 侧没有 pprof 生态等价物，提供可移植的运行时快照：
/// 线程数/RSS/fd/会话/关键计数；`/json` 为结构化输出）。
/// 只 bind 127.0.0.1（诊断面不对公网暴露）。
fn diag_port_loop(port: u16) {
    let listener = match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            log_warn(&format!("pprof_port: 绑定 127.0.0.1:{port} 失败（{e}）"));
            return;
        }
    };
    for conn in listener.incoming() {
        let Ok(mut stream) = conn else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        // 读请求行（只需要 path）。
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let path = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();
        let body = if path.starts_with("/json") {
            diag_snapshot_json().to_string()
        } else {
            let v = diag_snapshot_json();
            format!(
                "sodama diagnostics（Rust 无 Go pprof：本页为运行时快照）\n\
                 threads={} rss_kb={} fds={} conns_active={} udp_sessions={} \n\
                 traffic_up_rate={} traffic_down_rate={}\n\
                 events_total={} event_drops={}\n\
                 更多结构化数据：GET /json\n",
                v["threads"],
                v["rss_kb"],
                v["fds"],
                v["conns_active"],
                v["udp_sessions"],
                v["traffic_up_rate"],
                v["traffic_down_rate"],
                v["events_total"],
                v["event_drops"],
            )
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            if path.starts_with("/json") { "application/json" } else { "text/plain" },
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    }
}

/// 快照数据源：/proc/self 三件套 + 进程内计数。
fn diag_snapshot_json() -> serde_json::Value {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let status = read("/proc/self/status");
    let get = |k: &str| -> String {
        status
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}:")))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    let fds = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0);
    json!({
        "threads": get("Threads").parse::<u64>().unwrap_or(0),
        "rss_kb": get("VmRSS").split_whitespace().next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0),
        "vm_size_kb": get("VmSize").split_whitespace().next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0),
        "fds": fds,
        "conns_active": RELAY_STATS.conns_active.load(Ordering::Relaxed),
        "conns_total": RELAY_STATS.conns_total.load(Ordering::Relaxed),
        "udp_sessions": UDP_NAT_STATS.sessions_total.load(Ordering::Relaxed).saturating_sub(UDP_NAT_STATS.evicted.load(Ordering::Relaxed)),
        "traffic_up_rate": TRAFFIC_UP_RATE.load(Ordering::Relaxed),
        "traffic_down_rate": TRAFFIC_DOWN_RATE.load(Ordering::Relaxed),
        "events_total": EVENTS_TOTAL.load(Ordering::Relaxed),
        "events_unknown": EVENT_UNKNOWN_TOTAL.load(Ordering::Relaxed),
        "uptime_secs": STARTED.get().map(|t| t.elapsed().as_secs()).unwrap_or(0),
    })
}

/// A2 #6：读 global 布尔的统一口径（true/1/yes/on/enable 为真）。
fn global_on(cfg: Option<&config::Config>, key: &str) -> bool {
    cfg.and_then(|c| config::global_value(c, key))
        .map(|v| matches!(v.trim(), "true" | "1" | "yes" | "on" | "enable"))
        .unwrap_or(false)
}

/// A2 #6：**global 生效面**——把本批落地的旋钮接上消费点，并对仍未生效的键**显式告警**
/// （清点口径要求：解析不生效不能静默；见 ADR-0069 的偏离/余项清单）。
fn apply_global_effective_knobs(cfg: Option<&config::Config>, args: &Args) {
    let g = |k: &str| cfg.and_then(|c| config::global_value(c, k));

    // so_mark_from_dae：控制面自身 socket 的 SO_MARK（默认编译期 0x233）。
    if let Some(v) = g("so_mark_from_dae") {
        let t = v.trim();
        let parsed = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            t.parse::<u32>().ok()
        };
        match parsed {
            Some(m) => {
                outbound::set_so_mark(m);
                log(&format!("so_mark_from_dae: 0x{m:x}（控制面 socket 标记）"));
            }
            None => log_warn(&format!(
                "so_mark_from_dae '{t}' 非法（0x…/十进制），用默认 0x233"
            )),
        }
    }
    // mptcp / allow_insecure / udphop_interval / fallback_resolver。
    if global_on(cfg, "mptcp") {
        outbound::set_mptcp(true);
        log("mptcp: 拨号 socket 启用 IPPROTO_MPTCP（不支持的内核会回落 TCP 并告警）");
    }
    if global_on(cfg, "allow_insecure") {
        outbound::set_allow_insecure_default(true);
        log("allow_insecure: 全局默认跳过 TLS 证书校验（节点参数优先）");
    }
    if let Some(v) = g("udphop_interval") {
        match parse_duration_secs(&v) {
            Some(secs) if secs >= 5 => {
                outbound::set_udphop_default(secs);
                log(&format!(
                    "udphop_interval: {secs}s（hy2 节点默认端口跳跃间隔）"
                ));
            }
            _ => log_warn(&format!("udphop_interval '{v}' 非法（≥5s 的时长），忽略")),
        }
    }
    if let Some(v) = g("fallback_resolver") {
        match crate::sticky::set_fallback_resolver(&v) {
            Ok(()) => log(&format!("fallback_resolver: {v}（节点域名兜底解析）")),
            Err(e) => log_warn(&format!("{e}（忽略）")),
        }
    }
    // tls_fragment*（对照 dae：`tls_fragment` 开关 + `tls_fragment_length`=`50-100` 字节
    // 区间 + `tls_fragment_interval`=`10-20` 毫秒区间）。生效面 = **自实现 TLS 路径**
    // （REALITY/自实现 TLS1.3 的 ClientHello）；rustls/quinn 路径无法分片（ADR-0069 偏离）。
    if global_on(cfg, "tls_fragment") {
        let (lmin, lmax) = g("tls_fragment_length")
            .map(|v| parse_range(&v, 50, 100))
            .unwrap_or((50, 100));
        let (imin, imax) = g("tls_fragment_interval")
            .map(|v| parse_range(&v, 10, 20))
            .unwrap_or((10, 20));
        crate::tls13::configure_fragment(lmin, lmax, imin as u64, imax as u64);
        log(&format!(
            "tls_fragment: CH 分片 {lmin}-{lmax} 字节 / 间隔 {imin}-{imax} ms（自实现 TLS 路径；rustls/quinn 路径不支持——ADR-0069）"
        ));
    }
    // utls_imitate / tls_implementation（对照 dae）：sodama 的指纹实现固定为 Chrome-120
    // （REALITY 路径）；`chrome`/`utls` 接受，其余取值显式告警并沿用 chrome（不静默）。
    if let Some(v) = g("utls_imitate") {
        let v = v.trim().to_ascii_lowercase();
        if v.is_empty() || v == "chrome" {
            log("utls_imitate: chrome（= 内置 Chrome-120 指纹）");
        } else {
            log_warn(&format!(
                "utls_imitate '{v}' 暂不支持（仅内置 chrome/Chrome-120），沿用 chrome——ADR-0069"
            ));
        }
    }
    if let Some(v) = g("tls_implementation") {
        let v = v.trim().to_ascii_lowercase();
        match v.as_str() {
            "" | "utls" => log("tls_implementation: utls（= 自实现 Chrome-120 指纹）"),
            "tls" => log("tls_implementation: tls（rustls 路径；REALITY 仍走自实现指纹）"),
            other => log_warn(&format!(
                "tls_implementation '{other}' 未知（tls|utls），按 utls 处理——ADR-0069"
            )),
        }
    }
    // pprof_port：sodama 的等价形态 = 本机诊断端口（Rust 无 Go pprof；提供线程/fd/RSS/
    // 会话/计数快照，见 `diag_port_loop`）。
    if let Some(v) = g("pprof_port") {
        if let Some(port) = v.trim().parse::<u16>().ok().filter(|p| *p != 0) {
            std::thread::Builder::new()
                .name("diag-port".into())
                .spawn(move || diag_port_loop(port))
                .ok();
            log(&format!(
                "pprof_port: 诊断端口 127.0.0.1:{port}（/ 文本摘要、/json 结构化；Rust 无 Go pprof 等价——ADR-0069）"
            ));
        }
    }
    // bandwidth_max_tx/rx（A2 #6）：relay 泵令牌桶限额；设置后新连接走拷贝泵。
    for (key, limiter, name) in [
        ("bandwidth_max_tx", limiter_tx(), "上行"),
        ("bandwidth_max_rx", limiter_rx(), "下行"),
    ] {
        if let Some(v) = g(key) {
            match parse_bandwidth(&v) {
                Ok(bps) => {
                    limiter.set_rate(bps);
                    if bps > 0 {
                        log(&format!(
                            "bandwidth_max: {name} {bps} B/s（≈{:.1} Mbit/s；relay 新连接走拷贝泵以节流）",
                            bps as f64 * 8.0 / 1_000_000.0
                        ));
                    }
                }
                Err(e) => log_warn(&format!("{key} '{v}' 非法（{e}），忽略")),
            }
        }
    }
    // disable_thp：仅影响本进程（对照 dae `PR_SET_THP_DISABLE`；不改系统全局策略）。
    if global_on(cfg, "disable_thp") {
        let rc = unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1u64, 0u64, 0u64, 0u64) };
        if rc == 0 {
            log("disable_thp: 本进程已退出 THP（PR_SET_THP_DISABLE）");
        } else {
            log_warn("disable_thp: prctl 失败（旧内核？），忽略");
        }
    }

    // 未生效键的显式告警（清点要求；后续批次逐项补齐，见 ADR-0069 余项）。
    const INERT_KEYS: &[&str] = &[];
    let inert: Vec<String> = INERT_KEYS
        .iter()
        .filter(|k| g(k).is_some())
        .map(|k| (*k).to_string())
        .collect();
    if !inert.is_empty() {
        log_warn(&format!(
            "config global 中 {} 项已解析但当前不生效：{}（见 docs/capability-gap-review.md §2 / ADR-0069）",
            inert.len(),
            inert.join(", ")
        ));
    }
    let _ = args;
}

/// A2 #6：`auto_config_kernel_parameter`——写内核参数并登记期望值（被改回即纠正）。
/// 对照 dae `control_plane_datapath.go:133-175` + `SetForwarding/SetSendRedirects`：
/// - 全局：`net.ipv4.ip_forward=1`、`net.ipv6.conf.all.forwarding=1`；
/// - 每个 LAN 接口：`conf/<if>/{ipv4,ipv6}/forwarding=1`、`ipv4/conf/<if>/send_redirects=0`；
/// - 每个 WAN 接口：`conf/<if>.accept_ra == 1` 时改为 `2`（IPv6 自动配置仍可用）。
fn auto_configure_kernel_parameters(args: &Args) {
    const SYS: &str = "/proc/sys/net";
    let mut applied = 0usize;
    let mut failed = 0usize;
    let mut set_watched = |path: String, val: &str| {
        let p = std::path::Path::new(&path);
        match sysctl::set(p, val, true) {
            Ok(_) => applied += 1,
            Err(e) => {
                failed += 1;
                log_warn(&format!("auto_config_kernel_parameter: {e}"));
            }
        }
    };
    set_watched(format!("{SYS}/ipv4/ip_forward"), "1");
    set_watched(format!("{SYS}/ipv6/conf/all/forwarding"), "1");
    let lan: Vec<String> = args
        .lan
        .iter()
        .filter(|s| !s.contains('*'))
        .cloned()
        .collect();
    for ifname in &lan {
        set_watched(format!("{SYS}/ipv4/conf/{ifname}/forwarding"), "1");
        set_watched(format!("{SYS}/ipv6/conf/{ifname}/forwarding"), "1");
        set_watched(format!("{SYS}/ipv4/conf/{ifname}/send_redirects"), "0");
    }
    // WAN accept_ra：dae 只在当前值为 1 时改为 2（不改用户显式关闭/强制开启）。
    let wan: Vec<String> = args
        .wan
        .iter()
        .filter(|s| !s.contains('*'))
        .cloned()
        .collect();
    for ifname in &wan {
        let p = format!("{SYS}/ipv6/conf/{ifname}/accept_ra");
        if sysctl::read_value(std::path::Path::new(&p))
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            set_watched(p, "2");
        }
    }
    sysctl::start_watcher();
    log(&format!(
        "auto_config_kernel_parameter: 写入 {applied} 项（失败 {failed}），已登记期望值（被改回即纠正）"
    ));
}

/// A2 #6：启动等待网络（对照 dae `waitForNetworkOnline`）——判定：默认路由存在
/// 且（若配置了 fallback_resolver/bootstrap）DNS 能应答；最长 `timeout` 秒，
/// 每 2s 重试；超时只告警（订阅照样拉，本地节点照常用——dae 同语）。
fn wait_for_network(timeout: Duration) {
    fn has_default_route() -> bool {
        std::fs::read_to_string("/proc/net/route")
            .map(|t| {
                t.lines()
                    .skip(1)
                    .any(|l| l.split_whitespace().nth(1) == Some("00000000"))
            })
            .unwrap_or(true)
    }
    fn ipv6_default_route() -> bool {
        std::fs::read_to_string("/proc/net/ipv6_route")
            .map(|t| t.lines().any(|l| l.split_whitespace().nth(1) == Some("00")))
            .unwrap_or(true)
    }
    let start = Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if (has_default_route() || ipv6_default_route()) && dns_probe_ok() {
            if attempts > 1 {
                log(&format!(
                    "网络已就绪（{attempts} 次探测，{:?}）",
                    start.elapsed()
                ));
            }
            return;
        }
        if start.elapsed() >= timeout {
            log_warn(&format!(
                "等待网络超时（{:?}，{attempts} 次探测）：仍继续拉订阅，本地节点可用；可设 disable_waiting_network: true 跳过",
                start.elapsed()
            ));
            return;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// A2 #6：DNS 可达性探测（有配置的解析器就用解析器，否则一次系统解析）。
fn dns_probe_ok() -> bool {
    if let Some(f) = crate::sticky::fallback_resolver() {
        return crate::bootstrap::query_server(f, "example.com").is_ok();
    }
    match std::net::ToSocketAddrs::to_socket_addrs(&("example.com", 80u16)) {
        Ok(mut it) => it.next().is_some(),
        Err(_) => false,
    }
}

/// A2 #6：`log_level` 取值 → 内部级别（对照 dae logrus：panic/fatal/error/warn/info/debug/trace）。
fn parse_log_level(s: &str) -> Option<u32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" | "none" => Some(0),
        "panic" | "fatal" | "error" => Some(1),
        "warn" | "warning" => Some(2),
        "info" => Some(3),
        "debug" | "trace" => Some(4),
        _ => None,
    }
}

/// A2 #6 + #2：带级别的日志出口（过滤 + 轮转判定）。
/// 级别映射是 best-effort：既有调用大多按 info 归类；逐行分级可后续渐进补充
/// （不在本批把 250+ 行全部重标——那是行为面上无收益的大 diff，如实登记为边界）。
fn log_at(level: u32, msg: &str) {
    if level > LOG_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    // P38：`--disable-timestamp` 关闭时间戳前缀（对照 dae `--disable-timestamp`）。
    let line = log_line(
        LOG_TS_OFF.load(std::sync::atomic::Ordering::Relaxed),
        &now_hms(),
        msg,
    );
    let mut done = false;
    let mut rotate_due = false;
    if let Ok(mut g) = LOG_SINK.lock() {
        if let Some(f) = g.as_mut() {
            use std::io::Write as _;
            if writeln!(f, "{line}").and_then(|_| f.flush()).is_ok() {
                done = true;
                // A2 #2：轮转判定（只在文件 sink 下有意义）。
                let n = LOG_WRITTEN.fetch_add(line.len() as u64 + 1, Ordering::Relaxed)
                    + line.len() as u64
                    + 1;
                let max = LOG_MAX_SIZE_MB.load(Ordering::Relaxed);
                if max > 0 && n >= max * 1024 * 1024 {
                    rotate_due = true;
                }
            }
        }
    }
    if !done {
        if LOG_STDERR.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("{line}");
            let _ = std::io::stderr().flush();
        } else {
            println!("{line}");
            let _ = std::io::stdout().flush();
        }
    }
    if rotate_due {
        rotate_log_now();
    }
}

/// A2 #2：按大小轮转——`<log>` → `<log>.1.gz`（stored gzip，与 sysdump 同一实现），
/// 旧份依次后移，超过 `maxbackups` 的删除（0 = 不保留）；随后重开当前文件。
/// 对照 dae lumberjack（MaxSize/MaxBackups/Compress=true）；差异：份名用 `.N.gz` 序号
/// 而非时间戳（可预测、无时钟依赖）。
fn rotate_log_now() {
    let Some(path) = LOG_PATH.get() else {
        return;
    };
    let backups = LOG_MAX_BACKUPS.load(Ordering::Relaxed) as usize;
    // 关闭 sink → 移动/压缩 → 重开（失败不阻断日志：下次写入仍走旧/新句柄）。
    if let Ok(mut g) = LOG_SINK.lock() {
        *g = None;
    }
    // 旧份后移（从最老开始，避免覆盖）。
    for i in (1..backups).rev() {
        let from = format!("{path}.{i}.gz");
        let to = format!("{path}.{}.gz", i + 1);
        let _ = std::fs::rename(&from, &to);
    }
    if let Ok(data) = std::fs::read(path) {
        let gz = dump::gzip_store(&data);
        let _ = std::fs::write(format!("{path}.1.gz"), &gz);
    }
    // 清空当前文件（truncate 而非 rename：SIGHUP 外部 logrotate 衔接时行为一致）。
    let _ = std::fs::write(path, b"");
    LOG_WRITTEN.store(0, Ordering::Relaxed);
    let _ = open_log_file(path);
    log(&format!(
        "日志轮转：{path} -> {path}.1.gz（保留 {backups} 份）"
    ));
}

/// P38：日志行组装（时间戳开关拆成纯函数，便于单测；对照 dae `DisableTimestamp`）。
fn log_line(ts_off: bool, hms: &str, msg: &str) -> String {
    if ts_off {
        format!("[sodama] {msg}")
    } else {
        format!("[sodama] {hms} {msg}")
    }
}

/// P6：打开（或 SIGHUP 后重开）日志文件；best-effort，失败保留原输出。
/// A2 #2：以当前文件大小为轮转计数初值（重启不重置）。
fn open_log_file(path: &str) -> bool {
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => {
            let sz = f.metadata().map(|m| m.len()).unwrap_or(0);
            LOG_WRITTEN.store(sz, Ordering::Relaxed);
            if let Ok(mut g) = LOG_SINK.lock() {
                *g = Some(f);
            }
            true
        }
        Err(_) => false,
    }
}

fn reopen_log() {
    if let Some(path) = LOG_PATH.get() {
        if open_log_file(path) {
            log("日志文件已重开（SIGHUP）");
        } else {
            log(&format!("日志文件重开失败: {path}"));
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: sodama [options]\n\
         \n\
         options:\n\
           --version              A2：版本信息（版本+git sha / 构建 profile / 平台 / 许可；等同 `sodama version`，不需 root）\n\
           --ebpf <path>         eBPF object（默认 ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf）\n\
           --lan <ifname>        LAN 侧接口，可重复（默认 landae；`--lan none` = 不挂 LAN 钩子，本机网关模式）\n\
           --wan <ifname>        WAN 侧接口，可重复（默认 wan）\n\
           --dual <ifname>       单臂模式：同一接口同时挂 LAN/WAN 合用程序，可重复\n\
           --dae0 <ifname>       控制面设备（默认 dae0）\n\
           --dae0peer <ifname>   dae netns 内对端设备（默认 dae0peer）\n\
           --daens <name>        dae netns 名字（默认 daens）\n\
           --tproxy-port <port>  tproxy 监听端口（默认 12345）\n\
           --rules <path>        路由规则文件（sodama 语法，缺省时由 --proxy 生成）
           --config <path>       完整 dae .dae 配置（含 include；优先于 --rules；未给时依次找
                                 $XDG_CONFIG_HOME/sodama/config.dae → ~/.config/sodama/config.dae
                                 → /etc/sodama/config.dae）\n\
           --strict-config       配置中有规则无法编译时直接报错（默认列 deferred 后继续）\n\
           --status-socket <path> 状态面：Unix socket 上的 JSON（status/rules/config/maps + 控制命令；
                                 也可 config global.status_socket）\n\
           --log-file <path>     P6：日志写文件（默认 stdout；SIGHUP 时 reopen，轮转友好）\n\
           --dialer <url>        P4：代理出口拨号器（direct 或 socks5://host:port）\n\
           --relay-idle-timeout <s> P4：relay 空闲回收秒数（默认 300）
           --dial-timeout <s>       P11：relay 拨号超时秒数（默认 5；真实节点慢首连可调大）
           --dial-mode <m>          P14：ip|domain|domain+（默认 ip；域名模式嗅探 SNI/Host 后远端解析，绕 DNS 污染）
           --sniffing-timeout-ms <n> P14：嗅探等待上限毫秒（默认 100；仅 dial_mode != ip 时生效）
           --sniff-punt             P21：嗅探命中域名后按规则在 relay 侧重选出口（direct/block/用户组）
           --disable-timestamp      P38：日志关闭时间戳（对照 dae；也可 config global.disable_timestamp）
           --disable-pidfile        P38：不写 /var/run/sodama.pid（对照 dae）
           --subscribe <url>        P15：订阅（可重复；config subscription 段同源），与 --group 搭配；
                                     P34：多源默认按顺序回退（pacman 风格，subscription_failover）
           --group <name>           P15：选用 config 中的组（默认 proxy / 唯一组）
           --geodata-dir <dir>      P17a：geoip.dat/geosite.dat 搜索目录（可重复；也可 config
                                 global.geodata_dir（逗号分隔）；优先于 DAE_LOCATION_ASSET）
           --listen-socks <addr>    P12：本地 SOCKS5 入口（浏览器测试用；不加载 eBPF、不需 root）\n\
           --udp-idle-timeout <s>   P4：UDP NAT 会话空闲秒数（默认 60）\n\
           --forward <url>       旧写法：等价于 --dialer socks5://host:port
           --offload             P4c：启用 TCP relay offload（内核对拼，需 --dialer）
           --link-hdr <mode>     链路头模式 auto|l2|l3（默认 auto：按接口 arphrd 类型逐接口判定，
                                 tun/ppp/ipip/none → 无链路头 l3 变体；对照 dae linkHdrLen()）
           --xdp <ifname>        C4：XDP 计量探针接口（可重复；仅计数、恒 XDP_PASS，供实测调研）
           --no-splice           M1：关闭 relay splice 零拷贝（默认开：Direct/VLESS 明文）\n\
           --ebpf-debug          M1：eBPF 热路径调试打印（默认关）\n\
           --ktls                M2：尝试 kTLS（内核 TLS，实验；需 TLS1.3）\n\
           --max-conns <N>       P18e：relay 并发上限（0=不限；超限直接关闭并计数）\n\
           --dns-upstream <url>  P3a：DNS 上游（host:port 或 udp://host:port）\n\
           --watch-config <秒>    P33/P35：配置热驱动（0=关）。inotify 目录事件驱动为主（毫秒级 +
                                 100ms 去抖），<秒> 为无 inotify 时的兜底扫描间隔；变更自动 reload，
                                 且订阅节点走缓存（sub_cache_ttl，默认 1800s；失败源负缓存
                                 sub_fail_ttl 默认 600s）秒级生效——未变源不打订阅服务器
           --log-file <path>     P6/P35：日志写文件（默认 stdout；SIGHUP 时 reopen，轮转友好；
                                 可用 config global.log_file 代替；`--logfile` 同义）
           --logfile-maxsize <MB>   A2：内建轮转单文件上限（默认 0=不轮转；对照 dae lumberjack）
           --logfile-maxbackups <N> A2：轮转保留份数（默认 3；0=不保留；产物 <log>.<N>.gz）
           --dump                打印编译出的 match_set / LPM 内容\n\
           --compile-dump <path> 只编译规则并按对拍格式打印（不加载 eBPF，不需要 root）\n\
           --proxy <ipv4>        无 --rules 时加入「走代理」的目的 IP，可重复\n\
         \n\
         子命令（不加载 eBPF、不需 root）：\n\
           sodama validate <config.dae>       解析 + schema 校验 + routing 可编译性报告\n\
           sodama export-config <config.dae>  合并后的配置导出为 JSON\n\
           sodama export outline              A2：配置 schema（机器可读，供 UI/面板开发者；与 config-doc 同源登记表）\n\
           sodama extract-routing <config.dae> 输出可编译规则（deferred 到 stderr）\n\
           sodama status [--socket <path>] [--json]  查询状态面\n\
           sodama reload [--socket <path>] [--abort] P6/P38：热重载（等价 kill -HUP，同步等结果；\n\
                                 --abort = 关闭旧代已建连接，对照 dae reload --abort）
           sodama suspend|resume [--socket <path>] [--abort] P6/P38：no-load 挂起 / 恢复\n\
                                 （suspend --abort = 同时关闭全部已建连接）\n\
           sodama metrics [--socket <path>]     P6：Prometheus 文本格式统计导出\n\
           sodama sub-parse <url|path> [--tag <t>] [--json] [--limit <n>] [--timeout <s>] 只读：拉取订阅解析预览\n\
           sodama sysdump [--socket <path>] [--out <file>] P6：状态+规则+系统网络信息归档\n\
           sodama trace [--seconds N] [-4|-6] [--l4-proto tcp|udp] [--port N]
\n\
           sodama completion [bash|zsh|fish]   P38：输出 shell 补全脚本（对照 dae completion；\n\
                                 预生成副本在 install/shell-completion/）\n\
           sodama config-doc [--format md|json] [--out <file>] P38：输出配置参考（docs/config-reference.md 由此生成）\n\
         \n\
         运行中收到 SIGHUP 会重读 --rules/--config 并热重载（非活跃槽 → 切换 active），
         同时清除 suspend 状态并 reopen --log-file（对照 dae reload）；SIGUSR2 = suspend。
         P33：reload/SIGHUP 同时热更新运行时参数（relay/udp idle、dial_timeout、max_conns、
         dial_mode、sniffing_timeout、sniff-punt）；--watch-config 启用配置变更自动触发。
         P36：分流规则可独立成文件——config `rule_set {{ tag: 'url|路径' }}` 支持标准格式
         （Clash rule-provider YAML / sing-box rule-set JSON / 纯文本域名列表），URL 自动
         下载并缓存（global.rule_set_update_interval 秒，0=每次 reload 刷新；
         rule_set_cache_dir 可指定缓存目录）；routing 用 domain(ruleset: tag) 引用。"
    );
    std::process::exit(2);
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut args = Args {
        ebpf: "ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf".into(),
        lan: Vec::new(),
        no_lan: false,
        wan: Vec::new(),
        lan_given: false,
        wan_given: false,
        dual: Vec::new(),
        dae0: "dae0".into(),
        dae0peer: "dae0peer".into(),
        daens: "daens".into(),
        tproxy_port: 12345,
        rules: None,
        config: None,
        strict_config: false,
        status_socket: None,
        dialer: None,
        relay_idle_timeout: None,
        max_conns: None,
        dial_timeout: None,
        dial_mode: None,
        sniffing_timeout_ms: None,
        sniff_punt: false,
        subscribe: Vec::new(),
        geodata_dir: Vec::new(),
        group: None,
        listen_socks: None,
        udp_idle_timeout: None,
        forward: None,
        offload: false,
        link_hdr: LinkHdrMode::Auto,
        xdp: Vec::new(),
        splice: true,
        ebpf_debug: false,
        ktls: false,
        dns_upstream: None,
        dump: false,
        compile_dump: None,
        proxy_dsts: Vec::new(),
        log_file: None,
        watch_config: None,
        auto_config: false,
        disable_timestamp: false,
        disable_pidfile: false,
        logfile_maxsize: None,
        logfile_maxbackups: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("missing value for {a}"));
        match a.as_str() {
            "--ebpf" => args.ebpf = next()?,
            "--lan" => {
                let v = next()?;
                if v == "none" {
                    args.no_lan = true;
                } else {
                    args.lan.push(v);
                }
            }
            "--wan" => args.wan.push(next()?),
            "--dual" => args.dual.push(next()?),
            "--dae0" => args.dae0 = next()?,
            "--dae0peer" => args.dae0peer = next()?,
            "--daens" => args.daens = next()?,
            "--tproxy-port" => args.tproxy_port = next()?.parse()?,
            "--rules" => args.rules = Some(next()?),
            "--config" => args.config = Some(next()?),
            "--strict-config" => args.strict_config = true,
            "--status-socket" => args.status_socket = Some(next()?),
            "--log-file" => args.log_file = Some(next()?),
            "--watch-config" => args.watch_config = Some(next()?.parse()?),
            "--dialer" => args.dialer = Some(next()?),
            "--relay-idle-timeout" => args.relay_idle_timeout = Some(next()?.parse()?),
            "--dial-timeout" => args.dial_timeout = Some(next()?.parse()?),
            "--dial-mode" => {
                let v = next()?;
                match v.as_str() {
                    "ip" | "domain" | "domain+" | "domain++" => args.dial_mode = Some(v),
                    other => return Err(format!("--dial-mode 取值非法: {other}").into()),
                }
            }
            "--sniffing-timeout-ms" => args.sniffing_timeout_ms = Some(next()?.parse()?),
            "--sniff-punt" => args.sniff_punt = true,
            "--disable-timestamp" => args.disable_timestamp = true,
            "--disable-pidfile" => args.disable_pidfile = true,
            "--logfile" => args.log_file = Some(next()?),
            "--logfile-maxsize" => args.logfile_maxsize = Some(next()?.parse()?),
            "--logfile-maxbackups" => args.logfile_maxbackups = Some(next()?.parse()?),
            "--subscribe" => args.subscribe.push(next()?),
            "--geodata-dir" => args.geodata_dir.push(next()?),
            "--group" => args.group = Some(next()?),
            "--listen-socks" => args.listen_socks = Some(next()?),
            "--udp-idle-timeout" => args.udp_idle_timeout = Some(next()?.parse()?),
            "--forward" => args.forward = Some(next()?),
            "--offload" => args.offload = true,
            "--link-hdr" => {
                let v = next()?;
                args.link_hdr = match v.as_str() {
                    "auto" => LinkHdrMode::Auto,
                    "l2" => LinkHdrMode::L2,
                    "l3" => LinkHdrMode::L3,
                    other => {
                        return Err(format!("--link-hdr 取值非法: {other}（auto|l2|l3）").into())
                    }
                };
            }
            "--xdp" => args.xdp.push(next()?),
            "--no-splice" => args.splice = false,
            "--ebpf-debug" => args.ebpf_debug = true,
            "--ktls" => args.ktls = true,
            "--max-conns" => args.max_conns = Some(next()?.parse()?),
            "--dns-upstream" => args.dns_upstream = Some(next()?),
            "--dump" => args.dump = true,
            "--compile-dump" => args.compile_dump = Some(next()?),
            "--proxy" => {
                let ip: std::net::Ipv4Addr = next()?.parse()?;
                args.proxy_dsts.push(u32::from(ip).to_be());
            }
            "-h" | "--help" => usage(),
            other => return Err(format!("unknown option: {other}").into()),
        }
    }
    // 能力缺口 #3：记录 CLI 是否显式给出接口（config 回填的优先级依据；后面的默认值不算）。
    args.lan_given = !args.lan.is_empty();
    args.wan_given = !args.wan.is_empty();
    if args.lan.is_empty() && !args.no_lan && args.dual.is_empty() {
        args.lan.push("landae".into());
    }
    if args.wan.is_empty() && args.dual.is_empty() {
        args.wan.push("wan".into());
    }
    if args.proxy_dsts.is_empty() {
        args.proxy_dsts
            .push(u32::from(std::net::Ipv4Addr::new(1, 1, 1, 1)).to_be());
    }
    // P34：默认配置文件——未给 --config/--rules 时用 ~/.config/sodama/config.dae（若存在）。
    // 对拍（--compile-dump）排除在外，保持输出可复现。
    if args.config.is_none() && args.rules.is_none() && args.compile_dump.is_none() {
        if let Some(p) = default_config_path() {
            args.config = Some(p.to_string_lossy().into_owned());
            args.auto_config = true;
        }
    }
    Ok(args)
}

/// P34/P35：默认配置候选（顺序即优先级）——`$XDG_CONFIG_HOME/sodama/config.dae` →
/// `~/.config/sodama/config.dae` → `/etc/sodama/config.dae`（无 home 的软路由/OpenWrt 兜底）。
fn default_config_candidates(xdg: Option<&str>, home: Option<&str>) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(x) = xdg.filter(|s| !s.is_empty()) {
        out.push(std::path::Path::new(x).join("sodama").join("config.dae"));
    }
    if let Some(h) = home.filter(|s| !s.is_empty()) {
        out.push(
            std::path::Path::new(h)
                .join(".config")
                .join("sodama")
                .join("config.dae"),
        );
    }
    out.push(std::path::PathBuf::from("/etc/sodama/config.dae"));
    out
}

/// 按候选顺序返回第一个存在（且可读）的配置文件；无 home / 无 XDG 时落到 /etc/sodama。
/// `/etc` 候选额外要求可读：非 root 用户读到 640 root:root 的系统配置时当作不存在，
/// 避免普通用户被系统文件权限挡死（root/软路由/OpenWrt 场景不受影响）。
fn default_config_path() -> Option<std::path::PathBuf> {
    let xdg = std::env::var("XDG_CONFIG_HOME").ok();
    let home = std::env::var("HOME").ok();
    default_config_candidates(xdg.as_deref(), home.as_deref())
        .into_iter()
        .find(|p| {
            if !p.is_file() {
                return false;
            }
            if p.starts_with("/etc") && std::fs::File::open(p).is_err() {
                return false;
            }
            true
        })
}

fn if_nametoindex(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let c = CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(format!(
            "if_nametoindex({name}) failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(idx)
}

fn setns(fd: &OwnedFd, nstype: libc::c_int) -> Result<(), Box<dyn std::error::Error>> {
    let rc = unsafe { libc::setns(fd.as_raw_fd(), nstype) };
    if rc != 0 {
        return Err(format!("setns failed: {}", std::io::Error::last_os_error()).into());
    }
    Ok(())
}

/// 取接口 MAC。不能用 /sys/class/net（sysfs 视图跟随挂载点而不是当前 netns），
/// 用 SIOCGIFHWADDR ioctl，走 netlink/设备层，netns 语义正确。
fn read_mac(ifname: &str) -> Result<[u8; 6], Box<dyn std::error::Error>> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!(
            "socket() for mac query failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = ifname.as_bytes();
    if name.len() >= libc::IFNAMSIZ {
        return Err(format!("ifname too long: {ifname}").into());
    }
    for (i, b) in name.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }

    // P7：`as _` 同时适配 glibc（ioctl request= c_ulong）与 musl（c_int）
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as _, &mut ifr) };
    if rc != 0 {
        return Err(format!(
            "SIOCGIFHWADDR({ifname}) failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    let mut mac = [0u8; 6];
    let data = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    for (i, m) in mac.iter_mut().enumerate() {
        *m = data[i] as u8;
    }
    Ok(mac)
}

/// 创建 IP_TRANSPARENT 的 TCP 监听 socket（对照 dae AnyfromPool 的 tproxy listener）。
fn make_transparent_listener(port: u16) -> Result<TcpListener, Box<dyn std::error::Error>> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!("socket() failed: {}", std::io::Error::last_os_error()).into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let one: libc::c_int = 1;
    for (level, opt, name, value) in [
        (
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            "IP_TRANSPARENT",
            one,
        ),
        (libc::SOL_SOCKET, libc::SO_REUSEADDR, "SO_REUSEADDR", one),
        (
            libc::SOL_SOCKET,
            libc::SO_MARK,
            "SO_MARK",
            outbound::SO_MARK_VALUE.load(Ordering::Relaxed) as libc::c_int,
        ),
    ] {
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                opt,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(format!(
                "setsockopt({name}) failed: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("bind(:{port}) failed: {}", std::io::Error::last_os_error()).into());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(format!("listen failed: {}", std::io::Error::last_os_error()).into());
    }
    Ok(fd.into())
}

/// P16：IPV6_TRANSPARENT 的 TCP 监听 socket（`[::]:port`，V6ONLY）。
fn make_transparent_listener6(port: u16) -> Result<TcpListener, Box<dyn std::error::Error>> {
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!(
            "socket(AF_INET6) failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let one: libc::c_int = 1;
    for (level, opt, name, value) in [
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_TRANSPARENT,
            "IPV6_TRANSPARENT",
            one,
        ),
        (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, "IPV6_V6ONLY", one),
        (libc::SOL_SOCKET, libc::SO_REUSEADDR, "SO_REUSEADDR", one),
        (
            libc::SOL_SOCKET,
            libc::SO_MARK,
            "SO_MARK",
            outbound::SO_MARK_VALUE.load(Ordering::Relaxed) as libc::c_int,
        ),
    ] {
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                opt,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(format!(
                "setsockopt({name}) failed: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
    }
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    };
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "bind([::]:{port}) failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(format!("listen failed: {}", std::io::Error::last_os_error()).into());
    }
    Ok(fd.into())
}

/// 链路头模式（`--link-hdr`）。
/// 对照 dae：接口链路头长度由控制面按 netlink `Link.Attrs().EncapType` 判定
/// （`dae/control/control_plane_core_bind.go:61-77`：none/ipip/ppp/tun → 0，ether → 14，
/// 其它告警后按 14），再据此选 `_l2`/`_l3` 程序变体（同文件 :256-273）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkHdrMode {
    /// 逐接口按 sysfs arphrd 类型判定（默认）
    Auto,
    /// 强制以太（链路头 14B）
    L2,
    /// 强制无链路头（链路头 0B）
    L3,
}

/// 接口链路头长度（字节）。
///
/// 事实来源：`/sys/class/net/<if>/type` 就是 netlink 的 `IFLA_ARPHRD`（同一字段），
/// 故 dae 的 EncapType 判定可用它等价实现（sodama 不引 netlink 依赖）：
///   ARPHRD_ETHER(1) → 14
///   ARPHRD_PPP(512) / ARPHRD_TUNNEL(768) / ARPHRD_TUNNEL6(769) / ARPHRD_NONE(65534，tun) → 0
///   其它/读不到 → 14 + 告警（同 dae 默认分支）
fn link_hdr_len(ifname: &str, mode: LinkHdrMode) -> u32 {
    match mode {
        LinkHdrMode::L2 => 14,
        LinkHdrMode::L3 => 0,
        LinkHdrMode::Auto => {
            let path = format!("/sys/class/net/{ifname}/type");
            match std::fs::read_to_string(&path) {
                Ok(s) => match s.trim() {
                    "1" => 14,
                    "512" | "768" | "769" | "65534" => 0,
                    other => {
                        log(&format!(
                            "link-hdr: 接口 {ifname} 类型 {other} 未识别（{path}），按以太（14B）处理"
                        ));
                        14
                    }
                },
                Err(e) => {
                    log(&format!(
                        "link-hdr: 读 {path} 失败（{e}），按以太（14B）处理；可用 --link-hdr 覆盖"
                    ));
                    14
                }
            }
        }
    }
}

/// 按链路头长度选 TC 程序名：无链路头 → `_l3` 后缀变体。
fn tc_prog_name(base: &str, l3: bool) -> String {
    if l3 {
        format!("{base}_l3")
    } else {
        base.to_string()
    }
}

/// 把 L3 接口的 ifindex 登记进 `l3_ifindex_map`（回程路径 `sodama0_ingress` 据此跳过 MAC 改写）。
fn register_l3_ifindex(ebpf: &mut Ebpf, ifname: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let idx = if_nametoindex(ifname)?;
    let map = ebpf
        .map_mut("l3_ifindex_map")
        .ok_or("map l3_ifindex_map not found（对象版本过旧？）")?;
    let mut hm: HashMap<_, u32, u8> = HashMap::try_from(map)?;
    hm.insert(idx, 1u8, 0)?;
    log(&format!("link-hdr: {ifname} 登记为 L3（ifindex={idx}）"));
    Ok(idx)
}

/// 接口消失时按记下的 ifindex 清理 `l3_ifindex_map`。
/// 必须清：设备删除后 ifindex 会被复用，留旧条目会把新设备错认成 L3（回程不作 MAC 改写）。
fn unregister_l3_ifindex(ebpf: &mut Ebpf, idx: u32) -> Result<(), Box<dyn std::error::Error>> {
    let map = ebpf
        .map_mut("l3_ifindex_map")
        .ok_or("map l3_ifindex_map not found")?;
    let mut hm: HashMap<_, u32, u8> = HashMap::try_from(map)?;
    hm.remove(&idx)?;
    Ok(())
}

/// 能力缺口 #3：挂一个接口上某角色要求的全部钩子（L2/L3 按接口类型自动选变体；
/// L3 接口登记 `l3_ifindex_map`）。启动挂载与热插拔 watcher 共用；
/// 返回 `Some(ifindex)` 表示该接口按 L3 登记（供消失时清理）。
fn attach_role(
    ebpf: &mut Ebpf,
    iface: &str,
    role: ifwatch::Role,
    link_hdr: LinkHdrMode,
) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    let l3 = link_hdr_len(iface, link_hdr) == 0;
    let l3_idx = if l3 {
        Some(register_l3_ifindex(ebpf, iface)?)
    } else {
        None
    };
    match role {
        ifwatch::Role::Lan => {
            attach(
                ebpf,
                &tc_prog_name("sodama_lan_ingress", l3),
                iface,
                TcAttachType::Ingress,
            )?;
            // LAN egress 角色（对照 dae `setupLanInterface` 同时挂 lan_ingress + lan_egress，
            // `control_plane_core_bind.go:259-280`）：反向 conntrack 刷新——容器/独立
            // netns 出口场景下的回程状态保活（tproxy.c:2771-2855）。
            attach(
                ebpf,
                &tc_prog_name("sodama_lan_egress", l3),
                iface,
                TcAttachType::Egress,
            )?;
        }
        ifwatch::Role::Wan => {
            attach(
                ebpf,
                &tc_prog_name("sodama_wan_egress", l3),
                iface,
                TcAttachType::Egress,
            )?;
            attach(
                ebpf,
                &tc_prog_name("sodama_wan_ingress", l3),
                iface,
                TcAttachType::Ingress,
            )?;
        }
        ifwatch::Role::Dual => {
            attach(
                ebpf,
                &tc_prog_name("sodama_wan_lan_ingress", l3),
                iface,
                TcAttachType::Ingress,
            )?;
            attach(
                ebpf,
                &tc_prog_name("sodama_lan_wan_egress", l3),
                iface,
                TcAttachType::Egress,
            )?;
        }
    }
    Ok(l3_idx)
}

/// 能力缺口 #3：config `lan_interface`/`wan_interface` 的逗号/空白分隔解析。
fn split_iface_list(s: &str) -> Vec<String> {
    s.split([',', ' ', '\t'])
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

fn attach(
    ebpf: &mut Ebpf,
    name: &str,
    ifname: &str,
    attach_type: TcAttachType,
) -> Result<(), Box<dyn std::error::Error>> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} not found in object"))?
        .try_into()?;
    program.load()?;
    let _ = tc::qdisc_add_clsact(ifname);
    // P38（A1 #20）：attach 返回的是 `SchedClassifierLinkId`（弱句柄——drop 不摘钩，
    // 旧写的 `mem::forget` 是无操作）；真正的 link 由 program 内部 links 表持有，
    // 随 Ebpf/program（进程全程）存活，钩子随进程退出由内核回收。
    let _link = program.attach(ifname, attach_type)?;
    log(&format!("attached {name} to {ifname} ({attach_type:?})"));
    if let Ok(mut hooks) = HOOKS.lock() {
        hooks.push(format!("{name}@{ifname}"));
    }
    Ok(())
}

/// 对标批：把 `struct sk_buff` 字段偏移写入数据面（`trace_param_map`）。
///
/// aya-ebpf 没有 CO-RE field access，数据面的 `skb_send_sock` 探针需要运行内核的真实
/// 偏移（dae 用 clang CO-RE 读同一批字段，见 `kern/include/tcp_offload.h`）。
/// 解析失败（无 BTF / 内核未开 BTF）时返回 None：调用方跳过探针挂载并计数。
fn write_trace_params(ebpf: &mut Ebpf) -> Option<btfoff::SkBuffOffsets> {
    let off = match btfoff::sk_buff_offsets() {
        Ok(o) => o,
        Err(e) => {
            log(&format!(
                "offload 记账: BTF 解析失败（{e}），跳过 skb_send_sock 探针"
            ));
            return None;
        }
    };
    let map = match ebpf.map_mut("trace_param_map") {
        Some(m) => m,
        None => {
            log("offload 记账: 对象缺 trace_param_map，跳过探针");
            return None;
        }
    };
    let mut arr: Array<_, TraceParam> = match Array::try_from(map) {
        Ok(a) => a,
        Err(e) => {
            log(&format!("offload 记账: trace_param_map 类型不符（{e}）"));
            return None;
        }
    };
    let v = TraceParam {
        network_header: off.network_header,
        transport_header: off.transport_header,
        tail: off.tail,
        head: off.head,
    };
    if let Err(e) = arr.set(0, v, 0) {
        log(&format!("offload 记账: 写 trace_param_map 失败（{e}）"));
        return None;
    }
    log(&format!(
        "offload 记账: sk_buff 偏移 nh={} th={} tail={} head={}（vmlinux BTF）",
        v.network_header, v.transport_header, v.tail, v.head
    ));
    Some(off)
}

/// 对标批：挂载 offload 字节记账探针——优先 fentry，失败回退 kprobe。
///
/// 对照 dae `tcp_offload_hook.go` 的选用逻辑：fentry 在部分内核/固件上不可用
/// （无 CONFIG_DYNAMIC_FTRACE → 入口不是 5 字节 NOP；或目标已被其它 trampoline/直接
/// 调用占用 → EBUSY），kprobe 能挂在任意指令边界上。
/// 只在 `--offload` 下挂（记账只对 offload 会话有意义）。
fn attach_offload_accounting(ebpf: &mut Ebpf) {
    // 运维/诊断开关（与 SODAMA_NO_REACTOR 同风格）：跳过探针挂载，回退为只计数。
    // 用途：定位「记账探针对转发/性能有无影响」的 A/B；生产上也可用于隔离排障。
    if std::env::var_os("SODAMA_NO_OFFLOAD_ACCOUNT").is_some() {
        log("offload 记账: SODAMA_NO_OFFLOAD_ACCOUNT 已置，跳过 skb_send_sock 探针");
        return;
    }
    if write_trace_params(ebpf).is_none() {
        return;
    }

    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            log(&format!(
                "offload 记账: 读 /sys/kernel/btf/vmlinux 失败（{e}），跳过 fentry 直接试 kprobe"
            ));
            attach_offload_kprobe(ebpf);
            return;
        }
    };

    let fe_ret = (|| -> Result<(), Box<dyn std::error::Error>> {
        let p: &mut FEntry = ebpf
            .program_mut("skb_send_sock_account")
            .ok_or("program skb_send_sock_account not found")?
            .try_into()?;
        p.load("skb_send_sock", &btf)?;
        // P38：LinkId 弱句柄（drop 不摘钩）；钩子生命周期随 program/Ebpf。
        let _link = p.attach()?;
        Ok(())
    })();
    match fe_ret {
        Ok(()) => {
            log("offload 记账: fentry/skb_send_sock 已挂载（零开销探针）");
            if let Ok(mut hooks) = HOOKS.lock() {
                hooks.push("skb_send_sock_account@fentry".into());
            }
        }
        Err(e) => {
            log(&format!(
                "offload 记账: fentry 挂载失败（{e}），回退 kprobe/skb_send_sock"
            ));
            attach_offload_kprobe(ebpf);
        }
    }
}

/// kprobe 回退形态（与 fentry 共用记账主体，两者只在触发点上有别）。
fn attach_offload_kprobe(ebpf: &mut Ebpf) {
    let r = (|| -> Result<(), Box<dyn std::error::Error>> {
        let p: &mut KProbe = ebpf
            .program_mut("skb_send_sock_account_kprobe")
            .ok_or("program skb_send_sock_account_kprobe not found")?
            .try_into()?;
        p.load()?;
        // P38：同 fentry 分支：LinkId drop 不摘钩。
        let _link = p.attach("skb_send_sock", 0)?;
        Ok(())
    })();
    match r {
        Ok(()) => {
            log("offload 记账: kprobe/skb_send_sock 已挂载（fentry 的回退路径）");
            if let Ok(mut hooks) = HOOKS.lock() {
                hooks.push("skb_send_sock_account_kprobe@kprobe".into());
            }
        }
        Err(e) => log(&format!(
            "offload 记账: kprobe 也失败（{e}）；offload 字节记账不可用（计量降级）"
        )),
    }
}

/// C4：XDP 计量探针（可选）。**挂载失败不影响主路径**——它只是计量。
fn attach_xdp_probes(ebpf: &mut Ebpf, ifaces: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if ifaces.is_empty() {
        return Ok(());
    }
    let prog: &mut Xdp = ebpf
        .program_mut("sodama_xdp_observe")
        .ok_or("program sodama_xdp_observe not found（对象版本过旧？）")?
        .try_into()?;
    prog.load()?;
    for iface in ifaces {
        // Default：内核自选模式（驱动支持则 native，否则 generic）。
        match prog.attach(iface, XdpMode::Default) {
            Ok(_link) => {
                // P38：LinkId drop 不摘钩（真正的 link 由 program 持有，进程全程保活）。
                log(&format!(
                    "attached sodama_xdp_observe to {iface} (xdp, 仅计量)"
                ));
                if let Ok(mut hooks) = HOOKS.lock() {
                    hooks.push(format!("sodama_xdp_observe@{iface}"));
                }
            }
            Err(e) => log(&format!(
                "xdp: 挂载到 {iface} 失败（{e}），跳过（不影响转发）"
            )),
        }
    }
    Ok(())
}

/// P17b：找第一个 cgroup2 挂载点（对照 dae bpf_utils.go:261-290）。
fn find_cgroup2_mount() -> Option<std::path::PathBuf> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    for line in mounts.lines() {
        let mut it = line.split_whitespace();
        let _dev = it.next()?;
        let mp = it.next()?;
        let fstype = it.next()?;
        if fstype == "cgroup2" {
            return Some(std::path::PathBuf::from(mp));
        }
    }
    None
}

/// P17b：挂载 pname 采集钩子（cgroup2）。失败只告警继续（对照 dae
/// control_plane_datapath.go:149-152：cgroup2 不可用时 pname 规则静默不命中）。
fn attach_pname_hooks(ebpf: &mut Ebpf) {
    let Some(mnt) = find_cgroup2_mount() else {
        log("pname: 未找到 cgroup2 挂载点，pname 路由不可用（需要 cgroup2）");
        return;
    };
    let dir = match std::fs::File::open(&mnt) {
        Ok(d) => d,
        Err(e) => {
            log(&format!(
                "pname: 打开 cgroup2 挂载点 {} 失败: {e}；pname 路由不可用",
                mnt.display()
            ));
            return;
        }
    };

    // (程序名, 类型)：六个钩子，返回 1 放行（同 dae）。
    let sock_specs: [(&str, CgroupSockAttachType); 2] = [
        (
            "sodama_cgroup_sock_create",
            CgroupSockAttachType::SockCreate,
        ),
        (
            "sodama_cgroup_sock_release",
            CgroupSockAttachType::SockRelease,
        ),
    ];
    let addr_specs: [(&str, CgroupSockAddrAttachType); 4] = [
        ("sodama_cgroup_connect4", CgroupSockAddrAttachType::Connect4),
        ("sodama_cgroup_connect6", CgroupSockAddrAttachType::Connect6),
        (
            "sodama_cgroup_sendmsg4",
            CgroupSockAddrAttachType::UDPSendMsg4,
        ),
        (
            "sodama_cgroup_sendmsg6",
            CgroupSockAddrAttachType::UDPSendMsg6,
        ),
    ];
    let mut attached = 0usize;
    for (name, _ty) in sock_specs {
        let r = (|| -> Result<(), Box<dyn std::error::Error>> {
            let p: &mut CgroupSock = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("program {name} not found"))?
                .try_into()?;
            p.load()?;
            p.attach(&dir, CgroupAttachMode::Single)?;
            Ok(())
        })();
        match r {
            Ok(()) => {
                attached += 1;
                if let Ok(mut hooks) = HOOKS.lock() {
                    hooks.push(format!("{name}@{}", mnt.display()));
                }
            }
            Err(e) => log(&format!("pname: 挂载 {name} 失败: {e}")),
        }
    }
    for (name, ty) in addr_specs {
        let r = (|| -> Result<(), Box<dyn std::error::Error>> {
            let p: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("program {name} not found"))?
                .try_into()?;
            // aya-obj 的 attach_type 来自 section 名（connect4/sendmsg4/…），
            // CgroupSockAddr 会在 load 时从 section 取；这里类型仅作校验。
            let _ = ty;
            p.load()?;
            p.attach(&dir, CgroupAttachMode::Single)?;
            Ok(())
        })();
        match r {
            Ok(()) => {
                attached += 1;
                if let Ok(mut hooks) = HOOKS.lock() {
                    hooks.push(format!("{name}@{}", mnt.display()));
                }
            }
            Err(e) => log(&format!("pname: 挂载 {name} 失败: {e}")),
        }
    }
    if attached > 0 {
        log(&format!(
            "pname: cgroup2 钩子 {attached}/6 已挂载（{}），WAN egress 新连接可按进程名分流",
            mnt.display()
        ));
    } else {
        log("pname: cgroup2 钩子均未挂载，pname 路由不可用");
    }
}

/// tproxy 服务端：accept 后打印原始目的地址（tproxy 可见性），并对每行输入回显，
/// 直到对端关闭（最多 8 次）。每个连接一个线程：真实 dae 的 relay 是并发的，
/// 串行 accept 会让长连接堵死后续连接（rebind/故障注入测试会踩到）。
fn serve(listener: TcpListener) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // P7：tproxy 接受的连接关 Nagle（小包回程不叠加延迟 ACK 的 40ms）
                let _ = stream.set_nodelay(true);
                let b = std::thread::Builder::new()
                    .name("tproxy".into())
                    .stack_size(RELAY_HANDLER_STACK);
                if let Err(e) = b.spawn(move || handle_tproxy_conn(stream)) {
                    log(&format!("tproxy: 会话线程创建失败（{e}），丢弃该连接"));
                }
            }
            Err(e) => eprintln!("[sodama] accept error: {e}"),
        }
    }
}

fn handle_tproxy_conn(mut stream: TcpStream) {
    // P3b-1：TCP DNS（落到 tproxy 的 53 端口）交给 host ns 的 DNS 处理线程。
    // 能力缺口 #1：但 `must` 的 DNS 流**不被劫持**（dae `routing.md`：must_groupname
    // 不劫持/处理 DNS）——按普通代理连接继续往下走（relay / 回显夹具）。
    if let Ok(dst) = stream.local_addr() {
        let must = stream
            .peer_addr()
            .ok()
            .and_then(|p| lookup_conn_state(p, dst, 6))
            .map(|st| st.must)
            .unwrap_or(0);
        if dst.port() == 53 && must == 0 {
            match TCP_DNS_TX.get() {
                Some(tx) => match tx.send(stream) {
                    Ok(()) => return, // 连接所有权已移交
                    Err(e) => {
                        stream = e.0;
                        DNS_STATS.tcp_unsupported.fetch_add(1, Ordering::Relaxed);
                        log("tcp dns: 转交通道已关闭");
                    }
                },
                None => {
                    DNS_STATS.tcp_unsupported.fetch_add(1, Ordering::Relaxed);
                    log("tcp dns: DNS 处理线程未启动");
                }
            }
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
    // P4a：有拨号器时，tproxy 连接交给 host ns 的 relay 线程池做真实转发
    // （orig_dst = local_addr；出口 socket 打 SO_MARK）。
    if OUTBOUND.get().is_some() {
        match TCP_RELAY_TX.get() {
            Some(tx) => match tx.send(stream) {
                Ok(()) => return,
                Err(e) => {
                    stream = e.0;
                    log("relay: 转交通道已关闭");
                }
            },
            None => log("relay: 线程池未启动"),
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return;
    }
    let orig_dst = stream
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|e| format!("<{e}>"));
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|e| format!("<{e}>"));
    log(&format!("TPROXY ACCEPT orig_dst={orig_dst} peer={peer}"));
    // 回显夹具（无 dialer 的 up/ops-up 会话）：每读到一块数据就回一行 banner + 原样数据，
    // 直到对端关闭。**不要限制读次数**：早期版本限 8 次读（≈32KB），之后 shutdown(Both)
    // 使残余数据触发 RST——现象酷似“大流被中间设备 reset”，曾把 lab 排障引向 MTU/隧道
    // 方向（见 devlog §19）。夹具只用于 lab；生产会话必有 dialer，不会走到这里。
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = stream.write_all(
                    format!("sodama tproxy: orig_dst={orig_dst} peer={peer}\n").as_bytes(),
                );
                let _ = stream.write_all(&buf[..n]);
                let _ = stream.flush();
            }
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// 双向拷贝的一侧：记录字节数与活跃时间，EOF 后对写端半关闭。
/// `offloaded` = 内核对拼已生效：注册前已入队的数据仍需本线程排空，
/// 之后的任何 read 结果都不能当断连处理（psock 接管后 read 会返回 EAGAIN，
/// 实测也可能是其它错误码），一律驻留重试。offload 连接不在本路径驻留：
/// 看门狗（`offload_watch_loop`）统一判半关闭/超时并收尾（每连接 0 线程）。
/// P-AI：数据泵的字节去处——全局统计 + 本连接明细（收尾按域名归档）。
#[derive(Clone, Copy)]
struct ByteSink<'a> {
    global: &'a AtomicU64,
    session: Option<&'a AtomicU64>,
}

impl<'a> ByteSink<'a> {
    fn new(global: &'a AtomicU64, session: Option<&'a AtomicU64>) -> Self {
        Self { global, session }
    }
    /// 仅全局统计（offload 排空等无连接明细的旁路）。
    fn global_only(global: &'a AtomicU64) -> Self {
        Self {
            global,
            session: None,
        }
    }
    /// 单计数器（SOCKS 入口等本地统计；不计入全局/域名归档）。
    fn single(counter: &'a AtomicU64) -> Self {
        Self {
            global: counter,
            session: None,
        }
    }
    #[inline]
    fn add(&self, n: u64) {
        self.global.fetch_add(n, Ordering::Relaxed);
        if let Some(s) = self.session {
            s.fetch_add(n, Ordering::Relaxed);
        }
    }
}

fn pump(
    mut r: Box<dyn outbound::ReadHalf>,
    mut w: Box<dyn outbound::WriteHalf>,
    last_ns: &AtomicU64,
    bytes: ByteSink,
    offloaded: bool,
    stop: Option<&AtomicBool>,
    limiter: &'static RateLimiter,
) {
    // O8：64KB 读缓冲走池（短连接 churn 下免 malloc/页抖动）。
    let mut buf = bufpool::PoolBuf::zeroed(65536);
    let mut terminal_logged = false;
    loop {
        let read_res = r.read(&mut buf[..]);
        match read_res {
            Ok(0) | Err(_) if offloaded => {
                if !terminal_logged {
                    terminal_logged = true;
                    let how = match &read_res {
                        Ok(_) => "EOF".to_string(),
                        Err(e) => format!("{e}"),
                    };
                    log(&format!("offload: 泵收到终止信号（{how}），驻留等待看门狗"));
                }
                if stop.map(|s| s.load(Ordering::Relaxed)).unwrap_or(false) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            Ok(0) => break,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                break;
            }
            Err(e) => {
                log(&format!("pump: 读失败（{e}）"));
                break;
            }
            Ok(n) => {
                last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
                bytes.add(n as u64);
                // A2 #6：带宽限额（令牌桶；不足阻塞凑令牌 → 端到端背压）。
                limiter.throttle(n as u64);
                if let Err(e) = w.write_all(&buf[..n]) {
                    log(&format!("pump: 写失败（{e}）"));
                    break;
                }
            }
        }
    }
    let _ = w.shutdown_write();
}

// ---------------------------------------------------------------- A2 #6：带宽限额
/// `bandwidth_max_tx`/`bandwidth_max_rx`（字节/秒；0 = 不限）。
/// 落点在**用户态拷贝泵**（`pump`）做令牌桶节流 → 端到端背压。splice 零拷贝路径
/// 无法在用户态节流，因此限额生效时 relay 新连接强制走拷贝泵（见 `splice` 判定）。
/// 对照 dae：其限额在 outbound dialer 侧实现；sodama 无集中 dialer，等价落点在 relay 泵。
/// 进程级单例：所有连接共享配额；`set_rate` 可在配置 reload 时更新。
pub(crate) struct RateLimiter {
    /// 字节/秒（0 = 不限；运行期可改）。
    rate_bps: AtomicU64,
    /// (可用令牌, 上次补充时刻)。桶容量 = 1 秒的量。
    state: Mutex<(f64, Instant)>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            rate_bps: AtomicU64::new(0),
            state: Mutex::new((0.0, Instant::now())),
        }
    }

    fn rate(&self) -> u64 {
        self.rate_bps.load(Ordering::Relaxed)
    }

    /// 更新速率；桶重置为满（新速率下不继承旧状态的欠账）。
    fn set_rate(&self, bps: u64) {
        self.rate_bps.store(bps, Ordering::Relaxed);
        let mut g = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g = (bps as f64, Instant::now());
    }

    /// 为 `n` 字节发放令牌；不足则阻塞凑够。单次 sleep 上限 1s，小速率下分多轮补齐
    /// （不丢令牌也不超速）。
    fn throttle(&self, n: u64) {
        let rate = self.rate_bps.load(Ordering::Relaxed);
        if rate == 0 || n == 0 {
            return;
        }
        let rate = rate as f64;
        loop {
            let mut g = match self.state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let now = Instant::now();
            let dt = now.saturating_duration_since(g.1).as_secs_f64();
            g.0 = (g.0 + dt * rate).min(rate);
            g.1 = now;
            if g.0 >= n as f64 {
                g.0 -= n as f64;
                return;
            }
            let wait = (n as f64 - g.0) / rate;
            drop(g);
            std::thread::sleep(Duration::from_secs_f64(wait.min(1.0)));
        }
    }
}

fn limiter_tx() -> &'static RateLimiter {
    static L: OnceLock<RateLimiter> = OnceLock::new();
    L.get_or_init(RateLimiter::new)
}

fn limiter_rx() -> &'static RateLimiter {
    static L: OnceLock<RateLimiter> = OnceLock::new();
    L.get_or_init(RateLimiter::new)
}

/// 解析带宽限额（`100`=100 Mbit/s；`10mbps`/`10mbit`/`10m`=10 Mbit/s；
/// `1gbps`/`1g`；`500kb`/`500kbps`；`8192b`/`8192bytes` = 字节/秒；`0`/空 = 不限）。
fn parse_bandwidth(v: &str) -> Result<u64, String> {
    let t = v.trim().to_ascii_lowercase();
    if t.is_empty() || t == "0" {
        return Ok(0);
    }
    // 去掉可选的 "ps" 后缀（mbps → mb、kbps → kb），再切数字段与单位段。
    let body = t.strip_suffix("ps").unwrap_or(&t);
    let idx = body
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(body.len());
    let (num, unit) = body.split_at(idx);
    let n: f64 = num.parse().map_err(|_| format!("带宽数值非法: {v:?}"))?;
    let bps = match unit.trim() {
        "" | "m" | "mbit" | "mb" => n * 1_000_000.0 / 8.0,
        "g" | "gbit" | "gb" => n * 1_000_000_000.0 / 8.0,
        "k" | "kbit" | "kb" => n * 1_000.0 / 8.0,
        "b" | "byte" | "bytes" => n,
        other => return Err(format!("带宽单位未知: {other:?}（mbit/kbit/gbit/bytes）")),
    };
    Ok(bps.round().max(0.0) as u64)
}

// ---------------------------------------------------------------- M1：splice 零拷贝泵

/// splice 不可用（首调 EINVAL/ENOSYS）时回退用户态泵；Fatal 为传输中错误。
enum SpliceErr {
    Unsupported(io::Error),
    Fatal(io::Error),
}

/// M2：kTLS RX 下游 splice 辅助——队首若是已解密控制记录（NST 等）就消费掉。
///
/// 内核 `tls_sw_splice_read` 不支持控制记录：遇队首为非应用数据会 requeue 并返回
/// EINVAL。这里先用 MSG_PEEK 看 cmsg 记录类型（kTLS 应用数据=23 且带 cmsg；
/// 普通 socket 无 cmsg）：是控制记录才真正读掉；应用数据原封不动留给 splice。
/// 返回 Ok(true) = 消费了一条控制记录；Ok(false) = 队首是应用数据/暂无可读。
fn ktls_take_control_record(fd: RawFd) -> io::Result<bool> {
    #[repr(align(8))]
    struct Ctl([u8; 64]);
    fn peek(fd: RawFd, buf: &mut [u8], flags: i32) -> io::Result<(isize, Option<u8>)> {
        loop {
            let mut ctl = Ctl([0u8; 64]);
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctl.0.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = ctl.0.len() as _;
            let n = unsafe { libc::recvmsg(fd, &mut msg, flags) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let mut t = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_TLS
                        && (*cmsg).cmsg_type == libc::TLS_GET_RECORD_TYPE
                    {
                        t = Some(*libc::CMSG_DATA(cmsg));
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }
            return Ok((n, t));
        }
    }
    let mut buf = [0u8; 16384];
    let (n, t) = match peek(fd, &mut buf, libc::MSG_PEEK | libc::MSG_DONTWAIT) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e),
    };
    if n == 0 {
        return Ok(false); // EOF：交给 splice 处理
    }
    match t {
        Some(23) | None => Ok(false), // 应用数据（plain 无 cmsg，kTLS 为 23）：不动
        Some(_) => {
            // 控制记录：真正读掉（同一缓冲，忽略返回长度）。
            let _ = peek(fd, &mut buf, libc::MSG_DONTWAIT)?;
            Ok(true)
        }
    }
}

/// 单向 splice 泵：`src → pipe → dst`，大块零拷贝搬运（页级），EOF 时对 dst 半关闭。
/// 与 `pump` 语义对齐：返回 Ok = 已收到 EOF 且已 shutdown(dst, SHUT_WR)。
fn splice_pump(
    src: RawFd,
    dst: RawFd,
    last_ns: &AtomicU64,
    bytes: ByteSink,
) -> Result<(), SpliceErr> {
    const CHUNK: usize = 1 << 20;
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SpliceErr::Unsupported(io::Error::last_os_error()));
    }
    struct PipeGuard([i32; 2]);
    impl Drop for PipeGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0[0]);
                libc::close(self.0[1]);
            }
        }
    }
    let pipe = PipeGuard(fds);
    let (pr, pw) = (pipe.0[0], pipe.0[1]);
    // 扩大管道容量；失败忽略（默认 64KB，仅影响 syscall 频率）。
    unsafe {
        libc::fcntl(pw, libc::F_SETPIPE_SZ, CHUNK as libc::c_int);
    }
    let mut started = false;
    loop {
        let n = unsafe {
            libc::splice(
                src,
                std::ptr::null_mut(),
                pw,
                std::ptr::null_mut(),
                CHUNK,
                0,
            )
        };
        if n == 0 {
            break; // EOF：与 pump 一致，向对端传播半关闭
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // EINVAL：kTLS RX socket 遇到控制记录（NewSessionTicket 等）会 requeue
            // 记录并返回 EINVAL（内核要求改用带 cmsg 的 recvmsg）；此时管道尚未搬入
            // 任何数据，回退用户态泵（ktls_read 会用 cmsg 丢掉控制记录）即可续传。
            return Err(if !started || e.raw_os_error() == Some(libc::EINVAL) {
                SpliceErr::Unsupported(e)
            } else {
                SpliceErr::Fatal(e)
            });
        }
        started = true;
        let mut left = n as usize;
        while left > 0 {
            let m = unsafe {
                libc::splice(pr, std::ptr::null_mut(), dst, std::ptr::null_mut(), left, 0)
            };
            if m <= 0 {
                return Err(SpliceErr::Fatal(if m == 0 {
                    io::Error::other("splice: 管道提前关闭")
                } else {
                    io::Error::last_os_error()
                }));
            }
            left -= m as usize;
        }
        bytes.add(n as u64);
        last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
    }
    unsafe {
        libc::shutdown(dst, libc::SHUT_WR);
    }
    Ok(())
}

/// M1：一次 codec 首读（消费 VLESS 响应头等前缀）后切换到 splice；
/// 不可 splice 时回退 `pump`。`upstream_fd` 为底层 socket（Direct/VLESS 明文）。
fn pump_or_splice_down(
    mut from_remote: Box<dyn outbound::ReadHalf>,
    mut client: TcpStream,
    upstream_fd: RawFd,
    last_ns: &AtomicU64,
    sink: ByteSink,
    splice: bool,
    stop: Option<&AtomicBool>,
) {
    const PRE: usize = 65536;
    let mut buf = vec![0u8; PRE];
    if splice {
        match from_remote.read(&mut buf) {
            Ok(0) => {
                let _ = client.shutdown(std::net::Shutdown::Write);
                return;
            }
            Ok(n) => {
                if let Err(e) = client.write_all(&buf[..n]) {
                    log(&format!("pump: 写失败（{e}）"));
                    return;
                }
                sink.add(n as u64);
                last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
            }
            Err(e) => {
                log(&format!("pump: 读失败（{e}）"));
                return;
            }
        }
        // M2：先清掉队首控制记录（kTLS RX 的 NST 等）再 splice；splice 等数据时
        // 若先等来控制记录会返回 EINVAL（本轮 drain 没看到也正常）——下一轮
        // drain 会把它消费掉再重试；上限 8 轮。
        let mut attempts = 0u32;
        let outcome = loop {
            let mut moved = 0u32;
            while moved < 8 {
                match ktls_take_control_record(upstream_fd) {
                    Ok(true) => moved += 1,
                    Ok(false) => break,
                    Err(e) => {
                        log(&format!("splice: 读取控制记录失败（{e}）"));
                        break;
                    }
                }
            }
            match splice_pump(upstream_fd, client.as_raw_fd(), last_ns, sink) {
                Err(SpliceErr::Unsupported(e))
                    if e.raw_os_error() == Some(libc::EINVAL) && attempts < 8 =>
                {
                    attempts += 1;
                    continue;
                }
                r => break r,
            }
        };
        match outcome {
            Ok(()) => return,
            Err(SpliceErr::Unsupported(e)) => {
                RELAY_STATS.splice_fallbacks.fetch_add(1, Ordering::Relaxed);
                if !SPLICE_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
                    log(&format!("splice: 下游方向不可用（{e}），回退用户态泵"));
                }
            }
            Err(SpliceErr::Fatal(e)) => {
                log(&format!("splice: 下游传输错误（{e}）"));
                return;
            }
        }
    }
    pump(
        from_remote,
        Box::new(client),
        last_ns,
        sink,
        false,
        stop,
        limiter_rx(),
    );
}

// ---------------- offload 背压 fuse（对照 dae `fuseStep` / `tcp_offload_pause`） ----------------

/// 背压阈值（dae：64 MiB；`SODAMA_FUSE_MAX_BACKLOG` 可调，测试用）。
fn fuse_max_backlog() -> u64 {
    std::env::var("SODAMA_FUSE_MAX_BACKLOG")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(64 << 20)
}
/// 恢复阈值（dae：1 MiB）。
const FUSE_RESUME_BYTES: u64 = 1 << 20;
/// drain 上限（dae：10s）：stop 后泵尽力排空，超时强强 lift（保留可观测告警）。
const FUSE_DRAIN_WAIT: Duration = Duration::from_secs(10);

/// 写/删 pause 键（幂等；删不存在的键不算错）。
fn offload_pause_set(key: &SodaTuple, on: bool) -> std::io::Result<()> {
    let Some(m) = OFFLOAD_PAUSE.get() else {
        return Err(std::io::Error::other("pause map 未初始化"));
    };
    let Ok(mut m) = m.lock() else {
        return Err(std::io::Error::other("pause map 锁中毒"));
    };
    if on {
        m.insert(key, 1u8, 0)
            .map_err(|e| std::io::Error::other(e.to_string()))
    } else {
        match m.remove(key) {
            Ok(()) => Ok(()),
            Err(aya::maps::MapError::SyscallError(e))
                if e.io_error.raw_os_error() == Some(libc::ENOENT) =>
            {
                Ok(())
            }
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    }
}

/// 只读求和 `offload_sent` 的 per-CPU 记账（不删除；fuse 的 backlog 计算用）。
fn offload_sent_read(key: &SodaTuple) -> u64 {
    let Some(m) = OFFLOAD_SENT.get() else {
        return 0;
    };
    let Ok(m) = m.lock() else { return 0 };
    m.get(key, 0)
        .map(|v| v.iter().copied().sum::<u64>())
        .unwrap_or(0)
}

/// 读一侧 socket 的累计接收字节（TCP_INFO.tcpi_bytes_received）。
fn tcp_conn_rx_bytes(fd: RawFd) -> Option<u64> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut libc::tcp_info as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    Some(info.tcpi_bytes_received)
}

/// fuse 期间的转发泵：poll 两 fd → 可读即读到干→写对端；`stop` 置位且两侧读干后
/// 置 `drained` 并退出（lift 前置条件，对照 dae `drainResidual`；防数据乱序）。
fn spawn_fuse_pump(
    left_fd: RawFd,
    right_fd: RawFd,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    drained: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pass_bytes: std::sync::Arc<AtomicU64>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("fuse-pump".into())
        .spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let mut pfds = [
                    libc::pollfd {
                        fd: left_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: right_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                let stopped = stop.load(Ordering::Relaxed);
                let timeout = if stopped { 50 } else { 200 };
                let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, timeout) };
                let mut moved = 0u64;
                if rc > 0 {
                    for i in 0..2usize {
                        if pfds[i].revents & (libc::POLLIN | libc::POLLRDHUP) == 0 {
                            continue;
                        }
                        let (from, to) = if i == 0 {
                            (left_fd, right_fd)
                        } else {
                            (right_fd, left_fd)
                        };
                        loop {
                            let n = unsafe {
                                libc::read(from, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                            };
                            if n <= 0 {
                                break;
                            }
                            let n = n as usize;
                            let mut off = 0usize;
                            while off < n {
                                let w = unsafe {
                                    libc::write(
                                        to,
                                        buf[off..].as_ptr() as *const libc::c_void,
                                        n - off,
                                    )
                                };
                                if w <= 0 {
                                    break;
                                }
                                off += w as usize;
                            }
                            moved += n as u64;
                            if n < buf.len() {
                                break;
                            }
                        }
                    }
                }
                if moved > 0 {
                    pass_bytes.fetch_add(moved, Ordering::Relaxed);
                }
                if stopped && rc == 0 && moved == 0 {
                    drained.store(true, Ordering::Relaxed);
                    return;
                }
            }
        })
}

/// fuse 的单轮判定结果（抽成纯函数以便单测：真实对端积压在本地回环夹具下
/// 不可自然构造，判定逻辑用单测锁定）。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum FuseDecision {
    None,
    Engage,
    /// backlog 回落（或 engage 超时）→ 先停泵让用户态把残余数据排空（drain）。
    /// 不能直接 lift：两侧接收队列里可能还有 SK_PASS 数据，未 drain 就恢复内核
    /// 拼接会与用户态晚写的字节乱序（对照 dae `drainResidual` 前置）。
    DrainStart,
    /// 已 drain → 正常 lift（删 pause 键）。
    Lift,
    /// drain 超时 → 强制 lift（打告警）。
    LiftTimeout,
}

/// backlog = inflow −（内核推送 sent + 用户态泵 pass）；fused 时两阶段：
/// ① backlog 回落或超时 → DrainStart（置 stop）；② drained 或 drain 超时 → Lift。
/// 对照 dae `fuseStep`（`control/tcp_offload_linux.go:371-460`）。
#[allow(clippy::too_many_arguments)]
fn fuse_decision(
    inflow: u64,
    sent: u64,
    pass: u64,
    fused: bool,
    drained: bool,
    drain_started: bool,
    since_engage: Option<Duration>,
    since_drain_start: Option<Duration>,
    max_backlog: u64,
) -> (FuseDecision, i64) {
    let backlog = inflow as i64 - (sent as i64 + pass as i64);
    if fused {
        if drain_started {
            if drained {
                return (FuseDecision::Lift, backlog);
            }
            if since_drain_start
                .map(|d| d > FUSE_DRAIN_WAIT)
                .unwrap_or(false)
            {
                return (FuseDecision::LiftTimeout, backlog);
            }
            return (FuseDecision::None, backlog);
        }
        if backlog <= FUSE_RESUME_BYTES as i64
            || since_engage.map(|d| d > FUSE_DRAIN_WAIT).unwrap_or(false)
        {
            return (FuseDecision::DrainStart, backlog);
        }
        return (FuseDecision::None, backlog);
    }
    if backlog > max_backlog as i64 {
        return (FuseDecision::Engage, backlog);
    }
    (FuseDecision::None, backlog)
}

/// 每轮看门狗对单个 offload 会话调一次：计算 backlog → engage/lift。
/// backlog = （两侧 TCP_INFO 接收字节增量）− （内核推送字节 + 用户态泵字节）。
fn offload_fuse_step(e: &mut OffloadWatchEntry) {
    let Some((k_up, k_cl)) = e.keys.as_ref() else {
        return;
    };
    // 首轮采样 baseline（注册后尽快形成干净基线，对照 dae `newTCPRelayOffloadSession`）。
    if e.fuse_rx_base.is_none() {
        if let (Some(l), Some(r)) = (
            tcp_conn_rx_bytes(e.client_fd),
            tcp_conn_rx_bytes(e.upstream_fd),
        ) {
            e.fuse_rx_base = Some((l, r));
        }
        return;
    }
    let (Some(lr), Some(rr)) = (
        tcp_conn_rx_bytes(e.client_fd),
        tcp_conn_rx_bytes(e.upstream_fd),
    ) else {
        return;
    };
    let (lb, rb) = e.fuse_rx_base.unwrap();
    let inflow = lr.saturating_sub(lb) + rr.saturating_sub(rb);
    let sent = offload_sent_read(k_up) + offload_sent_read(k_cl);
    let pass = e.fuse_pass_bytes.load(Ordering::Relaxed);
    let drained = e
        .fuse_drained
        .as_ref()
        .map(|d| d.load(Ordering::Relaxed))
        .unwrap_or(false);
    let (decision, backlog) = fuse_decision(
        inflow,
        sent,
        pass,
        e.fuse_fused,
        drained,
        e.fuse_drain_started,
        e.fuse_since.map(|t| t.elapsed()),
        e.fuse_drain_since.map(|t| t.elapsed()),
        fuse_max_backlog(),
    );

    match decision {
        FuseDecision::None => {}
        FuseDecision::DrainStart => {
            if let Some(stop) = &e.fuse_stop {
                stop.store(true, Ordering::Relaxed);
            }
            e.fuse_drain_started = true;
            e.fuse_drain_since = Some(Instant::now());
            log(&format!(
                "offload fuse: #{id} backlog 回落，开始 drain（backlog={backlog}，泵转发 {pass} B）",
                id = e.id
            ));
        }
        FuseDecision::Lift | FuseDecision::LiftTimeout => {
            if decision == FuseDecision::LiftTimeout {
                log(&format!(
                    "offload fuse: #{id} drain 超时（{FUSE_DRAIN_WAIT:?}）但强制 lift（backlog={backlog}）",
                    id = e.id
                ));
            }
            if let Some(stop) = e.fuse_stop.take() {
                stop.store(true, Ordering::Relaxed);
            }
            let _ = offload_pause_set(k_up, false);
            let _ = offload_pause_set(k_cl, false);
            e.fuse_fused = false;
            e.fuse_since = None;
            e.fuse_drained = None;
            e.fuse_drain_started = false;
            e.fuse_drain_since = None;
            RELAY_STATS.fuse_lifts.fetch_add(1, Ordering::Relaxed);
            log(&format!(
                "offload fuse: #{id} 已 lift（backlog={backlog}，泵转发 {pass} B）",
                id = e.id
            ));
        }
        FuseDecision::Engage => {
            // all-or-nothing engage（对照 dae：部分失败回滚，保可用性）。
            if offload_pause_set(k_up, true).is_ok() && offload_pause_set(k_cl, true).is_ok() {
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let drained = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                match spawn_fuse_pump(
                    e.client_fd,
                    e.upstream_fd,
                    stop.clone(),
                    drained.clone(),
                    e.fuse_pass_bytes.clone(),
                ) {
                    Ok(_) => {
                        e.fuse_fused = true;
                        e.fuse_since = Some(Instant::now());
                        e.fuse_drain_started = false;
                        e.fuse_drain_since = None;
                        e.fuse_stop = Some(stop);
                        e.fuse_drained = Some(drained);
                        RELAY_STATS.fuse_engages.fetch_add(1, Ordering::Relaxed);
                        log(&format!(
                            "offload fuse: #{id} 已 engage（backlog={backlog}，阈值={}）",
                            fuse_max_backlog(),
                            id = e.id
                        ));
                    }
                    Err(err) => {
                        let _ = offload_pause_set(k_up, false);
                        let _ = offload_pause_set(k_cl, false);
                        RELAY_STATS.fuse_failures.fetch_add(1, Ordering::Relaxed);
                        log(&format!(
                            "offload fuse: #{id} 泵线程创建失败（{err}），已回滚",
                            id = e.id
                        ));
                    }
                }
            } else {
                let _ = offload_pause_set(k_up, false);
                let _ = offload_pause_set(k_cl, false);
                RELAY_STATS.fuse_failures.fetch_add(1, Ordering::Relaxed);
                log(&format!(
                    "offload fuse: #{id} pause 键写入失败，已回滚",
                    id = e.id
                ));
            }
        }
    }
}

/// 连接收尾：停泵、清 pause 键（幂等；键注销前的 fuse 残留必须清干净）。
fn offload_fuse_release(e: &mut OffloadWatchEntry) {
    if let Some(stop) = e.fuse_stop.take() {
        stop.store(true, Ordering::Relaxed);
    }
    if let Some((k_up, k_cl)) = e.keys.as_ref() {
        let _ = offload_pause_set(k_up, false);
        let _ = offload_pause_set(k_cl, false);
    }
    e.fuse_fused = false;
    e.fuse_drain_started = false;
    e.fuse_drain_since = None;
}

struct OffloadWatchEntry {
    id: u64,
    client_fd: RawFd,
    upstream_fd: RawFd,
    handle: Arc<RelayHandle>,
    /// 注册时的 fast_sock/guard 键（清理时由看门狗注销）。
    keys: Option<(SodaTuple, SodaTuple)>,
    client_closed: bool,
    upstream_closed: bool,
    first_close: Option<Instant>,
    err_logged: bool,
    /// 背压 fuse 状态（对照 dae `tcpRelayOffloadSession` 的 fuse 字段）。
    fuse_rx_base: Option<(u64, u64)>,
    fuse_fused: bool,
    fuse_since: Option<Instant>,
    /// 两阶段 lift：先 DrainStart（置 stop、等泵排空），再 Lift（删 pause 键）。
    fuse_drain_started: bool,
    fuse_drain_since: Option<Instant>,
    fuse_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    fuse_drained: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    fuse_pass_bytes: std::sync::Arc<AtomicU64>,
}

static OFFLOAD_WATCH: std::sync::LazyLock<(Mutex<Vec<OffloadWatchEntry>>, std::sync::Condvar)> =
    std::sync::LazyLock::new(|| (Mutex::new(Vec::new()), std::sync::Condvar::new()));

/// 注册一个 offload 连接（在 `handle_relay_conn` 内，注册后直接返回）。
fn offload_watch_register(e: OffloadWatchEntry) {
    // 注册时清残余 pause 键（对照 dae `tcp_offload_linux.go:306-333`：
    // 新连接不能继承上一条连接的暂停状态，否则下一跳永久暂停且无法自洽）。
    if let Some((k_up, k_cl)) = &e.keys {
        let _ = offload_pause_set(k_up, false);
        let _ = offload_pause_set(k_cl, false);
    }
    let (m, cv) = &*OFFLOAD_WATCH;
    match m.lock() {
        Ok(mut v) => v.push(e),
        Err(_) => return,
    }
    cv.notify_one();
}

/// offload 连接收尾：注销 fast_sock/guard 键 + 从 relay 注册表摘除。
fn offload_watch_cleanup(id: u64, keys: &Option<(SodaTuple, SodaTuple)>) {
    if let Some((k_up, k_cl)) = keys {
        // 对标批：摘键前汇总内核路径推送字节（两键各自归因，日志报总量）。
        // 与数据面存在竞态：读后到 remove 前可能仍有记账增量——接受的小误差。
        let sent = offload_sent_reclaim(k_up) + offload_sent_reclaim(k_cl);
        offload_guard_remove(k_up);
        offload_guard_remove(k_cl);
        if let Some(map) = RELAY_OFFLOAD.get() {
            if let Ok(mut m) = map.lock() {
                let _ = m.remove(k_up);
                let _ = m.remove(k_cl);
            }
        }
        log(&format!(
            "offload: #{id} 已注销 fast_sock 键（内核路径推送 {sent} B）"
        ));
    }
    relay_finish(id);
}

/// P7/M4 stage 2：全局 offload 看门狗（单线程，每 offload 连接 0 线程）。
///
/// 取代原先「每连接一个 monitor 线程 + 两个驻留泵线程」的模型：注册后直接返回，
/// 不再驻留用户态泵；由本线程统一 poll(RDHUP) 判定半关闭并在超时后强制回收，
/// 并负责 fast_sock 键注销与 `relay_finish`。
/// 实测规则（C 基准 + 逐级实验，不变）：
///   - 内核重定向会自行处理 FIN，但不会把 EOF 传给对端用户态；
///   - FIN 重定向尝试会在源 socket 上留下 POLLERR——这不是错误，**绝不能**
///     在传输中 force-close（会把在途重定向数据全部切断）；
///   - 用户态主动向对端传播 FIN 也会截断排队中的数据；
/// 因此：只在两侧都 RDHUP 时干净退出；只有一侧 RDHUP 超过 10s
/// （对照 dae relayHalfCloseTimeout）才强制关闭，保证连接最终可回收。
fn offload_watch_loop() {
    const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
    fn poll_revents(fd: RawFd) -> i16 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLRDHUP | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        if rc > 0 {
            pfd.revents
        } else {
            0
        }
    }
    let (m, cv) = &*OFFLOAD_WATCH;
    loop {
        {
            let mut v = m.lock().unwrap_or_else(|p| p.into_inner());
            let mut i = 0;
            while i < v.len() {
                let mut remove = false;
                {
                    let e = &mut v[i];
                    if e.handle.stop.load(Ordering::Relaxed) {
                        remove = true;
                    } else {
                        // 背压 fuse：每轮 tick 评估一次 backlog（engage/lift）。
                        offload_fuse_step(e);
                        let ce = if e.client_closed {
                            0
                        } else {
                            poll_revents(e.client_fd)
                        };
                        let ue = if e.upstream_closed {
                            0
                        } else {
                            poll_revents(e.upstream_fd)
                        };
                        if !e.err_logged && (ce | ue) & (libc::POLLERR | libc::POLLHUP) != 0 {
                            e.err_logged = true;
                            log(&format!(
                                "offload: 观察到 POLLERR/POLLHUP（client=0x{ce:x} upstream=0x{ue:x}），按被动策略忽略"
                            ));
                        }
                        if ce & libc::POLLRDHUP != 0 && !e.client_closed {
                            e.client_closed = true;
                            log("offload: 客户端半关闭（等待对端或 10s 超时）");
                        }
                        if ue & libc::POLLRDHUP != 0 && !e.upstream_closed {
                            e.upstream_closed = true;
                            log("offload: 上游半关闭（等待对端或 10s 超时）");
                        }
                        if e.client_closed && e.upstream_closed {
                            remove = true;
                        } else if e.client_closed || e.upstream_closed {
                            match e.first_close {
                                None => e.first_close = Some(Instant::now()),
                                Some(t) if t.elapsed() > HALF_CLOSE_TIMEOUT => {
                                    unsafe {
                                        libc::shutdown(e.client_fd, libc::SHUT_RDWR);
                                        libc::shutdown(e.upstream_fd, libc::SHUT_RDWR);
                                    }
                                    log("offload: 半关闭超时，强制关闭两侧");
                                    remove = true;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if remove {
                    let mut e = v.swap_remove(i);
                    offload_fuse_release(&mut e);
                    offload_watch_cleanup(e.id, &e.keys);
                    continue; // swap_remove 后 i 指向新元素，不递增
                }
                i += 1;
            }
            let empty = v.is_empty();
            drop(v);
            let wait = if empty {
                Duration::from_millis(500)
            } else {
                Duration::from_millis(200)
            };
            if let Ok(g) = m.lock() {
                let _ = cv.wait_timeout(g, wait);
            }
        }
    }
}

/// 构造 fast_sock 键：元组取「remote → local」方向（对照 dae makeTuplesKey）。
/// 地址统一为 16 字节形式（v4-mapped / v6 原始）；offload 目前仅 v4 路径生效。
fn addr16(ip: std::net::IpAddr) -> ([u8; 16], u8) {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[10] = 0xff;
            b[11] = 0xff;
            b[12..16].copy_from_slice(&v4.octets());
            (b, 0)
        }
        std::net::IpAddr::V6(v6) => (v6.octets(), 1),
    }
}

fn sodama_tuple_of(remote: SocketAddr, local: SocketAddr) -> Option<SodaTuple> {
    sodama_tuple_of_proto(remote, local, 6) // IPPROTO_TCP
}

/// P19：带协议的 5 元组键（TCP=6 / UDP=17）——conn_state 回读与 offload 共用。
fn sodama_tuple_of_proto(remote: SocketAddr, local: SocketAddr, l4proto: u8) -> Option<SodaTuple> {
    if remote.is_ipv4() != local.is_ipv4() {
        return None;
    }
    let (sip, v6) = addr16(remote.ip());
    let (dip, _) = addr16(local.ip());
    Some(SodaTuple {
        sip,
        dip,
        sport: remote.port().to_be(),
        dport: local.port().to_be(),
        l4proto,
        is_v6: v6,
        pad: [0; 2],
    })
}

/// P19 + 兜底：按 5 元组回读数据面选中的 outbound。
/// 优先序对照 dae `RetrieveRoutingResult`（`control/utils.go:64-80`）：
/// 先 conn_state（且 `has_routing`），miss/无路由再读 `routing_handoff_map`
/// （首包重定向时的交接条目，TTL 内有效）。
fn lookup_conn_outbound(remote: SocketAddr, local: SocketAddr, l4proto: u8) -> Option<u8> {
    if let Some(st) = lookup_conn_state(remote, local, l4proto) {
        if st.has_routing != 0 {
            return Some(st.outbound);
        }
    }
    lookup_routing_handoff(remote, local, l4proto).map(|e| (e.result & 0xff) as u8)
}

/// 读 routing_handoff_map（raw lookup；陈旧条目（> TTL）不采信）。
fn lookup_routing_handoff(
    remote: SocketAddr,
    local: SocketAddr,
    l4proto: u8,
) -> Option<SodaRoutingHandoffEntry> {
    let fd = HANDOFF_MAP_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return None;
    }
    let key = sodama_tuple_of_proto(remote, local, l4proto)?;
    let mut e = SodaRoutingHandoffEntry::default();
    let keyb = unsafe {
        std::slice::from_raw_parts(
            &key as *const SodaTuple as *const u8,
            std::mem::size_of::<SodaTuple>(),
        )
    };
    let valb = unsafe {
        std::slice::from_raw_parts_mut(
            &mut e as *mut SodaRoutingHandoffEntry as *mut u8,
            std::mem::size_of::<SodaRoutingHandoffEntry>(),
        )
    };
    if bpf_map_lookup_raw(fd, keyb, valb).is_err() {
        return None;
    }
    // 陈旧判定：now - last_seen > TTL → 不采信（dae 无显式 TTL，靠 reload 换代自然失效）。
    let now = monotonic_now_ns();
    if handoff_expired(now, e.last_seen_ns, SODAMA_HANDOFF_TTL_NS) {
        return None;
    }
    Some(e)
}

/// 能力缺口 #1：回读整条 conn_state（含 must）——DNS 交付侧据此区分
/// 「劫持到控制面」与「must：按普通代理流转发」。
fn lookup_conn_state(remote: SocketAddr, local: SocketAddr, l4proto: u8) -> Option<SodaConnState> {
    let fd = CONN_STATE_MAP_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return None;
    }
    let key = sodama_tuple_of_proto(remote, local, l4proto)?;
    let mut st = SodaConnState::default();
    let keyb = unsafe {
        std::slice::from_raw_parts(
            &key as *const SodaTuple as *const u8,
            std::mem::size_of::<SodaTuple>(),
        )
    };
    let valb = unsafe {
        std::slice::from_raw_parts_mut(
            &mut st as *mut SodaConnState as *mut u8,
            std::mem::size_of::<SodaConnState>(),
        )
    };
    if bpf_map_lookup_raw(fd, keyb, valb).is_err() {
        return None;
    }
    Some(st)
}

/// P19：为一条连接选组——数据面选中的用户组优先；查不到/非用户组返回 None（调用方回退默认组）。
fn resolve_group_dialer(
    remote: SocketAddr,
    local: SocketAddr,
    l4proto: u8,
) -> Option<outbound::Outbound> {
    let outbound = lookup_conn_outbound(remote, local, l4proto)?;
    group_dialer_by_outbound(outbound)
}

/// P21：按 outbound 索引取用户组拨号器（嗅探重判结果 → 组；非用户组返回 None）。
fn group_dialer_by_outbound(outbound: u8) -> Option<outbound::Outbound> {
    let lock = GROUP_SET.get()?;
    let gs = match lock.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let rt = gs.by_outbound(outbound)?.clone();
    Some(outbound::Outbound::Group(rt))
}

fn tuple_hex(t: &SodaTuple) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in t
        .sip
        .iter()
        .chain(t.dip.iter())
        .chain(t.sport.to_ne_bytes().iter())
        .chain(t.dport.to_ne_bytes().iter())
        .chain([t.l4proto, t.is_v6, 0, 0].iter())
    {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 注册 offload 时把两个键记进日志（便于与 verdict 调试 map 对照）。
fn log_offload_keys(up: &SodaTuple, cl: &SodaTuple) {
    log(&format!(
        "offload keys: up={} cl={}",
        tuple_hex(up),
        tuple_hex(cl)
    ));
}

/// P4c：把一对 relay socket 注册进 fast_sock（键 = 对端收到报文时的元组）：
/// 每个 socket 在 peer 的元组下，verdict 才能按收到报文的元组查到 peer socket。
/// P7：返回注册的两个键（连接结束时必须删除——sockmap 条目持有 socket 引用，
/// 不删会让已关闭连接的内核态 socket 与 map 条目一起泄漏）；部分失败回滚。
fn try_offload(client: &TcpStream, upstream: &TcpStream) -> Option<(SodaTuple, SodaTuple)> {
    let (Ok(cp), Ok(cl), Ok(up), Ok(ul)) = (
        client.peer_addr(),
        client.local_addr(),
        upstream.peer_addr(),
        upstream.local_addr(),
    ) else {
        return None;
    };
    let (Some(key_for_upstream), Some(key_for_client)) =
        (sodama_tuple_of(cp, cl), sodama_tuple_of(up, ul))
    else {
        return None;
    };
    let map = RELAY_OFFLOAD.get()?;
    let Ok(mut m) = map.lock() else {
        return None;
    };
    let r1 = m.insert(key_for_upstream, upstream.as_raw_fd(), 0);
    let r2 = m.insert(key_for_client, client.as_raw_fd(), 0);
    if r1.is_ok() && r2.is_ok() {
        // P8：Rust verdict 用 guard 镜像做预检，先写 fast_sock 再写 guard
        // （反过来的窗口里 guard 命中但 fast_sock 未命中会导致 redirect 丢包）。
        if offload_guard_write(&key_for_upstream) && offload_guard_write(&key_for_client) {
            log_offload_keys(&key_for_upstream, &key_for_client);
            return Some((key_for_upstream, key_for_client));
        }
        offload_guard_remove(&key_for_upstream);
        offload_guard_remove(&key_for_client);
        let _ = m.remove(&key_for_upstream);
        let _ = m.remove(&key_for_client);
        log("offload: guard 镜像写入失败，已回滚");
        return None;
    }
    if let Err(e) = &r1 {
        log(&format!("offload: 注册上游 socket 失败: {e}"));
    }
    if let Err(e) = &r2 {
        log(&format!("offload: 注册客户端 socket 失败: {e}"));
    }
    let _ = m.remove(&key_for_upstream);
    let _ = m.remove(&key_for_client);
    None
}

/// P8：guard 镜像写入（C 路线下无 guard map，视为成功）。
fn offload_guard_write(key: &SodaTuple) -> bool {
    match RELAY_OFFLOAD_GUARD.get() {
        None => true,
        Some(m) => match m.lock() {
            Ok(mut g) => g.insert(key, 1, 0).is_ok(),
            Err(_) => false,
        },
    }
}

/// P8：guard 镜像删除（best-effort）。
fn offload_guard_remove(key: &SodaTuple) {
    if let Some(m) = RELAY_OFFLOAD_GUARD.get() {
        if let Ok(mut g) = m.lock() {
            let _ = g.remove(key);
        }
    }
}

/// 对标批：汇总并清掉某 fast_sock 键在 `offload_sent` 里的记账（per-CPU 求和）。
/// 返回本次回收字节；累计到 `RELAY_STATS.offload_sent_bytes`。
/// 注意：读与 remove 之间数据面仍可能继续累加（已建立的推送不受用户态摘键影响），
/// 这部分尾账随 remove 一并丢弃——接受的小误差（对照 dae 的 per-key fuse 未实现，
/// 本表只做归因计量）。
fn offload_sent_reclaim(key: &SodaTuple) -> u64 {
    let Some(m) = OFFLOAD_SENT.get() else {
        return 0;
    };
    let Ok(mut m) = m.lock() else { return 0 };
    // 无流量时键不存在（KeyNotFound）是正常路径，静默按 0 计。
    let bytes = m
        .get(key, 0)
        .map(|v| v.iter().copied().sum::<u64>())
        .unwrap_or(0);
    match m.remove(key) {
        Ok(()) => {}
        // 键本就不存在（无流量/已摘）：与 get 的 KeyNotFound 一样不是错误。
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.raw_os_error() == Some(libc::ENOENT) => {}
        // 其余错误只记一次：不能因为滚动日志把真实簿记问题淹没。
        Err(e) => {
            static LOGGED: AtomicBool = AtomicBool::new(false);
            if !LOGGED.swap(true, Ordering::Relaxed) {
                log(&format!(
                    "offload_sent: 记账键回收失败（{e}），后续同类只静默忽略"
                ));
            }
        }
    }
    if bytes > 0 {
        RELAY_STATS
            .offload_sent_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }
    bytes
}

/// P7：offload 注册前的「前缀排空」——把 socket 接收队列里已有的数据经用户态
/// 泵写到对端；返回 true = 队列已空且可安全注册。
/// 对照 dae newTCPRelayOffloadSession：注册前 drain 内核队列，若仍有 pending 数据
/// 则拒绝 offload——否则队列里的数据会被用户态泵与内核重定向**双重处理**（C 基准
/// 实测出重复字节：8MB 流量多出 17B）。
fn drain_prefix(mut sock: &TcpStream, peer: &mut dyn outbound::WriteHalf, bytes: ByteSink) -> bool {
    if sock.set_nonblocking(true).is_err() {
        return false;
    }
    let mut buf = [0u8; 65536];
    let mut ok = true;
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                bytes.add(n as u64);
                if peer.write_all(&buf[..n]).is_err() {
                    ok = false;
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                ok = false;
                break;
            }
        }
    }
    let _ = sock.set_nonblocking(false);
    ok
}

/// P12：本地 SOCKS5 入口循环（不加载 eBPF；浏览器/桌面测试用）。
fn run_socks_server(listen: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::ToSocketAddrs as _;
    let addr: SocketAddr = listen
        .to_socket_addrs()
        .map_err(|e| format!("解析 --listen-socks {listen}: {e}"))?
        .next()
        .ok_or_else(|| format!("--listen-socks {listen} 无解析结果"))?;
    let Some(dialer) = OUTBOUND.get() else {
        return Err("--listen-socks 需要 --dialer <url> 或订阅组（--subscribe / config 的 subscription+group）".into());
    };
    let listener = std::net::TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    log(&format!(
        "SOCKS5 listening on {addr}（dialer: {}；CONNECT only、无认证）",
        dialer.name()
    ));
    for conn in listener.incoming() {
        match conn {
            Ok(c) => {
                std::thread::spawn(move || handle_socks_conn(c));
            }
            Err(e) => log(&format!("socks: accept 失败: {e}")),
        }
    }
    Ok(())
}

/// 处理一条 SOCKS5 CONNECT：握手 → 本地解析（域名）→ 拨号 → 回复 → 双向泵。
fn handle_socks_conn(mut client: TcpStream) {
    let Some(dialer) = OUTBOUND.get() else {
        return;
    };
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(10)));
    let target = match socksin::server_handshake(&mut client) {
        Ok(t) => t,
        Err(e) => {
            log(&format!("socks: 握手失败: {e}"));
            let _ = client.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    let tname = target.display();
    // P14：SOCKS 客户端给的是域名且开启 dial_mode 时，不做本地解析，域名直交节点。
    let mode = DIAL_MODE.load(Ordering::Relaxed);
    let dial_target = match target {
        socksin::SocksTarget::Domain(name, port) if mode != 0 => {
            log(&format!(
                "socks: {name}:{port} 远端解析（dial_mode {}）",
                dial_mode_name(mode)
            ));
            target::Target::domain(name, port)
        }
        t => match t.resolve().and_then(target::Target::from_socket_addr) {
            Ok(a) => a,
            Err(e) => {
                let _ = socksin::reply(&mut client, socksin::REP_GENERAL);
                log(&format!("socks: 解析 {tname} 失败: {e}"));
                let _ = client.shutdown(std::net::Shutdown::Both);
                return;
            }
        },
    };
    let dial_timeout = Duration::from_millis(RELAY_DIAL_TIMEOUT_MS.load(Ordering::Relaxed));
    let dialed = match dialer.dial_tcp(&dial_target, dial_timeout) {
        Ok(d) => d,
        Err(e) => {
            let _ = socksin::reply(&mut client, socksin::REP_GENERAL);
            log(&format!(
                "socks: dial {tname} 失败（{}）: {e}",
                dialer.name()
            ));
            let _ = client.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    if socksin::reply(&mut client, socksin::REP_SUCCEEDED).is_err() {
        let _ = client.shutdown(std::net::Shutdown::Both);
        return;
    }
    // 进入长连接阶段：清掉握手超时（浏览器连接可能长时间空闲）。
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    log(&format!("SOCKS {tname} established（{}）", dialer.name()));

    let outbound::DialedStream {
        from_remote,
        to_remote,
        socket: _,
        splice: _,
        splice_prelude: _,
    } = dialed;
    let last_ns = Arc::new(AtomicU64::new(monotonic_now_ns()));
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let Ok(c_read) = client.try_clone() else {
        let _ = client.shutdown(std::net::Shutdown::Both);
        return;
    };
    let (last2, up2) = (last_ns.clone(), up.clone());
    std::thread::spawn(move || {
        pump(
            Box::new(c_read),
            to_remote,
            last2.as_ref(),
            ByteSink::single(up2.as_ref()),
            false,
            None,
            limiter_tx(),
        );
    });
    pump(
        from_remote,
        Box::new(client),
        last_ns.as_ref(),
        ByteSink::single(down.as_ref()),
        false,
        None,
        limiter_rx(),
    );
    log(&format!(
        "SOCKS {tname} closed（up={}B down={}B）",
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed)
    ));
}

/// relay 一条连接：按 dialer 拨号到 orig_dst，双向转发（含半关闭）。
/// 组退化为线程泵路径的告警限流时间戳（秒，单调时钟）。
static GROUP_NOT_REACTOR_WARN_AT: AtomicU64 = AtomicU64::new(0);

/// 组因含不受支持成员而整体退回线程泵路径时，**限流**地报一次（同一进程 10 分钟最多一条）。
///
/// 为什么需要它：`codec_reactor_capable_all()` 是保守放行 —— 订阅里混进任一个
/// tuic/hysteria2/juicity/naive/QUIC 或带 shadow-tls 的 ss 节点，整组就不再走
/// Reactor（每连接 2 线程）。这是**正确但昂贵**的降级，且旧行为下完全静默；
/// 生产上曾因同类静默降级（Group 未声明 reactor 能力）白走了一段线程路径。
/// 有了这条日志，运维能从日志看出“组里混了不支持的协议”。
fn warn_group_not_reactor_once(group: &str) {
    let now = monotonic_now_ns() / 1_000_000_000;
    let last = GROUP_NOT_REACTOR_WARN_AT.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 600 {
        return;
    }
    if GROUP_NOT_REACTOR_WARN_AT
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return; // 另一线程刚报过
    }
    log(&format!(
        "组 {group}: 含不受 reactor 支持的成员，本组会话走线程泵路径（每连接 2 线程）——\
         如需零线程，请把组内统一为 vless/anytls/vmess/trojan/ss(非 shadow-tls)/ssr"
    ));
}

fn handle_relay_conn(mut client: TcpStream) {
    // P18e：并发上限（--max-conns；0=不限）。超限直接关闭并计数（对照 dae 并发限制）。
    let max = RELAY_MAX_CONNS.load(Ordering::Relaxed);
    if max != 0 && RELAY_STATS.conns_active.load(Ordering::Relaxed) >= max {
        RELAY_STATS.limit_rejected.fetch_add(1, Ordering::Relaxed);
        log(&format!("relay 并发上限 {max} 已满，拒绝新连接"));
        let _ = client.shutdown(std::net::Shutdown::Both);
        return;
    }
    let Ok(orig) = client.local_addr() else {
        return;
    };
    let Some(default_dialer) = OUTBOUND.get() else {
        return;
    };
    // P19：按规则选中的组分派（conn_state 回读；查不到/非用户组 → 默认组）。
    let resolved = client
        .peer_addr()
        .ok()
        .and_then(|peer| resolve_group_dialer(peer, orig, 6));
    let mut active = resolved;
    // P14：dial_mode != ip 时先做用户态嗅探（MSG_PEEK 只读，不消费字节流）
    let mode = DIAL_MODE.load(Ordering::Relaxed);
    let target = if mode != 0 {
        SNIFF_STATS.attempts.fetch_add(1, Ordering::Relaxed);
        let timeout = Duration::from_millis(SNIFF_TIMEOUT_MS.load(Ordering::Relaxed));
        match sniffer::sniff_domain(&client, timeout) {
            Some(name) => {
                SNIFF_STATS.hits.fetch_add(1, Ordering::Relaxed);
                log_debug(&format!("sniff {orig} → {name}（域名交节点远端解析）"));
                // P21：嗅探重判——用 (域名, 五元组) 在用户态重放规则（与数据面同语义）；
                // 命中 direct/block/用户组时在 relay 侧重选出口。
                if SNIFF_PUNT.load(Ordering::Relaxed) {
                    let peer = client.peer_addr().ok();
                    let ctx = rules::PuntCtx {
                        domain: Some(name.as_str()),
                        dip: orig.ip(),
                        sip: peer
                            .map(|p| p.ip())
                            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                        dport: orig.port(),
                        sport: peer.map(|p| p.port()).unwrap_or(0),
                        l4proto: 6,
                    };
                    SNIFF_STATS.punt_attempts.fetch_add(1, Ordering::Relaxed);
                    let outcome = match LAST_RULES.lock() {
                        Ok(g) => g.as_ref().map(|r| r.punt_match(&ctx)),
                        Err(p) => p.into_inner().as_ref().map(|r| r.punt_match(&ctx)),
                    };
                    match outcome {
                        Some(rules::PuntOutcome::Outbound {
                            id: rules::OUTBOUND_BLOCK,
                            ..
                        }) => {
                            SNIFF_STATS.punt_block.fetch_add(1, Ordering::Relaxed);
                            log(&format!(
                                "punt {name}（{orig}）→ block（嗅探重判，关闭连接）"
                            ));
                            let _ = client.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                        Some(rules::PuntOutcome::Outbound {
                            id: rules::OUTBOUND_DIRECT,
                            must,
                            ..
                        }) => {
                            SNIFF_STATS.punt_direct.fetch_add(1, Ordering::Relaxed);
                            log(&format!(
                                "punt {name}（{orig}）→ direct（嗅探重判{}）",
                                if must { "，must" } else { "" }
                            ));
                            active = Some(outbound::Outbound::Direct);
                            // 直连用原始目的 IP：与内核 direct 行为一致，避免本地解析嗅探域名。
                            target::Target::Ip(orig.ip(), orig.port())
                        }
                        Some(rules::PuntOutcome::Outbound { id, must, mark }) => {
                            match group_dialer_by_outbound(id) {
                                Some(d) => {
                                    SNIFF_STATS.punt_group.fetch_add(1, Ordering::Relaxed);
                                    log(&format!(
                                        "punt {name}（{orig}）→ outbound 0x{id:02x}（组 {}）{}",
                                        d.name(),
                                        if must { "[must]" } else { "" }
                                    ));
                                    active = Some(d);
                                }
                                None => {
                                    // 不是用户组（must_rules/控制面等）：保持原决策
                                    SNIFF_STATS.punt_keep.fetch_add(1, Ordering::Relaxed);
                                    if mark != 0 {
                                        log(&format!("punt {name}：outbound 0x{id:02x} mark=0x{mark:x} 无组映射，保持原决策"));
                                    }
                                }
                            }
                            target::Target::domain(name, orig.port())
                        }
                        Some(rules::PuntOutcome::ControlPlane)
                        | Some(rules::PuntOutcome::NoMatch)
                        | None => {
                            SNIFF_STATS.punt_keep.fetch_add(1, Ordering::Relaxed);
                            target::Target::domain(name, orig.port())
                        }
                    }
                } else {
                    // A2 #10：`dial_mode: domain`（严格档）按「真实域名」判定决定是否域名拨号；
                    // domain+（=2）按 dae 语义始终域名拨号（DomainPlus 分支）。
                    if mode == 1 && !real_domain_ok(&name) {
                        target::Target::Ip(orig.ip(), orig.port())
                    } else {
                        target::Target::domain(name, orig.port())
                    }
                }
            }
            None => {
                SNIFF_STATS.misses.fetch_add(1, Ordering::Relaxed);
                match target::Target::from_socket_addr(orig) {
                    Ok(t) => t,
                    Err(_) => return,
                }
            }
        }
    } else {
        match target::Target::from_socket_addr(orig) {
            Ok(t) => t,
            Err(_) => return,
        }
    };
    let dialer = active.as_ref().unwrap_or(default_dialer);
    let dial_timeout = Duration::from_millis(RELAY_DIAL_TIMEOUT_MS.load(Ordering::Relaxed));
    let dialed = match dialer.dial_tcp(&target, dial_timeout) {
        Ok(d) => d,
        Err(e) => {
            RELAY_STATS.dial_errors.fetch_add(1, Ordering::Relaxed);
            log(&format!(
                "relay: dial {target} 失败（{}）: {e}",
                dialer.name()
            ));
            let _ = client.shutdown(std::net::Shutdown::Both);
            return;
        }
    };
    log(&format!(
        "RELAY {target}{} established（{}）",
        if target.is_domain() {
            "（远端解析）"
        } else {
            ""
        },
        dialer.name()
    ));
    RELAY_STATS.conns_total.fetch_add(1, Ordering::Relaxed);
    RELAY_STATS.conns_active.fetch_add(1, Ordering::Relaxed);
    note_traffic();
    // P-AI：按域名统计（仅域名目标；收尾时归档字节明细）。
    let handled_domain: Option<Box<str>> = match &target {
        target::Target::Domain(n, _) => Some(n.as_str().into()),
        target::Target::Ip(..) => None,
    };
    if let Some(d) = &handled_domain {
        domain_stat_open(d);
    }
    let outbound::DialedStream {
        from_remote,
        mut to_remote,
        mut socket,
        splice: wire_splice,
        splice_prelude: wire_prelude,
    } = dialed;
    let mut offload_keys = None;
    if RELAY_OFFLOAD.get().is_some() && dialer.supports_offload() {
        // P7：先排空两侧接收队列（有数据则可能被双路径重复处理），
        // 队列排空且无错才注册；否则退回纯用户态泵（仍正确，只是无 offload）。
        let mut eligible = false;
        if let Some(sock) = socket.as_ref() {
            let c_ok = drain_prefix(
                &client,
                to_remote.as_mut(),
                ByteSink::global_only(&RELAY_STATS.bytes_up),
            );
            let u_ok = drain_prefix(
                sock,
                &mut client,
                ByteSink::global_only(&RELAY_STATS.bytes_down),
            );
            eligible = c_ok && u_ok;
        }
        if eligible {
            offload_keys = socket.as_ref().and_then(|s| try_offload(&client, s));
        }
        if offload_keys.is_some() {
            RELAY_STATS.offloaded_total.fetch_add(1, Ordering::Relaxed);
            log(&format!("OFFLOAD {target} 已注册（内核对拼）"));
        } else {
            RELAY_STATS.offload_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
    let offloaded = offload_keys.is_some();
    // I2：fd 预算压力（>80% soft limit）时新连接降级走用户态泵（保可用性，记账）。
    let fd_high = fd_pressure();
    // M1：splice 零拷贝（仅未 offload 时；直接拨号/VLESS 明文在拨号层置位）。
    // A2 #6：设置带宽限额时强制拷贝泵（splice 绕过用户态，无法节流）。
    let splice = wire_splice
        && !offloaded
        && limiter_tx().rate() == 0
        && limiter_rx().rate() == 0
        && RELAY_SPLICE.load(Ordering::Relaxed)
        && !fd_high;
    if fd_high && wire_splice && !offloaded && RELAY_SPLICE.load(Ordering::Relaxed) {
        RELAY_STATS.splice_fd_budget.fetch_add(1, Ordering::Relaxed);
    }
    // M4 stage 2：非 splice 的 rustls/明文链路（codec 会话）也可交 reactor——
    // 读半/写半在 worker 内非阻塞驱动（仅对已审计的协议种类开启）。
    let wire_codec = !splice && !offloaded && dialer.codec_reactor_capable();
    // 诊断（限流）：组因**含不受支持成员**而整组退回线程泵路径时，说一次。
    // 保守放行（`codec_reactor_capable_all`）的代价就是这条“性能悬崖”：
    // 订阅里混进一个 tuic/hy2/juicity/naive 节点，整组就不再走 Reactor。
    // 旧行为下这种降级是**静默**的（生产上曾因此少走三个月的零线程路径），
    // 这里把它变成可观测的。仅当确实是 Group 且非 reactor 能力时触发。
    if !wire_codec && !splice && !offloaded {
        if let outbound::Outbound::Group(g) = dialer {
            warn_group_not_reactor_once(g.name.as_str());
        }
    }
    let upstream_fd = socket.as_ref().map(|s| s.as_raw_fd());
    if splice {
        RELAY_STATS.splice_total.fetch_add(1, Ordering::Relaxed);
    }
    let id = NEXT_RELAY_ID.fetch_add(1, Ordering::Relaxed);
    // I2：reactor 会话由 worker 持有 socket（看门狗走 reactor::kill(id)），
    // 不克隆 fd 句柄；仅 offload / 传统线程泵路径保留可 shutdown 的句柄。
    let reactor_splice = splice && !offloaded && reactor::enabled();
    let reactor_codec = !splice && !offloaded && wire_codec && reactor::codec_available();
    let need_fd_handle = !(reactor_splice || reactor_codec);
    let client_clone = if need_fd_handle {
        match client.try_clone() {
            Ok(c) => Some(c),
            Err(_) => {
                let _ = client.shutdown(std::net::Shutdown::Both);
                return;
            }
        }
    } else {
        None
    };
    // QUIC（tuic）没有底层 TCP：upstream 用 Option（仅 janitor 强制关闭用）。
    let upstream_clone = if need_fd_handle {
        match socket.as_ref().map(|s| s.try_clone()) {
            Some(Ok(u)) => Some(u),
            Some(Err(_)) => {
                let _ = client.shutdown(std::net::Shutdown::Both);
                return;
            }
            None => None,
        }
    } else {
        None
    };
    let handle = Arc::new(RelayHandle {
        last_ns: AtomicU64::new(monotonic_now_ns()),
        offloaded: AtomicBool::new(offloaded),
        stop: AtomicBool::new(false),
        reactor_managed: reactor_splice || reactor_codec,
        client: client_clone,
        upstream: upstream_clone,
        domain: handled_domain,
        generation: current_datapath_generation(),
        conn_key: client.peer_addr().ok().map(|p| (p, orig)),
        bytes_up: AtomicU64::new(0),
        bytes_down: AtomicU64::new(0),
    });
    if let Ok(mut m) = RELAY_CONNS.lock() {
        m.insert(id, handle.clone());
    }
    // P7/M4 stage 2：offload 连接交全局看门狗（单线程，每连接 0 线程；
    // 半关闭判定/超时回收/fast_sock 注销均在 `offload_watch_loop` 统一完成）。
    if offloaded {
        if let Some(keys) = offload_keys.take() {
            let (Some(cf), Some(uf)) = (handle.client.as_ref(), handle.upstream.as_ref()) else {
                log("offload: 缺 fd 句柄，放弃内核路径并回收");
                if let Some(c) = &handle.client {
                    let _ = c.shutdown(std::net::Shutdown::Both);
                }
                offload_watch_cleanup(id, &Some(keys));
                return;
            };
            offload_watch_register(OffloadWatchEntry {
                id,
                client_fd: cf.as_raw_fd(),
                upstream_fd: uf.as_raw_fd(),
                handle: handle.clone(),
                keys: Some(keys),
                client_closed: false,
                upstream_closed: false,
                first_close: None,
                err_logged: false,
                fuse_rx_base: None,
                fuse_fused: false,
                fuse_since: None,
                fuse_drain_started: false,
                fuse_drain_since: None,
                fuse_stop: None,
                fuse_drained: None,
                fuse_pass_bytes: std::sync::Arc::new(AtomicU64::new(0)),
            });
            return;
        }
    }
    // M4：splice 连接的 epoll worker 池（每连接 0 线程）。需要响应头前缀的链路
    // （VLESS）由 worker 内 PreludeBuf 非阻塞消费后恢复；Direct 直接接管。
    if reactor_splice {
        if let Some(up) = socket.take() {
            let prelude: Option<Box<dyn outbound::ReadHalf>> = if wire_prelude {
                Some(from_remote)
            } else {
                None
            };
            if reactor::submit(client, up, handle.clone(), id, prelude) {
                return; // 注册表/统计由 reactor 收尾
            }
            relay_finish(id);
            return;
        }
    }
    // M4 stage 2：codec 会话（rustls VLESS-TCP / Trojan）交同一 worker 池（每连接 0 线程）。
    if reactor_codec {
        if let Some(up) = socket.take() {
            if reactor::submit_codec(client, up, handle.clone(), id, from_remote, to_remote) {
                RELAY_STATS
                    .reactor_codec_sessions
                    .fetch_add(1, Ordering::Relaxed);
                return; // 注册表/统计由 reactor 收尾
            }
            relay_finish(id);
            return;
        }
    }
    // 客户端 → 上游
    // O9：两个方向各一个泵，**最后一个泵结束时**才收尾（relay_finish）。
    // 旧行为是 handler 线程（上游→客户端）一结束就 relay_finish —— 连接随即从
    // RELAY_CONNS 摘除：另一个方向若还卡在 recv（半开连接 / 对端不关），既不会被
    // 空闲 janitor 回收（看不见），也不再计入 conns_active
    // （路由器实测：泄漏 54+ 泵线程 / 每线程 1MiB 栈 + 64KB 缓冲 + ~6 个 fd）。
    let sibling_read = client.try_clone().ok();
    let pumps_left = Arc::new(AtomicU32::new(if sibling_read.is_some() { 2 } else { 1 }));
    let pump_done = {
        let p = pumps_left.clone();
        move || {
            if p.fetch_sub(1, Ordering::AcqRel) == 1 {
                relay_finish(id);
            }
        }
    };
    if let Some(c_read) = sibling_read {
        let h2 = handle.clone();
        // H3 修复：上方向线程只持 fd **号码**，而 handler 栈上的 `socket`（kill dup）
        // 会在函数返回时析构（双泵收尾不覆盖它）——旧代码用它的号码，半关闭
        // 序（上方向仍在跑、handler 已返回）下会写入已关闭/被复用的 fd。
        // 改用 handle 内保活的 upstream dup：RELAY_CONNS 持有 handle 直至两个方向
        // 都 pump_done，号码寿命覆盖本线程的全部 splice 使用。
        let up_dst = handle.upstream.as_ref().map(|u| u.as_raw_fd());
        let done = pump_done.clone();
        std::thread::spawn(move || {
            let mut spliced = false;
            if splice {
                if let Some(dst) = up_dst {
                    match splice_pump(
                        c_read.as_raw_fd(),
                        dst,
                        &h2.last_ns,
                        ByteSink::new(&RELAY_STATS.bytes_up, Some(&h2.bytes_up)),
                    ) {
                        Ok(()) => spliced = true,
                        Err(SpliceErr::Unsupported(e)) => {
                            RELAY_STATS.splice_fallbacks.fetch_add(1, Ordering::Relaxed);
                            if !SPLICE_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
                                log(&format!("splice: 上游方向不可用（{e}），回退用户态泵"));
                            }
                        }
                        Err(SpliceErr::Fatal(e)) => {
                            log(&format!("splice: 上游传输错误（{e}）"));
                            spliced = true;
                        }
                    }
                }
            }
            if !spliced {
                pump(
                    Box::new(c_read),
                    to_remote,
                    &h2.last_ns,
                    ByteSink::new(&RELAY_STATS.bytes_up, Some(&h2.bytes_up)),
                    offloaded,
                    Some(&h2.stop),
                    limiter_tx(),
                );
            }
            done();
        });
    }
    // 上游 → 客户端（本线程）
    match upstream_fd {
        Some(src) if splice => pump_or_splice_down(
            from_remote,
            client,
            src,
            &handle.last_ns,
            ByteSink::new(&RELAY_STATS.bytes_down, Some(&handle.bytes_down)),
            true,
            Some(&handle.stop),
        ),
        _ => pump(
            from_remote,
            Box::new(client),
            &handle.last_ns,
            ByteSink::new(&RELAY_STATS.bytes_down, Some(&handle.bytes_down)),
            offloaded,
            Some(&handle.stop),
            limiter_rx(),
        ),
    }
    // P7：注销 fast_sock 键（sockmap 条目持有 socket 引用，不删会泄漏）；
    // P8：guard 镜像先摘，再摘 fast_sock。
    if let Some((k_up, k_cl)) = offload_keys {
        // 对标批：摘键前汇总该会话在内核路径被推送的字节（两个方向合计）。
        let sent = offload_sent_reclaim(&k_up) + offload_sent_reclaim(&k_cl);
        offload_guard_remove(&k_up);
        offload_guard_remove(&k_cl);
        if let Some(map) = RELAY_OFFLOAD.get() {
            if let Ok(mut m) = map.lock() {
                let _ = m.remove(&k_up);
                let _ = m.remove(&k_cl);
            }
        }
        log(&format!(
            "offload: {target} 已注销 fast_sock 键（内核路径推送 {sent} B）"
        ));
    }
    pump_done();
}

/// relay 会话收尾：摘注册表 + 活跃计数递减（线程泵路径与 reactor 共用）。
fn relay_finish(id: u64) {
    let handle = RELAY_CONNS.lock().ok().and_then(|mut m| m.remove(&id));
    RELAY_STATS.conns_active.fetch_sub(1, Ordering::Relaxed);
    // P-AI：连接收尾 → 域名统计归档（活跃 -1，累计本连接字节）。
    if let Some(h) = handle {
        if let Some(d) = &h.domain {
            domain_stat_close(
                d,
                h.bytes_up.load(Ordering::Relaxed),
                h.bytes_down.load(Ordering::Relaxed),
            );
        }
    }
}

/// relay janitor：空闲超过 RELAY_IDLE_SECS 的连接强制关闭（两侧 shutdown）。
fn relay_janitor_loop() {
    let tick = Duration::from_secs(5);
    loop {
        std::thread::sleep(tick);
        let idle_ns = RELAY_IDLE_SECS
            .load(Ordering::Relaxed)
            .saturating_mul(1_000_000_000);
        let now = monotonic_now_ns();
        let dead: Vec<(u64, Arc<RelayHandle>)> = match RELAY_CONNS.lock() {
            Ok(m) => m
                .iter()
                .filter(|(_, h)| {
                    // P4c：已 offload 的连接由内核对拼，用户态看不到活跃时间，
                    // 不参与空闲回收（sodama 的边界；dae 另有 tcp_info 看门狗）。
                    !h.offloaded.load(Ordering::Relaxed)
                        && now.saturating_sub(h.last_ns.load(Ordering::Relaxed)) > idle_ns
                })
                .map(|(id, h)| (*id, h.clone()))
                .collect(),
            Err(_) => continue,
        };
        for (id, h) in dead {
            // I2：reactor 会话由 worker 持有 socket，看门狗经 reactor::kill(id) 收尾；
            // 其余（offload/线程泵）保留 fd 句柄路径。
            if h.reactor_managed {
                reactor::kill(id);
            } else {
                if let Some(c) = &h.client {
                    let _ = c.shutdown(std::net::Shutdown::Both);
                }
                if let Some(u) = &h.upstream {
                    let _ = u.shutdown(std::net::Shutdown::Both);
                }
            }
            RELAY_STATS.evicted.fetch_add(1, Ordering::Relaxed);
            log(&format!("relay janitor: 回收空闲连接 #{id}"));
            if let Ok(mut m) = RELAY_CONNS.lock() {
                m.remove(&id);
            }
        }
    }
}

/// 组装规则文本：优先 --config（完整 .dae），其次 --rules，缺省用 --proxy 兜底。
/// 配置模式下同时把合并后的配置与路由提取结果存进只读状态面。
fn rules_text(args: &Args) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = &args.config {
        let cfg = config::load(Path::new(path))
            .map_err(|diags| format!("解析配置失败:\n{}", render_diags(&diags)))?;
        let diags = config::validate(&cfg);
        if !diags.is_empty() {
            return Err(format!("配置校验失败:\n{}", render_diags(&diags)).into());
        }
        let extract = config::extract_routing(&cfg)
            .map_err(|diags| format!("路由段提取失败:\n{}", render_diags(&diags)))?;
        if args.strict_config && !extract.deferred.is_empty() {
            return Err(format!(
                "--strict-config：{} 条规则无法编译（domain/geoip/pname 等，见 ADR-0011）",
                extract.deferred.len()
            )
            .into());
        }
        for d in extract.deferred.iter().take(5) {
            let file = cfg
                .files
                .get(d.loc.file)
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            log(&format!(
                "deferred rule {file}:{}: {} — {}",
                d.loc.line, d.rule, d.reason
            ));
        }
        if extract.deferred.len() > 5 {
            log(&format!(
                "... 另有 {} 条 deferred 规则（状态面 `config` 命令可查全部）",
                extract.deferred.len() - 5
            ));
        }
        if extract.supported.is_empty() {
            return Err("配置的 routing 段没有任何可编译规则".into());
        }
        for (group, mapped) in &extract.outbound_map {
            log(&format!("outbound 映射：组 \"{group}\" -> {mapped}"));
        }
        let mut text = extract.supported.join("\n");
        if let Some(fb) = &extract.fallback {
            text.push_str(&format!("\nfallback -> {fb}"));
        }
        if let Ok(mut g) = CONFIG_STATE.lock() {
            *g = Some((cfg, extract));
        }
        return Ok(text);
    }
    match &args.rules {
        Some(path) => {
            Ok(std::fs::read_to_string(path).map_err(|e| format!("read rules {path}: {e}"))?)
        }
        None => {
            let mut t = String::new();
            for ip in &args.proxy_dsts {
                let v4 = std::net::Ipv4Addr::from(u32::from_be(*ip));
                t.push_str(&format!("dip({v4}/32) -> proxy\n"));
            }
            t.push_str("fallback -> direct\n");
            Ok(t)
        }
    }
}

fn render_diags(diags: &[config::Diag]) -> String {
    diags
        .iter()
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// 把编译好的规则写进指定 epoch 槽（调用方负责随后切 active）。
fn write_rules(
    ebpf: &mut Ebpf,
    compiled: &rules::CompiledRules,
    slot: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = slot * MAX_MATCH_SET_LEN;
    {
        let map = ebpf
            .map_mut("routing_map")
            .ok_or("map routing_map not found")?;
        let mut routing_map: Array<_, rules::MatchSet> = Array::try_from(map)?;
        for (i, ms) in compiled.sets.iter().enumerate() {
            routing_map.set(base + i as u32, ms, 0)?;
        }
    }
    {
        let map = ebpf
            .map_mut("routing_meta_map")
            .ok_or("map routing_meta_map not found")?;
        let mut meta: Array<_, u32> = Array::try_from(map)?;
        meta.set(slot, compiled.sets.len() as u32, 0)?;
    }
    if !compiled.lpm_tries.is_empty() {
        let map = ebpf
            .map_mut("lpm_array_map")
            .ok_or("map lpm_array_map not found")?;
        // 内层 trie 的属性必须与 C 侧模板一致（LPM_TRIE + BPF_F_NO_PREALLOC，
        // key=4+16、value=4、max_entries 相同），否则内核拒绝 map-in-map 插入。
        let mut outer: ArrayOfMaps<_, LpmTrie<MapData, [u8; 16], u32>> =
            ArrayOfMaps::try_from(map)?;
        for (idx, prefixes) in &compiled.lpm_tries {
            let mut trie = LpmTrie::<MapData, [u8; 16], u32>::create(
                rules::LPM_MAX_ENTRIES,
                rules::BPF_F_NO_PREALLOC,
            )?;
            for (plen, data) in prefixes {
                trie.insert(&Key::new(*plen, *data), 1u32, 0)?;
            }
            outer.set(base + *idx, &trie, 0)?;
        }
    }
    Ok(())
}

/// 切 active epoch 槽（对照 dae active_routing_epoch_map）。
fn activate_slot(ebpf: &mut Ebpf, slot: u32) -> Result<(), Box<dyn std::error::Error>> {
    let map = ebpf
        .map_mut("active_routing_epoch_map")
        .ok_or("map active_routing_epoch_map not found")?;
    let mut active: Array<_, u32> = Array::try_from(map)?;
    active.set(0, slot, 0)?;
    ACTIVE_SLOT.store(slot, Ordering::SeqCst);
    Ok(())
}

/// P17a：按进程生命周期构建一次 geodata 上下文（懒解析文件；无 geo 规则时不碰磁盘）。
/// 编译只在主循环线程发生，这里用 Mutex 包住 RefCell 缓存（静态存储要求 Sync）。
fn geodata_for(args: &Args) -> &'static std::sync::Mutex<geodata::Geodata> {
    static GEO: std::sync::OnceLock<std::sync::Mutex<geodata::Geodata>> =
        std::sync::OnceLock::new();
    GEO.get_or_init(|| {
        let dirs = geodata::search_dirs(
            &args
                .geodata_dir
                .iter()
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>(),
            args.config.as_deref().map(std::path::Path::new),
        );
        std::sync::Mutex::new(geodata::Geodata::new(dirs))
    })
}

/// P18c：构建上游集合（CLI `--dns-upstream` 作为 tag "default"；配置 dns.upstream map
/// 的其它 tag 仍保留，供 dns.routing 引用；同名时 CLI 优先）。
fn build_upstream_set(args: &Args) -> Result<Arc<UpstreamSet>, Box<dyn std::error::Error>> {
    build_upstream_set_core(
        args.dns_upstream.clone(),
        args.config.as_deref().map(Path::new),
    )
    .map_err(|e| e.into())
}

/// 上游集合构建核心（启动/reload/`dns-bench` 共用；错误为字符串）。
/// P19：**单个上游失败不再拖垮整个集合**——域名解析失败/参数错的条目跳过并告警，
/// 其余（典型是 IP 字面量 DoH）照常生效；CLI `--dns-upstream` 显式给定时仍为硬错误。
fn build_upstream_set_core(
    cli: Option<String>,
    config_path: Option<&Path>,
) -> Result<Arc<UpstreamSet>, String> {
    let cfg_map = config_path
        .and_then(|p| config::load(p).ok())
        .map(|c| config::dns_upstream_map(&c))
        .unwrap_or_default();
    let cli_ups = match &cli {
        Some(url) => {
            Some(dnsup::Upstream::new(url).map_err(|e| format!("--dns-upstream {url}: {e}"))?)
        }
        None => None,
    };
    let mut by_tag: std::collections::HashMap<String, Arc<dnsup::Upstream>> =
        std::collections::HashMap::new();
    let mut first_ok: Option<Arc<dnsup::Upstream>> = None;
    let mut skipped: Vec<String> = Vec::new();
    for (tag, url) in &cfg_map {
        match dnsup::Upstream::new(url) {
            Ok(u) => {
                if first_ok.is_none() {
                    first_ok = Some(u.clone());
                }
                by_tag.insert(tag.clone(), u);
            }
            Err(e) => {
                skipped.push(tag.clone());
                log(&format!("dns.upstream {tag} 跳过（{e}）"));
            }
        }
    }
    if !skipped.is_empty() {
        log(&format!(
            "dns.upstream：{} 个上游不可用已跳过 {skipped:?}（其余照常生效）",
            skipped.len()
        ));
    }
    let legacy = cli_ups
        .or(first_ok)
        .or_else(|| dnsup::Upstream::new("8.8.8.8:53").ok())
        .ok_or("没有任何可用的 DNS 上游（含内置回退）")?;
    if cli.is_some() || by_tag.is_empty() {
        by_tag.insert("default".to_string(), legacy.clone());
    }
    Ok(Arc::new(UpstreamSet {
        by_tag,
        legacy,
        asis: Mutex::new(std::collections::HashMap::new()),
    }))
}

impl UpstreamSet {
    /// tag → url（供 dnsroute 编译校验与状态面）。
    fn tags_map(&self) -> std::collections::HashMap<String, String> {
        self.by_tag
            .iter()
            .map(|(k, v)| (k.clone(), v.url.clone()))
            .collect()
    }
}

/// A2 批次 5 修：配置诊断的可读摘要（首条详情 + 总数）——此前只报计数，
/// `dnsbind.dae` 权限被 git 操作重置为 0644 时日志只显示「1 项诊断」，
/// 定因需另跑 validate（2026-10-16 VM 矩阵归因教训）。
fn diag_summary(d: &[config::Diag]) -> String {
    let first = d.first().map(|x| x.to_string()).unwrap_or_default();
    if d.len() > 1 {
        format!("{} 条诊断，首条：{first}", d.len())
    } else {
        first
    }
}

/// P18c：编译 dns.routing（None = 未配置）。
fn build_dns_router(
    args: &Args,
    ups: &UpstreamSet,
) -> Result<Option<dnsroute::DnsRouter>, Box<dyn std::error::Error>> {
    let Some(path) = &args.config else {
        return Ok(None);
    };
    let cfg = config::load(Path::new(path))
        .map_err(|d| format!("加载配置失败（{}）", diag_summary(&d)))?;
    let tags = ups.tags_map();
    let geo_lock = geodata_for(args);
    let geo = geo_lock.lock().unwrap();
    let r =
        dnsroute::compile(&cfg, &tags, Some(&geo)).map_err(|e| format!("编译 dns.routing: {e}"))?;
    Ok(r)
}

/// 编译 + 写入非活跃槽 + 切换。返回规则条数。
fn reload_rules(args: &Args, ebpf: &mut Ebpf) -> Result<usize, Box<dyn std::error::Error>> {
    let text = rules_text(args)?;
    let geo = geodata_for(args);
    let geo = geo.lock().unwrap();
    // P19：组名 → outbound 索引（与 build_groups 的构建顺序一致；config 失败时回退隐式 proxy）
    let cfg = args
        .config
        .as_ref()
        .and_then(|p| config::load(std::path::Path::new(p)).ok());
    let groups = group_index_map(cfg.as_ref());
    // P36：规则集（`rule_set` 段）——远程 URL 带缓存（interval 内直接用；0=每次刷新），
    // 失败硬错（保留旧槽，不静默丢规则）；无 config 时为空仓库。
    let store = match cfg.as_ref() {
        Some(c) => {
            let interval = config::global_value(c, "rule_set_update_interval")
                .and_then(|v| parse_duration_secs(&v))
                .unwrap_or(86400);
            let cache_dir = config::global_value(c, "rule_set_cache_dir");
            ruleset::RuleSetStore::load(
                c,
                args.config.as_deref().map(Path::new),
                interval,
                cache_dir.as_deref(),
            )
            .map_err(|e| format!("规则集加载失败: {e}"))?
        }
        None => ruleset::RuleSetStore::empty(),
    };
    // 本地规则集文件加入 inotify 监听集合（改名单文件即热生效）
    let local_files: Vec<std::path::PathBuf> = store
        .iter()
        .filter_map(|rs| rs.local_path.clone())
        .collect();
    if let Ok(mut g) = RULESET_FILES.lock() {
        *g = local_files;
    }
    {
        let lock = RULESET_STORE.get_or_init(|| Mutex::new(ruleset::RuleSetStore::empty()));
        match lock.lock() {
            Ok(mut g) => *g = store,
            Err(p) => *p.into_inner() = store,
        }
    }
    let compiled = {
        let lock = RULESET_STORE.get().expect("ruleset store 已初始化");
        let guard = match lock.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        rules::parse_and_compile_full(&text, Some(&geo), &groups, Some(&guard))
            .map_err(|e| format!("compile rules: {e}"))?
    };
    for n in &compiled.notes {
        log(&format!("geoexp: {n}"));
    }
    let current = ACTIVE_SLOT.load(Ordering::SeqCst);
    let next = (current + 1) % EPOCH_SLOT_NUM;
    // 对照 dae clearReloadDomainRoutingMapSlot：清空即将写入的槽的域位图。
    clear_domain_slot(ebpf, next)?;
    write_rules(ebpf, &compiled, next)?;
    activate_slot(ebpf, next)?;
    if let Ok(mut g) = LAST_RULES.lock() {
        *g = Some(compiled.clone());
    }
    if let Ok(mut g) = DOMAIN_SETS.lock() {
        *g = compiled.domain_sets.clone();
    }
    log(&format!(
        "rules reloaded: {} match_sets -> slot {} (was {})",
        compiled.sets.len(),
        next,
        current
    ));
    if args.dump {
        print!("{}", compiled.dump());
        let _ = std::io::stdout().flush();
    }
    Ok(compiled.sets.len())
}

/// eBPF control_flags 位定义（与 ebpf-rs/src/common.rs 保持一致）。
const FLAG_SUSPEND: u32 = 1;
/// M1：热路径调试打印门控位。
const FLAG_DEBUG: u32 = 2;

/// 读改写 control_flags 的单个位（保留其它位；对照 dae suspend 的 no-load 状态）。
fn update_control_flag(
    ebpf: &mut Ebpf,
    mask: u32,
    on: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let map = ebpf
        .map_mut("control_flags_map")
        .ok_or("map control_flags_map not found（对象未包含 P6 控制位？）")?;
    let mut flags: Array<_, u32> = Array::try_from(map)?;
    let cur = flags.get(&0, 0).unwrap_or(0);
    let next = if on { cur | mask } else { cur & !mask };
    flags.set(0, next, 0)?;
    Ok(())
}

/// P6：写 control_flags_map 的 suspend 位（对照 dae suspend 的 no-load 状态）。
fn set_suspend(ebpf: &mut Ebpf, on: bool) -> Result<(), Box<dyn std::error::Error>> {
    update_control_flag(ebpf, FLAG_SUSPEND, on)
}

/// P6：一次完整热重载（对照 dae `dae reload`）：清除 suspend → 重编译/切槽 →
/// 重建域位图 → 记录结果；失败时保留旧规则（回滚等价于不切槽，reload_rules 内部先写非活跃槽）。
/// `startup=true` = 启动期初始下发（P19：跳过订阅重拉，见下）。
fn do_reload(args: &Args, ebpf: &mut Ebpf, startup: bool, fast: bool) -> ReloadOutcome {
    // P23：reload 重置粘滞 IP 状态（对照 dae ResetGlobalProxyStateForReload：
    // 新一代替换代际前不继承上一代可能已污染的代理 IP/失败状态）。
    if !startup {
        crate::sticky::reset();
        // 数据面代次递增：跨 reload 的旧缓存 → 纯 SYN 按「异代重路由」处理
        // （对照 dae 每次换代写新 datapath_generation，datapath_generation.go:20-27）。
        bump_datapath_generation(ebpf);
    }
    // P23/P33：配置解析一次，供 bootstrap / DNS 选项 / 运行时参数热更新共用。
    let cfg_loaded = args
        .config
        .as_ref()
        .and_then(|p| config::load(std::path::Path::new(p)).ok());
    if let Some(cfg) = &cfg_loaded {
        let boot = config::global_value(cfg, "bootstrap_resolver");
        if let Err(e) = bootstrap::configure(boot.as_deref()) {
            log(&format!("bootstrap resolver 热更新失败（保留旧值）: {e}"));
        }
        apply_dns_options(Some(cfg)); // P23：dns 段选项热更新
    }
    if SUSPENDED.load(Ordering::SeqCst) {
        match set_suspend(ebpf, false) {
            Ok(()) => {
                SUSPENDED.store(false, Ordering::SeqCst);
                log("已从 suspend 恢复（reload）");
            }
            Err(e) => log(&format!("清除 suspend 失败: {e}")),
        }
    }
    let out = match reload_rules(args, ebpf) {
        Ok(n) => {
            // P6/P18c：`--config` 模式下 dns.upstream/dns.routing 变更热切换
            // （--dns-upstream 显式给定时不覆盖）。失败保留旧对象（等价回滚）。
            if args.dns_upstream.is_none() {
                match build_upstream_set(args) {
                    Ok(new_ups) => {
                        let old = upstreams().map(|u| u.legacy.url.clone());
                        if old.as_deref() != Some(new_ups.legacy.url.as_str()) {
                            log(&format!(
                                "dns upstream 切换: {old:?} -> {} (tags={:?})",
                                new_ups.legacy.url,
                                {
                                    let mut v: Vec<String> =
                                        new_ups.by_tag.keys().cloned().collect();
                                    v.sort();
                                    v
                                }
                            ));
                        }
                        set_upstreams(new_ups.clone());
                        match build_dns_router(args, &new_ups) {
                            Ok(r) => {
                                let n = r
                                    .as_ref()
                                    .map(|r| r.request_rule_lines + r.response_rule_lines)
                                    .unwrap_or(0);
                                if let Some(r) = &r {
                                    for note in &r.notes {
                                        log(&format!("dnsroute: {note}"));
                                    }
                                }
                                log(&format!("dns.routing 重载: {n} 条规则"));
                                set_dns_router(r.map(Arc::new));
                            }
                            Err(e) => log(&format!("dns.routing 重载失败（保留旧路由）: {e}")),
                        }
                    }
                    Err(e) => log(&format!("reload: {e}（保留原上游）")),
                }
            }
            // 对照 dae reconcileCurrentBpfProjections：新槽需要重建域位图。
            reconcile_domain_bits(ebpf);
            // P18e：订阅热更新（重拉订阅 → 整体替换活动组成员）。
            // P19：启动期跳过——build_groups 刚拉过订阅；且此刻 eBPF 钩子已挂而 DNS
            // 监听线程尚未启动，重拉时解析节点域名会被自己的数据面拦截并自我阻塞
            // （getaddrinfo 超时卡死启动，钩子空挂 → 断网；重启后 DNS 缓存为空必现）。
            if !startup {
                // P0（2026-10-11）：本地部分（policy/组结构）随 reload 立即生效；
                // 订阅拉取与成员替换转入后台——reload 回执不再等待网络（旧实现可达 34s）。
                apply_group_policy_local(args);
                // P37（B1-B3）：watch 触发的 fast reload 对未变源 0 请求；
                // 手动 reload / SIGHUP 仍为 Full（强制拉取）。
                request_sub_refresh(
                    args,
                    if fast {
                        SubFetchMode::Fast
                    } else {
                        SubFetchMode::Full
                    },
                );
            }
            log(&format!("热重载完成（{n} 条 match_set）"));
            // P33：运行时参数热更新（CLI > config > 现值；仅变更时记日志）。
            if !startup {
                apply_runtime_params(args, cfg_loaded.as_ref());
            }
            // I6：热重载会重新编译规则/重建投影，同样回收一次分配器空闲页。
            trim_allocator();
            // P38：规则换代后立即刷新出口连通性投影——新组索引在首次 2s tick 前
            // 仍是全 0（dead），会把新流首包误杀（同启动期冷启动问题）。
            publish_outbound_connectivity();
            ReloadOutcome {
                ok: true,
                match_sets: n,
                slot: ACTIVE_SLOT.load(Ordering::SeqCst),
                error: None,
                at_sec: unix_now_sec(),
            }
        }
        Err(e) => {
            log(&format!("热重载失败，保持旧规则: {e}"));
            ReloadOutcome {
                ok: false,
                match_sets: 0,
                slot: ACTIVE_SLOT.load(Ordering::SeqCst),
                error: Some(e.to_string()),
                at_sec: unix_now_sec(),
            }
        }
    };
    if let Ok(mut g) = LAST_RELOAD.lock() {
        *g = Some(out.clone());
    }
    out
}

fn unix_now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------- 活跃度信号（优雅空闲）
//
// P37（2026-10-13 / A1）修订：健康探测节奏**只由「有流量吗」决定**——
//   * `note_traffic()`：每次 relay 建连打点（加上 conns_active 计数）——有真实转发。
// 无人用（无新连接、无活跃连接）时健康探测指数退避到 `probe_idle_cap`，
// 避免空闲时每 30s 拨全部节点（省 CPU/内存/节点握手）。
//
// 背景（devlog §13 对照研究）：旧实现把「状态面查询」也算作“有人在看”，
// 而面板秒级轮询 / health-track / watchdog / 任何 CLI 查询都会走 `status_json()`
// → 探针退避被永久钉在全速档（7×24 探测全部含死节点）。对照同类：
// mihomo 的状态 API（`tunnel.Proxies()`）不 touch、sing-box 仅在新连接 Touch——
// 「状态查询 ≠ 活跃」才是惯例。`note_watch()` 机制保留（供未来面板显式心跳），
// 但不再在任何自动路径上打点。

/// 最近一次状态面查询（unix 秒；0 = 从未）。
/// P37（A1）：已无自动打点来源——预留给未来的**显式**面板心跳（当前无调用点）。
static LAST_WATCH: AtomicU64 = AtomicU64::new(0);
/// 最近一次真实转发活动（unix 秒；0 = 从未）。
static LAST_TRAFFIC: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)] // P37（A1）：预留——仅允许“显式心跳”场景调用，状态查询不得再自动打点
pub fn note_watch() {
    LAST_WATCH.store(unix_now_sec(), Ordering::Relaxed);
}

pub fn note_traffic() {
    LAST_TRAFFIC.store(unix_now_sec(), Ordering::Relaxed);
}

/// 最近 `within` 秒内有人查询过状态。
pub fn watched_recently(within: u64) -> bool {
    let t = LAST_WATCH.load(Ordering::Relaxed);
    t > 0 && unix_now_sec().saturating_sub(t) < within
}

/// 最近 `within` 秒内**建立过新连接**（relay 建连打点）。
/// P37b（2026-10-13，CF 额度事故）：不再把「有活跃连接」算作活跃——挂机长连接
/// （推送保活/下载/SSH）不代表有人在用，旧语义让 busy 恒真（与 dae/sing-box 的
/// 「活跃 = 新连接/Touch」对齐：长连接本身不续期）。影响面只有健康探测节奏。
pub fn traffic_active(within: u64) -> bool {
    let t = LAST_TRAFFIC.load(Ordering::Relaxed);
    t > 0 && unix_now_sec().saturating_sub(t) < within
}

fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// conn_state 过期清扫（对照 dae control/conn_state_janitor.go；dae 在内核里也有
/// 到期判定，这里保留内核判定 + 用户态兜底回收，避免地图无限增长）。
// ---------------------------------------------------------------- A2 #13：流量历史
/// 1h 流量历史（对照 dae `control/runtime_stats.go`：1h 上限 / 30min 默认窗口 /
/// ≤180 点；dae 用 250ms 惰性桶，sodama 用 1s 采样线程——同一可观察形态，分辨率更粗）。
#[derive(Clone, Copy)]
struct TrafficPoint {
    /// unix 秒。
    t: u64,
    /// 上行字节/秒。
    up: u64,
    /// 下行字节/秒。
    down: u64,
}

/// 历史点数上限（1h）。
const TRAFFIC_HIST_MAX: usize = 3600;
/// 默认查询窗口（30min）与点数上限（180）——对照 dae `defaultRuntimeWindowSec`/`maxPoints`。
const TRAFFIC_WINDOW_SEC: u64 = 1800;
const TRAFFIC_MAX_POINTS: usize = 180;

fn traffic_hist() -> &'static Mutex<std::collections::VecDeque<TrafficPoint>> {
    static H: OnceLock<Mutex<std::collections::VecDeque<TrafficPoint>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(std::collections::VecDeque::with_capacity(TRAFFIC_HIST_MAX)))
}

/// 最近一次采样的速率（status/metrics 用，避免每查询都加锁算）。
static TRAFFIC_UP_RATE: AtomicU64 = AtomicU64::new(0);
static TRAFFIC_DOWN_RATE: AtomicU64 = AtomicU64::new(0);

/// 累计字节（TCP relay + UDP NAT；dae 在每次拷贝处记录，sodama 用累计计数采样）。
fn traffic_bytes_total() -> (u64, u64) {
    let up = RELAY_STATS.bytes_up.load(Ordering::Relaxed)
        + UDP_NAT_STATS.bytes_up.load(Ordering::Relaxed);
    let down = RELAY_STATS.bytes_down.load(Ordering::Relaxed)
        + UDP_NAT_STATS.bytes_down.load(Ordering::Relaxed);
    (up, down)
}

/// 1s 采样线程（对照 dae 的 runtime bucket 滚动；空转成本 = 两次原子读 + 一次 push）。
fn traffic_history_loop() {
    let mut last_mono = monotonic_now_ns();
    let (mut last_up, mut last_down) = traffic_bytes_total();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now_mono = monotonic_now_ns();
        let (up, down) = traffic_bytes_total();
        let elapsed = now_mono.saturating_sub(last_mono).max(1);
        let up_rate = up.saturating_sub(last_up) * 1_000_000_000 / elapsed;
        let down_rate = down.saturating_sub(last_down) * 1_000_000_000 / elapsed;
        last_mono = now_mono;
        last_up = up;
        last_down = down;
        TRAFFIC_UP_RATE.store(up_rate, Ordering::Relaxed);
        TRAFFIC_DOWN_RATE.store(down_rate, Ordering::Relaxed);
        let t = unix_now_sec();
        if let Ok(mut h) = traffic_hist().lock() {
            if h.len() >= TRAFFIC_HIST_MAX {
                h.pop_front();
            }
            h.push_back(TrafficPoint {
                t,
                up: up_rate,
                down: down_rate,
            });
        }
    }
}

/// status 面取样：窗口内降采样到 ≤`TRAFFIC_MAX_POINTS`（对照 dae `snapshot` 的
/// `windowSec`/`maxPoints` 语义：窗口过滤 + 点数上限）。
fn traffic_snapshot_json() -> serde_json::Value {
    let (up_total, down_total) = traffic_bytes_total();
    let now = unix_now_sec();
    let start = now.saturating_sub(TRAFFIC_WINDOW_SEC);
    let Ok(h) = traffic_hist().lock() else {
        return json!({"error": "history busy"});
    };
    let window: Vec<&TrafficPoint> = h.iter().filter(|p| p.t >= start).collect();
    let stride = window.len().div_ceil(TRAFFIC_MAX_POINTS).max(1);
    let samples: Vec<serde_json::Value> = window
        .iter()
        .step_by(stride)
        .map(|p| json!({"t": p.t, "up": p.up, "down": p.down}))
        .collect();
    json!({
        "updated_at_sec": now,
        "window_sec": TRAFFIC_WINDOW_SEC,
        "points": samples.len(),
        "samples_total": h.len(),
        "upload_rate": TRAFFIC_UP_RATE.load(Ordering::Relaxed),
        "download_rate": TRAFFIC_DOWN_RATE.load(Ordering::Relaxed),
        "upload_total": up_total,
        "download_total": down_total,
        "active_conns": RELAY_STATS.conns_active.load(Ordering::Relaxed),
        "udp_sessions": UDP_NAT_STATS
            .sessions_total
            .load(Ordering::Relaxed)
            .saturating_sub(UDP_NAT_STATS.evicted.load(Ordering::Relaxed)),
        "samples": samples,
    })
}

// ---------------------------------------------------------------- A2 #14：告警节流
/// 「持续条件」告警节流（对照 dae `control/alert_pacing.go` 的 `pacedAlert`）：
/// 同一条件跨多次巡检持续为真时——首次必发、冷却期内只累计**观察次数**、冷却结束
/// 后再次发出并把累计次数写进消息（「观察 N 次」）。与旧「固定步长单次」的区别：
/// 观察次数让「条件从未解除」可读（步长法只能看到孤立的几条）。
pub(crate) struct AlertPacer {
    last_emit_ns: AtomicU64,
    observations: AtomicU64,
    cooldown_ns: u64,
}

impl AlertPacer {
    pub(crate) const fn new(cooldown_ns: u64) -> Self {
        Self {
            last_emit_ns: AtomicU64::new(0),
            observations: AtomicU64::new(0),
            cooldown_ns,
        }
    }

    /// 记一次观察；返回 `(累计观察次数, 是否应输出)`（首次必发；冷却后复发）。
    pub(crate) fn observe(&self, now_ns: u64) -> (u64, bool) {
        let n = self.observations.fetch_add(1, Ordering::Relaxed) + 1;
        let last = self.last_emit_ns.load(Ordering::Relaxed);
        if last != 0 && now_ns.saturating_sub(last) < self.cooldown_ns {
            return (n, false);
        }
        if self
            .last_emit_ns
            .compare_exchange(last, now_ns, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return (n, false);
        }
        (n, true)
    }
}

/// redirect_track 容量告警节流（对照 dae `mapCapacityAlertCooldown = 1min`）。
static REDIRECT_CAPACITY_ALERT: AlertPacer = AlertPacer::new(60 * 1_000_000_000);
/// conn_state 容量告警节流（sodama 扩展；同口径）。
static CONN_STATE_CAPACITY_ALERT: AlertPacer = AlertPacer::new(60 * 1_000_000_000);

fn sweep_conn_state(ebpf: &mut Ebpf) -> Result<usize, Box<dyn std::error::Error>> {
    const TCP_TIMEOUT_NS: u64 = 300 * 1_000_000_000;
    const UDP_TIMEOUT_NS: u64 = 60 * 1_000_000_000;
    let map = ebpf
        .map_mut("conn_state_map")
        .ok_or("map conn_state_map not found")?;
    let mut conn_state: HashMap<_, SodaTuple, SodaConnState> = HashMap::try_from(map)?;
    let now = monotonic_now_ns();
    let mut dead: Vec<SodaTuple> = Vec::new();
    let mut total: usize = 0;
    for (k, v) in conn_state.iter().flatten() {
        total += 1;
        let timeout = if v.l4proto == 6 {
            TCP_TIMEOUT_NS
        } else {
            UDP_TIMEOUT_NS
        };
        if v.last_seen_ns <= now && now - v.last_seen_ns > timeout {
            dead.push(k);
        }
    }
    let n = dead.len();
    for k in &dead {
        let _ = conn_state.remove(k);
    }
    // A2 #14：容量告警（持续条件 + 观察次数；90% 阈值同 redirect_track 口径）。
    const CONN_STATE_CAPACITY: usize = 262144;
    if total * 100 >= CONN_STATE_CAPACITY * 90 {
        let (obs, emit) = CONN_STATE_CAPACITY_ALERT.observe(now);
        if emit {
            log_warn(&format!(
                "conn_state_map 容量告警：{total}/{CONN_STATE_CAPACITY}（≥90%；本次观察 {obs} 次，60s 一条）"
            ));
        }
    }
    Ok(n)
}

/// redirect_track 过期清扫（对照 dae control_plane.go:1671 `cleanupRedirectTrackMap`，
/// `redirectTrackTimeout = 5 * time.Minute`）。回程绑定只由回程流量续租、数据面从不
/// 主动删除；缺清理时地图单调填满（65536），此后所有进控制面的新流在
/// `publish_redirect_track` 插入失败处被 TC_ACT_SHOT 丢弃（DNS 与代理一并停摆，
/// 2026-10-08 生产实锤）。返回 (清理条数, 清理前总条数)。
fn sweep_redirect_track(ebpf: &mut Ebpf) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    const REDIRECT_TIMEOUT_NS: u64 = 300 * 1_000_000_000;
    /// 对照 ebpf-rs/src/maps.rs 的 `redirect_track` max_entries。
    const REDIRECT_TRACK_CAPACITY: usize = 65536;
    const CAPACITY_ALERT_PCT: usize = 90;

    let map = ebpf
        .map_mut("redirect_track")
        .ok_or("map redirect_track not found")?;
    let mut track: HashMap<_, SodaTuple, SodaRedirectEntry> = HashMap::try_from(map)?;
    let now = monotonic_now_ns();
    let mut dead: Vec<SodaTuple> = Vec::new();
    let mut total: usize = 0;
    for (k, v) in track.iter().flatten() {
        total += 1;
        if v.last_seen_ns <= now && now - v.last_seen_ns > REDIRECT_TIMEOUT_NS {
            dead.push(k);
        }
    }
    let n = dead.len();
    for k in &dead {
        let _ = track.remove(k);
    }
    // A2 #14：容量告警（对照上游 logMapCapacityAlert；持续条件 + 观察次数）。
    if total * 100 >= REDIRECT_TRACK_CAPACITY * CAPACITY_ALERT_PCT {
        let (obs, emit) = REDIRECT_CAPACITY_ALERT.observe(now);
        if emit {
            log_warn(&format!(
                "redirect_track 容量告警：{total}/{REDIRECT_TRACK_CAPACITY}（≥{CAPACITY_ALERT_PCT}%；本次观察 {obs} 次，60s 一条），过期清理未跟上"
            ));
        }
    }
    Ok((n, total))
}

/// routing_handoff 过期清扫（对照 dae `control/control_plane.go:1848-1918`
/// `cleanupRoutingHandoffMap`）：首包交接条目只由数据面写入、从不主动删除，
/// 缺清理时单调填满（65,536）——此后新首包 `publish_routing_handoff` 插入失败，
/// 控制面 `conn_state` miss 时失去首包路由兜底（主路径不受影响；
/// 2026-10-20 生产 72h 轮收口实锤满表，见 `docs/notes/prod-audit-2026-10-20` §4.1）。
/// 与 `redirect_track` 满表停摆（2026-10-08）同构。TTL 与读取侧一致（30s）；
/// 每轮删除上限避免长时间占用主循环（满表 8 轮 × 60s 清完，稳态远小于此）。
fn sweep_routing_handoff(ebpf: &mut Ebpf) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    /// 对照 ebpf-rs/src/maps.rs 的 `routing_handoff` max_entries。
    const ROUTING_HANDOFF_CAPACITY: usize = 65536;
    const CAPACITY_ALERT_PCT: usize = 90;
    /// 每轮最多删除条数。
    const DELETE_LIMIT: usize = 8192;

    let map = ebpf
        .map_mut("routing_handoff_map")
        .ok_or("map routing_handoff_map not found")?;
    let mut handoff: HashMap<_, SodaTuple, SodaRoutingHandoffEntry> = HashMap::try_from(map)?;
    let now = monotonic_now_ns();
    let mut dead: Vec<SodaTuple> = Vec::new();
    let mut total: usize = 0;
    for (k, v) in handoff.iter().flatten() {
        total += 1;
        if dead.len() < DELETE_LIMIT && handoff_expired(now, v.last_seen_ns, SODAMA_HANDOFF_TTL_NS)
        {
            dead.push(k);
        }
    }
    let n = dead.len();
    for k in &dead {
        let _ = handoff.remove(k);
    }
    // A2 #14：容量告警（对照 dae `logMapCapacityAlert`；持续条件 + 观察次数）。
    if total * 100 >= ROUTING_HANDOFF_CAPACITY * CAPACITY_ALERT_PCT {
        let (obs, emit) = ROUTING_HANDOFF_CAPACITY_ALERT.observe(now);
        if emit {
            log_warn(&format!(
                "routing_handoff 容量告警：{total}/{ROUTING_HANDOFF_CAPACITY}（≥{CAPACITY_ALERT_PCT}%；本次观察 {obs} 次，60s 一条），过期清理未跟上"
            ));
        }
    }
    Ok((n, total))
}

static ROUTING_HANDOFF_CAPACITY_ALERT: AlertPacer = AlertPacer::new(60 * 1_000_000_000);

/// P15/P19：构建全部节点组（config `group` 段顺序即索引顺序；无配置时为隐式 proxy 组）。
/// 订阅拉取失败/节点全部不支持时返回 None（回落为无 dialer，保持实验回显语义）。
fn build_groups(args: &Args) -> Option<outbound::Outbound> {
    let cfg = args.config.as_ref().and_then(|p| {
        config::load(std::path::Path::new(p))
            .map_err(|d| {
                log(&format!(
                    "订阅/组：配置解析失败（{}），跳过组构建",
                    diag_summary(&d)
                ));
            })
            .ok()
    });
    let group_specs = cfg.as_ref().map(config::groups).unwrap_or_default();
    let has_subs = cfg
        .as_ref()
        .map(|c| !config::subscriptions(c).is_empty())
        .unwrap_or(false);
    let has_nodes = cfg
        .as_ref()
        .map(|c| !config::inline_nodes(c).is_empty())
        .unwrap_or(false);
    if !has_subs && !has_nodes && args.subscribe.is_empty() {
        return None;
    }

    let nodes = fetch_nodes(cfg.as_ref(), args, &SubFetchMode::Full);
    if nodes.is_empty() {
        log("未获得任何可用节点，组不启用");
        return None;
    }

    // P19：全部组按 config 顺序注册；无 config 组时隐式单组 "proxy"（兼容旧行为）。
    let specs: Vec<(String, Option<config::GroupSpec>)> = if group_specs.is_empty() {
        vec![("proxy".to_string(), None)]
    } else {
        group_specs
            .into_iter()
            .map(|g| (g.name.clone(), Some(g)))
            .collect()
    };
    let mut groups = Vec::with_capacity(specs.len());
    let mut by_name = std::collections::HashMap::new();
    for (i, (name, spec)) in specs.iter().enumerate() {
        by_name.insert(name.clone(), i);
        groups.push(make_group_runtime(
            name,
            spec.as_ref(),
            &nodes,
            cfg.as_ref(),
        ));
    }
    let default_idx = select_default_group(&by_name, args);
    let default_rt = groups[default_idx].clone();
    if groups.len() > 1 {
        let names: Vec<&str> = specs.iter().map(|(n, _)| n.as_str()).collect();
        log(&format!(
            "P19 多组分派：{} 个组 {names:?}（outbound 索引 {} 起），默认组 {}",
            groups.len(),
            rules::GROUP_INDEX_BASE,
            specs[default_idx].0
        ));
    }

    let set = GroupSet {
        groups,
        default_idx,
    };
    let lock = GROUP_SET.get_or_init(|| std::sync::RwLock::new(GroupSet::default()));
    match lock.write() {
        Ok(mut g) => *g = set,
        Err(p) => *p.into_inner() = set,
    }
    Some(outbound::Outbound::Group(default_rt))
}

/// P19：默认组选择（`--group` 指定 > proxy > 第一个）。
fn select_default_group(by_name: &std::collections::HashMap<String, usize>, args: &Args) -> usize {
    args.group
        .as_deref()
        .and_then(|n| by_name.get(n).copied())
        .or_else(|| by_name.get("proxy").copied())
        .unwrap_or(0)
}

/// P15/P19：构建单个组（成员/策略/探测参数/udp_check）；成员为空也注册
/// （保索引稳定，订阅热更新可后续替换进成员）。
fn make_group_runtime(
    gname: &str,
    spec: Option<&config::GroupSpec>,
    nodes: &[subscribe::ParsedNode],
    cfg: Option<&config::Config>,
) -> std::sync::Arc<group::GroupRuntime> {
    let policy = group::parse_policy(spec.and_then(|g| g.policy.as_deref()));
    let filters = spec.map(|g| g.filters.clone()).unwrap_or_default();
    let members = group::build_members(nodes, &filters);
    if members.is_empty() {
        log(&format!(
            "组 {gname} 没有命中的节点（filter 过严？），暂为空组"
        ));
    }

    let global_str = |key: &str| cfg.and_then(|c| config::global_value(c, key));
    let check_urls: Vec<String> = match spec.and_then(|g| {
        if g.tcp_check_urls.is_empty() {
            None
        } else {
            Some(g.tcp_check_urls.clone())
        }
    }) {
        Some(v) => v,
        None => global_str("tcp_check_url")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|| vec!["http://cp.cloudflare.com".to_string()]),
    };
    let targets: Vec<(String, u16)> = check_urls
        .iter()
        .filter_map(|u| parse_check_target(u))
        .collect();
    let interval = spec
        .and_then(|g| g.check_interval.clone())
        .or_else(|| global_str("check_interval"))
        .and_then(|v| parse_duration_secs(&v))
        .unwrap_or(30);
    let tolerance = spec
        .and_then(|g| g.check_tolerance.clone())
        .or_else(|| global_str("check_tolerance"))
        .and_then(|v| parse_duration_secs(&v))
        .unwrap_or(1) as u32;
    // P18e：udp_check_dns（组级 > 全局；取第一个，域名在此解析一次，失败则禁用）。
    let udp_check_dns = spec
        .and_then(|g| g.udp_check_dns.clone())
        .or_else(|| global_str("udp_check_dns"))
        .and_then(|s| {
            use std::net::ToSocketAddrs as _;
            let first = s.split(',').next().unwrap_or("").trim().to_string();
            if first.is_empty() {
                return None;
            }
            match first.to_socket_addrs() {
                Ok(mut it) => it.next().map(|a| (a.ip().to_string(), a.port())),
                Err(e) => {
                    log(&format!(
                        "组 {gname}: udp_check_dns '{first}' 解析失败（{e}），UDP 检查禁用"
                    ));
                    None
                }
            }
        });

    let rt = group::GroupRuntime::new(
        gname.to_string(),
        policy.clone(),
        members,
        targets.clone(),
        interval,
        tolerance,
        udp_check_dns.clone(),
    );
    // P38：探测 HTTP 方法（对照 dae）：global 默认 HEAD，非法值 warn 后回落 CONNECT；
    // group 级覆盖（dae 不做 group 级校验，非法值在请求构造时失败）。
    let global_method = match global_str("tcp_check_http_method") {
        Some(m) if group::is_valid_http_method(&m) => m,
        Some(m) => {
            log(&format!(
                "tcp_check_http_method '{m}' 非法，回落 CONNECT（对照 dae patchTcpCheckHttpMethod）"
            ));
            "CONNECT".to_string()
        }
        None => "HEAD".to_string(),
    };
    let http_method = spec
        .and_then(|g| g.tcp_check_http_method.clone())
        .unwrap_or(global_method);
    rt.set_http_method(&http_method);
    // P34：订阅顺序回退（pacman 风格）——global `subscription_failover`（默认开）。
    let failover = global_str("subscription_failover")
        .map(|v| !matches!(v.trim(), "false" | "0" | "no" | "off"))
        .unwrap_or(true);
    rt.set_sub_failover(failover);
    // 优雅空闲：无人看状态且无流量时，健康探测退避到该上限（秒；0 = 不退避）。
    let idle_cap = global_str("probe_idle_cap")
        .and_then(|v| parse_duration_secs(&v))
        .unwrap_or(600);
    rt.set_idle_cap(idle_cap);
    log(&format!(
        "节点组 {gname}: {} 个成员, policy={}, check={targets:?} 每 {interval}s（http={http_method}）, 容忍 {tolerance} 次失败, udp_check={udp_check_dns:?}, 订阅顺序回退={}",
        rt.member_count(),
        group::policy_name(&policy),
        if failover { "开" } else { "关" }
    ));
    rt.spawn_health_loop();
    rt
}

/// P34：订阅 URL 规整——`~/` 展开；config 里的裸路径（无 scheme）优先按配置目录解析，
/// 便于把 `config.dae` 与订阅正文文件（如 `sub1.url`）放同一目录；URL/绝对路径语义不变。
fn resolve_sub_url(cfg_dir: Option<&Path>, url: &str) -> String {
    // 能力缺口 #2：先归一化 dae 风格 `http(s)-file://`——缓存键（子 seen/负缓存/节点缓存）
    // 与去重都以归一化文本为准，避免同一源两种写法各自一份缓存。
    let normalized = subscribe::normalize_url(url);
    let url: &str = &normalized;
    let expanded = match url.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(h) => format!("{h}/{rest}"),
            Err(_) => url.to_string(),
        },
        None => url.to_string(),
    };
    if expanded.contains("://") || expanded.starts_with('/') {
        return expanded;
    }
    if let Some(dir) = cfg_dir {
        let cand = dir.join(&expanded);
        if cand.is_file() {
            return cand.to_string_lossy().into_owned();
        }
    }
    expanded
}

/// P35：订阅节点缓存查询（fast reload 专用）——命中则回一份副本并覆写 tag/rank。
fn cache_get_sub(url: &str, tag: &str, rank: u32) -> Option<Vec<subscribe::ParsedNode>> {
    let ttl = SUB_CACHE_TTL_SECS.load(Ordering::Relaxed);
    if ttl == 0 {
        return None;
    }
    let cache = SUB_NODE_CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let hit = match cache.lock() {
        Ok(m) => m.get(url).cloned(),
        Err(p) => p.into_inner().get(url).cloned(),
    }?;
    let (at, nodes) = hit;
    let age = at.elapsed();
    if age > Duration::from_secs(ttl) {
        return None;
    }
    let mut ns = (*nodes).clone();
    for n in &mut ns {
        n.tag = tag.to_string();
        n.rank = rank;
    }
    log(&format!(
        "订阅 {tag}: 命中缓存（{:.1}s 前抓取，{} 个节点，顺序 #{rank}）",
        age.as_secs_f32(),
        ns.len()
    ));
    Some(ns)
}

fn cache_put_sub(url: &str, nodes: &[subscribe::ParsedNode]) {
    let cache = SUB_NODE_CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut m = match cache.lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    // 上限 32 条（tag/url 组合很少超过这个量级），按抓取时刻淘汰最旧
    if m.len() >= 32 && !m.contains_key(url) {
        if let Some(k) = m
            .iter()
            .min_by_key(|(_, (at, _))| *at)
            .map(|(k, _)| k.clone())
        {
            m.remove(&k);
        }
    }
    m.insert(
        url.to_string(),
        (Instant::now(), std::sync::Arc::new(nodes.to_vec())),
    );
}

/// P0（2026-10-11）：内存缓存里上次成功拉取的节点数（节点数骤降告警用）。
fn cache_peek_count(url: &str) -> Option<usize> {
    let cache = SUB_NODE_CACHE.get()?;
    let m = match cache.lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    m.get(url).map(|(_, nodes)| nodes.len())
}

/// 人类可读的时长（"42s"/"3min"/"2h"）。
fn fmt_age_secs(s: u64) -> String {
    if s < 90 {
        format!("{s}s")
    } else if s < 5400 {
        format!("{}min", s / 60)
    } else {
        format!("{}h", s / 3600)
    }
}

/// P37（2026-10-13 / B1/B3）：订阅拉取模式。
/// - `Full`：强制拉取（启动 / 手动 reload / SIGHUP / 周期刷新）——所有源打网；
/// - `Fast`：配置热重载触发——未变源走缓存（内存→磁盘）不打网；失败源在负缓存窗口内不打网；
/// - `Heal(set)`：自愈重试——仅 `set` 里的失败源打网，其余源走缓存（不再连带健康源）。
#[derive(Clone, Debug, PartialEq)]
enum SubFetchMode {
    Full,
    Fast,
    Heal(std::collections::HashSet<String>),
}

impl SubFetchMode {
    /// 队列合并（sub-refresh 后台线程）：取「更宽」的那个——
    /// 任一 Full → Full；Heal 之间取并集；Fast 与 Heal 混合 → Heal（打网集合更大）。
    fn merge(self, other: SubFetchMode) -> SubFetchMode {
        use SubFetchMode::*;
        match (self, other) {
            (Full, _) | (_, Full) => Full,
            (Heal(mut a), Heal(b)) => {
                a.extend(b);
                Heal(a)
            }
            (Heal(a), Fast) | (Fast, Heal(a)) => Heal(a),
            (Fast, Fast) => Fast,
        }
    }

    fn label(&self) -> String {
        match self {
            SubFetchMode::Full => "full".into(),
            SubFetchMode::Fast => "fast".into(),
            SubFetchMode::Heal(s) => format!("heal({} 源)", s.len()),
        }
    }
}

/// P34：拉取单个订阅并解析（失败记日志返回空；rank = 来源顺序）。
/// P35：订阅节点内存缓存（§B1 延长至 30min）——配置热重载命中时不重走网络。
/// P0（2026-10-11）：失败时回退磁盘缓存（最近一次成功正文）、登记来源状态；
/// 429（限流）触发冷却——冷却期内不再打网络，直接用缓存。
/// P37（2026-10-13 / B1/B2）：`mode` 决定非强制拉取的缓存优先策略与失败负缓存。
fn fetch_one_sub(
    tag: &str,
    url: &str,
    rank: u32,
    timeout: Duration,
    mode: &SubFetchMode,
    cfg_dir: Option<&Path>,
) -> Vec<subscribe::ParsedNode> {
    let mk_status = |ok: bool, error: Option<String>, nodes: usize, source: &'static str| {
        subscribe::record_source_status(subscribe::SourceStatus {
            tag: tag.to_string(),
            rank,
            at_sec: unix_now_sec(),
            ok,
            error,
            nodes,
            fails: 0, // record_source_status 会按前一条状态累计
            source,
            // C1：打网计数由 record_source_status 按 source=="net" 累计/沿用。
            fetches_total: 0,
            fetch_fail_total: 0,
            last_fetch_at: 0,
        });
    };
    // P0/P37：磁盘缓存读取（快路径与失败回退共用——最近一次成功正文，含凭据，权限 0600）。
    let disk_fallback = |why: &str| -> Option<Vec<subscribe::ParsedNode>> {
        let dir = cfg_dir?;
        let (body, age) = subscribe::disk_load(dir, tag)?;
        let text = subscribe::decode_body(&body).ok()?;
        let (mut ns, _errs) = subscribe::parse_subscription(&text, tag);
        if ns.is_empty() {
            return None;
        }
        for n in &mut ns {
            n.rank = rank;
        }
        log(&format!(
            "订阅 {tag}: {why}，回退磁盘缓存（{}前抓取，{} 个节点）",
            fmt_age_secs(age),
            ns.len()
        ));
        Some(ns)
    };
    // P37（B1/B3）：非强制模式——未变的源优先缓存、不打网。
    let cache_first = match mode {
        SubFetchMode::Full => false,
        SubFetchMode::Fast => true,
        // Heal(set)：只有集合内的失败源打网，其余走缓存。
        SubFetchMode::Heal(set) => !set.contains(tag),
    };
    if cache_first {
        if let Some(ns) = cache_get_sub(url, tag, rank) {
            mk_status(true, None, ns.len(), "memory");
            return ns;
        }
        // B2：失败源负缓存——窗口内不打网（磁盘兜底；没有则空手回去，组按「按源保留」沿用旧成员）。
        let fail_ttl = SUB_FAIL_TTL_SECS.load(Ordering::Relaxed);
        if let Some(remain) = subscribe::fetch_fail_remaining(url, fail_ttl) {
            if let Some(ns) = disk_fallback(&format!("失败负缓存中（剩 {remain}s）")) {
                mk_status(
                    true,
                    Some(format!("失败负缓存（剩 {remain}s）")),
                    ns.len(),
                    "disk",
                );
                return ns;
            }
            log(&format!(
                "订阅 {tag}: 失败负缓存中（剩 {remain}s），本轮跳过网络"
            ));
            return Vec::new();
        }
        // B1：URL 未变（曾成功拉取过）→ 磁盘缓存，不打网。
        // 对齐 dae：订阅拉取不随配置热重载发生；内容更新交给周期刷新/手动 reload。
        if subscribe::sub_seen(url) {
            if let Some(ns) = disk_fallback("URL 未变更（配置热重载不打网）") {
                mk_status(true, None, ns.len(), "disk");
                return ns;
            }
            // 磁盘缓存缺失（被清理/首跑未落盘）→ 兜底打网。
        }
    }
    let mut last_err: Option<String> =
        subscribe::cooldown_remaining(url).map(|remain| format!("限流冷却中（剩 {remain}s）"));
    if last_err.is_none() {
        // P0（2026-10-11）：链路截断是概率性的（生产实测：同一源分钟级内时好时坏），
        // 单次失败不放弃——最多重试 3 次（间隔 0.6s / 1.2s）。
        for attempt in 1..=3u32 {
            match subscribe::fetch(url, timeout)
                .and_then(|b| subscribe::decode_body(&b).map(|t| (b, t)))
            {
                Ok((body, text)) => {
                    let (mut ns, errs) = subscribe::parse_subscription(&text, tag);
                    for e in errs.iter().take(3) {
                        log(&format!("订阅 {tag}: {e}"));
                    }
                    if errs.len() > 3 {
                        log(&format!("订阅 {tag}: 另有 {} 行不支持", errs.len() - 3));
                    }
                    if ns.is_empty() {
                        last_err = Some("解析结果为空".into());
                    } else {
                        // 节点数骤降告警（截断被 CL 校验兜住后的第二道可见性；仅告警不拒绝）。
                        if let Some(prev) = cache_peek_count(url) {
                            if prev >= 8 && ns.len() * 2 < prev {
                                log(&format!(
                                "订阅 {tag}: 警告：节点数骤降 {prev} -> {}（疑似截断/套餐变更，请留意）",
                                ns.len()
                            ));
                            }
                        }
                        for n in &mut ns {
                            n.rank = rank;
                        }
                        log(&format!(
                            "订阅 {tag}: 拉取成功，{} 个节点（来源顺序 #{rank}）",
                            ns.len()
                        ));
                        cache_put_sub(url, &ns);
                        // P37（B1）：登记「曾成功拉取」——下次配置热重载（Fast）走磁盘缓存不打网。
                        subscribe::mark_sub_seen(url);
                        subscribe::clear_fetch_fail(url);
                        if let Some(dir) = cfg_dir {
                            if let Err(e) = subscribe::disk_store(dir, tag, &body) {
                                log(&format!("订阅 {tag}: 磁盘缓存写入失败: {e}"));
                            }
                        }
                        mk_status(true, None, ns.len(), "net");
                        return ns;
                    }
                }
                Err(e) => {
                    let es = e.to_string();
                    subscribe::note_fetch_error(url, &es);
                    if attempt < 3 {
                        log(&format!(
                            "订阅 {tag}: 第 {attempt} 次拉取失败（{es}），重试…"
                        ));
                        std::thread::sleep(Duration::from_millis(600 * attempt as u64));
                    }
                    last_err = Some(es);
                }
            }
        }
    }
    // 失败回退：磁盘缓存（最近一次成功正文，含凭据，权限 0600）。
    if let Some(ns) = disk_fallback(&format!(
        "拉取失败（{}）",
        last_err.clone().unwrap_or_default()
    )) {
        mk_status(true, last_err, ns.len(), "disk");
        return ns;
    }
    // 最后手段：截断宽容重取一次（仅当上面全部失败——首跑无缓存 + 链路持续截断时
    // 的可用性兜底；解出的部分节点仍会经健康探测自我验证，不写磁盘缓存以免污染
    // “上次完整副本”）。
    if last_err.is_some() {
        if let Ok(body) = subscribe::fetch_lenient(url, timeout) {
            if let Ok(text) = subscribe::decode_body(&body) {
                let (mut ns, _errs) = subscribe::parse_subscription(&text, tag);
                if !ns.is_empty() {
                    for n in &mut ns {
                        n.rank = rank;
                    }
                    log(&format!(
                        "订阅 {tag}: 警告：仅取得不完整正文（{} 字节，{} 个节点）——为可用性放行（截断容错）",
                        body.len(),
                        ns.len()
                    ));
                    cache_put_sub(url, &ns);
                    subscribe::mark_sub_seen(url);
                    subscribe::clear_fetch_fail(url);
                    mk_status(true, Some("截断容错：正文不完整".into()), ns.len(), "net");
                    return ns;
                }
            }
        }
    }
    let e = last_err.unwrap_or_else(|| "未知错误".into());
    log(&format!("订阅 {tag} 拉取失败: {e}"));
    mk_status(false, Some(e), 0, "net");
    Vec::new()
}

/// P0（2026-10-11）：按来源返回的拉取结果（「按源保留」语义需要区分来源成败）。
struct SourceFetch {
    tag: String,
    rank: u32,
    ok: bool,
    nodes: Vec<subscribe::ParsedNode>,
}

/// 拉取内联节点 + 全部订阅，**按来源**返回（组构建 / 订阅热更新共用）。
/// P34：来源顺序 = 内联 node(0) → CLI --subscribe(1..) → config subscription(声明顺序)；
/// 顺序回退（pacman 风格，`subscription_failover` 默认开）：前面来源有活节点就用它。
/// P37（B1/B2/B3）：`mode` 决定缓存优先/负缓存/定向重拉（见 `SubFetchMode`）。
fn fetch_sources(
    cfg: Option<&config::Config>,
    args: &Args,
    mode: &SubFetchMode,
) -> Vec<SourceFetch> {
    let node_specs = cfg.map(config::inline_nodes).unwrap_or_default();
    let sub_specs = cfg.map(config::subscriptions).unwrap_or_default();
    let timeout = Duration::from_secs(15);
    let cfg_dir = args
        .config
        .as_deref()
        .map(Path::new)
        .and_then(|p| p.parent());
    // 清理已不在配置里的来源状态（删源后不留幽灵条目）。
    let mut live: Vec<String> = Vec::new();
    if !node_specs.is_empty() {
        live.push("node".into());
    }
    live.extend((1..=args.subscribe.len()).map(|i| format!("cli{i}")));
    live.extend(sub_specs.iter().map(|s| s.tag.clone()));
    subscribe::prune_source_status(&live);
    let mut out: Vec<SourceFetch> = Vec::new();
    if !node_specs.is_empty() {
        let mut nodes = Vec::new();
        for n in &node_specs {
            match outbound::parse(&n.link) {
                Ok(o) => nodes.push(subscribe::ParsedNode {
                    name: n.name.clone(),
                    tag: "node".into(),
                    rank: 0,
                    outbound: o,
                }),
                Err(e) => log(&format!("节点 {} 不支持: {e}", n.name)),
            }
        }
        let ok = !nodes.is_empty();
        out.push(SourceFetch {
            tag: "node".into(),
            rank: 0,
            ok,
            nodes,
        });
    }
    let mut rank = 1u32;
    for (i, raw) in args.subscribe.iter().enumerate() {
        let tag = format!("cli{}", i + 1);
        let url = resolve_sub_url(None, raw);
        let nodes = fetch_one_sub(&tag, &url, rank, timeout, mode, cfg_dir);
        out.push(SourceFetch {
            tag,
            rank,
            ok: !nodes.is_empty(),
            nodes,
        });
        rank += 1;
    }
    for s in &sub_specs {
        let url = resolve_sub_url(cfg_dir, &s.url);
        let nodes = fetch_one_sub(&s.tag, &url, rank, timeout, mode, cfg_dir);
        out.push(SourceFetch {
            tag: s.tag.clone(),
            rank,
            ok: !nodes.is_empty(),
            nodes,
        });
        rank += 1;
    }
    out
}

/// 兼容旧调用方：扁平化全部来源的节点（启动期组构建）。
fn fetch_nodes(
    cfg: Option<&config::Config>,
    args: &Args,
    mode: &SubFetchMode,
) -> Vec<subscribe::ParsedNode> {
    fetch_sources(cfg, args, mode)
        .into_iter()
        .flat_map(|s| s.nodes)
        .collect()
}

/// P0（2026-10-11）：组 policy 本地热应用（不依赖任何订阅网络拉取）。
/// 背景：旧实现把 policy 应用塞在订阅热更新里，且「全源拉取失败」时早退——
/// 控制面板「手动切节点/恢复自动」会静默不生效（生产实测，见 §11）。
fn apply_group_policy_local(args: &Args) {
    let Some(lock) = GROUP_SET.get() else {
        return;
    };
    let Some(cfg) = args
        .config
        .as_ref()
        .and_then(|p| config::load(std::path::Path::new(p)).ok())
    else {
        return;
    };
    let group_specs = config::groups(&cfg);
    if group_specs.is_empty() {
        return;
    }
    let g = match lock.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    for spec in &group_specs {
        let want = group::parse_policy(spec.policy.as_deref());
        if let Some(rt) = g.groups.iter().find(|rt| rt.name == spec.name) {
            if *rt.policy() != want {
                log(&format!(
                    "热重载：组 {} policy -> {}",
                    spec.name,
                    group::policy_name(&want)
                ));
                rt.set_policy(want);
            }
        }
    }
}

/// P0（2026-10-11）：订阅热更新从 reload 关键路径解耦。
/// reload 立即返回回执；本函数把「拉取订阅 + 替换成员」投递到常驻后台线程，
/// 同一时刻最多一轮拉取；排队中的请求自动合并（P37/B1-B3：按 `SubFetchMode` 取更宽语义）。
static SUB_REFRESH_TX: std::sync::OnceLock<std::sync::mpsc::Sender<SubFetchMode>> =
    std::sync::OnceLock::new();

fn request_sub_refresh(args: &Args, mode: SubFetchMode) {
    let tx = SUB_REFRESH_TX.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<SubFetchMode>();
        let args = args.clone();
        let _ = std::thread::Builder::new()
            .name("sub-refresh".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                while let Ok(mut mode) = rx.recv() {
                    while let Ok(m2) = rx.try_recv() {
                        mode = mode.merge(m2);
                    }
                    log(&format!("订阅热更新：后台开始拉取（{}）", mode.label()));
                    reload_group_members(&args, &mode);
                    log("订阅热更新：本轮后台拉取结束");
                }
            });
        tx
    });
    if tx.send(mode).is_err() {
        log("订阅热更新：后台线程已退出（发送失败）");
    }
}

/// P1（2026-10-11）：订阅读周期刷新（对照 Clash 的 interval；dae 无此物）。
/// `global.subscription_update_interval`（秒；默认 21600 = 6h；0 = 关闭），±10% 抖动。
fn spawn_subscription_scheduler(args: &Args) {
    let cfg = args
        .config
        .as_ref()
        .and_then(|p| config::load(std::path::Path::new(p)).ok());
    let has_cfg_subs = cfg
        .as_ref()
        .map(|c| !config::subscriptions(c).is_empty())
        .unwrap_or(false);
    if args.subscribe.is_empty() && !has_cfg_subs {
        return;
    }
    let interval = cfg
        .as_ref()
        .and_then(|c| config::global_value(c, "subscription_update_interval"))
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(21600);
    if interval == 0 {
        log("订阅周期刷新: 已关闭（subscription_update_interval = 0）");
        return;
    }
    let args = args.clone();
    let _ = std::thread::Builder::new()
        .name("sub-timer".into())
        .spawn(move || {
            let jitter = (interval / 10).max(1);
            let mut next_periodic =
                unix_now_sec() + interval - jitter / 2 + rand::random::<u64>() % jitter;
            loop {
                std::thread::sleep(Duration::from_secs(60));
                let now = unix_now_sec();
                // P1（2026-10-11）：失败源自愈重试（退避 5min→1h；429 冷却仍然生效）。
                // P37（B3）：只对到期的失败源定向重拉（旧行为：连带健康源一起重打）。
                let due = subscribe::sources_due_for_retry(now);
                if !due.is_empty() {
                    log(&format!(
                        "订阅自动重试：{} 个失败源到退避窗口（{}），定向重拉",
                        due.len(),
                        due.join("/")
                    ));
                    request_sub_refresh(&args, SubFetchMode::Heal(due.into_iter().collect()));
                }
                if now >= next_periodic {
                    log(&format!("订阅周期刷新: 触发（间隔 {interval}s）"));
                    request_sub_refresh(&args, SubFetchMode::Full);
                    let jitter = (interval / 10).max(1);
                    next_periodic = now + interval - jitter / 2 + rand::random::<u64>() % jitter;
                }
            }
        });
    log(&format!(
        "订阅周期刷新: 已启用（每 {interval}s ±10%，失败源 5min→1h 退避自愈）"
    ));
}

/// P18e/P19：SIGHUP 订阅热更新——重拉订阅，按组 filter 替换成员（同名继承健康）。
/// 组名集合变化（config 编辑）时整体重建（不做健康继承，日志明示）。
/// P37：`mode` 决定本轮哪些源打网（Full/Fast/Heal，见 `SubFetchMode`）。
fn reload_group_members(args: &Args, mode: &SubFetchMode) {
    let Some(lock) = GROUP_SET.get() else {
        return;
    };
    let cfg = args.config.as_ref().and_then(|p| {
        config::load(std::path::Path::new(p))
            .map_err(|d| {
                log(&format!("订阅热更新：配置解析失败（{}）", diag_summary(&d)));
            })
            .ok()
    });
    let sources = fetch_sources(cfg.as_ref(), args, mode);
    let ok_count = sources.iter().filter(|s| s.ok).count();
    log(&format!(
        "订阅热更新：拉取完成（{ok_count}/{} 源成功）",
        sources.len()
    ));
    if ok_count == 0 {
        log("订阅热更新：全部来源拉取失败，保留旧成员");
        return;
    }
    // P0（2026-10-11）：按源保留——只有「拉取失败」的来源沿用旧成员（转换为
    // ParsedNode 后与成功来源一起过组过滤器）；成功来源整体替换；从配置删除的
    // 来源不在 sources 里，自然丢弃（旧实现：任何源失败即全量替换 → 该源被清空）。
    let rank_of: std::collections::HashMap<String, u32> =
        sources.iter().map(|s| (s.tag.clone(), s.rank)).collect();
    let failed: Vec<String> = sources
        .iter()
        .filter(|s| !s.ok)
        .map(|s| s.tag.clone())
        .collect();
    let nodes: Vec<subscribe::ParsedNode> = sources
        .iter()
        .filter(|s| s.ok)
        .flat_map(|s| s.nodes.iter().cloned())
        .collect();
    let group_specs = cfg.as_ref().map(config::groups).unwrap_or_default();
    let specs: Vec<(String, Option<config::GroupSpec>)> = if group_specs.is_empty() {
        vec![("proxy".to_string(), None)]
    } else {
        group_specs
            .into_iter()
            .map(|g| (g.name.clone(), Some(g)))
            .collect()
    };
    let mut g = match lock.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let old_names: Vec<String> = g.groups.iter().map(|r| r.name.clone()).collect();
    let new_names: Vec<String> = specs.iter().map(|(n, _)| n.clone()).collect();
    if old_names == new_names {
        for (i, (name, spec)) in specs.iter().enumerate() {
            let filters = spec.as_ref().map(|s| s.filters.clone()).unwrap_or_default();
            // P0：失败来源的旧成员转回 ParsedNode，与成功来源一起过滤/排序。
            let mut all_nodes = nodes.clone();
            if !failed.is_empty() {
                for m in g.groups[i].clone_members_by_tag(&failed) {
                    let rank = rank_of.get(&m.tag).copied().unwrap_or(m.rank);
                    all_nodes.push(subscribe::ParsedNode {
                        name: m.name,
                        tag: m.tag,
                        rank,
                        outbound: m.outbound,
                    });
                }
            }
            let carried = all_nodes.len() - nodes.len();
            let members = group::build_members(&all_nodes, &filters);
            if members.is_empty() {
                log(&format!(
                    "订阅热更新：组 {name} filter 后无成员，保留旧成员"
                ));
                continue;
            }
            let (n, inherited) = g.groups[i].replace_members(members);
            // policy 也随 config 热应用（控制面板「手动切节点/恢复自动」靠这条即时生效）。
            let want = group::parse_policy(spec.as_ref().and_then(|s| s.policy.as_deref()));
            if *g.groups[i].policy() != want {
                log(&format!(
                    "订阅热更新：组 {name} policy -> {}",
                    group::policy_name(&want)
                ));
                g.groups[i].set_policy(want);
            }
            log(&format!(
                "订阅热更新：组 {name} {n} 成员（继承 {inherited} 健康{carried_note}）",
                carried_note = if carried > 0 {
                    format!("；沿用失败源 {carried} 成员")
                } else {
                    String::new()
                }
            ));
        }
    } else {
        log(&format!(
            "订阅热更新：组集合变更 {old_names:?} -> {new_names:?}，重建全部组（不继承健康）"
        ));
        // M1 修复：旧世代显式停探测线程（否则线程 + 成员集随配置编辑史无界累积，
        // 且旧世代会继续对废弃节点打探测——与 P37 额度治理冲突）。
        let stopped = g.groups.iter().filter(|old| !old.stopped()).count();
        for old in g.groups.iter() {
            old.stop();
        }
        if stopped > 0 {
            log(&format!(
                "组集合变更：已停止 {stopped} 个旧世代健康探测线程"
            ));
        }
        let mut groups = Vec::with_capacity(specs.len());
        let mut by_name = std::collections::HashMap::new();
        for (i, (name, spec)) in specs.iter().enumerate() {
            by_name.insert(name.clone(), i);
            groups.push(make_group_runtime(
                name,
                spec.as_ref(),
                &nodes,
                cfg.as_ref(),
            ));
        }
        let default_idx = select_default_group(&by_name, args);
        *g = GroupSet {
            groups,
            default_idx,
        };
    }
}

fn parse_check_target(u: &str) -> Option<(String, u16)> {
    let https = u.starts_with("https://");
    let s = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .unwrap_or(u);
    let authority = s.split('/').next().unwrap_or(s);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>().ok()?)
        }
        _ => (authority.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() || host.starts_with('[') || host.contains(']') {
        None
    } else {
        Some((host, port))
    }
}

fn parse_duration_secs(v: &str) -> Option<u64> {
    let t = v.trim().trim_end_matches('s').trim();
    t.parse().ok()
}

/// P33：带单位毫秒解析（"150ms" / "1s" / 裸数字=ms）。
fn parse_ms(v: &str) -> Option<u64> {
    let t = v.trim();
    if let Some(x) = t.strip_suffix("ms") {
        return x.trim().parse().ok();
    }
    if let Some(x) = t.strip_suffix('s') {
        return x.trim().parse::<u64>().ok().map(|s| s.saturating_mul(1000));
    }
    t.parse().ok()
}

/// P33：运行时参数热更新（reload/SIGHUP 时调用）。
/// 优先级与启动一致：CLI 显式值 > config global > 保持现值；仅变更时记日志。
fn apply_runtime_params(args: &Args, cfg: Option<&config::Config>) {
    let g = |k: &str| cfg.and_then(|c| config::global_value(c, k));

    let apply_secs = |key: &str, cli: Option<u64>, cur: &AtomicU64| {
        if let Some(v) = cli.or_else(|| g(key).and_then(|s| parse_duration_secs(&s))) {
            let old = cur.swap(v, Ordering::SeqCst);
            if old != v {
                log(&format!("热更新: {key} {old}s -> {v}s"));
            }
        }
    };
    apply_secs(
        "relay_idle_timeout",
        args.relay_idle_timeout,
        &RELAY_IDLE_SECS,
    );
    apply_secs("udp_idle_timeout", args.udp_idle_timeout, &UDP_IDLE_SECS);

    if let Some(v) = args
        .dial_timeout
        .or_else(|| g("dial_timeout").and_then(|s| parse_duration_secs(&s)))
    {
        let ms = v.saturating_mul(1000);
        let old = RELAY_DIAL_TIMEOUT_MS.swap(ms, Ordering::SeqCst);
        if old != ms {
            log(&format!("热更新: dial_timeout {}s -> {v}s", old / 1000));
        }
    }
    if let Some(v) = args
        .max_conns
        .or_else(|| g("max_conns").and_then(|s| s.trim().parse().ok()))
    {
        let old = RELAY_MAX_CONNS.swap(v, Ordering::SeqCst);
        if old != v {
            log(&format!("热更新: max_conns {old} -> {v}"));
        }
    }
    if let Some(m) = args.dial_mode.clone().or_else(|| g("dial_mode")) {
        let b = match m.as_str() {
            "domain" => 1u8,
            "domain+" | "domain++" => 2,
            _ => 0,
        };
        let old = DIAL_MODE.swap(b, Ordering::SeqCst);
        if old != b {
            log(&format!("热更新: dial_mode {} -> {m}", dial_mode_name(old)));
        }
    }
    if let Some(ms) = args
        .sniffing_timeout_ms
        .or_else(|| g("sniffing_timeout").and_then(|s| parse_ms(&s)))
    {
        let old = SNIFF_TIMEOUT_MS.swap(ms, Ordering::SeqCst);
        if old != ms {
            log(&format!("热更新: sniffing_timeout {old}ms -> {ms}ms"));
        }
    }
    let punt = args.sniff_punt
        || g("auto_sniff_punt")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes" | "on"))
            .unwrap_or(false);
    let old = SNIFF_PUNT.swap(punt, Ordering::SeqCst);
    if old != punt {
        log(&format!("热更新: sniff-punt {old} -> {punt}"));
    }
    // P35：热驱动兜底扫描间隔 / 订阅缓存 TTL（watch 线程常驻，读静态值）。
    if let Some(s) = args
        .watch_config
        .or_else(|| g("watch_config").and_then(|v| parse_duration_secs(&v)))
    {
        let old = CONFIG_WATCH_INTERVAL.swap(s, Ordering::SeqCst);
        if old != s {
            log(&format!("热更新: watch_config {old}s -> {s}s（兜底扫描）"));
        }
    }
    if let Some(s) = g("sub_cache_ttl").and_then(|v| parse_duration_secs(&v)) {
        let old = SUB_CACHE_TTL_SECS.swap(s, Ordering::SeqCst);
        if old != s {
            log(&format!("热更新: sub_cache_ttl {old}s -> {s}s"));
        }
    }
    // P37（B2）：失败源负缓存窗口（fast 重载对窗口内失败源不打网）。
    if let Some(s) = g("sub_fail_ttl").and_then(|v| parse_duration_secs(&v)) {
        let old = SUB_FAIL_TTL_SECS.swap(s, Ordering::SeqCst);
        if old != s {
            log(&format!("热更新: sub_fail_ttl {old}s -> {s}s"));
        }
    }
}

/// P33：配置观察线程——轮询 --config/--rules 及其 include 文件（mtime+size），
/// 变化则经状态面通道向主循环发 reload（同步等结果并记日志）。
/// P35：配置观察线程——inotify 目录级事件（毫秒级，事件名过滤 + 去抖）为主，
/// 慢速兜底扫描（`CONFIG_WATCH_INTERVAL`，网络 FS 无 inotify 时）为辅；
/// 快照 (mtime,size) 复核后发 **fast reload**（订阅节点走缓存，改顺序/开关源秒级生效）。
fn config_watch_loop(extra: Vec<std::path::PathBuf>, tx: std::sync::mpsc::Sender<status::MainMsg>) {
    type Snap = Vec<(std::path::PathBuf, Option<std::time::SystemTime>, u64)>;
    let snap = |paths: &[std::path::PathBuf]| -> Snap {
        paths
            .iter()
            .map(|p| {
                let md = std::fs::metadata(p).ok();
                (
                    p.clone(),
                    md.as_ref().and_then(|m| m.modified().ok()),
                    md.map(|m| m.len()).unwrap_or(0),
                )
            })
            .collect()
    };
    let sweep_secs = || CONFIG_WATCH_INTERVAL.load(Ordering::Relaxed).max(1);
    let mut watcher = match watch::DirWatcher::new() {
        Ok(w) => {
            CONFIG_WATCH_INOTIFY.store(true, Ordering::Relaxed);
            log(&format!(
                "config-watch: inotify 已启用（目录级事件 + {}ms 去抖；兜底扫描 {}s）",
                watch::DEBOUNCE.as_millis(),
                sweep_secs()
            ));
            Some(w)
        }
        Err(e) => {
            log(&format!(
                "config-watch: inotify 不可用（{e}），降级为 {}s 轮询",
                sweep_secs()
            ));
            None
        }
    };
    let mut prev: Snap = Vec::new();
    let mut prev_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut warned = false;
    loop {
        let mut paths = extra.clone();
        if let Some((c, _)) = CONFIG_STATE.lock().ok().and_then(|g| g.clone()) {
            paths.extend(c.files.iter().cloned());
        }
        if let Ok(g) = RULESET_FILES.lock() {
            paths.extend(g.iter().cloned());
        }
        paths.sort();
        paths.dedup();
        if paths.is_empty() {
            std::thread::sleep(std::time::Duration::from_secs(sweep_secs()));
            continue;
        }
        let paths_changed = paths != prev_paths;
        // 每轮重建监听集合（include 集合随配置变化）：目录 → 关心的文件名
        if let Some(w) = watcher.as_mut() {
            let mut targets: std::collections::HashMap<
                std::path::PathBuf,
                std::collections::HashSet<Vec<u8>>,
            > = std::collections::HashMap::new();
            for p in &paths {
                if let (Some(d), Some(n)) = (p.parent(), p.file_name()) {
                    targets
                        .entry(d.to_path_buf())
                        .or_default()
                        .insert(n.as_encoded_bytes().to_vec());
                }
            }
            w.set_targets(&targets);
            if w.watched_dirs() == 0 && !warned {
                log("config-watch: inotify 无可用 watch（max_user_watches 上限？），仅靠兜底扫描");
                warned = true;
            }
        }
        // 等事件（inotify）或兜底间隔；事件先经去抖静默窗口合并。
        let mut via_event = false;
        match watcher.as_mut() {
            Some(w) => {
                if w.wait(Some(std::time::Duration::from_secs(sweep_secs()))) {
                    w.settle();
                    via_event = true;
                }
            }
            None => std::thread::sleep(std::time::Duration::from_secs(sweep_secs())),
        }
        let cur = snap(&paths);
        // 路径集合变化（新 include / reload 改写）或首轮：只重建基线；
        // 其余情况与上次快照比对——inotify 只是加速器，正确性由快照保证。
        let changed = !paths_changed && !prev.is_empty() && cur != prev;
        prev = cur;
        prev_paths = paths.clone();
        if !changed {
            continue;
        }
        log(&format!(
            "config-watch: 检测到配置变更（{}）→ 自动 reload",
            if via_event { "inotify" } else { "兜底扫描" }
        ));
        let (rtx, rrx) = std::sync::mpsc::channel();
        if tx
            .send(status::MainMsg::Query {
                cmd: "reload-fast".into(),
                reply: rtx,
            })
            .is_err()
        {
            log("config-watch: 主循环已退出，观察线程结束");
            return;
        }
        match rrx.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(resp) => {
                let brief = serde_json::from_str::<serde_json::Value>(&resp)
                    .ok()
                    .map(|v| {
                        format!(
                            "ok={} match_sets={} error={}",
                            v.get("ok")
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "-".into()),
                            v.get("match_sets")
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "-".into()),
                            v.get("error")
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "null".into()),
                        )
                    })
                    .unwrap_or_else(|| resp.chars().take(120).collect());
                log(&format!("config-watch: 自动 reload 完成（{brief}）"));
            }
            Err(_) => log("config-watch: 自动 reload 超时（60s）"),
        }
        // reload 可能更新 include 集合：重取快照基线（避免 reload 自身触发循环）
        let mut paths2 = extra.clone();
        if let Some((c, _)) = CONFIG_STATE.lock().ok().and_then(|g| g.clone()) {
            paths2.extend(c.files.iter().cloned());
        }
        if let Ok(g) = RULESET_FILES.lock() {
            paths2.extend(g.iter().cloned());
        }
        paths2.sort();
        paths2.dedup();
        prev = snap(&paths2);
        prev_paths = paths2;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A2 #1：`--version`（对照 dae rootCmd.Version：版本 + 运行时/平台 + 许可三行；
    // 在任何加载之前处理，无需 root/配置）。git sha 由 build.rs 注入（尽力而为）。
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 2 && matches!(argv[1].as_str(), "--version" | "-V" | "version") {
        print_version();
        return Ok(());
    }
    // K3 子命令（不加载 eBPF、不需要 root）
    if argv.len() >= 2
        && matches!(
            argv[1].as_str(),
            "validate"
                | "export-config"
                | "export"
                | "extract-routing"
                | "dns-bench"
                | "status"
                | "reload"
                | "suspend"
                | "resume"
                | "metrics"
                | "sub-parse"
                | "sysdump"
                | "trace"
                | "completion"
                | "config-doc"
        )
    {
        return run_subcommand(&argv);
    }
    // I2：尽早提升 fd 上限（router/高并发场景；子命令路径不需要）
    raise_nofile_limit();
    let mut args = parse_args()?;
    // P35：配置是行为参数的唯一事实来源——先把 config global 回填到未显式给出的 CLI 项，
    // 再打开日志/建状态面（log_file/status_socket/watch_config/geodata_dir 均可写进 config）。
    let cfg_boot = args
        .config
        .as_ref()
        .and_then(|p| config::load(std::path::Path::new(p)).ok());
    let cfg_boot_val = |k: &str| cfg_boot.as_ref().and_then(|c| config::global_value(c, k));
    if args.log_file.is_none() {
        args.log_file = cfg_boot_val("log_file");
    }
    // P38：时间戳开关（CLI 显式关优先；否则 config global.disable_timestamp；扩展键，dae 无）。
    if !args.disable_timestamp {
        if let Some(v) = cfg_boot_val("disable_timestamp") {
            args.disable_timestamp = matches!(v.trim(), "true" | "1" | "yes" | "on" | "enable");
        }
    }
    LOG_TS_OFF.store(args.disable_timestamp, Ordering::Relaxed);
    if args.status_socket.is_none() {
        args.status_socket = cfg_boot_val("status_socket");
    }
    if args.watch_config.is_none() {
        args.watch_config = cfg_boot_val("watch_config").and_then(|v| parse_duration_secs(&v));
    }
    if args.geodata_dir.is_empty() {
        if let Some(v) = cfg_boot_val("geodata_dir") {
            args.geodata_dir = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    // 能力缺口 #3：接口清单也可来自 config（CLI 显式给出优先；逗号分隔，支持 glob 与
    // `wan_interface: auto`）。回填后主流程与 CLI 路径完全同构（含热插拔 watcher）。
    if !args.lan_given && !args.no_lan && args.dual.is_empty() {
        if let Some(v) = cfg_boot_val("lan_interface") {
            let list = split_iface_list(&v);
            if !list.is_empty() {
                log(&format!("lan_interface（config）: {}", list.join(", ")));
                args.lan = list;
            }
        }
    }
    if !args.wan_given && args.dual.is_empty() {
        if let Some(v) = cfg_boot_val("wan_interface") {
            let list = split_iface_list(&v);
            if !list.is_empty() {
                log(&format!("wan_interface（config）: {}", list.join(", ")));
                args.wan = list;
            }
        }
    }
    // A2 #6：日志级别（config global.log_level；非法值回落 info——对照 dae `logrus.ParseLevel`
    // 失败回落 InfoLevel）。分级为 best-effort：既有调用大多按 info 归类（见 ADR-0069 偏离）。
    if let Some(v) = cfg_boot_val("log_level") {
        match parse_log_level(&v) {
            Some(l) => LOG_LEVEL.store(l, Ordering::Relaxed),
            None => {
                LOG_LEVEL.store(3, Ordering::Relaxed);
                log(&format!(
                    "log_level '{v}' 非法，回落 info（off/error/warning/info/debug）"
                ));
            }
        }
    }
    // A2 #2：内建日志轮转参数（CLI；对照 dae `--logfile-maxsize`/`--logfile-maxbackups`）。
    if let Some(mb) = args.logfile_maxsize {
        LOG_MAX_SIZE_MB.store(mb, Ordering::Relaxed);
    }
    if let Some(n) = args.logfile_maxbackups {
        LOG_MAX_BACKUPS.store(n, Ordering::Relaxed);
    }
    if let Some(path) = &args.log_file {
        if open_log_file(path) {
            let _ = LOG_PATH.set(path.clone());
            log(&format!("log file: {path}"));
        } else {
            eprintln!("[sodama] 无法打开日志文件 {path}，继续用 stdout");
        }
    }
    if args.auto_config {
        if let Some(c) = &args.config {
            log(&format!(
                "默认配置: {c}（未给 --config/--rules，P34；订阅切换/顺序见 subscription_failover）"
            ));
        }
    }
    // A2 #6：global 生效面（本批落地 8 项 + 未项显式告警；见 ADR-0069）。
    apply_global_effective_knobs(cfg_boot.as_ref(), &args);
    // A2 #6：`auto_config_kernel_parameter`（写 ip_forward/forwarding/send_redirects +
    // `accept_ra`；sysctl 管理器登记期望值，被改回即纠正——见 `sysctl.rs`）。
    if global_on(cfg_boot.as_ref(), "auto_config_kernel_parameter") {
        auto_configure_kernel_parameters(&args);
    }
    // A2 #6：`disable_waiting_network`（默认 false = 启动先等网络就绪再拉订阅，
    // 对照 dae `waitForNetworkOnline`；超时/跳过都只告警不阻断启动）。
    if !global_on(cfg_boot.as_ref(), "disable_waiting_network") {
        wait_for_network(Duration::from_secs(30));
    }

    let _ = STARTED.set(Instant::now());
    TPROXY_PORT.store(args.tproxy_port as u32, Ordering::SeqCst);
    if let Some(raw) = args.dialer.clone().or_else(|| args.forward.clone()) {
        let dialer = outbound::parse(&raw)?;
        log(&format!("relay dialer: {}", dialer.name()));
        let _ = OUTBOUND.set(dialer);
    }
    // P33：运行参数可由 config global 提供（CLI 显式值优先）；
    // reload/SIGHUP 时以同口径热更新（见 apply_runtime_params）。
    if let Some(s) = args
        .relay_idle_timeout
        .or_else(|| cfg_boot_val("relay_idle_timeout").and_then(|v| parse_duration_secs(&v)))
    {
        RELAY_IDLE_SECS.store(s, Ordering::SeqCst);
    }
    if let Some(n) = args
        .max_conns
        .or_else(|| cfg_boot_val("max_conns").and_then(|v| v.trim().parse().ok()))
    {
        RELAY_MAX_CONNS.store(n, Ordering::SeqCst);
    }
    if let Some(s) = args
        .dial_timeout
        .or_else(|| cfg_boot_val("dial_timeout").and_then(|v| parse_duration_secs(&v)))
    {
        RELAY_DIAL_TIMEOUT_MS.store(s.saturating_mul(1000), Ordering::SeqCst);
    }
    if let Some(s) = args
        .udp_idle_timeout
        .or_else(|| cfg_boot_val("udp_idle_timeout").and_then(|v| parse_duration_secs(&v)))
    {
        UDP_IDLE_SECS.store(s, Ordering::SeqCst);
    }
    RELAY_SPLICE.store(args.splice, Ordering::SeqCst);
    tls::set_ktls_enabled(args.ktls);

    // P14：dial_mode（CLI > config global.dial_mode > ip）
    {
        let mut mode = args.dial_mode.clone();
        if mode.is_none() {
            if let Some(cfg_path) = &args.config {
                if let Ok(cfg) = config::load(std::path::Path::new(cfg_path)) {
                    mode = config::global_value(&cfg, "dial_mode");
                }
            }
        }
        let m = match mode.as_deref() {
            None | Some("ip") => 0u8,
            Some("domain") => 1,
            Some("domain+") | Some("domain++") => 2,
            Some(other) => {
                eprintln!("[sodama] 未知 dial_mode {other}，按 ip 处理");
                0
            }
        };
        DIAL_MODE.store(m, Ordering::SeqCst);
        if let Some(ms) = args
            .sniffing_timeout_ms
            .or_else(|| cfg_boot_val("sniffing_timeout").and_then(|v| parse_ms(&v)))
        {
            SNIFF_TIMEOUT_MS.store(ms, Ordering::SeqCst);
        }
        // P21：sniff-punt 开关（CLI --sniff-punt > config global.auto_sniff_punt > 关）。
        let mut punt = args.sniff_punt;
        if !punt {
            if let Some(cfg_path) = &args.config {
                if let Ok(cfg) = config::load(std::path::Path::new(cfg_path)) {
                    if let Some(v) = config::global_value(&cfg, "auto_sniff_punt") {
                        punt = matches!(v.as_str(), "true" | "1" | "yes" | "on");
                    }
                }
            }
        }
        SNIFF_PUNT.store(punt, Ordering::SeqCst);
        if punt {
            if m == 0 {
                log("sniff-punt: 已开启，但 dial_mode=ip 不嗅探 → 不生效（需 domain/domain+）");
            } else {
                log("sniff-punt: 嗅探命中域名后将在 relay 侧按规则重选出口（direct/block/组）");
            }
        }
        // P23：bootstrap resolver（解析 DNS 上游/订阅/节点域名；直连不经数据面）。
        // 必须在 build_groups（解析节点链接）之前配置。
        let mut boot = None;
        if let Some(cfg_path) = &args.config {
            if let Ok(cfg) = config::load(std::path::Path::new(cfg_path)) {
                boot = config::global_value(&cfg, "bootstrap_resolver");
                apply_dns_options(Some(&cfg)); // P23：dns 段选项
            }
        }
        match bootstrap::configure(boot.as_deref()) {
            Ok(()) => {
                if bootstrap::enabled() {
                    log(&format!(
                        "bootstrap resolver: {}",
                        boot.as_deref().unwrap_or("")
                    ));
                }
            }
            Err(e) => log(&format!("bootstrap resolver 配置失败（忽略）: {e}")),
        }
        if m != 0 {
            log(&format!(
                "dial_mode: {}（嗅探上限 {}ms；命中 SNI/Host 则域名交节点远端解析）",
                dial_mode_name(m),
                SNIFF_TIMEOUT_MS.load(Ordering::SeqCst)
            ));
        }
    }

    // P15/P19：无 --dialer/--forward 时，用订阅/节点/组构建全部组（规则按组名分派）。
    if OUTBOUND.get().is_none() {
        if let Some(dialer) = build_groups(&args) {
            let name = dialer.name();
            log(&format!("relay dialer: {name}"));
            let _ = OUTBOUND.set(dialer);
        }
    }

    // 对拍模式：只编译规则（不加载 eBPF、不需要 root）。
    // 注意：必须在 DNS 上游解析/日志之前返回，保持 stdout 逐字节可控。
    if let Some(path) = &args.compile_dump {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read rules {path}: {e}"))?;
        let geo = geodata_for(&args);
        let geo = geo.lock().unwrap();
        // P19：带 --config 时按真实组名映射编译（对拍不带组的夹具时行为不变）
        let cfg = args
            .config
            .as_ref()
            .and_then(|p| config::load(std::path::Path::new(p)).ok());
        let groups = group_index_map(cfg.as_ref());
        let compiled = rules::parse_and_compile_with_groups(&text, Some(&geo), &groups)
            .map_err(|e| format!("compile rules: {e}"))?;
        print!("{}", compiled.dump_parity());
        let _ = std::io::stdout().flush();
        return Ok(());
    }

    // P12：本地 SOCKS5 入口模式（浏览器/桌面测试；不加载 eBPF、不需要 root）。
    if let Some(listen) = args.listen_socks.clone() {
        return run_socks_server(&listen);
    }

    // P3a/P18a/P18c：DNS 上游集合与路由必须在 host ns 创建/编译（上游查询走宿主路由，
    // 不经 dae0/自己的钩子）；上游：CLI 优先，否则 config dns.upstream map。
    let ups = build_upstream_set(&args)?;
    {
        let tags: Vec<String> = ups.by_tag.keys().cloned().collect();
        log(&format!(
            "dns upstream: legacy={} scheme={} addr={} tags=[{}]",
            ups.legacy.url,
            ups.legacy.spec.scheme.name(),
            ups.legacy.addr(),
            tags.join(",")
        ));
    }
    set_upstreams(ups.clone());
    match build_dns_router(&args, &ups) {
        Ok(Some(r)) => {
            for n in &r.notes {
                log(&format!("dnsroute: {n}"));
            }
            log(&format!(
                "dns.routing: request {} 条 / response {} 条，fallback={:?}/{:?}",
                r.request_rule_lines, r.response_rule_lines, r.req_fallback, r.resp_fallback
            ));
            set_dns_router(Some(Arc::new(r)));
        }
        Ok(None) => set_dns_router(None),
        Err(e) => return Err(e),
    }

    // SIGHUP = 热重载（对照 dae `dae reload`）；SIGUSR2 = suspend（对照 dae suspend）
    unsafe {
        let handler: extern "C" fn(libc::c_int) = on_sighup;
        libc::signal(libc::SIGHUP, handler as *const () as libc::sighandler_t);
        let handler2: extern "C" fn(libc::c_int) = on_sigusr2;
        libc::signal(libc::SIGUSR2, handler2 as *const () as libc::sighandler_t);
        // O8：终止信号 → 主循环走有界收尾（不再直接默认杀死）。
        let handler3: extern "C" fn(libc::c_int) = on_shutdown;
        libc::signal(libc::SIGTERM, handler3 as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler3 as *const () as libc::sighandler_t);
    }

    log(&format!("loading {}", args.ebpf));
    let data =
        std::fs::read(&args.ebpf).map_err(|e| format!("read eBPF object {}: {e}", args.ebpf))?;
    // bpf_conn_state_map_size（dae 同名 global 键，默认 262144）：启动时生效。
    // 变更需重启（dae 在代次交接时重建 map；sodama 无代次交接——偏离见 ADR-0067）。
    let conn_state_size: u32 = args
        .config
        .as_ref()
        .and_then(|p| config::load(std::path::Path::new(p)).ok())
        .and_then(|cfg| config::global_value(&cfg, "bpf_conn_state_map_size"))
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| (1024..=4_194_304).contains(n))
        .unwrap_or(262_144);
    let mut loader = aya::EbpfLoader::new();
    loader.map_max_entries("conn_state_map", conn_state_size);
    let mut ebpf = loader.load(&data).map_err(|e| format!("Ebpf::load: {e}"))?;
    migrate_pinned_conn_state(&mut ebpf, conn_state_size);

    // P18c+：把 dns_sender_pname_map 的 fd dup 一份给 DNS 线程
    // （raw BPF_MAP_LOOKUP_ELEM；避免 DNS 线程持有 Ebpf 借用）。
    if let Some(map) = ebpf.map("dns_sender_pname_map") {
        use std::os::fd::{AsFd, AsRawFd};
        let raw = match map {
            aya::maps::Map::HashMap(md) => Some(md.fd().as_fd().as_raw_fd()),
            _ => None,
        };
        if let Some(raw) = raw {
            let dup = unsafe { libc::dup(raw) };
            if dup >= 0 {
                DNS_PNAME_MAP_FD.store(dup, Ordering::Relaxed);
                let _ = std::thread::Builder::new()
                    .name("dns-pname-gc".into())
                    .spawn(move || dns_pname_gc_loop(dup));
            }
        }
    }

    // C3：事件 ringbuf 消费线程（独立持 map，不与 Ebpf 其他 Reader 争借）。
    // 失败只降级到「事件丢失且可见日志」：blocked/overflow 等观测不参与转发决策。
    if let Some(md) = ebpf.take_map("event_ringbuf") {
        match RingBuf::<MapData>::try_from(md) {
            Ok(rb) => {
                if let Err(e) = std::thread::Builder::new()
                    .name("ebpf-events".into())
                    .spawn(move || ebpf_event_loop(rb))
                {
                    log(&format!(
                        "event_ringbuf: 消费线程创建失败（{e}），事件通道不可用"
                    ));
                }
            }
            Err(e) => log(&format!(
                "event_ringbuf: RingBuf 打开失败（{e}），事件通道不可用"
            )),
        }
    } else {
        log("event_ringbuf: 对象不含该 map，事件通道不可用");
    }

    // P19：把 conn_state_map 的 fd dup 一份给 relay/UDP 线程
    // （按 5 元组回读该连接选中的用户组；组索引由规则编译写入）。
    if let Some(map) = ebpf.map("conn_state_map") {
        use std::os::fd::{AsFd, AsRawFd};
        if let aya::maps::Map::HashMap(md) = map {
            let raw = md.fd().as_fd().as_raw_fd();
            let dup = unsafe { libc::dup(raw) };
            if dup >= 0 {
                CONN_STATE_MAP_FD.store(dup, Ordering::Relaxed);
            }
        }
    }
    if let Some(map) = ebpf.map("routing_handoff_map") {
        use std::os::fd::{AsFd, AsRawFd};
        if let aya::maps::Map::HashMap(md) = map {
            let raw = md.fd().as_fd().as_raw_fd();
            let dup = unsafe { libc::dup(raw) };
            if dup >= 0 {
                HANDOFF_MAP_FD.store(dup, Ordering::Relaxed);
            }
        }
    }
    // A2 #13：1h 流量历史采样线程（1s 周期；dae 的 daed API 口径）。
    if let Err(e) = std::thread::Builder::new()
        .name("traffic-hist".into())
        .spawn(traffic_history_loop)
    {
        log_warn(&format!("traffic: 历史采样线程创建失败（{e}）"));
    }
    // 出口连通性投影 map：交给 2s 投影循环持有（take 后 ebpf 不再持有）。
    // P38：取图后立即全量置 1（乐观初值）——map 零初始化 = 所有出口「死」，而
    // GROUP_SET 的就绪晚于本处（投影循环首轮可能 early return）：该窗口内新流首包
    // 会被门禁 SHOT（实测缺陷，见 `publish_outbound_connectivity` 注释）。
    if let Some(s) = ebpf.take_map("outbound_connectivity_map") {
        if let Ok(mut arr) = Array::<MapData, u32>::try_from(s) {
            for key in 0..CONNECTIVITY_MAP_SIZE {
                let _ = arr.set(key, 1, 0);
            }
            let _ = OUTBOUND_CONNECTIVITY.set(Mutex::new(arr));
            if let Err(e) = std::thread::Builder::new()
                .name("connectivity".into())
                .spawn(connectivity_loop)
            {
                log(&format!("connectivity: 投影循环创建失败（{e}）"));
            }
        }
    }

    let root_ns = OwnedFd::from(
        std::fs::File::open("/proc/self/ns/net")
            .map_err(|e| format!("open /proc/self/ns/net: {e}"))?,
    );
    let dae_ns = OwnedFd::from(
        std::fs::File::open(format!("/var/run/netns/{}", args.daens))
            .map_err(|e| format!("open /var/run/netns/{}: {e}", args.daens))?,
    );

    // ---------- 1) host netns：LAN ingress / WAN egress+ingress / dae0 ingress ----------
    let dae0_ifindex = if_nametoindex(&args.dae0)?;
    // 能力缺口 #3：接口懒绑定/热插拔（对照 dae `interface_manager.go`）。
    // 启动先展开现有接口（模式支持 glob；wan 支持 `auto` = 默认路由接口），
    // 不存在的（含显式点名）不报错——登记 watcher，出现后主循环自动补挂。
    let (wan_patterns, auto_notes) = ifwatch::expand_auto(&args.wan);
    for n in &auto_notes {
        log(&format!("iface: wan auto {n}"));
    }
    let mut specs: Vec<ifwatch::Spec> = Vec::new();
    for p in &args.lan {
        specs.push(ifwatch::Spec {
            role: ifwatch::Role::Lan,
            pattern: p.clone(),
        });
    }
    for p in &wan_patterns {
        specs.push(ifwatch::Spec {
            role: ifwatch::Role::Wan,
            pattern: p.clone(),
        });
    }
    for p in &args.dual {
        specs.push(ifwatch::Spec {
            role: ifwatch::Role::Dual,
            pattern: p.clone(),
        });
    }
    let existing = ifwatch::list_interfaces();
    for s in &specs {
        if !existing
            .iter()
            .any(|n| ifwatch::pattern_matches(&s.pattern, n))
        {
            log(&format!(
                "iface: {} 模式 \"{}\" 当前无匹配接口（懒绑定：出现后自动挂载）",
                s.role.tag(),
                s.pattern
            ));
        }
    }
    let mut ifwatch = ifwatch::IfWatch::new(specs);
    // 已按 L3 登记的接口：iface 名 → ifindex（消失时按此清理 `l3_ifindex_map`）。
    let mut l3_mounts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for (iface, roles) in ifwatch.initial() {
        for role in roles {
            if let Some(idx) = attach_role(&mut ebpf, &iface, role, args.link_hdr)? {
                l3_mounts.insert(iface.clone(), idx);
            }
        }
    }
    attach(
        &mut ebpf,
        "sodama0_ingress",
        &args.dae0,
        TcAttachType::Ingress,
    )?;

    // C4：XDP 计量探针（可选；仅计数、恒 XDP_PASS，不改变转发行为）
    attach_xdp_probes(&mut ebpf, &args.xdp)?;

    // P17b：pname 采集（cgroup2）。失败不致命（规则不命中，同 dae）。
    attach_pname_hooks(&mut ebpf);

    // ---------- 2) dae netns：dae0peer ingress + tproxy listener ----------
    setns(&dae_ns, libc::CLONE_NEWNET)?;
    log(&format!("entered netns {}", args.daens));
    let dae0peer_mac = read_mac(&args.dae0peer)?;

    let listener = make_transparent_listener(args.tproxy_port)?;
    {
        let map = ebpf
            .map_mut("listen_socket_map")
            .ok_or("map listen_socket_map not found")?;
        let mut sockmap: SockMap<_> = SockMap::try_from(map)?;
        sockmap.set(0, &listener, 0)?;
    }
    log(&format!(
        "tproxy listener registered: 0.0.0.0:{} (sockmap key 0)",
        args.tproxy_port
    ));

    // P16：IPv6 tproxy 监听（sockmap key 2）；IPv6 不可用/被禁用时降级为仅 v4。
    match make_transparent_listener6(args.tproxy_port) {
        Ok(l6) => {
            {
                let map = ebpf
                    .map_mut("listen_socket_map")
                    .ok_or("map listen_socket_map not found")?;
                let mut sockmap: SockMap<_> = SockMap::try_from(map)?;
                sockmap.set(2, &l6, 0)?;
            }
            log(&format!(
                "tproxy listener registered: [::]:{} (sockmap key 2, IPv6)",
                args.tproxy_port
            ));
            let accept6 = l6.try_clone()?;
            std::thread::spawn(move || serve(accept6));
        }
        Err(e) => log(&format!("IPv6 tproxy listener 未启用（降级为仅 v4）: {e}")),
    }

    // P3a：UDP tproxy/DNS 监听（sockmap key 1）。DNS 查询被数据面判为控制面时
    // 经 dae0peer ingress 交付到这里；IP_ORIGDSTADDR 用于回包源地址。
    let udp_listener = make_transparent_udp(args.tproxy_port)?;
    {
        let map = ebpf
            .map_mut("listen_socket_map")
            .ok_or("map listen_socket_map not found")?;
        let mut sockmap: SockMap<_> = SockMap::try_from(map)?;
        sockmap.set(1, &udp_listener, 0)?;
    }
    log(&format!(
        "dns udp listener registered: 0.0.0.0:{} (sockmap key 1)",
        args.tproxy_port
    ));

    // P22：IPv6 UDP/DNS 监听（sockmap key 3）；IPv6 不可用/被禁用时降级为仅 v4。
    let udp_listener6 = match make_transparent_udp6(args.tproxy_port) {
        Ok(l6) => {
            {
                let map = ebpf
                    .map_mut("listen_socket_map")
                    .ok_or("map listen_socket_map not found")?;
                let mut sockmap: SockMap<_> = SockMap::try_from(map)?;
                sockmap.set(3, &l6, 0)?;
            }
            log(&format!(
                "udp v6 listener registered: [::]:{} (sockmap key 3, IPv6)",
                args.tproxy_port
            ));
            Some(l6)
        }
        Err(e) => {
            log(&format!("IPv6 udp listener 未启用（降级为仅 v4）: {e}"));
            None
        }
    };

    attach(
        &mut ebpf,
        "sodama0peer_ingress",
        &args.dae0peer,
        TcAttachType::Ingress,
    )?;

    // accept 线程必须在本线程处于 dae netns 时创建（线程继承创建者的 netns）。
    let accept_listener = listener.try_clone()?;
    std::thread::spawn(move || serve(accept_listener));

    // ---------- 3) 回到 host netns，写配置与首版规则 ----------
    setns(&root_ns, libc::CLONE_NEWNET)?;
    log("back to host netns");

    {
        let map = ebpf
            .map_mut("config_map")
            .ok_or("map config_map not found")?;
        let mut config_map: Array<_, SodaConfig> = Array::try_from(map)?;
        let generation = init_datapath_generation();
        config_map.set(
            0,
            SodaConfig {
                tproxy_port: args.tproxy_port as u32,
                dae0_ifindex,
                datapath_generation: generation,
                dae0peer_mac,
                so_mark: outbound::SO_MARK_VALUE.load(Ordering::Relaxed),
            },
            0,
        )?;
    }
    log(&format!(
        "config: dae0 ifindex={dae0_ifindex}, dae0peer mac={:02x?}, generation={}",
        dae0peer_mac,
        current_datapath_generation()
    ));

    let initial = do_reload(&args, &mut ebpf, true, false);
    if !initial.ok {
        return Err(format!("初始规则下发失败: {}", initial.error.unwrap_or_default()).into());
    }
    // M1：eBPF 热路径调试打印门控（control_flags bit 1；默认关，`--ebpf-debug` 开）
    if let Err(e) = update_control_flag(&mut ebpf, FLAG_DEBUG, args.ebpf_debug) {
        log(&format!("eBPF debug flag 设置失败：{e}"));
    }
    let n = initial.match_sets;
    log(&format!("路由规则已下发给数据面（{n} 条 match_set）"));
    log("running; SIGHUP 重载规则 / SIGUSR2 挂起，Ctrl-C 退出");
    // I6：启动水位——规则编译/订阅/geodata/BPF 装载的分配高水位会留在分配器
    // 空闲链中；启动完成后立即回收一次，让常驻水位直接落低（不必等 30s 周期 trim）。
    trim_allocator();

    // 只读状态面：请求经 channel 交给主循环（唯一持有 Ebpf 的地方）处理
    let (status_tx, status_rx) = std::sync::mpsc::channel::<status::MainMsg>();
    if let Some(sock) = &args.status_socket {
        status::serve(Path::new(sock), status_tx.clone())?;
        log(&format!("status socket（只读）: {sock}"));
    }
    // P33：配置文件热驱动（可选）——轮询 --config/--rules 及其 include 文件，
    // 变更即向主循环发 reload（等价自动 SIGHUP）。
    if let Some(secs) = args.watch_config.filter(|s| *s > 0) {
        CONFIG_WATCH_INTERVAL.store(secs, Ordering::SeqCst);
        let mut extra: Vec<std::path::PathBuf> = Vec::new();
        if let Some(p) = &args.config {
            extra.push(std::path::PathBuf::from(p));
        }
        if let Some(p) = &args.rules {
            extra.push(std::path::PathBuf::from(p));
        }
        let wtx = status_tx.clone();
        std::thread::spawn(move || config_watch_loop(extra, wtx));
        log(&format!(
            "config-watch: 已启用（inotify 事件驱动 + {}s 兜底；变更即 fast reload）",
            secs
        ));
    }
    // P1（2026-10-11）：订阅读周期刷新（后台；默认 6h，见 global.subscription_update_interval）。
    spawn_subscription_scheduler(&args);
    let _keep_tx = status_tx;

    // P3a：DNS 线程在 host ns（回包直接从宿主接口发向客户端；监听 fd 来自 daens）。
    {
        let dns_tx = _keep_tx.clone();
        std::thread::spawn(move || dns_loop(udp_listener, dns_tx));
    }
    // P22：v6 UDP/DNS 线程（同一处理逻辑，orig_dst/回包走 v6）。
    if let Some(l6) = udp_listener6 {
        let dns_tx = _keep_tx.clone();
        std::thread::spawn(move || dns_loop(l6, dns_tx));
    }
    // P38：dns.bind —— 明文 DNS 监听（对照 dae `Dns.Bind`；供 AdGuard/mosdns 指上游）。
    // 启动生效；reload 改端点需重启（偏离见 ADR-0068）。
    if let Some(bind) = dns_bind_from_config(cfg_boot.as_ref()) {
        start_dns_bind(&bind, &_keep_tx);
    }

    // P3b-1：TCP DNS 处理线程（host ns）。accept 在 daens，连接经通道转交到这里；
    // 上游 TCP 连接在本线程（host ns）建立，走宿主路由（不经自己的钩子）。
    {
        let (tcp_dns_tx, tcp_dns_rx) = std::sync::mpsc::channel::<TcpStream>();
        let _ = TCP_DNS_TX.set(tcp_dns_tx);
        let tcp_tx = _keep_tx.clone();
        std::thread::spawn(move || tcp_dns_loop(tcp_dns_rx, tcp_tx));
    }

    // P4a：relay 线程池（host ns）：accept 在 daens，连接转交到这里；拨号出口
    // 从 host ns 发出（socket 打 SO_MARK，数据面据此跳过，不自环）。
    if OUTBOUND.get().is_some() {
        // P4c：先把 fast_sock 从 Ebpf 里取出并挂上 sk_skb verdict（relay 线程要用）
        if args.offload {
            let map_data = ebpf
                .take_map("fast_sock")
                .ok_or("map fast_sock not found（对象未包含 offload 支持？）")?;
            let sh: SockHash<MapData, SodaTuple> = SockHash::try_from(map_data)?;
            let fd = sh.fd().try_clone()?;
            {
                let prog: &mut SkSkb = ebpf
                    .program_mut("sodama_tcp_offload")
                    .ok_or("program sodama_tcp_offload not found")?
                    .try_into()?;
                prog.load()?;
                prog.attach(&fd)?;
            }
            let _ = RELAY_OFFLOAD.set(Mutex::new(sh));
            // P9：Rust 数据面自带 offload_guard（verdict 用它做预检镜像）
            if let Some(g) = ebpf.take_map("offload_guard") {
                if let Ok(guard) = HashMap::try_from(g) {
                    let _ = RELAY_OFFLOAD_GUARD.set(Mutex::new(guard));
                }
            }
            // 对标批：offload_sent 记账表（键摘除时由 relay/watchdog 汇总回收）
            if let Some(s) = ebpf.take_map("offload_sent") {
                if let Ok(sent) = PerCpuHashMap::<MapData, SodaTuple, u64>::try_from(s) {
                    let _ = OFFLOAD_SENT.set(Mutex::new(sent));
                }
            }
            // 背压 fuse 的 pause 表（键在 = 暂停内核拼接；看门狗 engage/lift）。
            if let Some(s) = ebpf.take_map("tcp_offload_pause") {
                if let Ok(p) = HashMap::<MapData, SodaTuple, u8>::try_from(s) {
                    let _ = OFFLOAD_PAUSE.set(Mutex::new(p));
                }
            }
            log("TCP offload 已启用（fast_sock + offload_guard + sk_skb/stream_verdict）");
            // 对标批：skb_send_sock 字节记账（fentry → kprobe 回退；需 BTF，失败仅降级计量）
            attach_offload_accounting(&mut ebpf);
        }
        let (relay_tx, relay_rx) = std::sync::mpsc::channel::<TcpStream>();
        let _ = TCP_RELAY_TX.set(relay_tx);
        std::thread::spawn(move || {
            for stream in relay_rx {
                // I6：固定 1 MiB 栈（默认 8 MiB）；创建失败仅丢弃该连接——
                // 旧行为是 spawn panic 打死分发线程（20k 连接 / cgroup pids 撞限场景曾复现）。
                let b = std::thread::Builder::new()
                    .name("relay".into())
                    .stack_size(RELAY_HANDLER_STACK);
                if let Err(e) = b.spawn(move || handle_relay_conn(stream)) {
                    log(&format!("relay: 会话线程创建失败（{e}），丢弃该连接"));
                }
            }
        });
        std::thread::spawn(relay_janitor_loop);
        std::thread::spawn(offload_watch_loop);
        log("relay 线程池已启动（host ns）");
        // M4：splice 数据面的 epoll worker 池（每连接 0 线程；仅字节透明链路）
        if RELAY_SPLICE.load(Ordering::Relaxed) {
            reactor::init();
        }
    }

    // P4b：UDP NAT janitor（无论是否启用 dialer 都在跑；只清扫非 DNS 的代理 UDP 会话）
    std::thread::spawn(udp_nat_janitor_loop);

    // P38：pid 文件（对照 dae）：就绪后写 /var/run/sodama.pid；`--disable-pidfile` 跳过写；
    // 退出清理无条件执行（与 dae 一致）；写失败静默（/var/run 不可写不影响主流程）。
    write_pidfile(args.disable_pidfile);
    // A2 #18：`Type=notify` 就绪上报（规则已下发、监听已就绪、pid 已写）。
    sd_notify("READY=1\nSTATUS=sodama ready (rules loaded)");

    // 主循环：状态查询 + 检查重载标志 + 定期清扫 conn_state
    // O8：50ms tick 一并发控：SIGTERM 检测/热重载响应更快（20 次/s 空转可忽略）。
    let mut ticks: u64 = 0;
    let tick = Duration::from_millis(50);
    let janitor_ticks = (JANITOR_INTERVAL.as_millis() / tick.as_millis()).max(1) as u64;
    // 2026-10-20 生产轮：routing_handoff 清扫周期 60s（满表时全遍历一次；
    // 稳态条目少，成本随之下降。与 conn_state/redirect_track 的 5s 节拍分开）。
    let handoff_ticks = (Duration::from_secs(60).as_millis() / tick.as_millis()).max(1) as u64;
    // 能力缺口 #3：热插拔扫描间隔（1s）。扫描成本 = 读 /sys/class/net 目录名 + 模式匹配。
    let ifwatch_ticks = (Duration::from_secs(1).as_millis() / tick.as_millis()).max(1) as u64;
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            graceful_shutdown();
        }
        match status_rx.recv_timeout(tick) {
            Ok(status::MainMsg::Query { cmd, reply }) => {
                let resp = handle_status_query(&cmd, &mut ebpf, &args);
                let _ = reply.send(resp);
            }
            Ok(status::MainMsg::DnsPublish { updates }) => {
                if let Err(e) = publish_domain_bits(&mut ebpf, &updates) {
                    // A2 #11：入重试堆（对照 dae 的投影重试任务堆），主循环 tick 消费。
                    log_warn(&format!("domain_routing_map 写入失败: {e}（已排入重试）"));
                    publish_enqueue_retry(updates);
                }
            }
            Err(_) => {}
        }
        if SUSPEND_REQ.swap(false, Ordering::SeqCst) {
            match set_suspend(&mut ebpf, true) {
                Ok(()) => {
                    SUSPENDED.store(true, Ordering::SeqCst);
                    log("已挂起（no-load，全部流量 fail-open）；reload 或 SIGHUP 恢复");
                }
                Err(e) => log(&format!("suspend 失败: {e}")),
            }
        }
        if RELOAD.swap(false, Ordering::SeqCst) {
            reopen_log();
            sd_notify("RELOADING=1");
            do_reload(&args, &mut ebpf, false, false);
            sd_notify("READY=1\nSTATUS=sodama reloaded");
        }
        // A2 #3：trace 会话到期（清数据面过滤器位；未激活时是一次原子读）。
        trace_maybe_expired(&mut ebpf);
        // A2 #11：投影重试堆消费（空队列时是一次加锁读）。
        publish_retry_tick(&mut ebpf);
        ticks += 1;
        if ticks.is_multiple_of(janitor_ticks) {
            match sweep_conn_state(&mut ebpf) {
                Ok(0) => {}
                Ok(n) => log(&format!("conn_state janitor: 清理 {n} 条过期状态")),
                Err(e) => log(&format!("conn_state janitor 失败: {e}")),
            }
            match sweep_redirect_track(&mut ebpf) {
                Ok((0, _)) => {}
                Ok((n, _)) => log(&format!("redirect_track janitor: 清理 {n} 条过期回程绑定")),
                Err(e) => log(&format!("redirect_track janitor 失败: {e}")),
            }
            // O8：每 30s 回收分配器空闲页（churn 后 RSS 回落；避免高频 trim 抖动）。
            if (ticks / janitor_ticks).is_multiple_of(6) {
                trim_allocator();
            }
        }
        // 2026-10-20 生产轮：routing_handoff 过期条目清理（60s；主路径不依赖，
        // 但满表后首包兜底失效——见 `sweep_routing_handoff` 注释）。
        if ticks.is_multiple_of(handoff_ticks) {
            match sweep_routing_handoff(&mut ebpf) {
                Ok((0, _)) => {}
                Ok((n, total)) => log(&format!(
                    "routing_handoff janitor: 清理 {n} 条过期首包交接（清理前 {total} 条）"
                )),
                Err(e) => log(&format!("routing_handoff janitor 失败: {e}")),
            }
        }
        // 能力缺口 #3：接口热插拔（新增补挂 / 消失清理；对照 dae interface_manager）
        if ticks.is_multiple_of(ifwatch_ticks) {
            let (added, removed) = ifwatch.poll();
            for (iface, roles) in added {
                for role in roles {
                    match attach_role(&mut ebpf, &iface, role, args.link_hdr) {
                        Ok(idx) => {
                            if let Some(idx) = idx {
                                l3_mounts.insert(iface.clone(), idx);
                            }
                            log(&format!(
                                "hotplug: 接口 {iface} 出现 → 已挂 {} 钩子",
                                role.tag()
                            ));
                        }
                        Err(e) => log(&format!(
                            "hotplug: 接口 {iface} 挂 {} 钩子失败: {e}",
                            role.tag()
                        )),
                    }
                }
            }
            for iface in removed {
                if let Some(idx) = l3_mounts.remove(&iface) {
                    if let Err(e) = unregister_l3_ifindex(&mut ebpf, idx) {
                        log(&format!(
                            "hotplug: 接口 {iface} 的 l3_ifindex_map 清理失败: {e}"
                        ));
                    }
                }
                if let Ok(mut hooks) = HOOKS.lock() {
                    hooks.retain(|h| !h.ends_with(&format!("@{iface}")));
                }
                log(&format!(
                    "hotplug: 接口 {iface} 消失 → 已记账（TCX 钩子随 netdev 注销由内核回收）"
                ));
            }
        }
    }
}

/// O8：周期性把 glibc arena 空闲内存归还内核（churn 后 RSS 平台回落；多线程安全）。
#[cfg(target_env = "gnu")]
fn trim_allocator() {
    unsafe {
        libc::malloc_trim(0);
    }
}
// 边界（如实）：musl 的 malloc 没有 malloc_trim，释放后不归还内核页。
// 实测过换 mimalloc（每线程堆 + mi_collect 显式归还）：用户态很省且 RSS 会回落，
// 但 daemon 侧（50+ 线程 → 每线程堆/段）反而更高（66–87MB vs musl 37.8–50MB），
// 故保留系统分配器，不引入 mimalloc。
#[cfg(not(target_env = "gnu"))]
fn trim_allocator() {}

/// P38：pid 文件路径（与 dae `/var/run/dae.pid` 同口径）。
const PID_FILE_PATH: &str = "/var/run/sodama.pid";

/// 写 pid 文件（disabled=true 跳过）。best-effort：失败静默（对照 dae `_ = os.WriteFile`）。
fn write_pidfile(disabled: bool) {
    if disabled {
        return;
    }
    let _ = write_pidfile_at(Path::new(PID_FILE_PATH), std::process::id());
}

fn write_pidfile_at(path: &Path, pid: u32) -> std::io::Result<()> {
    std::fs::write(path, pid.to_string())
}

/// 删除 pid 文件（无条件；对照 dae 的 defer，不因 --disable-pidfile 跳过）。
fn remove_pidfile() {
    let _ = std::fs::remove_file(PID_FILE_PATH);
}

/// O8：优雅退出——有界等待在途连接收尾（≤300ms），随后退出。
/// 数据面钩子是 TCX bpf_link：fd 随进程关闭由内核原子摘除，不残留过滤器（不会黑洞）。
// ---------------------------------------------------------------- A2 #18：sd_notify
/// `sd_notify(3)` 的最小实现（不引入依赖）：向 `$NOTIFY_SOCKET` 发一条状态行。
/// systemd 单元的 `Type=notify` 依赖它；无该环境变量（非 systemd 启动/命令行调试）时是
/// 静默 no-op。抽象 socket（名字以 `@` 开头）= 首字节 NUL 的 Linux 抽象地址。
fn sd_notify(state: &str) {
    let Some(sock) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let name = sock.to_string_lossy().to_string();
    let mut addr: Vec<u8> = if let Some(rest) = name.strip_prefix('@') {
        let mut v = vec![0u8];
        v.extend_from_slice(rest.as_bytes());
        v
    } else {
        name.as_bytes().to_vec()
    };
    addr.truncate(107); // sockaddr_un.sun_path 上限（含 NUL 结束位）
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return;
    }
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in addr.iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + addr.len()) as libc::socklen_t;
    let _ = unsafe {
        libc::sendto(
            fd,
            state.as_ptr() as *const libc::c_void,
            state.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            len,
        )
    };
    let _ = unsafe { libc::close(fd) };
}

fn graceful_shutdown() -> ! {
    let t0 = std::time::Instant::now();
    let active = RELAY_STATS.conns_active.load(Ordering::Relaxed);
    log(&format!(
        "收到终止信号，优雅退出（在途 relay {active} 条，等待 ≤300ms）…"
    ));
    let deadline = t0 + Duration::from_millis(300);
    while std::time::Instant::now() < deadline
        && RELAY_STATS.conns_active.load(Ordering::Relaxed) > 0
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    log(&format!(
        "退出完成：{} ms（在途 relay {} 条）",
        t0.elapsed().as_millis(),
        RELAY_STATS.conns_active.load(Ordering::Relaxed)
    ));
    sd_notify("STOPPING=1");
    remove_pidfile();
    std::process::exit(0);
}

// ---------------------------------------------------------------- P3a：DNS（UDP 接管）

const IP_TRANSPARENT_OPT: libc::c_int = 19;
/// IP_ORIGDSTADDR 与 IP_RECVORIGDSTADDR 同值（linux/in.h）。
const IP_ORIGDSTADDR_OPT: libc::c_int = 20;
/// P22：IPV6_TRANSPARENT（linux/in6.h）；IPV6_RECVORIGDSTADDR 与 IPV6_ORIGDSTADDR 同值。
const IPV6_TRANSPARENT_OPT: libc::c_int = 75;
const IPV6_ORIGDSTADDR_OPT: libc::c_int = 74;

fn set_int_opt(
    fd: RawFd,
    level: libc::c_int,
    opt: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// v4/v6 通用 sockaddr 构造：返回 (storage, 长度)。
fn sockaddr_any_of(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(a) => {
            let sin = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            (
                st,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(a) => {
            let sin6 = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr.s6_addr = a.ip().octets();
            sin6.sin6_scope_id = a.scope_id();
            (
                st,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn sockaddr_to_std(st: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match st.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(st as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::from(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                u16::from_be(sin.sin_port),
            )))
        }
        // P22：UDP v6 回包/客户端地址
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(st as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::from(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                0,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// P38：原始 UDP 发送（对照 dae `raw_udp_linux.go`）：AF_INET/AF_INET6 + SOCK_RAW +
/// IPPROTO_UDP，IP_TRANSPARENT + SO_MARK，bind 到伪造源 IP（端口由我们自己构造在 UDP 头里），
/// 自构 UDP 头 + 伪头校验和。每次调用新建/关闭 fd（仅 DNS 回注兑底路径，频率极低）。
fn raw_udp_send(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    // 上限：65535 - 20（IPv4 头）- 8（UDP 头）；v6 同理保守。
    if payload.len() > 65507 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "raw udp: 载荷超过 65507",
        ));
    }
    if from.is_ipv4() != to.is_ipv4() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "raw udp: 源/目标地址族不一致",
        ));
    }
    let v6 = from.is_ipv6();
    let (af, proto, transparent) = if v6 {
        (libc::AF_INET6, libc::IPPROTO_UDP, IPV6_TRANSPARENT_OPT)
    } else {
        (libc::AF_INET, libc::IPPROTO_UDP, IP_TRANSPARENT_OPT)
    };
    let raw = unsafe { libc::socket(af, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_int_opt(
        fd.as_raw_fd(),
        if v6 {
            libc::IPPROTO_IPV6
        } else {
            libc::IPPROTO_IP
        },
        transparent,
        1,
    )?;
    // SO_MARK（与 dae 同语义：避开自己的钩子；失败不致命；值可配 `so_mark_from_dae`）。
    let _ = set_int_opt(
        fd.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_MARK,
        outbound::SO_MARK_VALUE.load(Ordering::Relaxed) as libc::c_int,
    );
    // bind 伪造源 IP（端口用 0：端口写在自构 UDP 头里；对照 dae 只绑地址）。
    let (st, len) = sockaddr_any_of(from);
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &st as *const _ as *const libc::sockaddr,
            len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // 自构 UDP 头 + 校验和。
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.extend_from_slice(&from.port().to_be_bytes());
    pkt.extend_from_slice(&to.port().to_be_bytes());
    pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // 校验和占位
    pkt.extend_from_slice(payload);
    let ck = udp_checksum(from.ip(), to.ip(), &pkt);
    pkt[6..8].copy_from_slice(&ck.to_be_bytes());
    let (dst, dlen) = sockaddr_any_of(to);
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dst as *const _ as *const libc::sockaddr,
            dlen,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// P38：UDP 校验和（含伪头；v4/v6 自动分流；一对一行转，回卷到 0 时转 0xffff）。
pub(crate) fn udp_checksum(src: std::net::IpAddr, dst: std::net::IpAddr, udp_packet: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |b: &[u8]| {
        let mut i = 0;
        while i + 1 < b.len() {
            sum = sum.wrapping_add(u16::from_be_bytes([b[i], b[i + 1]]) as u32);
            i += 2;
        }
        if i < b.len() {
            sum = sum.wrapping_add((b[i] as u32) << 8);
        }
    };
    match (src, dst) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
            add(&s.octets());
            add(&d.octets());
            add(&[0, libc::IPPROTO_UDP as u8]);
            add(&(udp_packet.len() as u16).to_be_bytes());
        }
        (std::net::IpAddr::V6(s), std::net::IpAddr::V6(d)) => {
            add(&s.octets());
            add(&d.octets());
            add(&(udp_packet.len() as u32).to_be_bytes());
            add(&[0, 0, 0, libc::IPPROTO_UDP as u8]);
        }
        _ => return 0,
    }
    add(udp_packet);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let r = !(sum as u16);
    if r == 0 {
        0xffff
    } else {
        r
    }
}

/// UDP 透明 socket（P22 起支持 v4/v6）。
fn new_udp_socket(family: libc::c_int) -> std::io::Result<OwnedFd> {
    let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if family == libc::AF_INET6 {
        set_int_opt(fd.as_raw_fd(), libc::IPPROTO_IPV6, IPV6_TRANSPARENT_OPT, 1)?;
    } else {
        set_int_opt(fd.as_raw_fd(), libc::IPPROTO_IP, IP_TRANSPARENT_OPT, 1)?;
    }
    set_int_opt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    // O7：UDP 突发/高 PPS 下默认收发缓冲（~212KB）会先丢包；失败不致命（内核会按 rmem_max 截断）。
    let _ = set_int_opt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, 8 << 20);
    let _ = set_int_opt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, 8 << 20);
    Ok(fd)
}

fn bind_udp(fd: &OwnedFd, addr: SocketAddr) -> std::io::Result<()> {
    let (st, len) = sockaddr_any_of(addr);
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &st as *const _ as *const libc::sockaddr,
            len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 透明 UDP 监听（在 daens 创建）：接收被 `bpf_sk_assign` 交付的 DNS，
/// 并用 IP_ORIGDSTADDR 取回原始目的地址（回包源地址/端口要一致）。
fn make_transparent_udp(port: u16) -> std::io::Result<OwnedFd> {
    let fd = new_udp_socket(libc::AF_INET)?;
    set_int_opt(fd.as_raw_fd(), libc::IPPROTO_IP, IP_ORIGDSTADDR_OPT, 1)?;
    bind_udp(
        &fd,
        SocketAddr::from(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            port,
        )),
    )?;
    Ok(fd)
}

/// P22：IPv6 透明 UDP 监听（sockmap key 3）。V6ONLY + IPV6_RECVORIGDSTADDR；
/// 接收被 `bpf_sk_assign` 交付的 v6 DNS 与普通 UDP。
fn make_transparent_udp6(port: u16) -> std::io::Result<OwnedFd> {
    let fd = new_udp_socket(libc::AF_INET6)?;
    set_int_opt(fd.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    set_int_opt(fd.as_raw_fd(), libc::IPPROTO_IPV6, IPV6_ORIGDSTADDR_OPT, 1)?;
    bind_udp(
        &fd,
        SocketAddr::from(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            port,
            0,
            0,
        )),
    )?;
    Ok(fd)
}

/// 回包 socket：绑定原始目的地址（IP_TRANSPARENT/IPV6_TRANSPARENT），源地址/端口与客户端预期一致。
fn make_transparent_udp_bound(addr: SocketAddr) -> std::io::Result<OwnedFd> {
    let fd = new_udp_socket(if addr.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    })?;
    bind_udp(&fd, addr)?;
    Ok(fd)
}

fn send_to_udp(fd: RawFd, to: SocketAddr, data: &[u8]) -> std::io::Result<()> {
    let (st, len) = sockaddr_any_of(to);
    let rc = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &st as *const _ as *const libc::sockaddr,
            len,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// O7：同一客户端地址批量回包（sendmmsg；回复 socket 绑定原始目的地址、不 connect）。
/// A2 #17：UDP GSO（`UDP_SEGMENT`）聚合发送计数与能力探测。
/// 对照 dae `anyfrom_pool.go` 的 GSO 路径：同目的、**等长**的多个数据报可以拼成
/// 一个大 buffer + `UDP_SEGMENT=<单段长>` cmsg，由内核切分成 N 个数据报（一次 syscall）。
/// 内核不支持（`UDP_SEGMENT` setsockopt 失败）时自动回落逐报发送（一次性告警）。
static UDP_GSO_SENDS: AtomicU64 = AtomicU64::new(0);
static UDP_GSO_DATAGRAMS: AtomicU64 = AtomicU64::new(0);
static UDP_GSO_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
const UDP_SEGMENT_OPT: libc::c_int = 103;

/// GSO 聚合发送：`datas` 必须同目的、等长（调用方保证）；成功返回 `true`。
/// 单次上限 `UDP_MAX_SEGMENTS`（对照内核 gso_max_size 的保守值：64 段 × 单段 ≤ 64KB 内）。
///
/// ⚠ 两个已踩过的内核行为（2026-10-17 实测，勿回退）：
///   1. cmsg 自体即可工作——**无需**任何 `setsockopt(UDP_SEGMENT, …)` 前置
///      （实测：零 setsockopt 下 12 B + SCM seg=4 → 3×4 B 数据报）。
///   2. `setsockopt(UDP_SEGMENT, 1)` 不是「能力探测」而是把 socket 级默认
///      `gso_size` 设为 1：此后该 socket 上**一切普通发送**（sendto/sendmmsg）
///      直接 EINVAL（实测）。A2 批次 5 曾用该探测，造成 UDP 回复路径在
///      ≥10k pps 触发批次发送后被永久污染（回程全灭事故根因）——禁止再引入。
fn send_gso_udp(fd: RawFd, to: SocketAddr, datas: &[&[u8]]) -> std::io::Result<bool> {
    const UDP_MAX_SEGMENTS: usize = 64;
    if datas.len() < 2 {
        return Ok(false);
    }
    if UDP_GSO_UNSUPPORTED.load(Ordering::Relaxed) {
        return Ok(false);
    }
    let seg_len = datas[0].len();
    if seg_len == 0 || seg_len > u16::MAX as usize || datas.iter().any(|d| d.len() != seg_len) {
        return Ok(false);
    }
    let n = datas.len().min(UDP_MAX_SEGMENTS);
    let (st, name_len) = sockaddr_any_of(to);
    let mut payload: Vec<u8> = Vec::with_capacity(seg_len * n);
    for d in datas.iter().take(n) {
        payload.extend_from_slice(d);
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    // cmsg：UDP_SEGMENT = 单段长度（u16）。msg_controllen 必须先设好：
    // glibc CMSG_FIRSTHDR 以 msg_controllen >= sizeof(cmsghdr) 作为取头前提，
    // 置 0 时恒返回 NULL（旧实现由此恒走回落，GSO 从未真正发出过）。
    //
    // 可移植性（musl 交叉构建）：`libc::msghdr` 在 musl 下 `msg_controllen` 是 `u32`
    // 且含私有填充字段（`__pad1`/`__pad2`）——不能结构体字面量构造。统一用
    // `zeroed()` + `as _` 赋值，字段类型交编译期推导（glibc usize / musl u32 均成立）。
    #[repr(align(8))]
    struct Ctl([u8; 64]);
    let mut ctl = Ctl([0u8; 64]);
    let cmsg_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    if cmsg_len > ctl.0.len() {
        return Ok(false);
    }
    // SAFETY：`msghdr` 全零 + 逐字段赋有效值（iov / control 缓冲区生命周期覆盖 sendmsg 调用）。
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = &st as *const _ as *mut libc::c_void;
    hdr.msg_namelen = name_len as _;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1 as _;
    hdr.msg_control = ctl.0.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = cmsg_len as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        if cmsg.is_null() {
            return Ok(false);
        }
        (*cmsg).cmsg_level = libc::SOL_UDP as _;
        (*cmsg).cmsg_type = UDP_SEGMENT_OPT as _;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut u16;
        *data = seg_len as u16;
    }
    let rc = unsafe { libc::sendmsg(fd, &hdr, 0) };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        // EMSGSIZE/EINVAL：内核/网卡拒绝该 GSO 尺寸 → 回落逐报（非致命）。
        return match e.raw_os_error() {
            Some(libc::EMSGSIZE) | Some(libc::EINVAL) => Ok(false),
            Some(libc::EOPNOTSUPP) => {
                if !UDP_GSO_UNSUPPORTED.swap(true, Ordering::Relaxed) {
                    log_warn("udp GSO: 内核不支持 UDP_SEGMENT，回落逐报发送");
                }
                Ok(false)
            }
            _ => Err(e),
        };
    }
    UDP_GSO_SENDS.fetch_add(1, Ordering::Relaxed);
    UDP_GSO_DATAGRAMS.fetch_add(n as u64, Ordering::Relaxed);
    Ok(true)
}

fn send_batch_to_udp(fd: RawFd, to: SocketAddr, datas: &[&[u8]]) -> std::io::Result<()> {
    if datas.is_empty() {
        return Ok(());
    }
    if datas.len() == 1 {
        return send_to_udp(fd, to, datas[0]);
    }
    // A2 #17：先试 GSO 聚合（同目的等长 ≥2 报 → 一次 syscall 内核切分）；
    // 内核不支持/尺寸被拒 → 回落 sendmmsg（保持原行为）。
    if datas.len() >= 2 && send_gso_udp(fd, to, datas)? {
        return Ok(());
    }
    const MAX: usize = 64;
    let n = datas.len().min(MAX);
    let (st, name_len) = sockaddr_any_of(to);
    let mut iovecs: [libc::iovec; MAX] = unsafe { std::mem::zeroed() };
    let mut names: [libc::sockaddr_storage; MAX] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; MAX] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        names[i] = st;
        iovecs[i] = libc::iovec {
            iov_base: datas[i].as_ptr() as *mut libc::c_void,
            iov_len: datas[i].len(),
        };
        msgs[i].msg_hdr.msg_name = &mut names[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen = name_len;
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    let mut done = 0usize;
    while done < n {
        let rc = unsafe {
            libc::sendmmsg(
                fd,
                msgs.as_mut_ptr().add(done),
                (n - done) as libc::c_uint,
                0,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => break,
                _ => return Err(e),
            }
        }
        if rc == 0 {
            break;
        }
        done += rc as usize;
    }
    Ok(())
}

/// L1 加固：cmsg 解析缓冲显式 8 字节对齐（`CMSG_DATA` 会强转 `sockaddr_in/in6` 并解引用；
/// 与 ktls 路径的 `Ctl` 同范式，避免 `[u8; N]` 仅 align-1 的形式 UB）。
#[repr(align(8))]
#[derive(Clone, Copy)]
struct CtlBuf([u8; 128]);

/// 收一个 UDP 报文，返回 (长度, 客户端地址, 原始目的地址)。
#[allow(dead_code)] // A/B 与降级路径保留
fn recv_with_orig_dst(
    fd: RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut control = CtlBuf([0u8; 128]);
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    // P7：msg_controllen 在 glibc 是 usize、musl 是 u32（socklen_t），用 as _ 适配。
    msg.msg_controllen = control.0.len() as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let client = sockaddr_to_std(&name).ok_or_else(|| std::io::Error::other("bad peer addr"))?;
    let orig = orig_dst_from_cmsgs(&msg)?;
    Ok((n as usize, client, orig))
}

/// 从 msghdr 的 cmsg 链里取原始目的地址（v4 IP_ORIGDSTADDR / v6 IPV6_ORIGDSTADDR）。
fn orig_dst_from_cmsgs(msg: &libc::msghdr) -> std::io::Result<SocketAddr> {
    let mut orig: Option<SocketAddr> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let c = &*cmsg;
            if c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == IP_ORIGDSTADDR_OPT {
                let sa = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let a4 = &*sa;
                orig = Some(SocketAddr::from(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from(u32::from_be(a4.sin_addr.s_addr)),
                    u16::from_be(a4.sin_port),
                )));
            } else if c.cmsg_level == libc::IPPROTO_IPV6 && c.cmsg_type == IPV6_ORIGDSTADDR_OPT {
                // P22：v6 原始目的地址（IPV6_RECVORIGDSTADDR）
                let sa = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let a6 = &*sa;
                orig = Some(SocketAddr::from(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(a6.sin6_addr.s6_addr),
                    u16::from_be(a6.sin6_port),
                    0,
                    a6.sin6_scope_id,
                )));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    orig.ok_or_else(|| std::io::Error::other("缺少 IP_ORIGDSTADDR（setsockopt 未生效？）"))
}

/// O7：UDP 监听批量收（recvmmsg + IP_ORIGDSTADDR）。
/// 首包阻塞，`MSG_WAITFORONE` 之后非阻塞排空——与逐包语义一致，只是每次 syscall 多收。
struct UdpRecvBatch {
    slots: Vec<Vec<u8>>,
    names: Vec<libc::sockaddr_storage>,
    ctrls: Vec<CtlBuf>,
    /// P38：持有所有权——`msgs[i].msg_hdr.msg_iov` 指向该 Vec 的元素，
    /// 释放会让指针悬垂（字段本意“不读但必须活”）。
    #[allow(dead_code)]
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    max: usize,
}

impl UdpRecvBatch {
    fn new(max: usize) -> Self {
        let max = max.max(1);
        let mut slots: Vec<Vec<u8>> = (0..max).map(|_| vec![0u8; 65536]).collect();
        let mut names: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; max];
        let mut ctrls: Vec<CtlBuf> = vec![CtlBuf([0u8; 128]); max];
        // 预先取堆指针（Vec 移动不改变堆地址），后续不再 realloc。
        let names_ptr = names.as_mut_ptr();
        let ctrls_ptr = ctrls.as_mut_ptr();
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(max);
        for s in slots.iter_mut() {
            iovecs.push(libc::iovec {
                iov_base: s.as_mut_ptr() as *mut libc::c_void,
                iov_len: s.len(),
            });
        }
        let iovecs_ptr = iovecs.as_mut_ptr();
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(max);
        for i in 0..max {
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            // SAFETY：names/ctrls/iovecs 容量固定且不再扩容，指针在结构生命周期内有效。
            m.msg_hdr.msg_name = unsafe { names_ptr.add(i) as *mut libc::c_void };
            m.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            m.msg_hdr.msg_iov = unsafe { iovecs_ptr.add(i) };
            m.msg_hdr.msg_iovlen = 1;
            m.msg_hdr.msg_control = unsafe { ctrls_ptr.add(i) as *mut libc::c_void };
            m.msg_hdr.msg_controllen = ctrls[i].0.len() as _;
            msgs.push(m);
        }
        UdpRecvBatch {
            slots,
            names,
            ctrls,
            iovecs,
            msgs,
            max,
        }
    }

    fn max_recv(&self) -> usize {
        if udp_batch_on() {
            self.max
        } else {
            1
        }
    }

    /// 返回本批收包数。`WouldBlock`/超时由调用方处理（沿用阻塞监听无超时的语义）。
    fn recv(&mut self, fd: RawFd) -> std::io::Result<usize> {
        let n = self.max_recv().min(self.max);
        loop {
            for i in 0..n {
                self.msgs[i].msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                self.msgs[i].msg_hdr.msg_controllen = self.ctrls[i].0.len() as _;
                self.msgs[i].msg_len = 0;
            }
            let rc = unsafe {
                libc::recvmmsg(
                    fd,
                    self.msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    crate::MSG_WAITFORONE,
                    std::ptr::null_mut(),
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            return Ok(rc as usize);
        }
    }

    /// 第 i 包：(data, client, orig_dst)。
    fn datagram(&self, i: usize) -> std::io::Result<(&[u8], SocketAddr, SocketAddr)> {
        let m = &self.msgs[i];
        let len = (m.msg_len as usize).min(self.slots[i].len());
        let client = sockaddr_to_std(&self.names[i])
            .ok_or_else(|| std::io::Error::other("bad peer addr"))?;
        let orig = orig_dst_from_cmsgs(&m.msg_hdr)?;
        Ok((&self.slots[i][..len], client, orig))
    }
}

// ---------------------------------------------------------------- P3b-1：缓存 + TCP

/// 客户端入口协议（决定应答是否按 UDP 尺寸截断；上游方向由 dnsup 负责）。
#[derive(Clone, Copy)]
enum ClientProto {
    Udp,
    Tcp,
}

/// 由 (question, 应答) 计算要写入数据面的域位图更新；hits = 命中的 domain 规则数。
fn domain_updates_for(
    q: &dns::Question,
    response: &[u8],
    slot: u32,
) -> (Vec<status::DnsUpdate>, usize) {
    let sets = DOMAIN_SETS.lock().map(|g| g.clone()).unwrap_or_default();
    let (bits, hits) = dns::matched_bitmap(&sets, &q.qname);
    if hits == 0 {
        return (Vec::new(), 0);
    }
    let (addrs, v6addrs) = dns::answer_a_and_aaaa_records(response);
    let mut updates: Vec<status::DnsUpdate> = addrs
        .iter()
        .map(|ip| status::DnsUpdate {
            slot,
            addr: dns::map_v4(*ip),
            bits: bits.clone(),
        })
        .collect();
    for ip in &v6addrs {
        updates.push(status::DnsUpdate {
            slot,
            addr: *ip,
            bits: bits.clone(),
        });
    }
    (updates, hits)
}

/// 发布域位图（UDP/TCP 共用）。缓存命中也要重发：reload 后新槽需要重建。
fn publish_live(
    q: &dns::Question,
    response: &[u8],
    tx: &std::sync::mpsc::Sender<status::MainMsg>,
    from_cache: bool,
) {
    if q.qtype != 1 && q.qtype != 28 {
        return;
    }
    let (updates, hits) = domain_updates_for(q, response, ACTIVE_SLOT.load(Ordering::SeqCst));
    if hits == 0 {
        return;
    }
    DNS_STATS.bitmap_matched.fetch_add(1, Ordering::Relaxed);
    if !from_cache {
        let (_, aaaa) = dns::answer_a_records(response);
        if aaaa > 0 {
            DNS_STATS
                .aaaa_published
                .fetch_add(aaaa as u64, Ordering::Relaxed);
        }
    }
    if !updates.is_empty() {
        let cnt = updates.len() as u64;
        if tx.send(status::MainMsg::DnsPublish { updates }).is_ok() {
            DNS_STATS.published_ips.fetch_add(cnt, Ordering::Relaxed);
        }
    }
}

/// 请求阶段选中的出口（P18c）。
enum Selected {
    /// 请求路由 reject（空应答）
    Reject,
    /// 实际上游 + 缓存作用域 + 应答路由用的「已服务」出口名
    Up(Arc<dnsup::Upstream>, String, dnsroute::ReqOut),
}

/// P18c：请求路由选择上游（asis / tag / legacy）；`client` 供 `sip()`，`pname` 供 `pname()`。
fn select_request_upstream(
    q: &dns::Question,
    client: Option<std::net::IpAddr>,
    pname: Option<&str>,
    orig_dst: Option<SocketAddr>,
) -> Result<Selected, String> {
    let set = upstreams().ok_or("DNS 上游未初始化")?;
    let Some(router) = dns_router() else {
        let u = set.legacy.clone();
        let scope = format!("legacy|{}", u.url);
        note_tag_hit("legacy");
        return Ok(Selected::Up(
            u,
            scope,
            dnsroute::ReqOut::Tag("default".into()),
        ));
    };
    match router.request_select_for(q, client, pname) {
        dnsroute::ReqOut::Reject => {
            note_tag_hit("reject");
            Ok(Selected::Reject)
        }
        dnsroute::ReqOut::AsIs => {
            // dae：asis 总是走 UDP 发往客户端原始目的；TCP 客户端路径拿不到时退回 legacy。
            match orig_dst {
                Some(orig) => {
                    let u = set.asis(orig)?;
                    let scope = format!("asis|{orig}");
                    note_tag_hit("asis");
                    Ok(Selected::Up(u, scope, dnsroute::ReqOut::AsIs))
                }
                None => {
                    let u = set.legacy.clone();
                    let scope = format!("legacy|{}", u.url);
                    note_tag_hit("legacy");
                    Ok(Selected::Up(
                        u,
                        scope,
                        dnsroute::ReqOut::Tag("default".into()),
                    ))
                }
            }
        }
        dnsroute::ReqOut::Tag(t) => {
            let u = set
                .get(&t)
                .ok_or_else(|| format!("dns.routing.request 出口 {t:?} 不在 dns.upstream"))?;
            let scope = format!("tag|{t}|{}", u.url);
            note_tag_hit(&t);
            Ok(Selected::Up(u, scope, dnsroute::ReqOut::Tag(t)))
        }
    }
}

/// 查询处理（UDP/TCP 共用）：请求路由 → 缓存 → 上游 → 应答路由（换上游重查深度 ≤3）
/// → 发布位图 → 回填缓存。UDP 最终应答按客户端公布尺寸截断（TCP 不截断）；
/// 位图从**完整**应答发布。上游经 `dnsup::Upstream`（P18a/b）；路由见 `dnsroute`（P18c）。
fn resolve_dns(
    query: &[u8],
    proto: ClientProto,
    client: Option<std::net::IpAddr>,
    pname: Option<&str>,
    orig_dst: Option<SocketAddr>,
    tx: &std::sync::mpsc::Sender<status::MainMsg>,
) -> Option<Vec<u8>> {
    let parsed = dns::parse_query(query);
    let edns = dns::query_edns(query);
    // 1) 请求路由（reject 先于缓存；对照 dae「Route request first, then check cache」）
    let selected = match &parsed {
        Some(q) => match select_request_upstream(q, client, pname, orig_dst) {
            Ok(s) => s,
            Err(e) => {
                DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                log(&format!("dns 请求路由失败: {e}"));
                return None;
            }
        },
        None => {
            // 无法解析 question：保持旧行为（legacy 直转，不进缓存/位图）
            let u = upstream()?;
            match u.exchange(query) {
                Ok(r) => return Some(serve_response(query, r, proto)),
                Err(e) => {
                    DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    log_warn(&format!("dns 上游 {} 查询失败: {e}", u.url));
                    return None;
                }
            }
        }
    };
    if matches!(selected, Selected::Reject) {
        DNS_STATS.rejects.fetch_add(1, Ordering::Relaxed);
        let resp = dns::empty_noerror(query);
        if resp.is_empty() {
            return None;
        }
        return Some(serve_response(query, resp, proto));
    }
    let (mut up, scope, mut served) = match selected {
        Selected::Up(u, scope, s) => (u, scope, s),
        Selected::Reject => unreachable!(),
    };
    // 2a) ECS 注入（sodama 扩展；上游 URL `ecs=auto|<CIDR>`）：
    //     客户端自带 OPT 时不动（透传）；注入后缓存作用域加前缀（不同子网不串答）。
    // P23：ipversion_prefer——若已知该域名有首选族（未过期缓存），
    // 把非首选族查询回空 NOERROR（对照 dae 的 ipversion_prefer 过滤）。
    if let Some(q) = &parsed {
        let pref = dns_opts().ipversion_prefer;
        let non_preferred = (pref == 4 && q.qtype == 28) || (pref == 6 && q.qtype == 1);
        if non_preferred {
            let preferred_type = if pref == 4 { 1u16 } else { 28u16 };
            let fresh = DNS_CACHE
                .lock()
                .ok()
                .is_some_and(|c| c.has_fresh(&q.qname, preferred_type, &scope, Instant::now()));
            if fresh {
                DNS_STATS.ipversion_filtered.fetch_add(1, Ordering::Relaxed);
                let resp = dns::empty_noerror(query);
                if !resp.is_empty() {
                    return Some(serve_response(query, resp, proto));
                }
            }
        }
    }
    let ecs_prefix = match up.spec.ecs {
        // P28：阶梯需要客户端**完整**地址（带主机位）——add_ecs 自己按前缀截断地址；
        // 上游回填的 scope 可能宽于/等于注入前缀，命中判定靠 truncate_prefix。
        Some(dnsup::EcsMode::Auto) => client.map(|c| (c, if c.is_ipv4() { 24 } else { 56 })),
        Some(dnsup::EcsMode::Prefix(ip, p)) => Some((ip, p)),
        None => None,
    };
    let ecs_query = ecs_prefix.and_then(|p| dns::add_ecs(query, p));
    // P28：只有实际注入时才参与作用域（客户端自带 OPT 时透传，仍用基础作用域）。
    let ecs_req = if ecs_query.is_some() {
        ecs_prefix
    } else {
        None
    };
    let mut last_injected = ecs_req;
    let query_send: &[u8] = ecs_query.as_deref().unwrap_or(query);
    // 2b) 缓存（按作用域；P28：ECS 阶梯查找——本机前缀/上游回填的更宽 scope）
    if let Some(q) = &parsed {
        let hit = DNS_CACHE.lock().ok().and_then(|mut c| {
            c.answer_from_cache_ecs_full(query, q, &edns, &scope, ecs_req, Instant::now())
        });
        if let Some(hit) = hit {
            DNS_STATS.responses.fetch_add(1, Ordering::Relaxed);
            publish_live(q, &hit.resp, tx, true);
            // A2 #7/#12：首选族命中缓存也要唤醒等待者（带记录性由应答内容判定）。
            let pref = dns_opts().ipversion_prefer;
            if pref != 0 && q.qtype == dns_pref_wait::preferred_qtype(pref) {
                let (a, aaaa) = dns::answer_a_and_aaaa_records(&hit.resp);
                dns_pref_wait::notify(&q.qname, !a.is_empty() || !aaaa.is_empty());
            }
            if hit.stale {
                // P29：RFC 8767——已返回 stale，尝试单飞后台刷新（对照 dae 的
                // refreshing CAS；失败保留旧条目，不影响本次应答）。
                maybe_spawn_optimistic_refresh(
                    q.clone(),
                    edns,
                    query_send.to_vec(),
                    scope.clone(),
                    hit.scope.clone(),
                    ecs_req,
                    up.clone(),
                );
            }
            return Some(serve_response(query, hit.resp, proto));
        }
    }
    // A2 #7/#12：ipversion_prefer 的 50ms 偏好等待（RFC 8305；对照 dae
    // `dns_preference_wait.go`）——**缓存未命中、即将上行**的非首选族查询登记等待
    // （缓存命中不登记：命中即答，不留未消费登记）；首选族应答到达且带记录则抑制
    // 本条应答（回空 NOERROR）；等待发生在应答就绪后（不占上游时间）。
    let pref_wait: Option<(dns_pref_wait::Entry, String)> =
        match (&parsed, dns_opts().ipversion_prefer) {
            (Some(q), pref) if dns_pref_wait::needs_deferred(pref as u16, q.qtype) => {
                Some((dns_pref_wait::register(&q.qname), q.qname.clone()))
            }
            _ => None,
        };
    // 3) 上游 + 应答路由（对照 dae resolveDNSUpstream 的递归重查；深度上限 3）
    let router = dns_router();
    let mut resp = match up.exchange(query_send) {
        Ok(r) => r,
        Err(e) => {
            DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
            log_warn(&format!("dns 上游 {} 查询失败: {e}", up.url));
            return None;
        }
    };
    let mut depth = 0usize;
    loop {
        let verdict = router
            .as_ref()
            .map(|r| r.response_select_for(&resp, &served, client, pname))
            .unwrap_or(dnsroute::RespOut::Accept);
        match verdict {
            dnsroute::RespOut::Accept => break,
            dnsroute::RespOut::Reject => {
                DNS_STATS.response_rejects.fetch_add(1, Ordering::Relaxed);
                resp = dns::strip_answers(&resp);
                break;
            }
            dnsroute::RespOut::Tag(t) => {
                if depth >= 2 {
                    DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    log("dns 应答路由重查过深（>3），放弃（检查 dns.routing.response 是否成环）");
                    return None;
                }
                depth += 1;
                DNS_STATS.relookups.fetch_add(1, Ordering::Relaxed);
                let set = upstreams()?;
                let Some(next) = set.get(&t) else {
                    DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    log(&format!("dns 应答路由出口 {t:?} 不在 dns.upstream"));
                    return None;
                };
                up = next;
                served = dnsroute::ReqOut::Tag(t);
                // 重查也按新上游的 ECS 配置注入
                let ecs_prefix2 = match up.spec.ecs {
                    Some(dnsup::EcsMode::Auto) => {
                        client.map(|c| (c, if c.is_ipv4() { 24 } else { 56 }))
                    }
                    Some(dnsup::EcsMode::Prefix(ip, p)) => Some((ip, p)),
                    None => None,
                };
                let ecs_query2 = ecs_prefix2.and_then(|p| dns::add_ecs(query, p));
                last_injected = if ecs_query2.is_some() {
                    ecs_prefix2
                } else {
                    None
                };
                resp = match up.exchange(ecs_query2.as_deref().unwrap_or(query)) {
                    Ok(r) => r,
                    Err(e) => {
                        DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                        log(&format!("dns 上游 {} 重查失败: {e}", up.url));
                        return None;
                    }
                };
            }
        }
    }
    DNS_STATS.responses.fetch_add(1, Ordering::Relaxed);
    // A2 #7/#12：首选族上游应答到达 → 唤醒同 qname 的等待者（带记录性按应答内容判）。
    if let Some(q) = &parsed {
        let pref = dns_opts().ipversion_prefer;
        if pref != 0 && q.qtype == dns_pref_wait::preferred_qtype(pref) {
            let (a, aaaa) = dns::answer_a_and_aaaa_records(&resp);
            dns_pref_wait::notify(&q.qname, !a.is_empty() || !aaaa.is_empty());
        }
    }
    if let Some((entry, qname)) = &pref_wait {
        if dns_pref_wait::wait(entry, qname, dns_pref_wait::PREFERENCE_DELAY) {
            DNS_STATS.ipversion_filtered.fetch_add(1, Ordering::Relaxed);
            let empty = dns::empty_noerror(query);
            if !empty.is_empty() {
                return Some(serve_response(query, empty, proto));
            }
        }
    }
    if let Some(q) = &parsed {
        publish_live(q, &resp, tx, false);
        // P23：fixed_domain_ttl——命中配置的域名用固定缓存寿命（0 = 立即过期，
        // 配合 optimistic cache 可供 stale；对照 dae fixedTtlDeadlineFunc）。
        let fixed = DNS_OPTS
            .lock()
            .ok()
            .and_then(|g| g.fixed_domain_ttl.get(&dns_key(&q.qname)).copied());
        // P28：ECS 回填——应答带 ECS 时按上游声明的 scope 入缓存
        // （scope=0 → 全局键 `0.0.0.0/0`，可跨子网复用）；无回显则回退请求前缀。
        let mut insert_scope = scope.clone();
        if let Some(injected) = last_injected {
            let ((ip, p), echoed) = ecs_effective_scope(&resp, injected);
            if echoed {
                DNS_STATS.ecs_echo.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut g) = ECS_SCOPE_LAST.lock() {
                    *g = Some(format!("{ip}/{p}"));
                }
            }
            insert_scope.push_str(&format!("|ecs={ip}/{p}"));
        }
        if let Ok(mut c) = DNS_CACHE.lock() {
            c.insert_scoped_with_fixed(q, &edns, &insert_scope, &resp, Instant::now(), fixed);
        }
    }
    Some(serve_response(query, resp, proto))
}

/// 发给客户端的最终应答：UDP 按客户端公布尺寸截断（缓存/上游都保留完整版），TCP 原样。
fn serve_response(query: &[u8], response: Vec<u8>, proto: ClientProto) -> Vec<u8> {
    match proto {
        ClientProto::Udp => dns::truncate_for_udp(&response, dns::client_udp_size(query)),
        ClientProto::Tcp => response,
    }
}

/// P28：入缓存时生效的 ECS 作用域——有回显则 `(truncate(回显地址, scope), scope)`
/// 且 `echoed=true`；无回显/家族不符则回退请求注入前缀。
fn ecs_effective_scope(resp: &[u8], injected: (IpAddr, u8)) -> ((IpAddr, u8), bool) {
    let (cip, cp) = injected;
    let max = if cip.is_ipv4() { 32 } else { 128 };
    match dns::parse_ecs_echo(resp)
        .filter(|e| e.family == if cip.is_ipv4() { 1 } else { 2 } && e.scope_prefix <= max)
    {
        Some(e) => (
            (dns::truncate_prefix(e.src, e.scope_prefix), e.scope_prefix),
            true,
        ),
        None => ((cip, cp), false),
    }
}

/// P29：stale 命中后的 RFC 8767 后台刷新（对照 dae `backgroundRefresh`）——
/// 单飞（同一 key 只跑一个）；失败保留旧条目；成功则按 ECS 回填 scope 入缓存，
/// 若得到不能入缓存的负应答则取代过期正值。
#[allow(clippy::too_many_arguments)]
fn maybe_spawn_optimistic_refresh(
    q: dns::Question,
    edns: dns::EdnsInfo,
    query_send: Vec<u8>,
    base_scope: String,
    hit_scope: String,
    injected: Option<(IpAddr, u8)>,
    up: Arc<dnsup::Upstream>,
) {
    let key = format!("{}|{}|{}|{}", hit_scope, q.qname, q.qtype, up.url);
    let started = match DNS_CACHE.lock() {
        Ok(mut c) => c.begin_refresh(&key),
        Err(p) => p.into_inner().begin_refresh(&key),
    };
    if !started {
        DNS_STATS.refresh_coalesced.fetch_add(1, Ordering::Relaxed);
        return;
    }
    DNS_STATS.refresh_spawned.fetch_add(1, Ordering::Relaxed);
    std::thread::spawn(move || {
        let result = up.exchange(&query_send);
        let mut c = DNS_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(bytes) => {
                let mut insert_scope = base_scope;
                if let Some(injected) = injected {
                    let ((ip, p), echoed) = ecs_effective_scope(&bytes, injected);
                    if echoed {
                        DNS_STATS.ecs_echo.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut g) = ECS_SCOPE_LAST.lock() {
                            *g = Some(format!("{ip}/{p}"));
                        }
                    }
                    insert_scope.push_str(&format!("|ecs={ip}/{p}"));
                }
                let fixed = DNS_OPTS
                    .lock()
                    .ok()
                    .and_then(|g| g.fixed_domain_ttl.get(&dns_key(&q.qname)).copied());
                let cached = c.insert_scoped_with_fixed(
                    &q,
                    &edns,
                    &insert_scope,
                    &bytes,
                    Instant::now(),
                    fixed,
                );
                if !cached && dns::is_negative_response(&bytes, q.qtype) {
                    // 负答不可入缓存：取代被它推翻的过期正值（RFC 8767 §4）。
                    c.remove_scoped(&q, edns.do_bit, &hit_scope);
                }
            }
            Err(e) => {
                DNS_STATS.refresh_err.fetch_add(1, Ordering::Relaxed);
                log(&format!("dns 后台刷新 {} 失败: {e}（保留旧条目）", up.url));
            }
        }
        c.end_refresh(&key);
    });
}

// ---------------------------------------------------------------- P38：dns.bind 明文监听

/// P38：`dns.bind` 端点（对照 dae `control.ParseEndpoint`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsBindEndpoint {
    addr: SocketAddr,
    udp: bool,
    tcp: bool,
}

/// P38：解析 `dns.bind`——纯 `ip:port` = 仅 UDP；`udp+tcp://ip:port`（scheme 按 `+`
/// 拆分，仅接受 udp/tcp）＝按 scheme 开监听（对照 dae `ErrBadLocalDNSBindFormat`）。
fn parse_dns_bind(raw: &str) -> Result<DnsBindEndpoint, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("dns.bind 为空".into());
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(DnsBindEndpoint {
            addr,
            udp: true,
            tcp: false,
        });
    }
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("dns.bind 非法（{raw}）：需要 `ip:port` 或 `udp+tcp://ip:port`"))?;
    let (mut udp, mut tcp) = (false, false);
    for s in scheme.split('+') {
        match s {
            "udp" => udp = true,
            "tcp" => tcp = true,
            other => return Err(format!("dns.bind 不支持协议 {other:?}（仅 udp/tcp）")),
        }
    }
    if !udp && !tcp {
        return Err(format!("dns.bind 缺少协议（{raw}）"));
    }
    let addr = rest
        .trim_end_matches('/')
        .parse::<SocketAddr>()
        .map_err(|e| format!("dns.bind 地址非法（{rest}）: {e}"))?;
    Ok(DnsBindEndpoint { addr, udp, tcp })
}

/// P38：从配置读 `dns.bind`（无配置/无键/空值 → None）。
fn dns_bind_from_config(cfg: Option<&config::Config>) -> Option<String> {
    let cfg = cfg?;
    for sec in cfg.sections.iter().filter(|s| s.name == "dns") {
        for item in &sec.items {
            if let config::Item::Param(p) = item {
                if p.key.as_deref() == Some("bind") {
                    let v = p.val.as_deref().unwrap_or("").trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

/// P38：启动 `dns.bind` 监听（对照 dae `NewDNSListener` + `Start`）。
/// 偏离（如实）：UDP 单线程串行处理（无 dae 的 16384 并发闸门，过载由内核丢包兑底）；
/// reload 不重启监听（端点变更需重启进程；dae 会 `RestartDNSListener`）。
fn start_dns_bind(raw: &str, tx: &std::sync::mpsc::Sender<status::MainMsg>) {
    let ep = match parse_dns_bind(raw) {
        Ok(ep) => ep,
        Err(e) => {
            log(&format!("dns.bind 解析失败: {e}（监听未启动）"));
            return;
        }
    };
    if let Ok(mut g) = DNS_BIND.lock() {
        let proto = match (ep.udp, ep.tcp) {
            (true, true) => "udp+tcp",
            (true, false) => "udp",
            (false, true) => "tcp",
            (false, false) => "none",
        };
        *g = Some(format!("{proto}://{}", ep.addr));
    }
    if ep.udp {
        let tx = tx.clone();
        std::thread::spawn(move || dns_bind_udp_loop(ep.addr, tx));
    }
    if ep.tcp {
        let tx = tx.clone();
        std::thread::spawn(move || dns_bind_tcp_loop(ep.addr, tx));
    }
}

/// P38：`dns.bind` UDP 监听——复用透明 DNS 的完整链路（resolve_dns：路由/上游/缓存/位图）。
fn dns_bind_udp_loop(addr: SocketAddr, tx: std::sync::mpsc::Sender<status::MainMsg>) {
    let sock = match std::net::UdpSocket::bind(addr) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("dns.bind: UDP 绑定 {addr} 失败: {e}"));
            return;
        }
    };
    log(&format!(
        "dns.bind: UDP 监听 {addr}（明文 DNS；供 AdGuard/mosdns 等指上游；路由/上游/缓存与透明 DNS 同一链路）"
    ));
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                log(&format!("dns.bind: recv 失败: {e}"));
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let query = &buf[..n];
        // QR 置位的包（应答/伪造）静默丢弃；头部不完整的丢掉（对照 dae dns_listener）。
        if query.len() < 12 || query[2] & 0x80 != 0 {
            continue;
        }
        DNS_STATS.bind_queries.fetch_add(1, Ordering::Relaxed);
        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resolve_dns(
                query,
                ClientProto::Udp,
                Some(peer.ip()),
                None,
                Some(addr),
                &tx,
            )
        }));
        let resp = match resolved {
            Ok(Some(r)) => r,
            // dae：超时/错误 → SERVFAIL；无法构造（畸形）则静默丢。
            Ok(None) => dns::servfail(query),
            Err(_) => {
                DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                log("dns.bind: 查询处理 panic（已隔离，连续出现请查日志）");
                dns::servfail(query)
            }
        };
        if resp.is_empty() {
            continue;
        }
        if let Err(e) = sock.send_to(&resp, peer) {
            log(&format!("dns.bind: 回包 {peer} 失败: {e}"));
        }
    }
}

/// P38：`dns.bind` TCP 监听（DNS over TCP，RFC 1035 §4.2.2：2 字节长度前缀）。
fn dns_bind_tcp_loop(addr: SocketAddr, tx: std::sync::mpsc::Sender<status::MainMsg>) {
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            log(&format!("dns.bind: TCP 绑定 {addr} 失败: {e}"));
            return;
        }
    };
    log(&format!("dns.bind: TCP 监听 {addr}（明文 DNS over TCP）"));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let tx = tx.clone();
        std::thread::spawn(move || dns_bind_tcp_conn(stream, addr, &tx));
    }
}

fn dns_bind_tcp_conn(
    mut stream: TcpStream,
    local: SocketAddr,
    tx: &std::sync::mpsc::Sender<status::MainMsg>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let peer = stream.peer_addr().ok();
    loop {
        let mut lenb = [0u8; 2];
        if stream.read_exact(&mut lenb).is_err() {
            return;
        }
        let len = u16::from_be_bytes(lenb) as usize;
        if len < 12 {
            return;
        }
        let mut query = vec![0u8; len];
        if stream.read_exact(&mut query).is_err() {
            return;
        }
        if query[2] & 0x80 != 0 {
            continue; // QR 置位（应答/伪造）：丢弃该查询，保持连接
        }
        DNS_STATS.bind_queries.fetch_add(1, Ordering::Relaxed);
        let client = peer.map(|p| p.ip());
        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resolve_dns(&query, ClientProto::Tcp, client, None, Some(local), tx)
        }));
        let resp = match resolved {
            Ok(Some(r)) => r,
            Ok(None) => dns::servfail(&query),
            Err(_) => {
                DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                dns::servfail(&query)
            }
        };
        if resp.is_empty() {
            return;
        }
        let n = resp.len().min(65535) as u16;
        if stream.write_all(&n.to_be_bytes()).is_err()
            || stream.write_all(&resp[..n as usize]).is_err()
        {
            return;
        }
    }
}

/// P3a/P3b/P4b UDP 线程（host ns）：一个透明监听同时承载
/// DNS（orig_dst port=53，解析/缓存/位图）与普通 UDP NAT（其他目的端口）。
fn dns_loop(listener: OwnedFd, tx: std::sync::mpsc::Sender<status::MainMsg>) {
    let fd = listener.as_raw_fd();
    // O7：批量收（recvmmsg）；DNS 与普通 UDP NAT 共用同一入口，按 orig_dst 分流。
    let mut batch = UdpRecvBatch::new(UDP_RECV_BATCH);
    loop {
        let got = match batch.recv(fd) {
            Ok(n) => n,
            Err(e) => {
                log(&format!("udp recv: {e}"));
                continue;
            }
        };
        // NAT 条目先收集，批内按会话聚合后 sendmmsg。
        let mut nat_entries: Vec<(&[u8], SocketAddr, SocketAddr)> = Vec::new();
        for i in 0..got {
            let (data, client, orig_dst) = match batch.datagram(i) {
                Ok(v) => v,
                Err(e) => {
                    log(&format!("udp recv: {e}"));
                    continue;
                }
            };
            if orig_dst.port() != 53 {
                // P4b：普通 UDP 代理流量 → NAT 会话表
                nat_entries.push((data, client, orig_dst));
                continue;
            }
            // 能力缺口 #1：must 的 DNS 流不劫持——按普通 UDP 代理流走 NAT 会话表
            // （组选择复用 conn_state 回读；数据面只对 must 的 UDP-53 流存 conn_state）。
            let must = lookup_conn_state(client, orig_dst, 17)
                .map(|st| st.must)
                .unwrap_or(0);
            if must != 0 {
                nat_entries.push((data, client, orig_dst));
                continue;
            }
            DNS_STATS.queries.fetch_add(1, Ordering::Relaxed);
            // P18c+：发送方进程名（WAN egress 新 UDP DNS 流由 eBPF 写入）
            let dns_pname = lookup_dns_pname(Some(client.ip()), client.port());
            // A2 #7/#12：偏好等待需要「A/AAAA 并发在飞」，而本循环是串行的——
            // 开启 `ipversion_prefer` 时把非首选族查询交给工作线程（默认关闭 → 零影响；
            // 对照 dae 的每查询一 goroutine，见 `dns_pref_wait` 模块头说明）。
            if dns_pref_wait::needs_deferred(
                dns_opts().ipversion_prefer as u16,
                dns::parse_query(data).map(|q| q.qtype).unwrap_or(0),
            ) {
                let data: Vec<u8> = data.to_vec();
                let orig = orig_dst;
                let pname = dns_pname.clone();
                let tx2 = tx.clone();
                let clip = client.ip();
                std::thread::Builder::new()
                    .name("dns-pref".into())
                    .spawn(move || {
                        let resolved =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                resolve_dns(
                                    &data,
                                    ClientProto::Udp,
                                    Some(clip),
                                    pname.as_deref(),
                                    Some(orig),
                                    &tx2,
                                )
                            }));
                        if let Ok(Some(resp)) = resolved {
                            if let Err(e) = reply_send(orig, client, &[&resp]) {
                                log(&format!("dns 回包 {client}: {e}"));
                            }
                        }
                    })
                    .ok();
                continue;
            }
            // panic 隔离：单次查询（含第三方 QUIC 栈）出 panic 不应杀死整个 DNS 线程
            let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                resolve_dns(
                    data,
                    ClientProto::Udp,
                    Some(client.ip()),
                    dns_pname.as_deref(),
                    Some(orig_dst),
                    &tx,
                )
            }));
            let resp = match resolved {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(_) => {
                    DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    log("dns 查询处理 panic（已隔离，连续出现请查日志）");
                    continue;
                }
            };
            if let Err(e) = reply_send(orig_dst, client, &[&resp]) {
                log(&format!("dns 回包 {client}: {e}"));
            }
        }
        if !nat_entries.is_empty() {
            udp_nat_handle_batch(&nat_entries);
        }
    }
}

/// P3b-1 TCP DNS 线程（host ns）：并发处理 accept 线程转交来的连接。
fn tcp_dns_loop(
    rx: std::sync::mpsc::Receiver<TcpStream>,
    tx: std::sync::mpsc::Sender<status::MainMsg>,
) {
    for stream in rx {
        let tx = tx.clone();
        std::thread::spawn(move || handle_tcp_dns_conn(stream, tx));
    }
}

/// 单条 TCP DNS 连接：2 字节长度前缀分帧，支持一条连接多查询（keep-alive）。
fn handle_tcp_dns_conn(mut stream: TcpStream, tx: std::sync::mpsc::Sender<status::MainMsg>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    // P18c：透明 socket 的 local_addr = 客户端原始目的地址（asis 用）；peer = 客户端地址（sip 用）
    let orig_dst = stream.local_addr().ok();
    let peer = stream.peer_addr().ok();
    let peer_ip = peer.map(|a| a.ip());
    let peer_port = peer.map(|a| a.port()).unwrap_or(0);
    loop {
        let mut lb = [0u8; 2];
        if stream.read_exact(&mut lb).is_err() {
            break;
        }
        let n = u16::from_be_bytes(lb) as usize;
        if n == 0 || n > 4096 {
            break;
        }
        let mut query = vec![0u8; n];
        if stream.read_exact(&mut query).is_err() {
            break;
        }
        DNS_STATS.tcp_queries.fetch_add(1, Ordering::Relaxed);
        let dns_pname = lookup_dns_pname(peer_ip, peer_port);
        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resolve_dns(
                &query,
                ClientProto::Tcp,
                peer_ip,
                dns_pname.as_deref(),
                orig_dst,
                &tx,
            )
        }));
        let resp = match resolved {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(_) => {
                DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
                log("dns TCP 查询处理 panic（已隔离）");
                break;
            }
        };
        DNS_STATS.tcp_responses.fetch_add(1, Ordering::Relaxed);
        let len = (resp.len() as u16).to_be_bytes();
        if stream
            .write_all(&len)
            .and_then(|_| stream.write_all(&resp))
            .and_then(|_| stream.flush())
            .is_err()
        {
            break;
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

// ---------------------------------------------------------------- A2 #11：投影重试堆
/// 投影重试队列（对照 dae `dns_controller_bpf.go:17-24` 的「更新任务堆 + 重试」）：
/// `domain_routing_map` 写入失败（map 更新错误）时不再只记一条日志，而是把同一批
/// updates 排进重试堆（指数退避；上限 `PUBLISH_MAX_ATTEMPTS` 次 / `PUBLISH_QUEUE_CAP`
/// 批），主循环 tick 消费——失败路径的重试语义与 dae 对等（daemon 内部状态，无需落盘）。
struct PublishRetry {
    updates: Vec<status::DnsUpdate>,
    attempts: u32,
    due_ns: u64,
}
const PUBLISH_MAX_ATTEMPTS: u32 = 5;
const PUBLISH_QUEUE_CAP: usize = 4096;

fn publish_retry_queue() -> &'static Mutex<Vec<PublishRetry>> {
    static Q: OnceLock<Mutex<Vec<PublishRetry>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(Vec::new()))
}

/// 投影重试计数（status/metrics 可见）。
static PUBLISH_RETRIES: AtomicU64 = AtomicU64::new(0);
static PUBLISH_DROPPED: AtomicU64 = AtomicU64::new(0);

/// 失败入队（退避 100ms → 1.6s；队列满则丢最旧并计数——不阻塞主循环）。
fn publish_enqueue_retry(updates: Vec<status::DnsUpdate>) {
    if updates.is_empty() {
        return;
    }
    let backoff_ms = 100u64 << PUBLISH_RETRIES.load(Ordering::Relaxed).min(4);
    let mut q = match publish_retry_queue().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if q.len() >= PUBLISH_QUEUE_CAP {
        q.remove(0);
        PUBLISH_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    q.push(PublishRetry {
        updates,
        attempts: 1,
        due_ns: monotonic_now_ns() + backoff_ms * 1_000_000,
    });
}

/// 主循环 tick：把到期的重试批次重新投影（合并同一 tick 的批次，语义与首次相同）。
fn publish_retry_tick(ebpf: &mut Ebpf) {
    let due: Vec<PublishRetry> = {
        let mut q = match publish_retry_queue().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if q.is_empty() {
            return;
        }
        let now = monotonic_now_ns();
        let mut due = Vec::new();
        let mut rest = Vec::new();
        for r in q.drain(..) {
            if r.due_ns <= now {
                due.push(r);
            } else {
                rest.push(r);
            }
        }
        *q = rest;
        due
    };
    for mut r in due {
        match publish_domain_bits(ebpf, &r.updates) {
            Ok(()) => {
                PUBLISH_RETRIES.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                r.attempts += 1;
                if r.attempts > PUBLISH_MAX_ATTEMPTS {
                    PUBLISH_DROPPED.fetch_add(1, Ordering::Relaxed);
                    log_warn(&format!(
                        "domain_routing_map 投影重试 {PUBLISH_MAX_ATTEMPTS} 次仍失败，放弃：{e}"
                    ));
                } else {
                    r.due_ns = monotonic_now_ns() + (100u64 << r.attempts.min(4)) * 1_000_000;
                    if let Ok(mut q) = publish_retry_queue().lock() {
                        q.push(r);
                    }
                }
            }
        }
    }
}

fn publish_domain_bits(
    ebpf: &mut Ebpf,
    updates: &[status::DnsUpdate],
) -> Result<(), Box<dyn std::error::Error>> {
    if updates.is_empty() {
        return Ok(());
    }
    let map = ebpf
        .map_mut("domain_routing_map")
        .ok_or("map domain_routing_map not found")?;
    let mut dm: HashMap<_, SodaEpochIp, SodaDomainRouting> = HashMap::try_from(map)?;
    for u in updates {
        let key = SodaEpochIp {
            slot: u.slot,
            addr: u.addr,
        };
        let mut val = dm.get(&key, 0).unwrap_or_default();
        for (i, b) in u.bits.iter().enumerate() {
            if i < val.bitmap.len() {
                val.bitmap[i] |= b;
            }
        }
        dm.insert(key, val, 0)?;
    }
    Ok(())
}

/// reload 后用 DNS 缓存重建域位图（对照 dae `reconcileCurrentBpfProjections`）。
/// 缓存命中的应答不会重新上行，若不重投影，新 epoch 槽会缺失这些域。
fn reconcile_domain_bits(ebpf: &mut Ebpf) {
    let entries = match DNS_CACHE.lock() {
        Ok(c) => c.snapshot(),
        Err(_) => return,
    };
    let slot = ACTIVE_SLOT.load(Ordering::SeqCst);
    let mut all = Vec::new();
    for (q, resp) in entries {
        let (updates, _) = domain_updates_for(&q, &resp, slot);
        all.extend(updates);
    }
    if all.is_empty() {
        return;
    }
    let n = all.len();
    match publish_domain_bits(ebpf, &all) {
        Ok(()) => log(&format!("reload: 从 DNS 缓存重建域位图（{n} 个 IP）")),
        Err(e) => log(&format!("reload: 域位图重建失败: {e}")),
    }
}

/// 对照 dae clearReloadDomainRoutingMapSlot：删除指定 epoch 槽的全部域位图条目。
fn clear_domain_slot(ebpf: &mut Ebpf, slot: u32) -> Result<(), Box<dyn std::error::Error>> {
    let Some(map) = ebpf.map_mut("domain_routing_map") else {
        return Ok(());
    };
    let mut dm: HashMap<_, SodaEpochIp, SodaDomainRouting> = HashMap::try_from(map)?;
    let keys: Vec<SodaEpochIp> = dm
        .iter()
        .filter_map(|r| r.ok().map(|(k, _)| k))
        .filter(|k| k.slot == slot)
        .collect();
    for k in keys {
        let _ = dm.remove(&k);
    }
    Ok(())
}

// ---------------------------------------------------------------- P4b：UDP NAT

/// 上游回包 → 客户端（每会话一个 reader 线程；O7：recvmmsg 批量收 + sendmmsg 批量回）。
/// M2 修复：会话退役（reader 致命退出 / janitor 空闲回收共用）——置 `alive=false`
/// 并从分片表摘除。旧行为仅 janitor 摘表：reader 死后退场时表项残留，而客户端上行
/// 会持续刷新 `last_ns`，使空闲回收永不触发（死会话 + 后端 fd 常驻）。
fn udp_nat_retire(sess: &UdpSession) {
    sess.alive.store(false, Ordering::Relaxed);
    if let Ok(mut t) = udp_nat_shard(&sess.key).lock() {
        if t.remove(&sess.key).is_some() {
            UDP_NAT_STATS.evicted.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn udp_session_reader(sess: Arc<UdpSession>) {
    // O8：槽走缓冲池且按需增长（空闲会话 ≈1×64KB）。
    let mut slots: Vec<bufpool::PoolBuf> = Vec::new();
    // P38：full-cone 端点每包的来源地址（回包选源用）。
    let mut srcs: Vec<SocketAddr> = Vec::new();
    loop {
        if !sess.alive.load(Ordering::Relaxed) {
            break;
        }
        let got = if sess.full_cone {
            match sess
                .relay
                .recv_batch_src(&mut slots, UDP_RECV_BATCH, &mut srcs)
            {
                Ok(n) => n,
                Err(e) if udp_read_retryable(&e) => continue,
                Err(e) => {
                    log(&format!("udp nat: 会话读结束（{e}）"));
                    udp_nat_retire(&sess);
                    break;
                }
            }
        } else {
            match sess.relay.recv_batch(&mut slots, UDP_RECV_BATCH) {
                Ok(n) => n,
                Err(e) if udp_read_retryable(&e) => continue,
                Err(e) => {
                    log(&format!("udp nat: 会话读结束（{e}）"));
                    udp_nat_retire(&sess);
                    break;
                }
            }
        };
        if got == 0 {
            continue;
        }
        sess.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
        let total: usize = slots.iter().take(got).map(|v| v.len()).sum();
        UDP_NAT_STATS
            .bytes_down
            .fetch_add(total as u64, Ordering::Relaxed);
        if sess.full_cone {
            // P38：回包源地址 = 本包的实际上游来源（full-cone 一个端点服务多目标）。
            for i in 0..got {
                let src = srcs.get(i).copied().unwrap_or(sess.key.client);
                let data = slots[i].as_slice();
                if let Err(e) = reply_send(src, sess.client, &[data]) {
                    UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                    log(&format!("udp nat: 回包 {} 失败: {e}", sess.client));
                }
            }
        } else {
            let datas: Vec<&[u8]> = slots.iter().take(got).map(|v| v.as_slice()).collect();
            // 回包源地址 = 会话目标（orig_dst；affine 会话的语义）。
            if let Err(e) = reply_send(sess.relay.target(), sess.client, &datas) {
                UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                log(&format!("udp nat: 回包 {} 失败: {e}", sess.client));
            }
        }
    }
}

/// 读循环可重试错误（非致命）。
fn udp_read_retryable(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

/// M3 修复：回包 socket 表上限。超出后逐出任意一条（被逐地址下次按需重建）。
const REPLY_SOCKET_CAP: usize = 128;

/// P38：透明回包 socket 全局缓存（DNS 与 UDP NAT 共用；多线程读者共用一把短锁）。
static REPLY_SOCKETS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<SocketAddr, Arc<OwnedFd>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// 取（或创建）绑定 addr 的透明回包 socket；保留原始错误（raw_udp 回退判定要用 errno）。
fn reply_socket_global(addr: SocketAddr) -> std::io::Result<Arc<OwnedFd>> {
    let mut map = REPLY_SOCKETS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(s) = map.get(&addr) {
        return Ok(s.clone());
    }
    // M3 修复：旧实现只插不删（键=历史用过的全部目的地址），长跑大 pps 下 fd/RSS 缓慢抬升。
    if map.len() >= REPLY_SOCKET_CAP {
        if let Some(k) = map.keys().next().copied() {
            map.remove(&k);
            UDP_NAT_STATS
                .reply_sockets_evicted
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    let fd = make_transparent_udp_bound(addr)?;
    let a = Arc::new(fd);
    map.insert(addr, a.clone());
    Ok(a)
}

/// P38：回包发送（统一入口：DNS 透明回包与 UDP NAT 回包）——先走透明 socket；
/// 绑不上/发不出且满足 dae 的回退条件（源端口 53、地址族一致、EADDRINUSE/EADDRNOTAVAIL）
/// 时回退 raw socket 伪造源地址发送（对照 dae `tryRawUDPFallback`）。
fn reply_send(from: SocketAddr, to: SocketAddr, datas: &[&[u8]]) -> std::io::Result<()> {
    match reply_socket_global(from) {
        Ok(fd) => match send_batch_to_udp(fd.as_raw_fd(), to, datas) {
            Ok(()) => Ok(()),
            Err(e) if raw_udp_eligible(&e, from, to) => {
                UDP_NAT_STATS
                    .raw_udp_fallbacks
                    .fetch_add(1, Ordering::Relaxed);
                raw_udp_send_all(from, to, datas)
            }
            Err(e) => Err(e),
        },
        Err(e) if raw_udp_eligible(&e, from, to) => {
            UDP_NAT_STATS
                .raw_udp_fallbacks
                .fetch_add(1, Ordering::Relaxed);
            raw_udp_send_all(from, to, datas)
        }
        Err(e) => {
            log(&format!("udp 回包 socket {from}: {e}"));
            Err(e)
        }
    }
}

/// 回退条件（对照 dae `shouldTryRawUDPFallback`，保持同样窄的口径）：
/// 失败于 bind/发送、源端口为 53（DNS 回注）、与目标同地址族。
fn raw_udp_eligible(e: &std::io::Error, from: SocketAddr, to: SocketAddr) -> bool {
    if from.port() != 53 {
        return false;
    }
    if from.is_ipv4() != to.is_ipv4() {
        return false;
    }
    matches!(
        e.raw_os_error(),
        Some(libc::EADDRINUSE) | Some(libc::EADDRNOTAVAIL)
    )
}

fn raw_udp_send_all(from: SocketAddr, to: SocketAddr, datas: &[&[u8]]) -> std::io::Result<()> {
    for d in datas {
        raw_udp_send(from, to, d)?;
    }
    Ok(())
}

/// P38：端点 TTL 分类（对照 dae：`DnsNatTimeout` 17s / `QuicNatTimeout` 5min / 代理型
/// dialer 地板 5min / 普通 NAT 默认 30s——sodama 保留自己的 NAT 默认值 `nat_default`）。
fn udp_ttl_secs(nat_default: u64, dst_port: u16, quic_or_domain: bool, proxied: bool) -> u64 {
    if dst_port == 53 && !proxied {
        return UDP_TTL_DNS_SECS;
    }
    if quic_or_domain {
        return UDP_TTL_QUIC_SECS.max(nat_default);
    }
    if proxied {
        return UDP_TTL_PROXY_FLOOR_SECS.max(nat_default);
    }
    nat_default
}

/// P38：QUIC Initial 形态判定（长包 + 长头位；与旧内联条件一致）。
fn is_quic_initial(probe: &[u8]) -> bool {
    probe.len() >= 1200 && probe[0] & 0xC0 == 0xC0
}

/// P38：端点创建失败负缓存（对照 dae `cacheFailureLocked`：2s 占位，防拨号/建 socket 风暴）。
static UDP_NEG_CACHE: std::sync::LazyLock<Mutex<std::collections::HashMap<UdpFlowKey, Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
const UDP_NEG_CACHE_TTL: Duration = Duration::from_secs(2);

fn udp_neg_cache_hit(key: &UdpFlowKey) -> bool {
    let mut g = UDP_NEG_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    g.retain(|_, t| t.elapsed() < UDP_NEG_CACHE_TTL);
    g.contains_key(key)
}

fn udp_neg_cache_put(key: UdpFlowKey) {
    let mut g = UDP_NEG_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    g.insert(key, Instant::now());
}

fn udp_sess_lookup(key: &UdpFlowKey) -> Option<Arc<UdpSession>> {
    udp_nat_shard(key)
        .lock()
        .ok()
        .and_then(|t| t.get(key).cloned())
}

/// P38：取（或创建）一条 UDP 端点：普通明文 UDP → Full-Cone（key.client，任意目标复用）；
/// QUIC Initial / 代理型协议 → dest-affine（key.dst）。创建路径含 QUIC 嗅探与拨号（不持锁）。
fn udp_nat_session(
    client: SocketAddr,
    orig_dst: SocketAddr,
    probe: &[u8],
) -> Option<Arc<UdpSession>> {
    // P20：QUIC Initial 识别 + SNI 嗅探（解 Initial 加密；失败仅计识别数）。
    // 识别命中 → dest-affine（对照 dae：QUIC 需目的亲和）。
    let quic = is_quic_initial(probe);
    if quic {
        SNIFF_STATS.quic_initial.fetch_add(1, Ordering::Relaxed);
        if let quicsniff::QuicSniff::Found(name) = quicsniff::sniff(probe) {
            SNIFF_STATS.quic_sni.fetch_add(1, Ordering::Relaxed);
            log_debug(&format!(
                "quic sniff {client} → {name}（SNI，Initial 解密）"
            ));
        }
    }
    // 快路径：猜一个键查已有端点（full-cone 的首包猜 dst=None，命中即复用）。
    let guess = UdpFlowKey {
        client,
        dst: if quic { Some(orig_dst) } else { None },
    };
    if let Some(s) = udp_sess_lookup(&guess) {
        return Some(s);
    }
    // 负缓存（对照 dae：创建失败 2s 内不打拨号）。
    if udp_neg_cache_hit(&guess) {
        UDP_NAT_STATS.negcache_hits.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    // 慢路径：先拨号（不持锁——TLS/协议拨号可能耗一个 RTT）
    // P5/P19：按规则选中的组分派（conn_state 回读；回退默认组）
    let resolved = resolve_group_dialer(client, orig_dst, 17);
    let proxied_request = resolved
        .as_ref()
        .or(OUTBOUND.get())
        .is_some_and(|o| o.supports_udp());
    let relay = match resolved.as_ref().or(OUTBOUND.get()) {
        Some(o) if o.supports_udp() => match o.dial_udp(
            orig_dst,
            Duration::from_millis(RELAY_DIAL_TIMEOUT_MS.load(Ordering::Relaxed)),
        ) {
            Ok(Some(r)) => {
                UDP_NAT_STATS
                    .sessions_proxied
                    .fetch_add(1, Ordering::Relaxed);
                r
            }
            Ok(None) => {
                // 组内无可用 UDP 出口（成员不支持或协商失败）→ 直连回退（计数）。
                UDP_NAT_STATS
                    .direct_fallback
                    .fetch_add(1, Ordering::Relaxed);
                match outbound::Outbound::direct_udp(orig_dst) {
                    Ok(r) => r,
                    Err(e) => {
                        UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                        log(&format!("udp nat: 建出口失败: {e}"));
                        udp_neg_cache_put(guess);
                        return None;
                    }
                }
            }
            Err(e) => {
                UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                log(&format!("udp nat: dial_udp {orig_dst} 失败: {e}"));
                udp_neg_cache_put(guess);
                return None;
            }
        },
        Some(_) => {
            UDP_NAT_STATS
                .direct_fallback
                .fetch_add(1, Ordering::Relaxed);
            match outbound::Outbound::direct_udp(orig_dst) {
                Ok(r) => r,
                Err(e) => {
                    UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                    log(&format!("udp nat: 建直连出口失败: {e}"));
                    udp_neg_cache_put(guess);
                    return None;
                }
            }
        }
        None => match outbound::Outbound::direct_udp(orig_dst) {
            Ok(r) => r,
            Err(e) => {
                UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                log(&format!("udp nat: 建直连出口失败: {e}"));
                udp_neg_cache_put(guess);
                return None;
            }
        },
    };
    // P38：full-cone 仅直连型（代理型的实现是「会话即目标」）；QUIC 嗅探命中保持 affine。
    let full_cone = !quic && relay.is_plain();
    let key = UdpFlowKey {
        client,
        dst: if full_cone { None } else { Some(orig_dst) },
    };
    if let Some(s) = udp_sess_lookup(&key) {
        return Some(s);
    }
    if udp_neg_cache_hit(&key) {
        UDP_NAT_STATS.negcache_hits.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let _ = relay.set_read_timeout(Some(Duration::from_secs(2)));
    let ttl_secs = udp_ttl_secs(
        UDP_IDLE_SECS.load(Ordering::Relaxed),
        orig_dst.port(),
        quic,
        proxied_request,
    );
    let s = Arc::new(UdpSession {
        key,
        client,
        relay,
        last_ns: AtomicU64::new(monotonic_now_ns()),
        alive: AtomicBool::new(true),
        generation: current_datapath_generation(),
        ttl_secs,
        full_cone,
    });
    // 插入可能与其他线程竞争：已有则用已有的，新建的会话随 drop 关闭。
    match udp_nat_shard(&key).lock() {
        Ok(mut table) => match table.get(&key) {
            Some(prev) => Some(prev.clone()),
            None => {
                table.insert(key, s.clone());
                UDP_NAT_STATS.sessions_total.fetch_add(1, Ordering::Relaxed);
                if full_cone {
                    UDP_NAT_STATS.cone_sessions.fetch_add(1, Ordering::Relaxed);
                }
                let r = s.clone();
                std::thread::spawn(move || udp_session_reader(r));
                Some(s)
            }
        },
        Err(_) => None,
    }
}

/// P38：单包上行（full-cone 端点按包目标；affine 会话用固定目标）。
fn udp_sess_send_one(
    sess: &UdpSession,
    orig_dst: SocketAddr,
    data: &[u8],
) -> std::io::Result<usize> {
    if sess.full_cone {
        sess.relay.send_payload_to(orig_dst, data)
    } else {
        sess.relay.send_payload(data)
    }
}

/// O7：一批客户端报文——按会话聚合后批量上行（同会话顺序保持；跨会话重排不影响 UDP）。
fn udp_nat_handle_batch(entries: &[(&[u8], SocketAddr, SocketAddr)]) {
    if entries.is_empty() {
        return;
    }
    if entries.len() == 1 {
        let &(data, client, orig_dst) = &entries[0];
        if let Some(sess) = udp_nat_session(client, orig_dst, data) {
            sess.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
            match udp_sess_send_one(&sess, orig_dst, data) {
                Ok(n) => {
                    UDP_NAT_STATS
                        .bytes_up
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                    log(&format!("udp nat: 上行 {orig_dst} 失败: {e}"));
                }
            }
        }
        return;
    }
    let mut per_sess: Vec<(Arc<UdpSession>, Vec<(&[u8], SocketAddr)>)> = Vec::new();
    for &(data, client, orig_dst) in entries {
        let Some(sess) = udp_nat_session(client, orig_dst, data) else {
            continue;
        };
        sess.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
        if let Some((_, v)) = per_sess.iter_mut().find(|(s, _)| Arc::ptr_eq(s, &sess)) {
            v.push((data, orig_dst));
        } else {
            per_sess.push((sess, vec![(data, orig_dst)]));
        }
    }
    for (sess, items) in per_sess {
        let orig = sess.relay.target();
        // full-cone 端点：目标各异，逐包发送；affine：同目标批量。
        let r = if sess.full_cone {
            let mut total = 0usize;
            let mut err = None;
            for (data, dst) in &items {
                match sess.relay.send_payload_to(*dst, data) {
                    Ok(n) => total += n,
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            match err {
                None => Ok(total),
                Some(e) => Err(e),
            }
        } else {
            let datas: Vec<&[u8]> = items.iter().map(|(d, _)| *d).collect();
            sess.relay.send_batch(&datas)
        };
        match r {
            Ok(n) => {
                UDP_NAT_STATS
                    .bytes_up
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => {
                UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                log(&format!("udp nat: 上行 {orig} 失败: {e}"));
            }
        }
    }
}

/// UDP NAT janitor：空闲超过端点 TTL 的会话标记回收（reader 随之下线）。
/// P38：1s tick（对照 dae 250ms 基础扫描；1s 粒度足够）+ 逐会话 TTL + 负缓存清理。
fn udp_nat_janitor_loop() {
    let tick = Duration::from_secs(1);
    loop {
        std::thread::sleep(tick);
        let now = monotonic_now_ns();
        let mut dead: Vec<Arc<UdpSession>> = Vec::new();
        for shard in UDP_NAT.iter() {
            if let Ok(t) = shard.lock() {
                dead.extend(
                    t.iter()
                        .filter(|(_, s)| {
                            let ttl_ns = s.ttl_secs.saturating_mul(1_000_000_000);
                            now.saturating_sub(s.last_ns.load(Ordering::Relaxed)) > ttl_ns
                        })
                        .map(|(_, s)| s.clone()),
                );
            }
        }
        for s in dead {
            udp_nat_retire(&s);
        }
        // 负缓存过期项清理（防无界增长；正常条目由 hit 路径惰性清理）。
        if let Ok(mut g) = UDP_NEG_CACHE.lock() {
            g.retain(|_, t| t.elapsed() < UDP_NEG_CACHE_TTL);
        }
    }
}

// ---------------------------------------------------------------- P38：会话 abort

/// P38：abort 范围（对照 dae `AbortConnections` / `AbortGeneration` 的两种语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbortScope {
    /// `reload --abort`：只关「旧代」会话（代次 != 当前；对照 dae `AbortGeneration`）。
    OldGeneration,
    /// `suspend --abort`：关全部已建会话（dae suspend 的空配置换代等价于此）。
    All,
}

/// P38：单会话是否在 abort 范围内（纯函数，便于单测）。
fn abort_should_kill(scope: AbortScope, session_gen: u16, current_gen: u16) -> bool {
    match scope {
        AbortScope::All => true,
        AbortScope::OldGeneration => session_gen != current_gen,
    }
}

/// P38：关闭范围内的已建会话（TCP relay / reactor / UDP NAT）并清理对应 conn_state
/// （对照 dae `SessionManager.AbortGeneration`：先 TCP 后 UDP、逐流关 socket、再 scrub）。
/// 返回 (关闭会话数, 清理 conn_state 条数)。
/// A2 #9：统计在飞会话数（按 abort 范围：`OldGeneration` = 旧代）。
/// 对照 dae `control_plane_drain.go` 的 `drainTracker`（Acquire/Count/IdleCh）——
/// sodama 的语义等价物就是「会话登记表里尚存的旧代条目数」。
fn count_sessions(scope: AbortScope) -> usize {
    let cur = current_datapath_generation();
    let mut n = 0usize;
    if let Ok(g) = RELAY_CONNS.lock() {
        n += g
            .values()
            .filter(|h| abort_should_kill(scope, h.generation, cur))
            .count();
    }
    for shard in UDP_NAT.iter() {
        if let Ok(t) = shard.lock() {
            n += t
                .values()
                .filter(|s| abort_should_kill(scope, s.generation, cur))
                .count();
        }
    }
    n
}

/// A2 #9：**drain 预算**——reload 后等待旧代在飞会话自然结束（最长 `budget`），
/// 到期仍有余量则如实回报（不强制关闭；要强制请用 `--abort`）。
/// 返回 `(drained, waited_secs, remaining)`。
fn drain_old_generation(budget: Duration) -> (bool, f64, usize) {
    let t0 = Instant::now();
    let mut remaining = count_sessions(AbortScope::OldGeneration);
    while remaining > 0 && t0.elapsed() < budget {
        std::thread::sleep(Duration::from_millis(100));
        remaining = count_sessions(AbortScope::OldGeneration);
    }
    (remaining == 0, t0.elapsed().as_secs_f64(), remaining)
}

fn abort_sessions(ebpf: &mut Ebpf, scope: AbortScope) -> (usize, usize) {
    let cur = current_datapath_generation();
    // 1) 快照（持锁只收集，不执行关闭）
    let mut tcp: Vec<(u64, Arc<RelayHandle>)> = Vec::new();
    if let Ok(g) = RELAY_CONNS.lock() {
        for (id, h) in g.iter() {
            if abort_should_kill(scope, h.generation, cur) {
                tcp.push((*id, h.clone()));
            }
        }
    }
    let mut udp: Vec<Arc<UdpSession>> = Vec::new();
    for shard in UDP_NAT.iter() {
        if let Ok(t) = shard.lock() {
            for s in t.values() {
                if abort_should_kill(scope, s.generation, cur) {
                    udp.push(s.clone());
                }
            }
        }
    }
    // 2) 执行关闭：先 TCP 后 UDP（对照 dae 的顺序）
    let mut killed = 0usize;
    let mut scrubbed = 0usize;
    for (id, h) in &tcp {
        if h.reactor_managed {
            reactor::kill(*id);
        }
        if let Some(c) = &h.client {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        if let Some(u) = &h.upstream {
            let _ = u.shutdown(std::net::Shutdown::Both);
        }
        h.stop.store(true, Ordering::Relaxed);
        if let Some((client, orig)) = h.conn_key {
            if remove_conn_state(ebpf, client, orig, 6) {
                scrubbed += 1;
            }
        }
        killed += 1;
    }
    for s in &udp {
        udp_nat_retire(s);
        if remove_conn_state(ebpf, s.client, s.relay.target(), 17) {
            scrubbed += 1;
        }
        killed += 1;
    }
    (killed, scrubbed)
}

/// P38：删除单条 conn_state（abort 用；best-effort，找不到/无 map 返回 false）。
fn remove_conn_state(
    ebpf: &mut Ebpf,
    client: SocketAddr,
    orig_dst: SocketAddr,
    l4proto: u8,
) -> bool {
    let Some(key) = sodama_tuple_of_proto(client, orig_dst, l4proto) else {
        return false;
    };
    let Some(map) = ebpf.map_mut("conn_state_map") else {
        return false;
    };
    let Ok(mut conn_state) = HashMap::<_, SodaTuple, SodaConnState>::try_from(map) else {
        return false;
    };
    conn_state.remove(&key).is_ok()
}

// ---------------------------------------------------------------- K3：子命令

fn run_subcommand(argv: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // 子命令的 stdout 留给数据（JSON/文本），诊断信息一律 stderr。
    LOG_STDERR.store(true, std::sync::atomic::Ordering::Relaxed);
    match argv[1].as_str() {
        // A2 #5：`export outline`（对照 dae `config.ExportOutlineJson`）——机器可读的
        // 配置 schema（供 UI/面板开发者），与 `config-doc` 同源（`key_docs()` 登记表）。
        "export" => match argv.get(2).map(|s| s.as_str()) {
            Some("outline") => {
                println!("{}", serde_json::to_string_pretty(&export_outline_json())?);
                Ok(())
            }
            other => Err(format!(
                "用法: sodama export outline（未知子命令 {}；dae 仅有 outline）",
                other.unwrap_or("<无>")
            )
            .into()),
        },
        "validate" | "export-config" | "extract-routing" => {
            let path = argv
                .get(2)
                .ok_or("用法: sodama validate|export-config|extract-routing <config.dae>")?;
            let cfg = config::load(Path::new(path))
                .map_err(|diags| format!("解析失败:\n{}", render_diags(&diags)))?;
            match argv[1].as_str() {
                "validate" => {
                    println!("entry: {}", cfg.entry.display());
                    println!("files: {}", cfg.files.len());
                    for f in &cfg.files {
                        println!("  - {}", f.display());
                    }
                    println!("sections:");
                    for sec in &cfg.sections {
                        let rules = sec
                            .items
                            .iter()
                            .filter(|i| matches!(i, config::Item::Rule(_)))
                            .count();
                        let params = sec
                            .items
                            .iter()
                            .filter(|i| matches!(i, config::Item::Param(_)))
                            .count();
                        let subs = sec
                            .items
                            .iter()
                            .filter(|i| matches!(i, config::Item::Section(_)))
                            .count();
                        println!(
                            "  {:<12} rules={rules} params={params} subsections={subs}",
                            sec.name
                        );
                    }
                    let diags = config::validate(&cfg);
                    if !diags.is_empty() {
                        for d in &diags {
                            eprintln!("{d}");
                        }
                        return Err(format!("schema 校验失败（{} 条）", diags.len()).into());
                    }
                    println!("OK: schema 校验通过");
                    match config::extract_routing(&cfg) {
                        Ok(ex) => {
                            println!(
                                "routing: {} 条可编译, {} 条 deferred",
                                ex.supported.len(),
                                ex.deferred.len()
                            );
                            for d in &ex.deferred {
                                let file = cfg
                                    .files
                                    .get(d.loc.file)
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_default();
                                println!(
                                    "  deferred {file}:{}: {} — {}",
                                    d.loc.line, d.rule, d.reason
                                );
                            }
                            // 与运行时保持一致：0 条可编译规则时引擎拒启，validate 也报错
                            if ex.supported.is_empty() {
                                return Err("routing 段没有任何可编译规则（引擎会拒绝启动；\
                                    至少留一条规则，例如 dip(192.168.0.0/16) -> direct）"
                                    .into());
                            }
                            Ok(())
                        }
                        Err(diags) => {
                            for d in &diags {
                                eprintln!("{d}");
                            }
                            Err("路由段提取失败".into())
                        }
                    }
                }
                "export-config" => {
                    println!("{}", serde_json::to_string_pretty(&config::to_json(&cfg))?);
                    Ok(())
                }
                _ => {
                    let ex = config::extract_routing(&cfg)
                        .map_err(|diags| format!("路由段提取失败:\n{}", render_diags(&diags)))?;
                    for line in &ex.supported {
                        println!("{line}");
                    }
                    if let Some(fb) = &ex.fallback {
                        println!("fallback -> {fb}");
                    }
                    for d in &ex.deferred {
                        eprintln!("deferred: {} — {}", d.rule, d.reason);
                    }
                    Ok(())
                }
            }
        }
        "status" => {
            let mut sock = "/tmp/sodama-status.sock".to_string();
            let mut raw = false;
            let mut cmd = "status".to_string();
            let mut it = argv.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--socket" => {
                        sock = it.next().ok_or("--socket 需要值")?.clone();
                    }
                    "--cmd" => {
                        cmd = it.next().ok_or("--cmd 需要值")?.clone();
                    }
                    "--json" => raw = true,
                    other => return Err(format!("未知参数 {other}").into()),
                }
            }
            let resp = status::client(Path::new(&sock), &cmd)?;
            if raw {
                println!("{resp}");
            } else {
                print_status_human(&resp)?;
            }
            Ok(())
        }
        "reload" | "suspend" | "resume" => {
            // P38：`--abort`（对照 dae `reload/suspend --abort`）——随命令发给守护进程。
            // A2 #9：`--drain <secs>` / `--drain=<secs>`（仅 reload 有意义）——等旧代
            // 在飞会话自然排空的预算（对照 dae `control_plane_drain.go` 的 drain 语义）。
            let abort = argv.iter().any(|a| a == "--abort");
            let mut drain_secs = 0u64;
            let mut filtered: Vec<String> = Vec::new();
            let mut it = argv.iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--abort" => {}
                    "--drain" => {
                        drain_secs = it.next().ok_or("--drain 需要秒数")?.parse()?;
                    }
                    other => {
                        if let Some(v) = other.strip_prefix("--drain=") {
                            drain_secs = v.parse()?;
                        } else {
                            filtered.push(other.to_string());
                        }
                    }
                }
            }
            let (sock, _) = parse_socket_args(&filtered, 2)?;
            let cmd = reload_cmd(&argv[1], abort, drain_secs);
            let resp = status::client(Path::new(&sock), &cmd)?;
            println!("{resp}");
            let bad = serde_json::from_str::<serde_json::Value>(&resp)
                .ok()
                .map(|v| {
                    v.get("error").map(|e| !e.is_null()).unwrap_or(false)
                        || v.get("ok") == Some(&serde_json::Value::Bool(false))
                })
                .unwrap_or(false);
            if bad {
                std::process::exit(1);
            }
            Ok(())
        }
        "metrics" => {
            let (sock, _) = parse_socket_args(argv, 2)?;
            let resp = status::client(Path::new(&sock), "metrics")?;
            println!("{resp}");
            Ok(())
        }
        "sub-parse" => {
            // 只读：拉取订阅 → base64/明文解码 → 逐行解析节点。不加载 eBPF、不改配置。
            // 面板「导入订阅」前的解析预览就靠这一步（复用运行时同一套解析逻辑）。
            let mut src = String::new();
            let mut tag = "sub".to_string();
            let mut timeout = 15u64;
            let mut limit = 200usize;
            let mut json_out = false;
            let mut it = argv.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--tag" => tag = it.next().ok_or("--tag 需要值")?.clone(),
                    "--timeout" => timeout = it.next().ok_or("--timeout 需要值")?.parse()?,
                    "--limit" => limit = it.next().ok_or("--limit 需要值")?.parse()?,
                    "--json" => json_out = true,
                    other if src.is_empty() && !other.starts_with("--") => src = other.to_string(),
                    other => return Err(format!("未知参数 {other}").into()),
                }
            }
            if src.is_empty() {
                return Err(
                    "用法: sodama sub-parse <url|path> [--tag <t>] [--timeout <s>] [--limit <n>] [--json]"
                        .into(),
                );
            }
            let timeout = Duration::from_secs(timeout.clamp(1, 120));
            let started = std::time::Instant::now();
            let body = subscribe::fetch(&src, timeout).map_err(|e| format!("拉取订阅失败: {e}"))?;
            let plain = String::from_utf8_lossy(&body).into_owned();
            let text =
                subscribe::decode_body(&body).map_err(|e| format!("订阅正文解码失败: {e}"))?;
            let format = if text == plain {
                if subscribe::is_sip008(&text) {
                    "sip008"
                } else {
                    "plain"
                }
            } else {
                "base64"
            };
            let (nodes, errors) = subscribe::parse_subscription(&text, &tag);
            let mut protos: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for n in &nodes {
                *protos.entry(n.outbound.protocol()).or_default() += 1;
            }
            let elapsed_ms = started.elapsed().as_millis() as u64;
            let take = if limit == 0 {
                nodes.len()
            } else {
                limit.min(nodes.len())
            };
            if json_out {
                let list: Vec<serde_json::Value> = nodes
                    .iter()
                    .take(take)
                    .map(|n| {
                        json!({
                            "name": n.name,
                            "protocol": n.outbound.protocol(),
                            "addr": n.outbound.server_addr().map(|a| a.to_string()),
                            "detail": n.outbound.name(),
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "ok": true,
                        "tag": tag,
                        "source": src,
                        "bytes": body.len(),
                        "format": format,
                        "count": nodes.len(),
                        "protocols": protos,
                        "nodes": list,
                        "truncated": nodes.len() > take,
                        "errors": errors,
                        "elapsed_ms": elapsed_ms,
                    }))?
                );
            } else {
                println!("tag: {tag}");
                println!("source: {src}");
                println!("bytes: {}（{format}）", body.len());
                println!("nodes: {}（{elapsed_ms} ms）", nodes.len());
                let ps: Vec<String> = protos.iter().map(|(k, v)| format!("{k} {v}")).collect();
                println!("protocols: {}", ps.join(", "));
                for n in nodes.iter().take(take) {
                    println!(
                        "  - {} [{}] {}",
                        n.name,
                        n.outbound.protocol(),
                        n.outbound.name()
                    );
                }
                if nodes.len() > take {
                    println!("  … 其余 {} 个节点（--limit 0 看全部）", nodes.len() - take);
                }
                for e in &errors {
                    println!("  ! {e}");
                }
            }
            Ok(())
        }
        "sysdump" => {
            // A2 #4：现场归档（对照 dae `dae sysdump`）——状态面 JSON + 系统网络现场
            // （路由/网卡/sysctl/nft/iptables/邻居）打包为 `.tar.gz`。
            // `--json` 保留旧行为（单份 JSON，便于管道消费）。
            let mut sock = "/tmp/sodama-status.sock".to_string();
            let mut out: Option<String> = None;
            let mut json_only = false;
            let mut it = argv.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--socket" => sock = it.next().ok_or("--socket 需要值")?.clone(),
                    "--out" => out = Some(it.next().ok_or("--out 需要值")?.clone()),
                    "--json" => json_only = true,
                    other => return Err(format!("未知参数 {other}").into()),
                }
            }
            let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
            for key in ["status", "rules", "config", "maps"] {
                let val = match status::client(Path::new(&sock), key) {
                    Ok(resp) => serde_json::from_str::<serde_json::Value>(&resp)
                        .unwrap_or_else(|_| json!(resp)),
                    Err(e) => json!({"error": e.to_string()}),
                };
                entries.push((format!("{key}.json"), serde_json::to_vec_pretty(&val)?));
            }
            entries.push((
                "system.json".into(),
                serde_json::to_vec_pretty(&system_info_json())?,
            ));
            if json_only {
                let mut map = serde_json::Map::new();
                map.insert("generated_at_sec".into(), json!(unix_now_sec()));
                for (name, data) in &entries {
                    let key = name.trim_end_matches(".json").to_string();
                    map.insert(key, serde_json::from_slice(data).unwrap_or(json!(null)));
                }
                let text = serde_json::to_string_pretty(&serde_json::Value::Object(map))?;
                match out {
                    Some(path) => {
                        std::fs::write(&path, &text)?;
                        eprintln!("sysdump -> {path}（JSON）");
                    }
                    None => println!("{text}"),
                }
                return Ok(());
            }
            // 系统网络现场（外部命令缺失/失败均如实记录，不中断归档）。
            for (name, prog, cargs) in [
                (
                    "net/routes.txt",
                    "ip",
                    &["-o", "route", "show", "table", "all"][..],
                ),
                ("net/addresses.txt", "ip", &["-o", "addr", "show"][..]),
                ("net/links.txt", "ip", &["-o", "-s", "link", "show"][..]),
                ("net/neigh.txt", "ip", &["-o", "neigh", "show"][..]),
                ("net/netfilter-nft.txt", "nft", &["list", "ruleset"][..]),
                ("net/iptables-save.txt", "iptables-save", &[][..]),
                ("net/ip6tables-save.txt", "ip6tables-save", &[][..]),
            ] {
                entries.push((name.into(), sysdump_cmd(prog, cargs).into_bytes()));
            }
            entries.push(("net/sysctl-net.txt".into(), sysdump_sysctl_net()));
            entries.push(("version.txt".into(), version_text().into_bytes()));
            entries.push((
                "README.txt".into(),
                "sodama sysdump：status/rules/config/maps + system + 现场（ip/nft/iptables/sysctl）。\n"
                    .as_bytes()
                    .to_vec(),
            ));
            let now = unix_now_sec();
            let mut tar = dump::TarWriter::new();
            for (name, data) in &entries {
                tar.add(name, data, now);
            }
            let gz = dump::gzip_store(&tar.finish());
            let path = out.unwrap_or_else(|| format!("sodama-sysdump.{now}.tar.gz"));
            std::fs::write(&path, &gz)?;
            println!(
                "sysdump -> {path}（{} 文件，{} 字节；`tar xzf` 查看）",
                entries.len(),
                gz.len()
            );
            Ok(())
        }
        "trace" => {
            // A2 #3：`trace`——向守护进程开一个短时 trace 会话（数据面已在判决策做
            // 内核侧筛选），随后读守护进程写的 trace 文件并做展示层过滤。
            // 对照 dae `trace -4/-6 -p tcp|udp -P <port> --drop-only -o <file>`。
            let mut secs = 5u64;
            let mut v4 = false;
            let mut v6 = false;
            let mut l4: Option<String> = None;
            let mut port: Option<u16> = None;
            let mut drop_only = false;
            let mut out: Option<String> = None;
            let mut sock = "/tmp/sodama-status.sock".to_string();
            let mut it = argv.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--seconds" => secs = it.next().ok_or("--seconds 需要值")?.parse()?,
                    "-4" | "--ipv4" => v4 = true,
                    "-6" | "--ipv6" => v6 = true,
                    "-p" | "--l4-proto" => {
                        let v = it.next().ok_or("--l4-proto 需要值（tcp|udp）")?;
                        match v.as_str() {
                            "tcp" | "udp" => l4 = Some(v.clone()),
                            other => return Err(format!("未知 L4 协议 {other}（tcp|udp）").into()),
                        }
                    }
                    "-P" | "--port" => port = Some(it.next().ok_or("--port 需要值")?.parse()?),
                    "--drop-only" => drop_only = true,
                    "-o" | "--output" => out = Some(it.next().ok_or("-o 需要值")?.clone()),
                    "--socket" => sock = it.next().ok_or("--socket 需要值")?.clone(),
                    other => return Err(format!("未知参数 {other}").into()),
                }
            }
            if v4 && v6 {
                return Err("--ipv4 与 --ipv6 不能同时指定（对照 dae trace）".into());
            }
            let ipver = if v6 {
                2
            } else if v4 {
                1
            } else {
                0
            };
            let l4no = match l4.as_deref() {
                Some("tcp") => 6u32,
                Some("udp") => 17u32,
                _ => 0u32,
            };
            let mut cmd = format!("trace secs={secs} ipver={ipver}");
            if l4no != 0 {
                cmd.push_str(&format!(" l4={l4no}"));
            }
            if let Some(p) = port {
                cmd.push_str(&format!(" port={p}"));
            }
            if drop_only {
                cmd.push_str(" drop_only=1");
            }
            let resp = status::client(Path::new(&sock), &cmd)
                .map_err(|e| format!("无法连接守护进程（{sock}）：{e}"))?;
            let v: serde_json::Value = serde_json::from_str(&resp).unwrap_or(json!({}));
            if v.get("ok").and_then(|b| b.as_bool()) != Some(true) {
                return Err(format!(
                    "守护进程拒绝 trace：{}",
                    v.get("error").and_then(|s| s.as_str()).unwrap_or(&resp)
                )
                .into());
            }
            let secs = v.get("seconds").and_then(|x| x.as_u64()).unwrap_or(secs);
            let file = v
                .get("file")
                .and_then(|x| x.as_str())
                .ok_or("回执缺 file 字段（旧守护进程？）")?
                .to_string();
            let filters = TraceFilters {
                v4_only: v4,
                v6_only: v6,
                l4: l4.clone(),
                port,
                drop_only,
            };
            let mut writer: Box<dyn std::io::Write> = match &out {
                Some(p) => Box::new(std::fs::File::create(p)?),
                None => Box::new(std::io::stdout()),
            };
            let shown =
                stream_trace_lines(&file, Duration::from_secs(secs), &filters, &mut writer)?;
            if let Some(p) = &out {
                eprintln!("trace -> {p}（{shown} 行）");
            } else {
                eprintln!("trace: 会话结束（{shown} 行；产出于 {file}）");
            }
            Ok(())
        }
        "dns-bench" => run_dns_bench(argv),
        "config-doc" => run_config_doc(argv),
        "completion" => run_completion(argv),
        _ => unreachable!(),
    }
}

/// P38：补全用的子命令清单（与 `main()` 的分派表保持一致）。
const COMPLETION_SUBCOMMANDS: &[&str] = &[
    "validate",
    "export-config",
    "export",
    "extract-routing",
    "status",
    "reload",
    "suspend",
    "resume",
    "metrics",
    "sub-parse",
    "sysdump",
    "trace",
    "dns-bench",
    "completion",
];

/// P38：补全用的顶层参数清单（与 `parse_args()` 的 match 保持一致）。
const COMPLETION_FLAGS: &[&str] = &[
    "--ebpf",
    "--lan",
    "--wan",
    "--dual",
    "--dae0",
    "--dae0peer",
    "--daens",
    "--tproxy-port",
    "--rules",
    "--config",
    "--strict-config",
    "--status-socket",
    "--log-file",
    "--watch-config",
    "--dialer",
    "--relay-idle-timeout",
    "--dial-timeout",
    "--dial-mode",
    "--sniffing-timeout-ms",
    "--sniff-punt",
    "--disable-timestamp",
    "--disable-pidfile",
    "--subscribe",
    "--geodata-dir",
    "--group",
    "--listen-socks",
    "--udp-idle-timeout",
    "--forward",
    "--offload",
    "--link-hdr",
    "--xdp",
    "--no-splice",
    "--ebpf-debug",
    "--ktls",
    "--max-conns",
    "--dns-upstream",
    "--dump",
    "--compile-dump",
    "--proxy",
    "--help",
];

const COMPLETION_BASH: &str = r##"# sodama bash completion（由 `sodama completion bash` 生成）
_sodama() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local subcmds="@SUBCMDS@"
    local flags="@FLAGS@"
    case "$prev" in
        --config|--rules|--ebpf|--log-file|--status-socket|--compile-dump|--listen-socks)
            COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
        --dial-mode) COMPREPLY=( $(compgen -W "ip domain domain+ domain++" -- "$cur") ); return ;;
        --link-hdr) COMPREPLY=( $(compgen -W "auto l2 l3" -- "$cur") ); return ;;
        --lan|--wan|--dual|--xdp|--dae0|--dae0peer)
            COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") ); return ;;
    esac
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") ); return
    fi
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcmds" -- "$cur") ); return
    fi
    case "${COMP_WORDS[1]}" in
        completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
        status) COMPREPLY=( $(compgen -W "--socket --cmd --json" -- "$cur") ) ;;
        reload|suspend|resume) COMPREPLY=( $(compgen -W "--socket --abort --drain=" -- "$cur") ) ;;
        metrics) COMPREPLY=( $(compgen -W "--socket" -- "$cur") ) ;;
        sysdump) COMPREPLY=( $(compgen -W "--socket --out" -- "$cur") ) ;;
        sub-parse) COMPREPLY=( $(compgen -W "--tag --timeout --limit --json" -- "$cur") ) ;;
        trace) COMPREPLY=( $(compgen -W "--seconds" -- "$cur") ) ;;
        dns-bench) COMPREPLY=( $(compgen -W "--config --names --tags --runs --rounds --concurrency --client" -- "$cur") ) ;;
        validate|export-config|extract-routing) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
    esac
}
complete -F _sodama sodama
"##;

const COMPLETION_ZSH: &str = r##"#compdef sodama
# sodama zsh completion（由 `sodama completion zsh` 生成）
_sodama() {
    local -a subcmds flags
    subcmds=(@SUBCMDS@)
    flags=(@FLAGS@)
    if (( CURRENT == 2 )); then
        _describe -t commands "子命令" subcmds
        _describe -t options "参数" flags
        return
    fi
    case "${words[2]}" in
        completion) _values "shell" bash zsh fish ;;
        status) _values "参数" --socket --cmd --json ;;
        reload|suspend|resume) _values "参数" --socket --abort --drain ;;
        metrics) _values "参数" --socket ;;
        sysdump) _values "参数" --socket --out ;;
        sub-parse) _values "参数" --tag --timeout --limit --json ;;
        trace) _values "参数" --seconds ;;
        dns-bench) _values "参数" --config --names --tags --runs --rounds --concurrency --client ;;
        validate|export-config|extract-routing) _files ;;
        *)
            case "${words[CURRENT]}" in
                -*) _describe -t options "参数" flags ;;
                *) _files ;;
            esac ;;
    esac
}
_sodama "$@"
"##;

/// 生成指定 shell 的补全脚本（对照 dae `completion [bash|zsh|fish]`；输出到 stdout）。
fn completion_script(shell: &str) -> Option<String> {
    let subcmds = COMPLETION_SUBCOMMANDS.join(" ");
    let flags = COMPLETION_FLAGS.join(" ");
    match shell {
        "bash" => Some(
            COMPLETION_BASH
                .replace("@SUBCMDS@", &subcmds)
                .replace("@FLAGS@", &flags),
        ),
        "zsh" => Some(
            COMPLETION_ZSH
                .replace("@SUBCMDS@", &subcmds)
                .replace("@FLAGS@", &flags),
        ),
        "fish" => {
            let mut s = String::from(
                "# sodama fish completion（由 `sodama completion fish` 生成）\ncomplete -c sodama -f\n",
            );
            s.push_str(&format!(
                "complete -c sodama -n __fish_use_subcommand -a \"{subcmds}\"\n"
            ));
            for f in COMPLETION_FLAGS {
                if *f == "--help" {
                    s.push_str("complete -c sodama -s h -l help -d \"显示帮助\"\n");
                    continue;
                }
                let name = f.trim_start_matches('-');
                s.push_str(&format!("complete -c sodama -l {name}\n"));
            }
            Some(s)
        }
        _ => None,
    }
}

/// A2 #1：版本信息文本（`--version` / sysdump 的 version.txt 共用）。
/// git sha / 构建 profile 由 `build.rs` 尽力注入（无 git 时为 unknown）。
fn version_text() -> String {
    format!(
        "{}\nrust {} {}/{}\nCopyright (c) 2026 sodama project\nLicense GNU AGPLv3 <https://www.gnu.org/licenses/agpl-3.0.html>\n",
        env!("SODAMA_VERSION_FULL", "sodama unknown"),
        env!("SODAMA_BUILD_PROFILE", "unknown"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// A2 #1：`--version` 输出（对照 dae rootCmd.Version 的多行格式：版本 + 运行时/平台 + 许可）。
fn print_version() {
    print!("{}", version_text());
}

/// A2 #4：跑一条取证命令（挂起最多 5s；缺失/失败如实记录）。
fn sysdump_cmd(prog: &str, args: &[&str]) -> String {
    use std::process::{Command, Stdio};
    let mut child = match Command::new(prog)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return format!("（{prog} 不可用: {e}）\n"),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                return format!("（{prog} 超时 5s，已终止）\n");
            }
        }
    }
    match child.wait_with_output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            if !o.stderr.is_empty() {
                s.push_str("\n# stderr:\n");
                s.push_str(&String::from_utf8_lossy(&o.stderr));
            }
            if !o.status.success() {
                s.push_str(&format!("\n# 退出码: {:?}\n", o.status.code()));
            }
            s
        }
        Err(e) => format!("（{prog} 读取输出失败: {e}）\n"),
    }
}

/// A2 #4：遍历 `/proc/sys/net`（全部 net sysctl，路径 = `net/...`）。
/// 读不到的条目跳过（procfs 条目可能瞬态消失）。
fn sysdump_sysctl_net() -> Vec<u8> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut String) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                walk(&p, base, out);
            } else if let Ok(txt) = std::fs::read_to_string(&p) {
                let rel = p.strip_prefix(base).unwrap_or(&p).display().to_string();
                out.push_str(&format!("{rel} = {}\n", txt.trim()));
            }
        }
    }
    let base = std::path::Path::new("/proc/sys/net");
    let mut out = String::new();
    walk(base, base, &mut out);
    out.into_bytes()
}

/// A2 #5：`export outline`——配置 schema（机器可读，供 UI/面板开发者）。
/// 与 `config-doc --format json` 同源（`config::key_docs()` 登记表）；
/// 额外带上版本与生成器标识，字段结构与 dae `ExportOutlineJson` 同一用途（用途同、字段名可不同）。
fn export_outline_json() -> serde_json::Value {
    let mut sections: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for k in config::key_docs() {
        let sec = sections
            .entry(k.section.to_string())
            .or_insert_with(|| json!({}));
        if let Some(m) = sec.as_object_mut() {
            m.insert(
                k.key.to_string(),
                json!({
                    "desc": k.desc,
                    "default": k.default,
                    "consumed": k.consumed,
                }),
            );
        }
    }
    // 段清单（与 config.rs 的 KNOWN_SECTIONS 同源，保证 UI 能列全所有段）。
    let known: Vec<&str> = config::KNOWN_SECTIONS.to_vec();
    json!({
        "outline": "sodama-config",
        "version": env!("SODAMA_VERSION_FULL", env!("CARGO_PKG_VERSION")),
        "generator": "sodama export outline（schema 登记表：loader/src/config.rs key_docs()）",
        "sections": sections,
        "known_sections": known,
    })
}

/// A2 #3：trace 展示层过滤器（内核侧已按同一条件筛过；此处为用户终态过滤 +
/// `-o` 重定向服务，两侧一致由单测锁定）。
#[derive(Debug, Default, Clone)]
struct TraceFilters {
    v4_only: bool,
    v6_only: bool,
    l4: Option<String>,
    port: Option<u16>,
    drop_only: bool,
}

/// 一行 trace 的解析结果（只取过滤需要的字段；其余保留原文打印）。
#[derive(Debug, PartialEq, Eq)]
struct TraceLine {
    v: u8,
    l4: String,
    sport: u16,
    dport: u16,
    act: String,
}

/// 解析 `format_trace_line` 产出的行（键值对自描述；未知/损坏行 → None 不打印）。
fn parse_trace_line(line: &str) -> Option<TraceLine> {
    let mut v = None;
    let mut l4 = None;
    let mut sport = None;
    let mut dport = None;
    let mut act = None;
    for kv in line.split_whitespace() {
        // 首列是时间戳（无 `=`）——跳过而非报错；必填字段在末尾统一验证。
        let Some((k, val)) = kv.split_once('=') else {
            continue;
        };
        match k {
            "v" => v = val.parse::<u8>().ok(),
            "l4" => l4 = Some(val.to_string()),
            "sport" => sport = val.parse::<u16>().ok(),
            "dport" => dport = val.parse::<u16>().ok(),
            "act" => act = Some(val.to_string()),
            _ => {}
        }
    }
    Some(TraceLine {
        v: v?,
        l4: l4?,
        sport: sport?,
        dport: dport?,
        act: act?,
    })
}

/// 展示层过滤（与数据面 `trace_filter_map` 同语义）。
fn trace_line_matches(tl: &TraceLine, f: &TraceFilters) -> bool {
    if f.v4_only && tl.v != 4 {
        return false;
    }
    if f.v6_only && tl.v != 6 {
        return false;
    }
    if let Some(l4) = &f.l4 {
        if &tl.l4 != l4 {
            return false;
        }
    }
    if let Some(p) = f.port {
        if tl.sport != p && tl.dport != p {
            return false;
        }
    }
    if f.drop_only && tl.act != "shot" {
        return false;
    }
    true
}

/// 读 trace 文件并过滤打印（轮询读；截止后把剩余读完）。返回匹配行数。
fn stream_trace_lines(
    file: &str,
    window: Duration,
    filters: &TraceFilters,
    out: &mut dyn std::io::Write,
) -> Result<u64, Box<dyn std::error::Error>> {
    use std::io::Read as _;
    // 守护进程在会话开始时截断/新建文件：等它出现（最多 2s）。
    let mut f = {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match std::fs::File::open(file) {
                Ok(f) => break f,
                Err(e) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                    let _ = e;
                }
                Err(e) => return Err(format!("打开 trace 文件 {file} 失败: {e}").into()),
            }
        }
    };
    let deadline = Instant::now() + window + Duration::from_millis(300);
    let mut pending = String::new();
    let mut buf = [0u8; 16 * 1024];
    let mut shown = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n > 0 {
            pending.push_str(&String::from_utf8_lossy(&buf[..n]));
            while let Some(pos) = pending.find('\n') {
                let line = pending[..pos].to_string();
                pending.drain(..=pos);
                if let Some(tl) = parse_trace_line(&line) {
                    if trace_line_matches(&tl, filters) {
                        writeln!(out, "{line}")?;
                        shown += 1;
                    }
                }
            }
            continue;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(shown)
}

/// A2 #3：trace 解析/过滤单测（展示层与数据面同语义；行格式由 `format_trace_line` 锁定）。
#[cfg(test)]
mod trace_tests {
    use super::*;

    #[test]
    fn parse_and_filter_trace_line() {
        let line = "18:31:02 v=4 l4=tcp sip=10.0.0.2 sport=41000 dip=1.1.1.1 dport=443 outbound=0x2 act=redir";
        let tl = parse_trace_line(line).expect("应可解析");
        assert_eq!(tl.v, 4);
        assert_eq!(tl.l4, "tcp");
        assert_eq!(tl.sport, 41000);
        assert_eq!(tl.dport, 443);
        assert_eq!(tl.act, "redir");
        // 空过滤：全过
        assert!(trace_line_matches(&tl, &TraceFilters::default()));
        // -4 且是 v4 → 过；-6 → 不过
        assert!(trace_line_matches(
            &tl,
            &TraceFilters {
                v4_only: true,
                ..Default::default()
            }
        ));
        assert!(!trace_line_matches(
            &tl,
            &TraceFilters {
                v6_only: true,
                ..Default::default()
            }
        ));
        // 端口：sport 或 dport 任一命中
        assert!(trace_line_matches(
            &tl,
            &TraceFilters {
                port: Some(443),
                ..Default::default()
            }
        ));
        assert!(!trace_line_matches(
            &tl,
            &TraceFilters {
                port: Some(80),
                ..Default::default()
            }
        ));
        // drop-only：redir 不过
        assert!(!trace_line_matches(
            &tl,
            &TraceFilters {
                drop_only: true,
                ..Default::default()
            }
        ));
        // 损坏行（缺字段）→ None（不打印）；非键值行（分隔线）同理
        assert!(parse_trace_line("v=4 l4=tcp sip=1.1.1.1").is_none());
        assert!(parse_trace_line("kernel: something").is_none());
    }

    #[test]
    fn trace_line_stream_filter() {
        let dir = std::env::temp_dir().join(format!("sodama-trace-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("trace.log");
        std::fs::write(
            &path,
            "18:31:02 v=4 l4=tcp sip=10.0.0.2 sport=41000 dip=1.1.1.1 dport=443 outbound=0x2 act=redir\n\
             18:31:03 v=6 l4=udp sip=2001:db8::1 sport=5353 dip=2001:db8::2 dport=53 outbound=0x1 act=shot\n",
        )
        .unwrap();
        let mut out: Vec<u8> = Vec::new();
        let n = stream_trace_lines(
            path.to_str().unwrap(),
            Duration::from_millis(0),
            &TraceFilters {
                drop_only: true,
                ..Default::default()
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 1);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("act=shot") && !s.contains("act=redir"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// P38：`sodama config-doc [--format md|json] [--out <file>]`：输出配置参考
///（对照 dae `hack/ci` 的配置文档生成器；`docs/config-reference.md` 由此生成）。
fn run_config_doc(argv: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut format = "md".to_string();
    let mut out_path: Option<String> = None;
    let mut it = argv.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--format" => format = it.next().ok_or("--format 需要值")?.clone(),
            "--out" => out_path = Some(it.next().ok_or("--out 需要值")?.clone()),
            other => return Err(format!("未知参数 {other}").into()),
        }
    }
    let text = match format.as_str() {
        "md" => config_doc_markdown(),
        "json" => {
            let list: Vec<serde_json::Value> = config::key_docs()
                .iter()
                .map(|k| {
                    json!({
                        "section": k.section,
                        "key": k.key,
                        "desc": k.desc,
                        "default": k.default,
                        "consumed": k.consumed,
                    })
                })
                .collect();
            serde_json::to_string_pretty(&list)? + "\n"
        }
        other => return Err(format!("--format 取值非法: {other}（md|json）").into()),
    };
    match out_path {
        Some(p) => {
            std::fs::write(&p, &text)?;
            eprintln!("config-doc -> {p}");
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// P38：配置参考的 markdown 渲染（分组 + 生效面标记；生成物与单测锁定同步）。
fn config_doc_markdown() -> String {
    let mut out = String::new();
    out.push_str("# sodama 配置参考（自动生成，不要手工编辑）\n\n");
    out.push_str("由 `sodama config-doc` 从 `loader/src/config.rs` 的 `key_docs()` 生成；");
    out.push_str("修改请改登记表并重新生成（`cargo test` 的 drift 用例会锁定同步）。\n\n");
    out.push_str("「生效」列：✅ = 键有消费点；⚠️ = 解析通过但当前无消费点——");
    out.push_str("不把解析写成生效（口径见 `docs/capability-gap-review.md` §2）。\n\n");
    for section in ["global", "dns", "group"] {
        out.push_str(&format!("## {section}\n\n"));
        out.push_str("| 键 | 说明 | 默认 | 生效 |\n|---|---|---|---|\n");
        for k in config::key_docs().iter().filter(|k| k.section == section) {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                k.key,
                k.desc,
                if k.default.is_empty() {
                    "—".to_string()
                } else {
                    format!("`{}`", k.default)
                },
                if k.consumed {
                    "✅"
                } else {
                    "⚠️ 无消费点"
                },
            ));
        }
        out.push('\n');
    }
    out.push_str("## 其它段\n\n");
    out.push_str(
        "`include` / `routing` / `subscription` / `node` / `rule_set` / `dns.fixed_domain_ttl` ",
    );
    out.push_str(
        "见 `docs/deploy.md`、`sodama/lab/gateway.dae` 示例与 `docs/capability-gap-review.md`。\n",
    );
    out
}

/// P38：`sodama completion [bash|zsh|fish]`（对照 dae completion 子命令）。
fn run_completion(argv: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let shell = argv.get(2).map(|s| s.as_str()).unwrap_or("");
    match completion_script(shell) {
        Some(s) => {
            print!("{s}");
            Ok(())
        }
        None => Err("用法: sodama completion [bash|zsh|fish]".into()),
    }
}

/// P18c+：`dns-bench`——对配置里的上游做同域名延迟对比（A/B）。
/// 工具用：需 root（上游 socket 打 SO_MARK，避免被运行中的网关自己接管）。
///
/// 用法： sodama dns-bench --config <file.dae> --names a.com,b.com
///        [--tags t1,t2] [--runs N] [--client <IP>]
/// `--client` 供 `ecs=auto` 上游注入子网（缺省不注入）。
fn run_dns_bench(argv: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg: Option<String> = None;
    let mut names: Vec<String> = Vec::new();
    let mut tags: Vec<String> = Vec::new();
    let mut runs = 5usize;
    let mut rounds = 1usize;
    let mut concurrency = 1usize;
    let mut client: Option<std::net::IpAddr> = None;
    let mut it = argv.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => cfg = Some(it.next().ok_or("--config 需要值")?.clone()),
            "--names" => {
                names = it
                    .next()
                    .ok_or("--names 需要值")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            "--tags" => {
                tags = it
                    .next()
                    .ok_or("--tags 需要值")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            "--runs" => runs = it.next().ok_or("--runs 需要值")?.parse()?,
            "--rounds" => rounds = it.next().ok_or("--rounds 需要值")?.parse()?,
            "--concurrency" => concurrency = it.next().ok_or("--concurrency 需要值")?.parse()?,
            "--client" => client = Some(it.next().ok_or("--client 需要值")?.parse()?),
            other => return Err(format!("未知参数 {other}").into()),
        }
    }
    let cfg = cfg.ok_or("用法: sodama dns-bench --config <file.dae> --names a.com,b.com [--tags t1,t2] [--runs N] [--rounds R] [--concurrency C] [--client <IP>]")?;
    if names.is_empty() {
        return Err("--names 不能为空".into());
    }
    if runs == 0 || runs > 100 {
        return Err("--runs 取值 1..=100".into());
    }
    if rounds == 0 || rounds > 100 {
        return Err("--rounds 取值 1..=100".into());
    }
    if concurrency == 0 || concurrency > 64 {
        return Err("--concurrency 取值 1..=64".into());
    }
    let ups = build_upstream_set_core(None, Some(Path::new(&cfg)))?;
    let mut sel: Vec<String> = if tags.is_empty() {
        ups.by_tag.keys().cloned().collect()
    } else {
        tags.clone()
    };
    sel.sort();
    for t in &sel {
        if !ups.by_tag.contains_key(t) {
            return Err(format!(
                "dns.upstream 里没有 tag {t:?}（可用: {:?}）",
                ups.by_tag.keys().collect::<Vec<_>>()
            )
            .into());
        }
    }
    let total = runs * rounds;
    println!(
        "dns-bench: per-point total={total}（runs={runs}×rounds={rounds}, concurrency={concurrency}） client={} names={} tags={}",
        client.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
        names.join(","),
        sel.join(",")
    );
    println!(
        "{:<10} {:<6} {:<24} {:>5} {:>9} {:>9} {:>9} {:>9} {:>8} {:>6}",
        "tag", "scheme", "name", "ok", "min_ms", "avg_ms", "p50_ms", "p95_ms", "ancount", "ttl"
    );
    for name in &names {
        for tag in &sel {
            let up = ups.by_tag.get(tag).unwrap();
            let (times, errs, ancount_last, ttl_last) =
                bench_one(up, name, client, total, concurrency);
            let (min, avg, p50, p95) = if times.is_empty() {
                (f64::NAN, f64::NAN, f64::NAN, f64::NAN)
            } else {
                let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
                let avg = times.iter().sum::<f64>() / times.len() as f64;
                let mut s = times.clone();
                s.sort_by(|a, b| a.partial_cmp(b).unwrap());
                (min, avg, s[s.len() / 2], pct(&s, 0.95))
            };
            println!(
                "{:<10} {:<6} {:<24} {:>5} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>8} {:>6}",
                tag,
                up.spec.scheme.name(),
                name,
                format!("{}/{}", times.len(), total),
                min,
                avg,
                p50,
                p95,
                ancount_last,
                if ttl_last == 0 {
                    "-".to_string()
                } else {
                    ttl_last.to_string()
                }
            );
            if errs > 0 {
                println!("            （{tag} {name}: {errs} 次失败）");
            }
        }
    }
    Ok(())
}

/// 百分位（已排序；nearest-rank）。
fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((p * sorted.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

/// 单点 bench：total 次交换，concurrency 个线程（scoped）并发；返回
/// (样本毫秒, 失败次数, 末次 ancount, 末次 TTL)。
fn bench_one(
    up: &Arc<dnsup::Upstream>,
    name: &str,
    client: Option<std::net::IpAddr>,
    total: usize,
    concurrency: usize,
) -> (Vec<f64>, usize, usize, u32) {
    let workers = concurrency.min(total).max(1);
    let mut all: Vec<f64> = Vec::with_capacity(total);
    let mut errs = 0usize;
    let mut ancount_last = 0usize;
    let mut ttl_last = 0u32;
    let per = total.div_ceil(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for w in 0..workers {
            handles.push(scope.spawn(move || {
                let mut times = Vec::new();
                let mut errs = 0usize;
                let mut ancount = 0usize;
                let mut ttl = 0u32;
                for i in 0..per {
                    let id = 0x100u16.wrapping_add((w * per + i) as u16);
                    let q = dns::build_query(name, 1, id);
                    let q = match up.spec.ecs {
                        Some(dnsup::EcsMode::Auto) => client
                            .and_then(|c| dns::add_ecs(&q, dns::ecs_auto_prefix(c)))
                            .unwrap_or(q),
                        Some(dnsup::EcsMode::Prefix(ip, p)) => {
                            dns::add_ecs(&q, (ip, p)).unwrap_or(q)
                        }
                        None => q,
                    };
                    let t0 = Instant::now();
                    match up.exchange(&q) {
                        Ok(resp) => {
                            times.push(t0.elapsed().as_secs_f64() * 1000.0);
                            if let Some(t) = dns::first_answer_ttl(&resp) {
                                ttl = t;
                            }
                            let (v4, v6) = dns::answer_a_and_aaaa_records(&resp);
                            ancount = v4.len() + v6.len();
                        }
                        Err(_) => errs += 1,
                    }
                }
                (times, errs, ancount, ttl)
            }));
        }
        for h in handles {
            let (t, e, a, ttl) = h.join().unwrap_or_default();
            all.extend(t);
            errs += e;
            if a > 0 || ancount_last == 0 {
                ancount_last = a;
            }
            if ttl > 0 {
                ttl_last = ttl;
            }
        }
    });
    (all, errs, ancount_last, ttl_last)
}

/// P38：控制命令拼装（`reload --abort` 等；拆出便于单测）。
fn abort_cmd(base: &str, abort: bool) -> String {
    if abort {
        format!("{base} --abort")
    } else {
        base.to_string()
    }
}

/// A2 #9：控制命令拼装（`reload [--abort] [--drain=N]`；拆出便于单测）。
fn reload_cmd(base: &str, abort: bool, drain_secs: u64) -> String {
    let mut c = abort_cmd(base, abort);
    if drain_secs > 0 {
        c.push_str(&format!(" --drain={drain_secs}"));
    }
    c
}

/// P6：解析 `--socket <path>` / `--out <path>`（子命令公用）。
fn parse_socket_args(
    argv: &[String],
    start: usize,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let mut sock = "/tmp/sodama-status.sock".to_string();
    let mut out = None;
    let mut it = argv.iter().skip(start);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => sock = it.next().ok_or("--socket 需要值")?.clone(),
            "--out" => out = Some(it.next().ok_or("--out 需要值")?.clone()),
            other => return Err(format!("未知参数 {other}").into()),
        }
    }
    Ok((sock, out))
}

/// P6 sysdump：系统网络信息（best-effort；ip 命令存在时用 JSON 输出）。
fn system_info_json() -> serde_json::Value {
    let cmd_json = |args: &[&str]| {
        std::process::Command::new("ip")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
    };
    json!({
        "uname": std::process::Command::new("uname").arg("-a").output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()),
        "hostname": std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).ok(),
        "ip_addr": cmd_json(&["-j", "addr"]),
        "ip_link": cmd_json(&["-j", "link"]),
        "ip_rule": cmd_json(&["-j", "rule"]),
        "ip_route": cmd_json(&["-j", "route"]),
    })
}

fn print_status_human(raw: &str) -> Result<(), Box<dyn std::error::Error>> {
    let v: serde_json::Value = serde_json::from_str(raw)?;
    if let Some(err) = v.get("error") {
        println!("error: {err}");
        return Ok(());
    }
    println!("sodama status");
    for key in [
        "version",
        "pid",
        "kernel",
        "uptime_sec",
        "active_slot",
        "tproxy_port",
        "dialer",
    ] {
        if let Some(x) = v.get(key) {
            println!("  {key}: {x}");
        }
    }
    for key in [
        "rules",
        "maps",
        "stats",
        "hooks",
        "config",
        "events",
        "offload_sent",
        "xdp",
    ] {
        if let Some(x) = v.get(key) {
            println!("  {key}: {x}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- K3：只读状态面

fn rules_json(compiled: &rules::CompiledRules) -> serde_json::Value {
    let sets: Vec<serde_json::Value> = compiled
        .sets
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let mut v = serde_json::Map::new();
            v.insert("slot".into(), json!(i));
            v.insert("type".into(), json!(rules::type_name(m.type_)));
            v.insert("not".into(), json!(m.not != 0));
            v.insert("outbound".into(), json!(format!("0x{:02x}", m.outbound)));
            v.insert("mark".into(), json!(format!("0x{:x}", m.mark)));
            v.insert("must".into(), json!(m.must != 0));
            match m.type_ {
                rules::MATCH_IP_SET | rules::MATCH_SOURCE_IP_SET | rules::MATCH_MAC => {
                    v.insert("lpm_index".into(), json!(m.lpm_index()));
                }
                rules::MATCH_PORT | rules::MATCH_SOURCE_PORT => {
                    let (a, b) = m.port_range();
                    v.insert("port".into(), json!(format!("{a}-{b}")));
                }
                rules::MATCH_L4_PROTO | rules::MATCH_IP_VERSION => {
                    v.insert("mask".into(), json!(format!("0x{:x}", m.mask())));
                }
                rules::MATCH_DSCP => {
                    v.insert("dscp".into(), json!(m.dscp()));
                }
                _ => {}
            }
            serde_json::Value::Object(v)
        })
        .collect();
    json!({"count": compiled.sets.len(), "sets": sets})
}

fn count_map<K: aya::Pod, V: aya::Pod>(ebpf: &mut Ebpf, name: &str) -> Option<usize> {
    let map = ebpf.map_mut(name)?;
    let hm: HashMap<_, K, V> = HashMap::try_from(map).ok()?;
    Some(hm.iter().count())
}

/// P7：fast_sock（SockHash）条目数。注意 offload 启用后该 map 已被 take_map
/// 移出 Ebpf（存在 RELAY_OFFLOAD），所以两条路径都要查。
fn count_fast_sock(ebpf: &mut Ebpf) -> Option<usize> {
    if let Some(map) = ebpf.map_mut("fast_sock") {
        if let Ok(sh) = SockHash::<_, SodaTuple>::try_from(map) {
            return Some(sh.iter().count());
        }
    }
    let mutex = RELAY_OFFLOAD.get()?;
    let guard = mutex.lock().ok()?;
    Some(guard.iter().count())
}

fn read_pname_hits(ebpf: &mut Ebpf) -> u64 {
    use aya::maps::PerCpuArray;
    let Some(map) = ebpf.map_mut("sodama_stats_map") else {
        return 0;
    };
    let arr: PerCpuArray<_, u64> = match PerCpuArray::try_from(map) {
        Ok(a) => a,
        Err(_) => return 0,
    };
    // 索引 15 = SODAMA_STAT_PNAME_HITS（与 ebpf-rs/common.rs 对齐）
    arr.get(&15u32, 0)
        .map(|values| values.iter().copied().sum::<u64>())
        .unwrap_or(0)
}

/// 对标批：`sodama_stats_map` 全量快照（per-CPU 求和；键序对照 ebpf-rs/src/common.rs
/// 的 `SODAMA_STAT_*`：0..=12 对齐 dae `enum bpf_stats_key`，13+ 为 sodama 自有）。
#[derive(Default)]
struct EbpfStats {
    udp_conn_overflow: u64,
    tcp_conn_overflow: u64,
    redirect_overflow: u64,
    redirect_update_failed: u64,
    rebind_rejected: u64,
    syn_rebind_rejected: u64,
    stateless_tcp_passthrough: u64,
    frag_tail_passed: u64,
    parse_unsupported_l4: u64,
    unsolicited_udp_seen: u64,
    sockmark_fallback: u64,
    event_drops: u64,
    rebind_rerouted: u64,
    offload_redirects: u64,
    offload_verdicts: u64,
    offload_sent_bytes: u64,
    account_drops: u64,
    offload_pause_passes: u64,
    /// 对标批：`skb_send_sock` 探针内部计数（0 字节问题的诊断三件套）
    probe_calls: u64,
    probe_parse_fail: u64,
    probe_guard_miss: u64,
}

fn read_stats(ebpf: &mut Ebpf) -> EbpfStats {
    use aya::maps::PerCpuArray;
    let Some(map) = ebpf.map_mut("sodama_stats_map") else {
        return EbpfStats::default();
    };
    let arr: PerCpuArray<_, u64> = match PerCpuArray::try_from(map) {
        Ok(a) => a,
        Err(_) => return EbpfStats::default(),
    };
    let get = |i: u32| {
        arr.get(&i, 0)
            .map(|values| values.iter().copied().sum::<u64>())
            .unwrap_or(0)
    };
    EbpfStats {
        udp_conn_overflow: get(0),
        tcp_conn_overflow: get(1),
        redirect_overflow: get(2),
        redirect_update_failed: get(3),
        rebind_rejected: get(4),
        syn_rebind_rejected: get(5),
        stateless_tcp_passthrough: get(6),
        frag_tail_passed: get(7),
        parse_unsupported_l4: get(8),
        unsolicited_udp_seen: get(9),
        sockmark_fallback: get(10),
        event_drops: get(11),
        rebind_rerouted: get(12),
        offload_redirects: get(13),
        offload_verdicts: get(14),
        offload_sent_bytes: get(16),
        account_drops: get(17),
        probe_calls: get(18),
        probe_parse_fail: get(19),
        probe_guard_miss: get(20),
        offload_pause_passes: get(21),
    }
}

/// C4：XDP 计量探针的计数（包/字节/IPv4/IPv6/其它，键序对照 SODAMA_XDP_*）。
/// map 不存在（未挂载）→ None，让 status 区分「0 包」与「没有探针」。
fn read_xdp_stats(ebpf: &mut Ebpf) -> Option<(u64, u64, u64, u64, u64)> {
    use aya::maps::PerCpuArray;
    let map = ebpf.map_mut("xdp_stats_map")?;
    let arr: PerCpuArray<_, u64> = PerCpuArray::try_from(map).ok()?;
    let get = |i: u32| {
        arr.get(&i, 0)
            .map(|values| values.iter().copied().sum::<u64>())
            .unwrap_or(0)
    };
    Some((get(0), get(1), get(2), get(3), get(4)))
}

/// P19：单个组的 JSON（status 的 `group` 与 `groups[]` 共用）。
fn group_json(g: &group::GroupRuntime, index: usize, default: bool) -> serde_json::Value {
    let snap = g.snapshot();
    let (current, pinned, pinned_ok) = g.current_and_pinned();
    json!({
        "name": g.name,
        "index": index,
        "default": default,
        "policy": group::policy_name(&g.policy()),
        "pinned": pinned,
        "pinned_ok": pinned_ok,
        "current": current,
        "probe_interval_secs": g.stats.probe_interval.load(Ordering::Relaxed),
        "probe_active": g.stats.probe_active.load(Ordering::Relaxed) == 1,
        "members": g.member_count(),
        "alive": snap.iter().filter(|x| x.alive).count(),
        "dials": g.stats.dials.load(Ordering::Relaxed),
        "failovers": g.stats.failovers.load(Ordering::Relaxed),
        "probes_ok": g.stats.probes_ok.load(Ordering::Relaxed),
        "probes_fail": g.stats.probes_fail.load(Ordering::Relaxed),
        "probes_stragglers": g.stats.probes_stragglers.load(Ordering::Relaxed),
        "codec_reactor_capable": g.codec_reactor_capable_all(),
        "subscription_failover": g.sub_failover_enabled(),
        "active_tag": g.active_tag(),
        "nodes": snap.iter().map(|n| json!({
            "name": n.name, "tag": n.tag, "alive": n.alive, "last_ms": n.last_ms, "ema_ms": n.ema_ms,
            // 可公开的协议事实（TCP/UDP/传输/安全/地址；不带任何凭据）
            "protocol": n.facts.protocol,
            "transport": n.facts.transport,
            "security": n.facts.security,
            "udp": n.facts.udp,
            "addr": n.facts.addr.map(|a| a.to_string()),
        })).collect::<Vec<_>>(),
    })
}

/// P36：规则集状态（tag/计数/缓存年龄；URL 不外显，避免 token 泄露）。
fn rule_sets_json() -> serde_json::Value {
    let Some(lock) = RULESET_STORE.get() else {
        return serde_json::Value::Array(Vec::new());
    };
    let g = match lock.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let mut arr: Vec<serde_json::Value> = g
        .iter()
        .map(|rs| {
            json!({
                "tag": rs.tag,
                "remote": rs.remote,
                "from_cache": rs.from_cache,
                "updated_secs_ago": rs.updated_secs_ago,
                "entries": rs.data.total(),
                "full": rs.data.full.len(),
                "suffix": rs.data.suffix.len(),
                "keyword": rs.data.keyword.len(),
                "regex": rs.data.regex.len(),
                "ignored": rs.data.ignored,
                // 软失败原因（None = 本次加载正常）；面板据此把该条标红。
                "error": rs.error,
            })
        })
        .collect();
    arr.sort_by(|a, b| a["tag"].as_str().cmp(&b["tag"].as_str()));
    serde_json::Value::Array(arr)
}

/// C3：事件通道状态（status/metrics 共用；`by_type` 覆盖 5 个已知类型 + unknown）。
/// `suppressed` 是各类日志限速抑制数之和（“真实事件数”看 consumed/by_type）。
fn events_json(stats: &EbpfStats) -> serde_json::Value {
    let mut by_type = serde_json::Map::new();
    for (slot, t) in [
        EV_BLOCKED,
        EV_UDP_CONN_OVERFLOW,
        EV_TCP_CONN_OVERFLOW,
        EV_BLOCKED_ALIVE,
        EV_REDIRECT_REBIND_REJECTED,
        EV_SYN_REBIND_REJECTED,
        EV_REDIRECT_UPDATE_FAILED,
        EV_SYN_REBIND_REROUTED,
    ]
    .into_iter()
    .enumerate()
    {
        by_type.insert(
            event_type_name(t).to_string(),
            json!(EVENT_COUNTS[slot].load(Ordering::Relaxed)),
        );
    }
    by_type.insert(
        "unknown".to_string(),
        json!(EVENT_UNKNOWN_TOTAL.load(Ordering::Relaxed)),
    );
    let suppressed = EVENT_SUPPRESSED
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .sum::<u64>()
        + EVENT_UNKNOWN_SUPPRESSED.load(Ordering::Relaxed);
    json!({
        "consumed": EVENTS_TOTAL.load(Ordering::Relaxed),
        "suppressed": suppressed,
        "by_type": by_type,
        "dropped_kernel": stats.event_drops,
    })
}

/// P6：状态面主查询体（status / metrics 共用数据源）。
fn status_json(ebpf: &mut Ebpf) -> serde_json::Value {
    // P37（2026-10-13 / A1）：状态查询**不再**回写「有人在看」信号。
    // 旧行为让面板轮询 / health-track / watchdog / CLI 把探测退避永久重置为全速档，
    // 与同类惯例相反（mihomo 状态 API 不 touch、sing-box 只在新连接 Touch；见 devlog §13）。
    let rules_state = LAST_RULES.lock().ok().and_then(|g| g.clone());
    let cfg_state = CONFIG_STATE.lock().ok().and_then(|g| g.clone());
    let conn_state = count_map::<SodaTuple, SodaConnState>(ebpf, "conn_state_map");
    let redirect_track = count_map::<SodaTuple, SodaRedirectEntry>(ebpf, "redirect_track");
    let domain_routing = count_map::<SodaEpochIp, SodaDomainRouting>(ebpf, "domain_routing_map");
    let routing_handoff =
        count_map::<SodaTuple, SodaRoutingHandoffEntry>(ebpf, "routing_handoff_map");
    // P17b：cookie→pname 条目数 + 规则 VM 的 pname 命中计数
    let cookie_pid = count_map::<u64, SodaPidPname>(ebpf, "cookie_pid_map");
    let pname_hits = read_pname_hits(ebpf);
    // P7：offload 键计数（0 = 无泄漏；连接回收后必须归零）
    let fast_sock = count_fast_sock(ebpf);
    let stats = read_stats(ebpf);
    let xdp = read_xdp_stats(ebpf);
    let cache = match DNS_CACHE.lock() {
        Ok(c) => (
            c.len(),
            c.hits,
            c.misses,
            c.inserts,
            c.evictions,
            c.expired,
            c.stale_hits,
            c.optimistic,
        ),
        Err(_) => (0, 0, 0, 0, 0, 0, 0, true),
    };
    let dnso = dns_opts();
    let reload = LAST_RELOAD.lock().ok().and_then(|g| g.clone());
    let cfg_summary = cfg_state.as_ref().map(|(c, ex)| {
        json!({
            "entry": c.entry.display().to_string(),
            "files": c.files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "sections": c.sections.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
            "routing_supported": ex.supported.len(),
            "routing_deferred": ex.deferred.len(),
            "outbound_map": ex.outbound_map,
            "fallback": ex.fallback,
        })
    });
    // P19：默认组（兼容旧口径）+ 全部组
    let (default_group_json, groups_json) = match GROUP_SET.get() {
        Some(l) => {
            let gs = match l.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let all: Vec<serde_json::Value> = gs
                .groups
                .iter()
                .enumerate()
                .map(|(i, g)| group_json(g, i, i == gs.default_idx))
                .collect();
            let def = gs
                .default_group()
                .map(|g| group_json(g, gs.default_idx, true))
                .unwrap_or(serde_json::Value::Null);
            (def, serde_json::Value::Array(all))
        }
        None => (
            serde_json::Value::Null,
            serde_json::Value::Array(Vec::new()),
        ),
    };
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim(),
        "uptime_sec": STARTED.get().map(|t| t.elapsed().as_secs()).unwrap_or(0),
        "active_slot": ACTIVE_SLOT.load(Ordering::SeqCst),
        "tproxy_port": TPROXY_PORT.load(Ordering::SeqCst),
        "suspended": SUSPENDED.load(Ordering::SeqCst),
        "reload": reload.as_ref().map(|r| json!({
            "ok": r.ok, "match_sets": r.match_sets, "slot": r.slot,
            "error": r.error, "at_sec": r.at_sec,
        })),
        "config_watch": {
            "enabled": CONFIG_WATCH_INTERVAL.load(Ordering::Relaxed) > 0,
            "interval_secs": CONFIG_WATCH_INTERVAL.load(Ordering::Relaxed),
            "transport": if CONFIG_WATCH_INOTIFY.load(Ordering::Relaxed) { "inotify" } else { "poll" },
            "debounce_ms": crate::watch::DEBOUNCE.as_millis() as u64,
            "sub_cache_ttl_secs": SUB_CACHE_TTL_SECS.load(Ordering::Relaxed),
            "sub_fail_ttl_secs": SUB_FAIL_TTL_SECS.load(Ordering::Relaxed),
        },
        "domain_stats": snapshot_domain_stats(),
        "rule_sets": rule_sets_json(),
        "subscriptions": subscribe::source_status_json(),
        "dialer": match OUTBOUND.get() {
            Some(o) => o.name(),
            None => "none".to_string(),
        },
        "relay": {
            "conns_total": RELAY_STATS.conns_total.load(Ordering::Relaxed),
            "conns_active": RELAY_STATS.conns_active.load(Ordering::Relaxed),
            "bytes_up": RELAY_STATS.bytes_up.load(Ordering::Relaxed),
            "bytes_down": RELAY_STATS.bytes_down.load(Ordering::Relaxed),
            "dial_errors": RELAY_STATS.dial_errors.load(Ordering::Relaxed),
            "evicted": RELAY_STATS.evicted.load(Ordering::Relaxed),
            "idle_timeout_secs": RELAY_IDLE_SECS.load(Ordering::Relaxed),
            "offload_enabled": RELAY_OFFLOAD.get().is_some(),
            "offloaded_total": RELAY_STATS.offloaded_total.load(Ordering::Relaxed),
            "offload_failures": RELAY_STATS.offload_failures.load(Ordering::Relaxed),
            "splice_enabled": RELAY_SPLICE.load(Ordering::Relaxed),
            "splice_total": RELAY_STATS.splice_total.load(Ordering::Relaxed),
            "reactor_codec_sessions": RELAY_STATS.reactor_codec_sessions.load(Ordering::Relaxed),
            "splice_fallbacks": RELAY_STATS.splice_fallbacks.load(Ordering::Relaxed),
            "splice_fd_budget": RELAY_STATS.splice_fd_budget.load(Ordering::Relaxed),
            "pipe_created": RELAY_STATS.pipe_created.load(Ordering::Relaxed),
            "pipe_reused": RELAY_STATS.pipe_reused.load(Ordering::Relaxed),
            "pipe_released": RELAY_STATS.pipe_released.load(Ordering::Relaxed),
            "pipe_discarded": RELAY_STATS.pipe_discarded.load(Ordering::Relaxed),
            "fds_used": fd_used(),
            "fds_soft_limit": NOFILE_SOFT.load(Ordering::Relaxed),
            "max_conns": RELAY_MAX_CONNS.load(Ordering::Relaxed),
            "limit_rejected": RELAY_STATS.limit_rejected.load(Ordering::Relaxed),
        },
        "sniffing": {
            "dial_mode": dial_mode_name(DIAL_MODE.load(Ordering::Relaxed)),
            "timeout_ms": SNIFF_TIMEOUT_MS.load(Ordering::Relaxed),
            "attempts": SNIFF_STATS.attempts.load(Ordering::Relaxed),
            "hits": SNIFF_STATS.hits.load(Ordering::Relaxed),
            "misses": SNIFF_STATS.misses.load(Ordering::Relaxed),
            "quic_initial": SNIFF_STATS.quic_initial.load(Ordering::Relaxed),
            "quic_sni": SNIFF_STATS.quic_sni.load(Ordering::Relaxed),
            "punt_enabled": SNIFF_PUNT.load(Ordering::Relaxed),
            "punt_attempts": SNIFF_STATS.punt_attempts.load(Ordering::Relaxed),
            "punt_direct": SNIFF_STATS.punt_direct.load(Ordering::Relaxed),
            "punt_block": SNIFF_STATS.punt_block.load(Ordering::Relaxed),
            "punt_group": SNIFF_STATS.punt_group.load(Ordering::Relaxed),
            "punt_keep": SNIFF_STATS.punt_keep.load(Ordering::Relaxed),
        },
        // P17b：pname 采集面（cgroup2 钩子 + cookie→pname map）
        "pname": {
            "driver": "cgroup2",
            "enabled": HOOKS.lock().map(|h| h.iter().any(|x| x.starts_with("sodama_cgroup_"))).unwrap_or(false),
            "hooks": HOOKS.lock().map(|h| h.iter().filter(|x| x.starts_with("sodama_cgroup_")).count()).unwrap_or(0),
            "map_entries": cookie_pid,
            "hits": pname_hits,
        },
        "group": default_group_json,
        "groups": groups_json,
        "udp_nat": {
            "sessions_active": UDP_NAT
                .iter()
                .map(|s| s.lock().map(|t| t.len()).unwrap_or(0))
                .sum::<usize>(),
            "sessions_total": UDP_NAT_STATS.sessions_total.load(Ordering::Relaxed),
            "sessions_proxied": UDP_NAT_STATS.sessions_proxied.load(Ordering::Relaxed),
            "direct_fallback": UDP_NAT_STATS.direct_fallback.load(Ordering::Relaxed),
            "bytes_up": UDP_NAT_STATS.bytes_up.load(Ordering::Relaxed),
            "bytes_down": UDP_NAT_STATS.bytes_down.load(Ordering::Relaxed),
            "evicted": UDP_NAT_STATS.evicted.load(Ordering::Relaxed),
            "errors": UDP_NAT_STATS.errors.load(Ordering::Relaxed),
            "reply_sockets_evicted": UDP_NAT_STATS.reply_sockets_evicted.load(Ordering::Relaxed),
            "cone_sessions": UDP_NAT_STATS.cone_sessions.load(Ordering::Relaxed),
            "negcache_hits": UDP_NAT_STATS.negcache_hits.load(Ordering::Relaxed),
            "raw_udp_fallbacks": UDP_NAT_STATS.raw_udp_fallbacks.load(Ordering::Relaxed),
            "gso_sends": UDP_GSO_SENDS.load(Ordering::Relaxed),
            "gso_datagrams": UDP_GSO_DATAGRAMS.load(Ordering::Relaxed),
            "gso_unsupported": UDP_GSO_UNSUPPORTED.load(Ordering::Relaxed),
            "idle_timeout_secs": UDP_IDLE_SECS.load(Ordering::Relaxed),
        },
        "hooks": HOOKS.lock().map(|h| h.clone()).unwrap_or_default(),
        "rules": rules_state.as_ref().map(|c| json!({"count": c.sets.len()})),
        "maps": {"conn_state": conn_state, "redirect_track": redirect_track, "domain_routing": domain_routing, "fast_sock": fast_sock, "routing_handoff": routing_handoff, "connectivity_dead_groups": CONNECTIVITY_DEAD_GROUPS.load(Ordering::Relaxed)},
        "stats": {
            "udp_conn_overflow": stats.udp_conn_overflow,
            "tcp_conn_overflow": stats.tcp_conn_overflow,
            "redirect_overflow": stats.redirect_overflow,
            "redirect_update_failed": stats.redirect_update_failed,
            "rebind_rejected": stats.rebind_rejected,
            "syn_rebind_rejected": stats.syn_rebind_rejected,
            "stateless_tcp_passthrough": stats.stateless_tcp_passthrough,
            "frag_tail_passed": stats.frag_tail_passed,
            "parse_unsupported_l4": stats.parse_unsupported_l4,
            "unsolicited_udp_seen": stats.unsolicited_udp_seen,
            "sockmark_fallback": stats.sockmark_fallback,
            "rebind_rerouted": stats.rebind_rerouted,
            "offload_redirects": stats.offload_redirects,
            "offload_verdicts": stats.offload_verdicts,
            "offload_pause_passes": stats.offload_pause_passes,
            "event_drops": stats.event_drops,
            "domain_publish_retries": PUBLISH_RETRIES.load(Ordering::Relaxed),
            "domain_publish_dropped": PUBLISH_DROPPED.load(Ordering::Relaxed),
        },
        "events": events_json(&stats),
        "traffic": traffic_snapshot_json(),
        "real_domain": real_domain::snapshot(),
        "sysctl": {
            "watched": sysctl::expectations().len(),
            "rewrites": sysctl::rewrites(),
        },
        "trace": {
            "active": TRACE_UNTIL_NS.load(Ordering::Relaxed) > monotonic_now_ns(),
            "file": TRACE_PATH.get().map(|p| p.display().to_string()),
            "events": TRACE_EVENTS.load(Ordering::Relaxed),
            "write_errors": TRACE_WRITE_ERRS.load(Ordering::Relaxed),
        },
        "offload_sent": {
            "reclaimed_bytes": RELAY_STATS.offload_sent_bytes.load(Ordering::Relaxed),
            "kernel_bytes": stats.offload_sent_bytes,
            "account_drops": stats.account_drops,
            // 探针内部计数：calls=0 → 钩子未落在推流路径；parse_fail/guard_miss 定位键不符
            "probe_calls": stats.probe_calls,
            "probe_parse_fail": stats.probe_parse_fail,
            "probe_guard_miss": stats.probe_guard_miss,
        },
        // 背压 fuse（对照 dae tcp_offload_pause / fuseStep）
        "offload_fuse": {
            "engages": RELAY_STATS.fuse_engages.load(Ordering::Relaxed),
            "lifts": RELAY_STATS.fuse_lifts.load(Ordering::Relaxed),
            "failures": RELAY_STATS.fuse_failures.load(Ordering::Relaxed),
            "threshold": fuse_max_backlog(),
            "pause_passes": stats.offload_pause_passes,
        },
        // C4：未挂载 XDP 探针时为 null（区分「0 包」与「没探针」）
        "xdp": match xdp {
            Some((packets, bytes, ipv4, ipv6, other)) => json!({
                "packets": packets, "bytes": bytes, "ipv4": ipv4, "ipv6": ipv6, "other": other,
            }),
            None => serde_json::Value::Null,
        },
        "dns": {
            "upstream": upstream().map(|u| u.addr().to_string()),
            "upstream_url": upstream().map(|u| u.url.clone()),
            "upstream_scheme": upstream().map(|u| u.spec.scheme.name()),
            "upstreams": upstreams().map(|s| {
                let mut m = serde_json::Map::new();
                let mut keys: Vec<String> = s.by_tag.keys().cloned().collect();
                keys.sort();
                for k in keys {
                    if let Some(u) = s.by_tag.get(&k) {
                        m.insert(k, json!(u.url));
                    }
                }
                serde_json::Value::Object(m)
            }),
            "routing": {
                "request_rules": dns_router().map(|r| r.request_rule_lines),
                "response_rules": dns_router().map(|r| r.response_rule_lines),
                "request_fallback": dns_router().map(|r| format!("{:?}", r.req_fallback)),
                "response_fallback": dns_router().map(|r| format!("{:?}", r.resp_fallback)),
                "rejects": DNS_STATS.rejects.load(Ordering::Relaxed),
                "response_rejects": DNS_STATS.response_rejects.load(Ordering::Relaxed),
                "relookups": DNS_STATS.relookups.load(Ordering::Relaxed),
                "upstream_hits": DNS_TAG_HITS
                    .lock()
                    .map(|g| {
                        let mut m = serde_json::Map::new();
                        let mut keys: Vec<String> = g.keys().cloned().collect();
                        keys.sort();
                        for k in keys {
                            m.insert(k.clone(), json!(g[&k]));
                        }
                        serde_json::Value::Object(m)
                    })
                    .unwrap_or(serde_json::Value::Null),
                "notes": dns_router().map(|r| r.notes.clone()).unwrap_or_default(),
            },
            "queries": DNS_STATS.queries.load(Ordering::Relaxed),
            "ecs": {
                "echo": DNS_STATS.ecs_echo.load(Ordering::Relaxed),
                "scope": ECS_SCOPE_LAST.lock().ok().and_then(|g| g.clone()),
            },
            "refresh": {
                "spawned": DNS_STATS.refresh_spawned.load(Ordering::Relaxed),
                "coalesced": DNS_STATS.refresh_coalesced.load(Ordering::Relaxed),
                "err": DNS_STATS.refresh_err.load(Ordering::Relaxed),
                "inflight": DNS_CACHE.lock().map(|c| c.refreshing_len()).unwrap_or(0),
            },
            "responses": DNS_STATS.responses.load(Ordering::Relaxed),
            "published_ips": DNS_STATS.published_ips.load(Ordering::Relaxed),
            "bitmap_matched": DNS_STATS.bitmap_matched.load(Ordering::Relaxed),
            "aaaa_published": DNS_STATS.aaaa_published.load(Ordering::Relaxed),
            "upstream_errors": DNS_STATS.upstream_errors.load(Ordering::Relaxed),
            "tcp_queries": DNS_STATS.tcp_queries.load(Ordering::Relaxed),
            "tcp_responses": DNS_STATS.tcp_responses.load(Ordering::Relaxed),
            "tcp_unsupported": DNS_STATS.tcp_unsupported.load(Ordering::Relaxed),
            "cache_entries": cache.0, "cache_hits": cache.1, "cache_misses": cache.2,
            "cache_inserts": cache.3, "cache_evictions": cache.4, "cache_expired": cache.5,
            "optimistic_cache": cache.7, "stale_hits": cache.6,
            "ipversion_prefer": dnso.ipversion_prefer,
            "ipversion_filtered": DNS_STATS.ipversion_filtered.load(Ordering::Relaxed),
            "fixed_domain_ttl": dnso.fixed_domain_ttl.len(),
            "domain_sets": DOMAIN_SETS.lock().map(|g| g.len()).unwrap_or(0),
            "bind": DNS_BIND.lock().ok().and_then(|g| g.clone()),
            "pref_wait_pending": dns_pref_wait::pending(),
            "bind_queries": DNS_STATS.bind_queries.load(Ordering::Relaxed),
        },
        "config": cfg_summary,
    })
}

/// P6：Prometheus 文本格式（status JSON 的扁平化；计数用 counter，其余 gauge）。
fn metrics_text(v: &serde_json::Value) -> String {
    fn get(v: &serde_json::Value, path: &[&str]) -> u64 {
        let mut cur = v;
        for p in path {
            match cur.get(p) {
                Some(x) => cur = x,
                None => return 0,
            }
        }
        cur.as_u64().unwrap_or(0)
    }
    fn emit(out: &mut String, kind: &str, name: &str, val: u64) {
        out.push_str(&format!("# TYPE {name} {kind}\n{name} {val}\n"));
    }
    let mut s = String::new();
    let b = |p: bool| if p { 1 } else { 0 };
    emit(
        &mut s,
        "gauge",
        "sodama_uptime_seconds",
        get(v, &["uptime_sec"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_active_slot",
        get(v, &["active_slot"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_suspended",
        b(v.get("suspended")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_reload_success",
        b(v.get("reload")
            .and_then(|r| r.get("ok"))
            .and_then(|x| x.as_bool())
            .unwrap_or(true)),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_reload_match_sets",
        get(v, &["reload", "match_sets"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_conns_total",
        get(v, &["relay", "conns_total"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_relay_conns_active",
        get(v, &["relay", "conns_active"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_bytes_up",
        get(v, &["relay", "bytes_up"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_bytes_down",
        get(v, &["relay", "bytes_down"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_dial_errors",
        get(v, &["relay", "dial_errors"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_evicted",
        get(v, &["relay", "evicted"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_offloaded_total",
        get(v, &["relay", "offloaded_total"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_offload_failures",
        get(v, &["relay", "offload_failures"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_splice_total",
        get(v, &["relay", "splice_total"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_reactor_codec_sessions",
        get(v, &["relay", "reactor_codec_sessions"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_splice_fallbacks",
        get(v, &["relay", "splice_fallbacks"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_relay_limit_rejected",
        get(v, &["relay", "limit_rejected"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_udp_nat_sessions_active",
        get(v, &["udp_nat", "sessions_active"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_udp_nat_sessions_total",
        get(v, &["udp_nat", "sessions_total"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_udp_nat_sessions_proxied",
        get(v, &["udp_nat", "sessions_proxied"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_udp_nat_direct_fallback",
        get(v, &["udp_nat", "direct_fallback"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_udp_nat_bytes_up",
        get(v, &["udp_nat", "bytes_up"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_udp_nat_bytes_down",
        get(v, &["udp_nat", "bytes_down"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_udp_nat_evicted",
        get(v, &["udp_nat", "evicted"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_udp_nat_errors",
        get(v, &["udp_nat", "errors"]),
    );
    for (name, path) in [
        ("sodama_udp_nat_cone_sessions", ["udp_nat", "cone_sessions"]),
        ("sodama_udp_nat_negcache_hits", ["udp_nat", "negcache_hits"]),
        (
            "sodama_udp_nat_raw_udp_fallbacks",
            ["udp_nat", "raw_udp_fallbacks"],
        ),
    ] {
        emit(&mut s, "counter", name, get(v, &path));
    }
    for (name, path) in [
        ("sodama_dns_queries", ["dns", "queries"]),
        ("sodama_dns_responses", ["dns", "responses"]),
        ("sodama_dns_published_ips", ["dns", "published_ips"]),
        ("sodama_dns_bitmap_matched", ["dns", "bitmap_matched"]),
        ("sodama_dns_upstream_errors", ["dns", "upstream_errors"]),
        ("sodama_dns_tcp_queries", ["dns", "tcp_queries"]),
        ("sodama_dns_tcp_responses", ["dns", "tcp_responses"]),
        ("sodama_dns_bind_queries", ["dns", "bind_queries"]),
        ("sodama_dns_cache_hits", ["dns", "cache_hits"]),
        ("sodama_dns_cache_misses", ["dns", "cache_misses"]),
        ("sodama_dns_cache_inserts", ["dns", "cache_inserts"]),
        ("sodama_dns_cache_evictions", ["dns", "cache_evictions"]),
    ] {
        emit(&mut s, "counter", name, get(v, &path));
    }
    emit(
        &mut s,
        "gauge",
        "sodama_traffic_upload_rate",
        get(v, &["traffic", "upload_rate"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_traffic_download_rate",
        get(v, &["traffic", "download_rate"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_dns_cache_entries",
        get(v, &["dns", "cache_entries"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_dns_domain_sets",
        get(v, &["dns", "domain_sets"]),
    );
    // P17b：pname（cgroup2）
    emit(
        &mut s,
        "gauge",
        "sodama_pname_hooks",
        get(v, &["pname", "hooks"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_pname_map_entries",
        get(v, &["pname", "map_entries"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_pname_hits",
        get(v, &["pname", "hits"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_map_conn_state",
        get(v, &["maps", "conn_state"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_map_redirect_track",
        get(v, &["maps", "redirect_track"]),
    );
    emit(
        &mut s,
        "gauge",
        "sodama_map_domain_routing",
        get(v, &["maps", "domain_routing"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_rebind_rejected",
        get(v, &["stats", "rebind_rejected"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_redirect_update_failed",
        get(v, &["stats", "redirect_update_failed"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_offload_redirects",
        get(v, &["stats", "offload_redirects"]),
    );
    emit(
        &mut s,
        "counter",
        "sodama_offload_verdicts",
        get(v, &["stats", "offload_verdicts"]),
    );
    // C3/对标批/C4：事件通道、offload 记账、XDP 计量（未挂载时相关值为 0）
    for (name, path) in [
        ("sodama_events_total", ["events", "consumed"]),
        ("sodama_events_suppressed", ["events", "suppressed"]),
        ("sodama_event_drops", ["events", "dropped_kernel"]),
        ("sodama_conn_overflow", ["stats", "conn_overflow"]),
        (
            "sodama_offload_sent_bytes_reclaimed",
            ["offload_sent", "reclaimed_bytes"],
        ),
        (
            "sodama_offload_sent_bytes_kernel",
            ["offload_sent", "kernel_bytes"],
        ),
        (
            "sodama_offload_account_drops",
            ["offload_sent", "account_drops"],
        ),
        ("sodama_xdp_packets", ["xdp", "packets"]),
        ("sodama_xdp_bytes", ["xdp", "bytes"]),
    ] {
        emit(&mut s, "counter", name, get(v, &path));
    }
    let dialer = v
        .get("dialer")
        .and_then(|x| x.as_str())
        .unwrap_or("none")
        .replace(['"', '\\', '\n'], "_");
    s.push_str(&format!(
        "# TYPE sodama_info gauge\nsodama_info{{dialer=\"{dialer}\"}} 1\n"
    ));
    s
}

fn handle_status_query(cmd: &str, ebpf: &mut Ebpf, args: &Args) -> String {
    match cmd {
        "status" => status_json(ebpf).to_string(),
        cmd if cmd == "reload"
            || cmd.starts_with("reload ")
            || cmd == "reload-fast"
            || cmd.starts_with("reload-fast ") =>
        {
            // P35：reload-fast（watch 触发的自动 reload）订阅节点走缓存；
            // 手动 reload/SIGHUP 始终强制重拉（P18e 语义）。
            // P38：`reload --abort` 在切代后关闭旧代已建连接（对照 dae abort）。
            let abort = cmd.split_whitespace().any(|a| a == "--abort");
            let drain_secs = cmd
                .split_whitespace()
                .find_map(|a| a.strip_prefix("--drain="))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let out = do_reload(args, ebpf, false, cmd.starts_with("reload-fast"));
            let (killed, scrubbed) = if abort {
                let (k, s) = abort_sessions(ebpf, AbortScope::OldGeneration);
                log(&format!(
                    "reload --abort：关闭旧代会话 {k} 条（conn_state 清理 {s} 条）"
                ));
                (k, s)
            } else {
                (0, 0)
            };
            // A2 #9：drain 预算（`reload --drain=<secs>`）——等旧代在飞会话自然结束。
            let (drained, waited, remaining) = if drain_secs > 0 {
                let (d, w, r) = drain_old_generation(Duration::from_secs(drain_secs.min(600)));
                log(&format!(
                    "reload --drain={drain_secs}：{}（等待 {w:.1}s，余 {r} 条旧代会话）",
                    if d { "已排空" } else { "预算内未排空（如实回报，不强制关闭）" }
                ));
                (d, w, r)
            } else {
                (true, 0.0, 0)
            };
            json!({
                "ok": out.ok,
                "match_sets": out.match_sets,
                "slot": out.slot,
                "error": out.error,
                "at_sec": out.at_sec,
                "aborted": killed,
                "conn_state_scrubbed": scrubbed,
                "drain": {"budget_secs": drain_secs, "waited_secs": waited, "remaining": remaining, "drained": drained},
            })
            .to_string()
        }
        "suspend" | "suspend --abort" => match set_suspend(ebpf, true) {
            Ok(()) => {
                SUSPENDED.store(true, Ordering::SeqCst);
                let (killed, scrubbed) = if cmd.ends_with("--abort") {
                    let (k, s) = abort_sessions(ebpf, AbortScope::All);
                    log(&format!(
                        "suspend --abort：关闭已建会话 {k} 条（conn_state 清理 {s} 条）"
                    ));
                    (k, s)
                } else {
                    (0, 0)
                };
                log("已挂起（no-load，全部流量 fail-open）；reload 恢复");
                json!({"ok": true, "suspended": true, "aborted": killed, "conn_state_scrubbed": scrubbed})
                    .to_string()
            }
            Err(e) => json!({"ok": false, "error": e.to_string()}).to_string(),
        },
        "resume" => match set_suspend(ebpf, false) {
            Ok(()) => {
                SUSPENDED.store(false, Ordering::SeqCst);
                log("已从 suspend 恢复（fail-open 解除）");
                json!({"ok": true, "suspended": false}).to_string()
            }
            Err(e) => json!({"ok": false, "error": e.to_string()}).to_string(),
        },
        "metrics" => metrics_text(&status_json(ebpf)),
        cmd if cmd == "trace" || cmd.starts_with("trace ") => {
            // A2 #3：`trace secs=<n> [l4=<6|17>] [port=<n>] [ipver=<0|1|2>] [drop_only=1]`
            // ——写数据面过滤器（内核侧筛选）+ 开会话；事件由常驻消费线程落盘，
            // CLI 读同一文件做展示层过滤（文件路径随回执返回）。
            let mut seconds = 5u64;
            let mut l4 = None;
            let mut port = None;
            let mut ipver = 0u32;
            let mut drop_only = false;
            for part in cmd.split_whitespace().skip(1) {
                if let Some(v) = part.strip_prefix("secs=") {
                    seconds = v.parse().unwrap_or(5);
                } else if let Some(v) = part.strip_prefix("l4=") {
                    l4 = v.parse::<u32>().ok();
                } else if let Some(v) = part.strip_prefix("port=") {
                    port = v.parse::<u32>().ok();
                } else if let Some(v) = part.strip_prefix("ipver=") {
                    ipver = v.parse().unwrap_or(0);
                } else if let Some(v) = part.strip_prefix("drop_only=") {
                    drop_only = v == "1";
                }
            }
            match arm_trace(ebpf, seconds, l4, port, ipver, drop_only) {
                Ok((secs, file)) => json!({
                    "ok": true,
                    "seconds": secs,
                    "file": file,
                    "l4": l4,
                    "port": port,
                    "ipver": ipver,
                    "drop_only": drop_only,
                })
                .to_string(),
                Err(e) => json!({"ok": false, "error": e}).to_string(),
            }
        }
        "rules" => {
            let rules_state = LAST_RULES.lock().ok().and_then(|g| g.clone());
            match rules_state {
                Some(c) => rules_json(&c).to_string(),
                None => json!({"error": "尚无编译结果"}).to_string(),
            }
        }
        "config" => {
            let cfg_state = CONFIG_STATE.lock().ok().and_then(|g| g.clone());
            match cfg_state {
                Some((c, ex)) => {
                    let deferred: Vec<serde_json::Value> = ex
                        .deferred
                        .iter()
                        .map(|d| {
                            json!({
                                "file": c.files.get(d.loc.file).map(|p| p.display().to_string()),
                                "line": d.loc.line,
                                "rule": d.rule,
                                "reason": d.reason,
                            })
                        })
                        .collect();
                    json!({
                        "config": config::to_json(&c),
                        "routing": {
                            "supported": ex.supported,
                            "deferred": deferred,
                            "fallback": ex.fallback,
                            "outbound_map": ex.outbound_map,
                        },
                    })
                    .to_string()
                }
                None => json!({"config": null, "note": "当前会话不是 --config 模式"}).to_string(),
            }
        }
        "maps" => {
            let conn_state = count_map::<SodaTuple, SodaConnState>(ebpf, "conn_state_map");
            let redirect_track = count_map::<SodaTuple, SodaRedirectEntry>(ebpf, "redirect_track");
            let domain_routing =
                count_map::<SodaEpochIp, SodaDomainRouting>(ebpf, "domain_routing_map");
            let fast_sock = count_fast_sock(ebpf);
            let routing_handoff = count_map::<SodaTuple, SodaRoutingHandoffEntry>(ebpf, "routing_handoff_map");
            let stats = read_stats(ebpf);
            json!({
                "conn_state": conn_state,
                "redirect_track": redirect_track,
                "domain_routing": domain_routing,
                "fast_sock": fast_sock,
                "routing_handoff": routing_handoff,
                "connectivity_dead_groups": CONNECTIVITY_DEAD_GROUPS.load(Ordering::Relaxed),
                "rebind_rejected": stats.rebind_rejected,
                "redirect_update_failed": stats.redirect_update_failed,
                "syn_rebind_rejected": stats.syn_rebind_rejected,
                "rebind_rerouted": stats.rebind_rerouted,
                "redirect_overflow": stats.redirect_overflow,
                "offload_redirects": stats.offload_redirects,
                "offload_verdicts": stats.offload_verdicts,
                "offload_pause_passes": stats.offload_pause_passes,
                "event_drops": stats.event_drops,
                "udp_conn_overflow": stats.udp_conn_overflow,
                "tcp_conn_overflow": stats.tcp_conn_overflow,
                "stateless_tcp_passthrough": stats.stateless_tcp_passthrough,
                "frag_tail_passed": stats.frag_tail_passed,
                "parse_unsupported_l4": stats.parse_unsupported_l4,
                "unsolicited_udp_seen": stats.unsolicited_udp_seen,
                "offload_sent_bytes": stats.offload_sent_bytes,
                "account_drops": stats.account_drops,
            })
            .to_string()
        }
        other => json!({
            "error": format!(
                "unknown command '{other}'（命令：status|rules|config|maps|metrics|reload|suspend|resume）"
            )
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_ttl_boundary() {
        let ttl = SODAMA_HANDOFF_TTL_NS;
        // 10ns 前：未过期
        assert!(!handoff_expired(100, 90, ttl));
        // 正好 TTL：不计过期（与读取侧一致：用 `>` 而非 `>=`）
        assert!(!handoff_expired(ttl, 0, ttl));
        // 超 1ns：过期
        assert!(handoff_expired(ttl + 1, 0, ttl));
        // 时钟回退（last_seen 在未来）：不过期
        assert!(!handoff_expired(0, 100, ttl));
    }

    // ---- P38：CLI 小件 ----

    #[test]
    fn abort_scope_and_cmd() {
        // suspend --abort：全部会话；reload --abort：只关旧代
        assert!(abort_should_kill(AbortScope::All, 7, 7));
        assert!(!abort_should_kill(AbortScope::OldGeneration, 7, 7));
        assert!(abort_should_kill(AbortScope::OldGeneration, 6, 7));
        assert_eq!(abort_cmd("reload", false), "reload");
        assert_eq!(reload_cmd("reload", false, 0), "reload");
        assert_eq!(reload_cmd("reload", true, 0), "reload --abort");
        assert_eq!(reload_cmd("reload", false, 5), "reload --drain=5");
        assert_eq!(reload_cmd("reload", true, 5), "reload --abort --drain=5");
        assert_eq!(abort_cmd("reload", true), "reload --abort");
        assert_eq!(abort_cmd("suspend", true), "suspend --abort");
    }

    #[test]
    fn parse_dns_bind_endpoint() {
        // 纯 ip:port = 仅 UDP（对照 dae ParseEndpoint）
        let ep = parse_dns_bind("127.0.0.1:5353").unwrap();
        assert_eq!(ep.addr, "127.0.0.1:5353".parse().unwrap());
        assert!(ep.udp && !ep.tcp);
        let ep = parse_dns_bind("[::1]:5353").unwrap();
        assert!(ep.udp && !ep.tcp);
        // URL 形式：scheme 按 + 拆
        let ep = parse_dns_bind("udp+tcp://127.0.0.1:53").unwrap();
        assert!(ep.udp && ep.tcp);
        let ep = parse_dns_bind("tcp://127.0.0.1:5300").unwrap();
        assert!(!ep.udp && ep.tcp);
        // 非法：未知协议 / 缺协议 / 缺端口 / 空
        assert!(parse_dns_bind("https://127.0.0.1:53").is_err());
        assert!(parse_dns_bind("://127.0.0.1:53").is_err());
        assert!(parse_dns_bind("udp://127.0.0.1").is_err());
        assert!(parse_dns_bind("127.0.0.1").is_err());
        assert!(parse_dns_bind("  ").is_err());
    }

    #[test]
    fn gso_segments_on_loopback() {
        // A2 #17：loopback 上验证 UDP_SEGMENT 真把大 buffer 切成独立数据报
        // （内核不支持/拒绝时跳过——单测环境可能为旧内核/受限 netns）。
        let recv = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv.local_addr().unwrap();
        let send = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        use std::os::fd::AsRawFd as _;
        recv.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let payloads: Vec<Vec<u8>> = vec![b"aaaa".to_vec(), b"bbbb".to_vec(), b"cccc".to_vec()];
        let refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let gso_sent = send_gso_udp(send.as_raw_fd(), recv_addr, &refs).unwrap();
        if gso_sent {
            let mut got = Vec::new();
            for _ in 0..3 {
                let mut buf = [0u8; 64];
                let (n, _) = recv.recv_from(&mut buf).expect("GSO 后应收到 3 个数据报");
                got.push(buf[..n].to_vec());
            }
            assert_eq!(got, payloads, "GSO 应被内核切成 3 个独立数据报");
        } else {
            eprintln!("SKIP: GSO 发送被内核拒绝（回落路径已验证普通发送可用）");
        }
        // 回归守护（A2-5 事故）：无论 GSO 与否，socket 必须保持干净——
        // 普通发送永远可用。（历史实现用 `setsockopt(UDP_SEGMENT, 1)` 做“探测”，
        // 该值 = socket 级默认 gso_size=1 → 此后普通 send 恒 EINVAL，UDP 回复全灭。）
        let sn = send
            .send_to(&payloads[0], recv_addr)
            .expect("GSO 之后同 socket 的普通发送必须可用");
        assert_eq!(sn, 4);
        let mut buf = [0u8; 64];
        let (n, _) = recv.recv_from(&mut buf).expect("GSO 后普通发送应送达");
        assert_eq!(&buf[..n], payloads[0].as_slice());
    }

    #[test]
    fn parse_bandwidth_units() {
        assert_eq!(parse_bandwidth("0").unwrap(), 0);
        assert_eq!(parse_bandwidth("").unwrap(), 0);
        // 裸数字 = Mbit/s
        assert_eq!(parse_bandwidth("100").unwrap(), 12_500_000);
        // 带单位
        assert_eq!(parse_bandwidth("10mbps").unwrap(), 1_250_000);
        assert_eq!(parse_bandwidth("1g").unwrap(), 125_000_000);
        assert_eq!(parse_bandwidth("500kb").unwrap(), 62_500);
        assert_eq!(parse_bandwidth("8192B").unwrap(), 8192);
        // 纯数字 + ps 后缀（不得 panic）
        assert_eq!(parse_bandwidth("100ps").unwrap(), 12_500_000);
        assert!(parse_bandwidth("abc").is_err());
        assert!(parse_bandwidth("10 furlongs").is_err());
    }

    #[test]
    fn rate_limiter_throttles_small_writes() {
        // 1 MB/s：一次 64KB 写入应放行（桶初始满 = 1s 的量）。
        let l = RateLimiter::new();
        l.set_rate(1_000_000);
        let t0 = Instant::now();
        l.throttle(65536);
        assert!(t0.elapsed() < Duration::from_millis(100), "桶满时不应延迟");
        // 把 1MB 额度花光后，再来 128KB 需要 ~0.13s 等令牌。
        l.throttle(1_000_000 - 65536);
        let t1 = Instant::now();
        l.throttle(131_072);
        let dt = t1.elapsed();
        assert!(
            dt >= Duration::from_millis(100) && dt < Duration::from_millis(500),
            "节流等待应约 0.13s，实测 {dt:?}"
        );
        // rate=0 → 恢复不限速（立即返回）。
        l.set_rate(0);
        let t2 = Instant::now();
        l.throttle(10_000_000);
        assert!(t2.elapsed() < Duration::from_millis(50), "0 = 不限速");
    }

    #[test]
    fn alert_pacer_first_emits_then_cooldown() {
        // A2 #14：首次必发 → 冷却期内只计数 → 冷却后复发（带累计观察次数）。
        let p = AlertPacer::new(1_000_000_000);
        assert_eq!(p.observe(100), (1, true));
        assert_eq!(p.observe(200), (2, false));
        assert_eq!(p.observe(999_999_999), (3, false));
        assert_eq!(p.observe(1_000_000_100), (4, true));
    }

    #[test]
    fn log_rotation_creates_gz_backup() {
        let dir = std::env::temp_dir().join(format!("sodama-logrot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sodama.log");
        std::fs::write(&path, "line1\nline2\n").unwrap();
        let _ = LOG_PATH.set(path.display().to_string());
        assert!(open_log_file(path.to_str().unwrap()), "打开日志文件");
        LOG_MAX_BACKUPS.store(2, Ordering::Relaxed);
        rotate_log_now();
        let gz_path = dir.join("sodama.log.1.gz");
        assert!(gz_path.exists(), "轮转产物 {gz_path:?} 应存在");
        let gz = std::fs::read(&gz_path).unwrap();
        assert_eq!(crate::dump::gunzip_store(&gz), b"line1\nline2\n");
        // 当前文件只剩「轮转」这一条日志（旧内容已压入 .1.gz）
        let now_content = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(
            now_content.contains("日志轮转"),
            "当前文件应含轮转提示：{now_content:?}"
        );
        assert!(!now_content.contains("line1"), "旧内容不应留在当前文件");
        assert!(LOG_SINK.lock().unwrap().is_some(), "轮转后应重开 sink");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_log_level_values() {
        assert_eq!(parse_log_level("off"), Some(0));
        assert_eq!(parse_log_level("ERROR"), Some(1));
        assert_eq!(parse_log_level(" warning "), Some(2));
        assert_eq!(parse_log_level("info"), Some(3));
        assert_eq!(parse_log_level("debug"), Some(4));
        assert_eq!(parse_log_level("trace"), Some(4));
        assert_eq!(parse_log_level("verbose"), None);
    }

    #[test]
    fn log_line_timestamp_toggle() {
        assert_eq!(
            log_line(false, "2026-10-16 12:00:00", "hello"),
            "[sodama] 2026-10-16 12:00:00 hello"
        );
        assert_eq!(
            log_line(true, "2026-10-16 12:00:00", "hello"),
            "[sodama] hello"
        );
    }

    #[test]
    fn config_doc_registry_covers_all_keys() {
        // 登记表必须覆盖三个键白名单的全部键（新增键忘了同步会在这里红）。
        let docs = config::key_docs();
        for (section, keys) in [
            ("global", config::GLOBAL_KEYS),
            ("dns", config::DNS_KEYS),
            ("group", config::GROUP_KEYS),
        ] {
            for k in keys {
                assert!(
                    docs.iter().any(|d| d.section == section && d.key == *k),
                    "{section}.{k} 缺少 config-doc 登记"
                );
            }
        }
    }

    #[test]
    fn config_reference_artifact_in_sync() {
        // docs/config-reference.md 必须与生成器一致（防止文档 drift）。
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/config-reference.md");
        if !path.exists() {
            return; // 裁剪源码树（打包后）跳过
        }
        let want = config_doc_markdown();
        let got = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            got, want,
            "docs/config-reference.md 与 `sodama config-doc` 不一致（重新生成即可）"
        );
    }

    #[test]
    fn completion_scripts_cover_subcommands_and_flags() {
        let bash = completion_script("bash").unwrap();
        assert!(bash.contains("complete -F _sodama sodama"));
        assert!(bash.contains("--dialer"));
        assert!(bash.contains("bash zsh fish"));
        let zsh = completion_script("zsh").unwrap();
        assert!(zsh.starts_with("#compdef sodama"));
        assert!(zsh.contains("--compile-dump"));
        let fish = completion_script("fish").unwrap();
        assert!(fish.contains("__fish_use_subcommand"));
        assert!(fish.contains("-l dialer"));
        for sub in COMPLETION_SUBCOMMANDS {
            assert!(bash.contains(sub), "bash 缺少子命令 {sub}");
            assert!(zsh.contains(sub), "zsh 缺少子命令 {sub}");
            assert!(fish.contains(sub), "fish 缺少子命令 {sub}");
        }
        assert!(completion_script("powershell").is_none());
    }

    #[test]
    fn completion_artifacts_in_sync() {
        // 预生成副本（install/shell-completion/）必须与生成器一致——防止 drift。
        // 裁剪源码树（如打包后）无该目录时跳过。
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install/shell-completion");
        if !base.exists() {
            return;
        }
        for (shell, file) in [
            ("bash", "sodama.bash"),
            ("zsh", "sodama.zsh"),
            ("fish", "sodama.fish"),
        ] {
            let want = completion_script(shell).unwrap();
            let got = std::fs::read_to_string(base.join(file)).unwrap_or_default();
            assert_eq!(
                got, want,
                "{file} 与 `sodama completion {shell}` 不一致（重新生成即可）"
            );
        }
    }

    #[test]
    fn pidfile_write_read_remove() {
        let dir = std::env::temp_dir().join(format!("sodama-pidfile-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sodama.pid");
        let _ = std::fs::remove_file(&path);
        // 写入 → 内容为十进制 pid
        write_pidfile_at(&path, 4242).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "4242");
        // 覆盖写（dae 同语义：已存在直接覆盖）
        write_pidfile_at(&path, 7).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "7");
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- eBPF 缺口批次：offload 背压 fuse 的判定逻辑（纯函数锁定） ----

    #[test]
    fn fuse_decision_engage_drain_and_lift() {
        let none = None;
        // 未 fused：backlog 超阈值 → Engage
        let (d, backlog) = fuse_decision(100_000, 10, 0, false, false, false, none, none, 65_536);
        assert_eq!(d, FuseDecision::Engage);
        assert_eq!(backlog, 99_990);
        // 未超阈值 → None
        let (d, _) = fuse_decision(1_000, 10, 0, false, false, false, none, none, 65_536);
        assert_eq!(d, FuseDecision::None);
        // fused、未开始 drain、backlog 回落 → DrainStart（先停泵排空，不直接删键）
        let (d, _) = fuse_decision(
            100_000,
            99_000,
            500,
            true,
            false,
            false,
            Some(Duration::from_secs(1)),
            none,
            65_536,
        );
        assert_eq!(d, FuseDecision::DrainStart);
        // fused、未 drain_started 且 backlog 高 → 保持（继续 pause）
        let (d, _) = fuse_decision(
            10_000_000,
            10,
            0,
            true,
            false,
            false,
            Some(Duration::from_secs(1)),
            none,
            65_536,
        );
        assert_eq!(d, FuseDecision::None);
        // fused、未 drain_started、engage 超时 → 也进入 DrainStart（不能卡死）
        let (d, _) = fuse_decision(
            10_000_000,
            10,
            0,
            true,
            false,
            false,
            Some(Duration::from_secs(11)),
            none,
            65_536,
        );
        assert_eq!(d, FuseDecision::DrainStart);
        // drain_started + drained → Lift
        let (d, _) = fuse_decision(
            100_000,
            99_000,
            500,
            true,
            true,
            true,
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(1)),
            65_536,
        );
        assert_eq!(d, FuseDecision::Lift);
        // drain_started + 未 drained（未超时）→ 保持（等泵排空）
        let (d, _) = fuse_decision(
            100_000,
            99_000,
            500,
            true,
            false,
            true,
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(1)),
            65_536,
        );
        assert_eq!(d, FuseDecision::None);
        // drain_started + drain 超时 → LiftTimeout（强制 lift 但可观测）
        let (d, _) = fuse_decision(
            100_000,
            10,
            0,
            true,
            false,
            true,
            Some(Duration::from_secs(12)),
            Some(Duration::from_secs(11)),
            65_536,
        );
        assert_eq!(d, FuseDecision::LiftTimeout);
        // 计数回退（inflow < sent）→ backlog 负值，不 engage
        let (d, backlog) = fuse_decision(0, 1_000, 0, false, false, false, none, none, 65_536);
        assert_eq!(d, FuseDecision::None);
        assert_eq!(backlog, -1_000);
    }

    #[test]
    fn fuse_threshold_env_override() {
        // SODAMA_FUSE_MAX_BACKLOG 可调（测试用）；未设时默认 64 MiB。
        // 注意：env 是进程级，测试不写它（避免并行测试互相干扰），只验证默认值。
        if std::env::var("SODAMA_FUSE_MAX_BACKLOG").is_err() {
            assert_eq!(fuse_max_backlog(), 64 << 20);
        }
    }

    // ---- P37（2026-10-13）SubFetchMode 合并语义 ----

    #[test]
    fn subfetch_mode_merge_prefers_wider() {
        use SubFetchMode::*;
        let heal = |tags: &[&str]| Heal(tags.iter().map(|s| s.to_string()).collect());
        // 任一 Full → Full（超集）
        assert_eq!(Fast.merge(Full), Full);
        assert_eq!(heal(&["a"]).merge(Full), Full);
        // Heal 之间取并集
        let m = heal(&["a"]).merge(heal(&["b", "c"]));
        match m {
            Heal(s) => {
                assert!(s.contains("a") && s.contains("b") && s.contains("c"));
            }
            other => panic!("期待 Heal，得到 {other:?}"),
        }
        // Fast 与 Heal 混合 → Heal（打网集合更大）
        assert_eq!(Fast.merge(heal(&["a"])), heal(&["a"]));
        // Fast 之间仍为 Fast
        assert_eq!(Fast.merge(Fast), Fast);
    }

    #[test]
    fn posix_tz_simple_forms() {
        // OpenWrt 的 /etc/TZ 就是这种形式；生产踩坑：musl 在 TZ 未设时不读它。
        assert_eq!(parse_posix_tz("CST-8"), Some(8 * 3600));
        assert_eq!(parse_posix_tz("UTC0"), Some(0));
        assert_eq!(parse_posix_tz("UTC"), Some(0));
        assert_eq!(parse_posix_tz("EST5"), Some(-5 * 3600));
        assert_eq!(parse_posix_tz("<+08>-8"), Some(8 * 3600));
        assert_eq!(parse_posix_tz("CST-8:30"), Some(8 * 3600 + 30 * 60));
        assert_eq!(parse_posix_tz(""), None);
        assert_eq!(parse_posix_tz("8"), None); // 缺名字
        assert_eq!(parse_posix_tz("CST-x"), None); // 偏移非数字
                                                   // 带 DST 的完整形式：只取标准时部分（不误解 DST 规则）
        assert_eq!(parse_posix_tz("CST-8CDT-7,M3.2.0,M11.1.0"), Some(8 * 3600));
    }

    #[test]
    fn epoch_to_civil_matches_known_instants() {
        assert_eq!(epoch_to_civil(0), (1970, 1, 1, 0, 0, 0));
        // 2026-10-08 16:37:12 UTC（= 北京时间 2026-10-09 00:37:12）
        assert_eq!(epoch_to_civil(1791477432), (2026, 10, 8, 16, 37, 12));
        assert_eq!(
            epoch_to_civil(1791477432 + 8 * 3600),
            (2026, 10, 9, 0, 37, 12)
        );
        // 闰日与跨世纪
        assert_eq!(epoch_to_civil(951782400), (2000, 2, 29, 0, 0, 0));
        // 负 epoch（偏移可能把时间拉到之前）
        assert_eq!(epoch_to_civil(-86400), (1969, 12, 31, 0, 0, 0));
    }

    #[test]
    fn default_config_candidates_order_and_no_home_fallback() {
        let c = default_config_candidates(Some("/xdg"), Some("/home/u"));
        assert_eq!(c[0], std::path::PathBuf::from("/xdg/sodama/config.dae"));
        assert_eq!(
            c[1],
            std::path::PathBuf::from("/home/u/.config/sodama/config.dae")
        );
        assert_eq!(c[2], std::path::PathBuf::from("/etc/sodama/config.dae"));
        // 无 home/XDG（软路由/OpenWrt）：仍能落到 /etc/sodama
        let c = default_config_candidates(None, None);
        assert_eq!(c, vec![std::path::PathBuf::from("/etc/sodama/config.dae")]);
        let c = default_config_candidates(Some(""), Some(""));
        assert_eq!(c, vec![std::path::PathBuf::from("/etc/sodama/config.dae")]);
    }

    /// O7：会话表分片——同 key 始终同片，不同 key 能铺开（避免单锁竞争）。
    #[test]
    fn udp_nat_shard_stable_and_spread() {
        let k = UdpFlowKey {
            client: "10.0.0.1:1000".parse().unwrap(),
            dst: Some("1.1.1.1:53".parse().unwrap()),
        };
        assert!(std::ptr::eq(udp_nat_shard(&k), udp_nat_shard(&k)));
        let mut set = std::collections::HashSet::new();
        for i in 0..64u16 {
            let kk = UdpFlowKey {
                client: SocketAddr::from(([10, 0, 0, 1], 1000 + i)),
                dst: Some(SocketAddr::from(([1, 1, 1, 1], 53))),
            };
            set.insert(udp_nat_shard(&kk) as *const _ as usize);
        }
        assert!(set.len() > 4, "分片过少：{}", set.len());
        // full-cone 键（dst=None）与 affine 键落在同一分片算法下（稳定且可区分）
        let cone = UdpFlowKey {
            client: "10.0.0.1:1000".parse().unwrap(),
            dst: None,
        };
        assert!(std::ptr::eq(udp_nat_shard(&cone), udp_nat_shard(&cone)));
    }

    #[test]
    fn udp_ttl_classification_and_quic() {
        // dae 分类：DNS 17s；QUIC|域名 5min；代理地板 5min；其余 = NAT 默认
        assert_eq!(udp_ttl_secs(60, 53, false, false), 17);
        assert_eq!(udp_ttl_secs(60, 443, true, false), 300);
        assert_eq!(udp_ttl_secs(60, 443, false, true), 300);
        assert_eq!(udp_ttl_secs(60, 8080, false, false), 60);
        assert_eq!(udp_ttl_secs(600, 8080, false, false), 600);
        assert_eq!(udp_ttl_secs(10, 53, false, true), 300);
        // QUIC Initial 形态判定
        let mut q = vec![0u8; 1200];
        q[0] = 0xC0;
        assert!(is_quic_initial(&q));
        q[0] = 0x40;
        assert!(!is_quic_initial(&q));
        assert!(!is_quic_initial(&[0xC0; 100]));
    }

    #[test]
    fn udp_checksum_golden_vector() {
        // 黄金向量（python 标准算法生成）：src=10.0.0.1:1000 dst=10.0.0.2:2000 payload="hello"
        let pkt: Vec<u8> = vec![
            0x03, 0xE8, 0x07, 0xD0, 0x00, 0x0D, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o',
        ];
        let ck = udp_checksum(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            &pkt,
        );
        assert_eq!(ck, 0x9c47);
        // v6 伪头（同一载荷；python 生成）
        let ck6 = udp_checksum(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            &pkt,
        );
        assert_eq!(ck6, 0x54d5);
        // 家族不一致 → 0（不发）
        assert_eq!(
            udp_checksum(
                "10.0.0.1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                &pkt
            ),
            0
        );
    }

    /// P19：单个上游构造失败（如非法 URL）应被跳过，其余照常生效——
    /// 不再让一个坏条目把整个上游集（进而全机 DNS）拖垮。
    #[test]
    fn upstream_set_skips_broken_entries() {
        let dir = std::env::temp_dir().join(format!("sodama-uptest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("t.dae");
        std::fs::write(
            &cfg,
            concat!(
                "global { }\n",
                "dns {\n",
                "    upstream {\n",
                "        bad: 'https://'\n",
                "        good: 'udp://127.0.0.1:53'\n",
                "    }\n",
                "}\n",
                "routing { fallback: proxy }\n"
            ),
        )
        .unwrap();
        // config::load 默认校验权限（≤0640），测试文件收紧到 0600。
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let set = build_upstream_set_core(None, Some(&cfg)).expect("至少 good 可用");
        assert!(set.by_tag.contains_key("good"), "{:?}", set.by_tag.keys());
        assert!(!set.by_tag.contains_key("bad"));
        assert_eq!(set.legacy.url, "udp://127.0.0.1:53");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- C3/对标批：eBPF 用户态镜像结构尺寸自检 ----

    /// 两侧镜像（ebpf-rs/src/common.rs ↔ loader）一旦漂移，事件解码会按错位字节读、
    /// ringbuf 长度校验失效；用尺寸断言把漂移钉死在测试里（dae 靠 C/Go 同仓编译
    /// 保证 ABI，而这里是两个独立构建单元，只能显式自检）。
    #[test]
    fn ebpf_mirror_struct_sizes() {
        assert_eq!(std::mem::size_of::<SodaEvent>(), 72);
        assert_eq!(std::mem::size_of::<TraceParam>(), 16);
        assert_eq!(std::mem::size_of::<SodaTuple>(), 40);
    }
}

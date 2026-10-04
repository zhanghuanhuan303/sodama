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
use aya::maps::{Array, ArrayOfMaps, HashMap, LpmTrie, MapData, SockHash, SockMap};
use aya::programs::tc::{self, TcAttachType};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SchedClassifier, SkSkb};
use aya::programs::{CgroupSockAddrAttachType, CgroupSockAttachType};
use aya::Ebpf;
use serde_json::json;

mod anytls;
mod bootstrap;
mod brutal;
mod bufpool;
mod config;
mod dns;
mod dnsroute;
mod dnsup;
mod geodata;
mod group;
mod h2client;
mod h3client;
mod hpack;
mod huffman_table;
mod hysteria2;
mod juicity;
mod outbound;
mod quicsniff;
mod quicsock;
mod quicvarint;
mod reactor;
mod reality;
mod rules;
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
mod target;
mod tls;
mod tls13;
mod trojan;
mod tuic;
mod vision;
mod vless;
mod vmess;
mod ws;

/// dae 给控制面自己的 socket 打的内部 mark（对照 so_mark_from_dae / dae_socket_mark）。
/// 副作用：避免监听 socket 的 sk_mark 为 0 时新连接继承 SYN 上的 TPROXY_MARK
/// （内核 net.ipv4.tcp_fwmark_accept=1 时的 inet_request_mark 行为）。
const DAE_SOCKET_MARK: libc::c_int = 0x233;

/// 与 ebpf-rs/src/common.rs 的 SODAMA_MAX_MATCH_SET_LEN 保持一致。
const MAX_MATCH_SET_LEN: u32 = rules::MAX_MATCH_SET_LEN;
const EPOCH_SLOT_NUM: u32 = 2;
/// conn_state janitor 扫描间隔
const JANITOR_INTERVAL: Duration = Duration::from_secs(5);

static RELOAD: AtomicBool = AtomicBool::new(false);
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
/// M1：splice 不可用回退日志（只打一次，避免刷屏）。
static SPLICE_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);
/// P11：relay 拨号超时（毫秒，默认 5000；真实节点首连可能较慢）
static RELAY_DIAL_TIMEOUT_MS: AtomicU64 = AtomicU64::new(5000);
/// P4b：UDP NAT 会话空闲阈值（秒）。
static UDP_IDLE_SECS: AtomicU64 = AtomicU64::new(60);

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
    /// P18e：并发上限拒绝数（--max-conns）。
    limit_rejected: AtomicU64,
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
    limit_rejected: AtomicU64::new(0),
};

/// P18e：relay 并发上限（0 = 不限；对照 dae relay 的并发上限）。
static RELAY_MAX_CONNS: AtomicU64 = AtomicU64::new(0);

/// P4c：offload 用的 fast_sock SOCKHASH（从 Ebpf 中取出后由 relay 线程共享写入）。
static RELAY_OFFLOAD: OnceLock<Mutex<SockHash<MapData, SodaTuple>>> = OnceLock::new();
/// P8：Rust/aya-ebpf offload 对象的预检镜像（HASH map，与 fast_sock 同步双写）。
static RELAY_OFFLOAD_GUARD: OnceLock<Mutex<HashMap<MapData, SodaTuple, u8>>> = OnceLock::new();

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
}
static UDP_NAT_STATS: UdpNatStats = UdpNatStats {
    sessions_total: AtomicU64::new(0),
    sessions_proxied: AtomicU64::new(0),
    direct_fallback: AtomicU64::new(0),
    bytes_up: AtomicU64::new(0),
    bytes_down: AtomicU64::new(0),
    evicted: AtomicU64::new(0),
    errors: AtomicU64::new(0),
};

/// 一条 UDP NAT 会话：每个 (client, orig_dst) 一个出口（direct 或 ss），
/// 回包用绑定原始目的地址的透明 socket 直接发给客户端（不绕 dae0）。
struct UdpSession {
    client: SocketAddr,
    relay: outbound::UdpRelay,
    reply: Arc<OwnedFd>,
    last_ns: AtomicU64,
    alive: AtomicBool,
}

static UDP_NAT: std::sync::LazyLock<Vec<UdpNatShard>> = std::sync::LazyLock::new(|| {
    (0..UDP_NAT_SHARDS)
        .map(|_| Mutex::new(std::collections::HashMap::new()))
        .collect()
});
type UdpNatShard = Mutex<std::collections::HashMap<(SocketAddr, SocketAddr), Arc<UdpSession>>>;

/// O7：会话表分片数（单锁在包速率下会成为竞争点；按 key hash 选片）。
const UDP_NAT_SHARDS: usize = 16;
/// O7：监听/回程一次 recvmmsg 最多收包数。
const UDP_RECV_BATCH: usize = 32;

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
fn udp_nat_shard(key: &(SocketAddr, SocketAddr)) -> &'static UdpNatShard {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for ip in [key.0.ip(), key.1.ip()] {
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
    for p in [key.0.port(), key.1.port()] {
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
    client: TcpStream,
    /// QUIC 协议（tuic）没有底层 TCP，为 None。
    upstream: Option<TcpStream>,
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
    dae0peer_mac: [u8; 6],
    pad: [u8; 2],
}
unsafe impl aya::Pod for SodaConfig {}

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
    pad: [u8; 3],
}
unsafe impl aya::Pod for SodaConnState {}

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

struct Args {
    ebpf: String,
    /// LAN 侧接口（ingress 分流）；`--lan none` = 不挂 LAN 钩子（纯本机网关）
    lan: Vec<String>,
    /// 是否显式声明不挂 LAN 钩子（`--lan none`；阻止默认值 landae）
    no_lan: bool,
    /// WAN 侧接口（egress 分流 + ingress 状态刷新）
    wan: Vec<String>,
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
}

fn log(msg: &str) {
    let line = format!("[sodama] {msg}");
    let mut done = false;
    if let Ok(mut g) = LOG_SINK.lock() {
        if let Some(f) = g.as_mut() {
            use std::io::Write as _;
            if writeln!(f, "{line}").and_then(|_| f.flush()).is_ok() {
                done = true;
            }
        }
    }
    if !done {
        println!("{line}");
        let _ = std::io::stdout().flush();
    }
}

/// P6：打开（或 SIGHUP 后重开）日志文件；best-effort，失败保留原输出。
fn open_log_file(path: &str) -> bool {
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => {
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
           --ebpf <path>         eBPF object（默认 ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf）\n\
           --lan <ifname>        LAN 侧接口，可重复（默认 landae；`--lan none` = 不挂 LAN 钩子，本机网关模式）\n\
           --wan <ifname>        WAN 侧接口，可重复（默认 wan）\n\
           --dual <ifname>       单臂模式：同一接口同时挂 LAN/WAN 合用程序，可重复\n\
           --dae0 <ifname>       控制面设备（默认 dae0）\n\
           --dae0peer <ifname>   dae netns 内对端设备（默认 dae0peer）\n\
           --daens <name>        dae netns 名字（默认 daens）\n\
           --tproxy-port <port>  tproxy 监听端口（默认 12345）\n\
           --rules <path>        路由规则文件（sodama 语法，缺省时由 --proxy 生成）\n\
           --config <path>       完整 dae .dae 配置（含 include；优先于 --rules）\n\
           --strict-config       配置中有规则无法编译时直接报错（默认列 deferred 后继续）\n\
           --status-socket <path> 状态面：Unix socket 上的 JSON（status/rules/config/maps + 控制命令）\n\
           --log-file <path>     P6：日志写文件（默认 stdout；SIGHUP 时 reopen，轮转友好）\n\
           --dialer <url>        P4：代理出口拨号器（direct 或 socks5://host:port）\n\
           --relay-idle-timeout <s> P4：relay 空闲回收秒数（默认 300）
           --dial-timeout <s>       P11：relay 拨号超时秒数（默认 5；真实节点慢首连可调大）
           --dial-mode <m>          P14：ip|domain|domain+（默认 ip；域名模式嗅探 SNI/Host 后远端解析，绕 DNS 污染）
           --sniffing-timeout-ms <n> P14：嗅探等待上限毫秒（默认 100；仅 dial_mode != ip 时生效）
           --sniff-punt             P21：嗅探命中域名后按规则在 relay 侧重选出口（direct/block/用户组）
           --subscribe <url>        P15：订阅（可重复；config subscription 段同源），与 --group 搭配
           --group <name>           P15：选用 config 中的组（默认 proxy / 唯一组）
           --geodata-dir <dir>      P17a：geoip.dat/geosite.dat 搜索目录（可重复；优先于 DAE_LOCATION_ASSET）
           --listen-socks <addr>    P12：本地 SOCKS5 入口（浏览器测试用；不加载 eBPF、不需 root）\n\
           --udp-idle-timeout <s>   P4：UDP NAT 会话空闲秒数（默认 60）\n\
           --forward <url>       旧写法：等价于 --dialer socks5://host:port\n\
           --offload             P4c：启用 TCP relay offload（内核对拼，需 --dialer）\n\
           --no-splice           M1：关闭 relay splice 零拷贝（默认开：Direct/VLESS 明文）\n\
           --ebpf-debug          M1：eBPF 热路径调试打印（默认关）\n\
           --ktls                M2：尝试 kTLS（内核 TLS，实验；需 TLS1.3）\n\
           --max-conns <N>       P18e：relay 并发上限（0=不限；超限直接关闭并计数）\n\
           --dns-upstream <url>  P3a：DNS 上游（host:port 或 udp://host:port）\n\
           --dump                打印编译出的 match_set / LPM 内容\n\
           --compile-dump <path> 只编译规则并按对拍格式打印（不加载 eBPF，不需要 root）\n\
           --proxy <ipv4>        无 --rules 时加入「走代理」的目的 IP，可重复\n\
         \n\
         子命令（不加载 eBPF、不需 root）：\n\
           sodama validate <config.dae>       解析 + schema 校验 + routing 可编译性报告\n\
           sodama export-config <config.dae>  合并后的配置导出为 JSON\n\
           sodama extract-routing <config.dae> 输出可编译规则（deferred 到 stderr）\n\
           sodama status [--socket <path>] [--json]  查询状态面\n\
           sodama reload [--socket <path>]      P6：热重载（等价 kill -HUP，同步等结果）\n\
           sodama suspend|resume [--socket <path>] P6：no-load 挂起 / 恢复（对照 dae suspend）\n\
           sodama metrics [--socket <path>]     P6：Prometheus 文本格式统计导出\n\
           sodama sysdump [--socket <path>] [--out <file>] P6：状态+规则+系统网络信息归档\n\
           sodama trace [--seconds N]           P6：过滤 sodama 的 ftrace 输出（需 root）\n\
         \n\
         运行中收到 SIGHUP 会重读 --rules/--config 并热重载（非活跃槽 → 切换 active），\n\
         同时清除 suspend 状态并 reopen --log-file（对照 dae reload）；SIGUSR2 = suspend。"
    );
    std::process::exit(2);
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut args = Args {
        ebpf: "ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf".into(),
        lan: Vec::new(),
        no_lan: false,
        wan: Vec::new(),
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
        splice: true,
        ebpf_debug: false,
        ktls: false,
        dns_upstream: None,
        dump: false,
        compile_dump: None,
        proxy_dsts: Vec::new(),
        log_file: None,
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
            "--subscribe" => args.subscribe.push(next()?),
            "--geodata-dir" => args.geodata_dir.push(next()?),
            "--group" => args.group = Some(next()?),
            "--listen-socks" => args.listen_socks = Some(next()?),
            "--udp-idle-timeout" => args.udp_idle_timeout = Some(next()?.parse()?),
            "--forward" => args.forward = Some(next()?),
            "--offload" => args.offload = true,
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
    Ok(args)
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
        (libc::SOL_SOCKET, libc::SO_MARK, "SO_MARK", DAE_SOCKET_MARK),
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
        (libc::SOL_SOCKET, libc::SO_MARK, "SO_MARK", DAE_SOCKET_MARK),
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
    let link = program.attach(ifname, attach_type)?;
    // link 持有 TCX/BPF link 的 fd，drop 即摘除钩子；实验进程全程保活。
    std::mem::forget(link);
    log(&format!("attached {name} to {ifname} ({attach_type:?})"));
    if let Ok(mut hooks) = HOOKS.lock() {
        hooks.push(format!("{name}@{ifname}"));
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
                std::thread::spawn(move || handle_tproxy_conn(stream));
            }
            Err(e) => eprintln!("[sodama] accept error: {e}"),
        }
    }
}

fn handle_tproxy_conn(mut stream: TcpStream) {
    // P3b-1：TCP DNS（落到 tproxy 的 53 端口）交给 host ns 的 DNS 处理线程。
    if let Ok(dst) = stream.local_addr() {
        if dst.port() == 53 {
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
    let mut buf = [0u8; 4096];
    for _ in 0..8 {
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
fn pump(
    mut r: Box<dyn outbound::ReadHalf>,
    mut w: Box<dyn outbound::WriteHalf>,
    last_ns: &AtomicU64,
    bytes: &AtomicU64,
    offloaded: bool,
    stop: Option<&AtomicBool>,
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
                bytes.fetch_add(n as u64, Ordering::Relaxed);
                if let Err(e) = w.write_all(&buf[..n]) {
                    log(&format!("pump: 写失败（{e}）"));
                    break;
                }
            }
        }
    }
    let _ = w.shutdown_write();
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
    bytes: &AtomicU64,
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
        bytes.fetch_add(n as u64, Ordering::Relaxed);
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
                RELAY_STATS
                    .bytes_down
                    .fetch_add(n as u64, Ordering::Relaxed);
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
            match splice_pump(
                upstream_fd,
                client.as_raw_fd(),
                last_ns,
                &RELAY_STATS.bytes_down,
            ) {
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
        &RELAY_STATS.bytes_down,
        false,
        stop,
    );
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
}

static OFFLOAD_WATCH: std::sync::LazyLock<(Mutex<Vec<OffloadWatchEntry>>, std::sync::Condvar)> =
    std::sync::LazyLock::new(|| (Mutex::new(Vec::new()), std::sync::Condvar::new()));

/// 注册一个 offload 连接（在 `handle_relay_conn` 内，注册后直接返回）。
fn offload_watch_register(e: OffloadWatchEntry) {
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
        offload_guard_remove(k_up);
        offload_guard_remove(k_cl);
        if let Some(map) = RELAY_OFFLOAD.get() {
            if let Ok(mut m) = map.lock() {
                let _ = m.remove(k_up);
                let _ = m.remove(k_cl);
            }
        }
        log(&format!("offload: #{id} 已注销 fast_sock 键"));
    }
    relay_finish(id);
}

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
                    let e = v.swap_remove(i);
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

/// P19：按连接 5 元组从 conn_state_map 回读数据面选中的 outbound（raw lookup）。
fn lookup_conn_outbound(remote: SocketAddr, local: SocketAddr, l4proto: u8) -> Option<u8> {
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
    Some(st.outbound)
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
    let Some(map) = RELAY_OFFLOAD.get() else {
        return None;
    };
    let Ok(mut m) = map.lock() else {
        return None;
    };
    let r1 = m.insert(&key_for_upstream, upstream.as_raw_fd(), 0);
    let r2 = m.insert(&key_for_client, client.as_raw_fd(), 0);
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

/// P7：offload 注册前的「前缀排空」——把 socket 接收队列里已有的数据经用户态
/// 泵写到对端；返回 true = 队列已空且可安全注册。
/// 对照 dae newTCPRelayOffloadSession：注册前 drain 内核队列，若仍有 pending 数据
/// 则拒绝 offload——否则队列里的数据会被用户态泵与内核重定向**双重处理**（C 基准
/// 实测出重复字节：8MB 流量多出 17B）。
fn drain_prefix(
    mut sock: &TcpStream,
    peer: &mut dyn outbound::WriteHalf,
    bytes: &AtomicU64,
) -> bool {
    if sock.set_nonblocking(true).is_err() {
        return false;
    }
    let mut buf = [0u8; 65536];
    let mut ok = true;
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                bytes.fetch_add(n as u64, Ordering::Relaxed);
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
            up2.as_ref(),
            false,
            None,
        );
    });
    pump(
        from_remote,
        Box::new(client),
        last_ns.as_ref(),
        down.as_ref(),
        false,
        None,
    );
    log(&format!(
        "SOCKS {tname} closed（up={}B down={}B）",
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed)
    ));
}

/// relay 一条连接：按 dialer 拨号到 orig_dst，双向转发（含半关闭）。
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
                log(&format!("sniff {orig} → {name}（域名交节点远端解析）"));
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
                    target::Target::domain(name, orig.port())
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
            let c_ok = drain_prefix(&client, to_remote.as_mut(), &RELAY_STATS.bytes_up);
            let u_ok = drain_prefix(sock, &mut client, &RELAY_STATS.bytes_down);
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
    // M1：splice 零拷贝（仅未 offload 时；直接拨号/VLESS 明文在拨号层置位）。
    let splice = wire_splice && !offloaded && RELAY_SPLICE.load(Ordering::Relaxed);
    // M4 stage 2：非 splice 的 rustls/明文链路（codec 会话）也可交 reactor——
    // 读半/写半在 worker 内非阻塞驱动（仅对已审计的协议种类开启）。
    let wire_codec = !splice && !offloaded && dialer.codec_reactor_capable();
    let upstream_fd = socket.as_ref().map(|s| s.as_raw_fd());
    if splice {
        RELAY_STATS.splice_total.fetch_add(1, Ordering::Relaxed);
    }
    let id = NEXT_RELAY_ID.fetch_add(1, Ordering::Relaxed);
    // QUIC（tuic）没有底层 TCP：upstream 用 Option（仅 janitor 强制关闭用）。
    let Ok(client_clone) = client.try_clone() else {
        let _ = client.shutdown(std::net::Shutdown::Both);
        return;
    };
    let upstream = match socket.as_ref().map(|s| s.try_clone()) {
        Some(Ok(u)) => Some(u),
        Some(Err(_)) => {
            let _ = client.shutdown(std::net::Shutdown::Both);
            return;
        }
        None => None,
    };
    let handle = Arc::new(RelayHandle {
        last_ns: AtomicU64::new(monotonic_now_ns()),
        offloaded: AtomicBool::new(offloaded),
        stop: AtomicBool::new(false),
        client: client_clone,
        upstream,
    });
    if let Ok(mut m) = RELAY_CONNS.lock() {
        m.insert(id, handle.clone());
    }
    // P7/M4 stage 2：offload 连接交全局看门狗（单线程，每连接 0 线程；
    // 半关闭判定/超时回收/fast_sock 注销均在 `offload_watch_loop` 统一完成）。
    if offloaded {
        if let Some(keys) = offload_keys.take() {
            let up_fd = handle.upstream.as_ref().map(|u| u.as_raw_fd());
            if let Some(uf) = up_fd {
                offload_watch_register(OffloadWatchEntry {
                    id,
                    client_fd: handle.client.as_raw_fd(),
                    upstream_fd: uf,
                    handle: handle.clone(),
                    keys: Some(keys),
                    client_closed: false,
                    upstream_closed: false,
                    first_close: None,
                    err_logged: false,
                });
                return;
            }
            // offload 必有 upstream socket；防御性兑底：键已取出则直接回收，
            // 不能落入驻留泵（无看门狗时无从置 stop）。
            log("offload: 无 upstream socket，放弃内核路径并回收");
            let _ = handle.client.shutdown(std::net::Shutdown::Both);
            offload_watch_cleanup(id, &Some(keys));
            return;
        }
    }
    // M4：splice 连接的 epoll worker 池（每连接 0 线程）。需要响应头前缀的链路
    // （VLESS）由 prelude 线程用 codec 读半消费后恢复；Direct 直接接管。
    if splice && !offloaded && reactor::enabled() {
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
    if wire_codec && reactor::codec_available() {
        if let Some(up) = socket.take() {
            if reactor::submit_codec(client, up, handle.clone(), id, from_remote, to_remote) {
                return; // 注册表/统计由 reactor 收尾
            }
            relay_finish(id);
            return;
        }
    }
    // 客户端 → 上游
    if let Ok(c_read) = client.try_clone() {
        let h2 = handle.clone();
        let up_dst = upstream_fd;
        std::thread::spawn(move || {
            if splice {
                if let Some(dst) = up_dst {
                    match splice_pump(c_read.as_raw_fd(), dst, &h2.last_ns, &RELAY_STATS.bytes_up) {
                        Ok(()) => return,
                        Err(SpliceErr::Unsupported(e)) => {
                            RELAY_STATS.splice_fallbacks.fetch_add(1, Ordering::Relaxed);
                            if !SPLICE_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
                                log(&format!("splice: 上游方向不可用（{e}），回退用户态泵"));
                            }
                        }
                        Err(SpliceErr::Fatal(e)) => {
                            log(&format!("splice: 上游传输错误（{e}）"));
                            return;
                        }
                    }
                }
            }
            pump(
                Box::new(c_read),
                to_remote,
                &h2.last_ns,
                &RELAY_STATS.bytes_up,
                offloaded,
                Some(&h2.stop),
            );
        });
    }
    // 上游 → 客户端（本线程）
    match upstream_fd {
        Some(src) if splice => pump_or_splice_down(
            from_remote,
            client,
            src,
            &handle.last_ns,
            true,
            Some(&handle.stop),
        ),
        _ => pump(
            from_remote,
            Box::new(client),
            &handle.last_ns,
            &RELAY_STATS.bytes_down,
            offloaded,
            Some(&handle.stop),
        ),
    }
    // P7：注销 fast_sock 键（sockmap 条目持有 socket 引用，不删会泄漏）；
    // P8：guard 镜像先摘，再摘 fast_sock。
    if let Some((k_up, k_cl)) = offload_keys {
        offload_guard_remove(&k_up);
        offload_guard_remove(&k_cl);
        if let Some(map) = RELAY_OFFLOAD.get() {
            if let Ok(mut m) = map.lock() {
                let _ = m.remove(&k_up);
                let _ = m.remove(&k_cl);
            }
        }
        log(&format!("offload: {target} 已注销 fast_sock 键"));
    }
    relay_finish(id);
}

/// relay 会话收尾：摘注册表 + 活跃计数递减（线程泵路径与 reactor 共用）。
fn relay_finish(id: u64) {
    if let Ok(mut m) = RELAY_CONNS.lock() {
        m.remove(&id);
    }
    RELAY_STATS.conns_active.fetch_sub(1, Ordering::Relaxed);
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
            let _ = h.client.shutdown(std::net::Shutdown::Both);
            if let Some(u) = &h.upstream {
                let _ = u.shutdown(std::net::Shutdown::Both);
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
                trie.insert(&Key::new(*plen, *data), &1u32, 0)?;
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
    if cli.is_some() {
        by_tag.insert("default".to_string(), legacy.clone());
    } else if by_tag.is_empty() {
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

/// P18c：编译 dns.routing（None = 未配置）。
fn build_dns_router(
    args: &Args,
    ups: &UpstreamSet,
) -> Result<Option<dnsroute::DnsRouter>, Box<dyn std::error::Error>> {
    let Some(path) = &args.config else {
        return Ok(None);
    };
    let cfg =
        config::load(Path::new(path)).map_err(|d| format!("加载配置失败（{} 项诊断）", d.len()))?;
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
    let compiled = rules::parse_and_compile_with_groups(&text, Some(&geo), &groups)
        .map_err(|e| format!("compile rules: {e}"))?;
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
fn do_reload(args: &Args, ebpf: &mut Ebpf, startup: bool) -> ReloadOutcome {
    // P23：reload 重置粘滞 IP 状态（对照 dae ResetGlobalProxyStateForReload：
    // 新一代替换代际前不继承上一代可能已污染的代理 IP/失败状态）。
    if !startup {
        crate::sticky::reset();
    }
    // P23：bootstrap resolver 跟随配置热更新（组/上游重建前生效）。
    if let Some(cfg_path) = &args.config {
        if let Ok(cfg) = config::load(std::path::Path::new(cfg_path)) {
            let boot = config::global_value(&cfg, "bootstrap_resolver");
            if let Err(e) = bootstrap::configure(boot.as_deref()) {
                log(&format!("bootstrap resolver 热更新失败（保留旧值）: {e}"));
            }
            apply_dns_options(Some(&cfg)); // P23：dns 段选项热更新
        }
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
                reload_group_members(args);
            }
            log(&format!("热重载完成（{n} 条 match_set）"));
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

/// 解析 `--dialer`：G1 支持 direct / socks5:// / ss:// / trojan://（见 outbound）。

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
fn sweep_conn_state(ebpf: &mut Ebpf) -> Result<usize, Box<dyn std::error::Error>> {
    const TCP_TIMEOUT_NS: u64 = 300 * 1_000_000_000;
    const UDP_TIMEOUT_NS: u64 = 60 * 1_000_000_000;
    let map = ebpf
        .map_mut("conn_state_map")
        .ok_or("map conn_state_map not found")?;
    let mut conn_state: HashMap<_, SodaTuple, SodaConnState> = HashMap::try_from(map)?;
    let now = monotonic_now_ns();
    let mut dead: Vec<SodaTuple> = Vec::new();
    for item in conn_state.iter() {
        if let Ok((k, v)) = item {
            let timeout = if v.l4proto == 6 {
                TCP_TIMEOUT_NS
            } else {
                UDP_TIMEOUT_NS
            };
            if v.last_seen_ns <= now && now - v.last_seen_ns > timeout {
                dead.push(k);
            }
        }
    }
    let n = dead.len();
    for k in &dead {
        let _ = conn_state.remove(k);
    }
    Ok(n)
}

/// P15/P19：构建全部节点组（config `group` 段顺序即索引顺序；无配置时为隐式 proxy 组）。
/// 订阅拉取失败/节点全部不支持时返回 None（回落为无 dialer，保持实验回显语义）。
fn build_groups(args: &Args) -> Option<outbound::Outbound> {
    let cfg = args.config.as_ref().and_then(|p| {
        config::load(std::path::Path::new(p))
            .map_err(|d| {
                log(&format!(
                    "订阅/组：配置解析失败（{} 条诊断），跳过组构建",
                    d.len()
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

    let nodes = fetch_nodes(cfg.as_ref(), args);
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
        policy,
        members,
        targets.clone(),
        interval,
        tolerance,
        udp_check_dns.clone(),
    );
    log(&format!(
        "节点组 {gname}: {} 个成员, policy={policy:?}, check={targets:?} 每 {interval}s, 容忍 {tolerance} 次失败, udp_check={udp_check_dns:?}",
        rt.member_count()
    ));
    rt.spawn_health_loop();
    rt
}

/// 拉取内联节点 + 全部订阅（config subscription 与 CLI `--subscribe`）——
/// 组构建与 SIGHUP 订阅热更新共用。
fn fetch_nodes(cfg: Option<&config::Config>, args: &Args) -> Vec<subscribe::ParsedNode> {
    let node_specs = cfg.map(config::inline_nodes).unwrap_or_default();
    let sub_specs = cfg.map(config::subscriptions).unwrap_or_default();
    let mut nodes: Vec<subscribe::ParsedNode> = Vec::new();
    for n in &node_specs {
        match outbound::parse(&n.link) {
            Ok(o) => nodes.push(subscribe::ParsedNode {
                name: n.name.clone(),
                tag: "node".into(),
                outbound: o,
            }),
            Err(e) => log(&format!("节点 {} 不支持: {e}", n.name)),
        }
    }
    let timeout = Duration::from_secs(15);
    let cli_subs: Vec<(String, String)> = args
        .subscribe
        .iter()
        .enumerate()
        .map(|(i, u)| (format!("cli{}", i + 1), u.clone()))
        .collect();
    for (tag, url) in sub_specs
        .iter()
        .map(|s| (s.tag.clone(), s.url.clone()))
        .chain(cli_subs)
    {
        match subscribe::fetch(&url, timeout).and_then(|b| subscribe::decode_body(&b)) {
            Ok(text) => {
                let (mut ns, errs) = subscribe::parse_subscription(&text, &tag);
                for e in errs.iter().take(3) {
                    log(&format!("订阅 {tag}: {e}"));
                }
                if errs.len() > 3 {
                    log(&format!("订阅 {tag}: 另有 {} 行不支持", errs.len() - 3));
                }
                log(&format!("订阅 {tag}: 拉取成功，{} 个节点", ns.len()));
                nodes.append(&mut ns);
            }
            Err(e) => log(&format!("订阅 {tag} 拉取失败: {e}")),
        }
    }
    nodes
}

/// P18e/P19：SIGHUP 订阅热更新——重拉订阅，按组 filter 替换成员（同名继承健康）。
/// 组名集合变化（config 编辑）时整体重建（不做健康继承，日志明示）。
fn reload_group_members(args: &Args) {
    let Some(lock) = GROUP_SET.get() else {
        return;
    };
    let cfg = args.config.as_ref().and_then(|p| {
        config::load(std::path::Path::new(p))
            .map_err(|d| {
                log(&format!("订阅热更新：配置解析失败（{} 条诊断）", d.len()));
            })
            .ok()
    });
    let nodes = fetch_nodes(cfg.as_ref(), args);
    if nodes.is_empty() {
        log("订阅热更新：未获得任何节点，保留旧成员");
        return;
    }
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
            let members = group::build_members(&nodes, &filters);
            if members.is_empty() {
                log(&format!(
                    "订阅热更新：组 {name} filter 后无成员，保留旧成员"
                ));
                continue;
            }
            let (n, inherited) = g.groups[i].replace_members(members);
            log(&format!(
                "订阅热更新：组 {name} {n} 成员（继承 {inherited} 健康）"
            ));
        }
    } else {
        log(&format!(
            "订阅热更新：组集合变更 {old_names:?} -> {new_names:?}，重建全部组（不继承健康）"
        ));
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // K3 子命令（不加载 eBPF、不需要 root）
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 2
        && matches!(
            argv[1].as_str(),
            "validate"
                | "export-config"
                | "extract-routing"
                | "dns-bench"
                | "status"
                | "reload"
                | "suspend"
                | "resume"
                | "metrics"
                | "sysdump"
                | "trace"
        )
    {
        return run_subcommand(&argv);
    }
    let args = parse_args()?;
    if let Some(path) = &args.log_file {
        if open_log_file(path) {
            let _ = LOG_PATH.set(path.clone());
            log(&format!("log file: {path}"));
        } else {
            eprintln!("[sodama] 无法打开日志文件 {path}，继续用 stdout");
        }
    }

    let _ = STARTED.set(Instant::now());
    TPROXY_PORT.store(args.tproxy_port as u32, Ordering::SeqCst);
    if let Some(raw) = args.dialer.clone().or_else(|| args.forward.clone()) {
        let dialer = outbound::parse(&raw)?;
        log(&format!("relay dialer: {}", dialer.name()));
        let _ = OUTBOUND.set(dialer);
    }
    if let Some(s) = args.relay_idle_timeout {
        RELAY_IDLE_SECS.store(s, Ordering::SeqCst);
    }
    if let Some(n) = args.max_conns {
        RELAY_MAX_CONNS.store(n, Ordering::SeqCst);
    }
    if let Some(s) = args.dial_timeout {
        RELAY_DIAL_TIMEOUT_MS.store(s.saturating_mul(1000), Ordering::SeqCst);
    }
    if let Some(s) = args.udp_idle_timeout {
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
        if let Some(ms) = args.sniffing_timeout_ms {
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
    let mut ebpf = Ebpf::load(&data).map_err(|e| format!("Ebpf::load: {e}"))?;

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
    for iface in &args.lan {
        attach(
            &mut ebpf,
            "sodama_lan_ingress",
            iface,
            TcAttachType::Ingress,
        )?;
    }
    for iface in &args.wan {
        attach(&mut ebpf, "sodama_wan_egress", iface, TcAttachType::Egress)?;
        attach(
            &mut ebpf,
            "sodama_wan_ingress",
            iface,
            TcAttachType::Ingress,
        )?;
    }
    for iface in &args.dual {
        attach(
            &mut ebpf,
            "sodama_wan_lan_ingress",
            iface,
            TcAttachType::Ingress,
        )?;
        attach(
            &mut ebpf,
            "sodama_lan_wan_egress",
            iface,
            TcAttachType::Egress,
        )?;
    }
    attach(
        &mut ebpf,
        "sodama0_ingress",
        &args.dae0,
        TcAttachType::Ingress,
    )?;

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
        config_map.set(
            0,
            SodaConfig {
                tproxy_port: args.tproxy_port as u32,
                dae0_ifindex,
                dae0peer_mac,
                pad: [0; 2],
            },
            0,
        )?;
    }
    log(&format!(
        "config: dae0 ifindex={dae0_ifindex}, dae0peer mac={:02x?}",
        dae0peer_mac
    ));

    let initial = do_reload(&args, &mut ebpf, true);
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

    // 只读状态面：请求经 channel 交给主循环（唯一持有 Ebpf 的地方）处理
    let (status_tx, status_rx) = std::sync::mpsc::channel::<status::MainMsg>();
    if let Some(sock) = &args.status_socket {
        status::serve(Path::new(sock), status_tx.clone())?;
        log(&format!("status socket（只读）: {sock}"));
    }
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
            log("TCP offload 已启用（fast_sock + offload_guard + sk_skb/stream_verdict）");
        }
        let (relay_tx, relay_rx) = std::sync::mpsc::channel::<TcpStream>();
        let _ = TCP_RELAY_TX.set(relay_tx);
        std::thread::spawn(move || {
            for stream in relay_rx {
                std::thread::spawn(move || handle_relay_conn(stream));
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

    // 主循环：状态查询 + 检查重载标志 + 定期清扫 conn_state
    // O8：50ms tick 一并发控：SIGTERM 检测/热重载响应更快（20 次/s 空转可忽略）。
    let mut ticks: u64 = 0;
    let tick = Duration::from_millis(50);
    let janitor_ticks = (JANITOR_INTERVAL.as_millis() / tick.as_millis()).max(1) as u64;
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
                    log(&format!("domain_routing_map 写入失败: {e}"));
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
            do_reload(&args, &mut ebpf, false);
        }
        ticks += 1;
        if ticks % janitor_ticks == 0 {
            match sweep_conn_state(&mut ebpf) {
                Ok(0) => {}
                Ok(n) => log(&format!("conn_state janitor: 清理 {n} 条过期状态")),
                Err(e) => log(&format!("conn_state janitor 失败: {e}")),
            }
            // O8：每 30s 回收分配器空闲页（churn 后 RSS 回落；避免高频 trim 抖动）。
            if (ticks / janitor_ticks) % 6 == 0 {
                trim_allocator();
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
#[cfg(not(target_env = "gnu"))]
fn trim_allocator() {}

/// O8：优雅退出——有界等待在途连接收尾（≤300ms），随后退出。
/// 数据面钩子是 TCX bpf_link：fd 随进程关闭由内核原子摘除，不残留过滤器（不会黑洞）。
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
fn send_batch_to_udp(fd: RawFd, to: SocketAddr, datas: &[&[u8]]) -> std::io::Result<()> {
    if datas.is_empty() {
        return Ok(());
    }
    if datas.len() == 1 {
        return send_to_udp(fd, to, datas[0]);
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
    let mut control = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    // P7：msg_controllen 在 glibc 是 usize、musl 是 u32（socklen_t），用 as _ 适配。
    msg.msg_controllen = control.len() as _;
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
    ctrls: Vec<[u8; 128]>,
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    max: usize,
}

impl UdpRecvBatch {
    fn new(max: usize) -> Self {
        let max = max.max(1);
        let mut slots: Vec<Vec<u8>> = (0..max).map(|_| vec![0u8; 65536]).collect();
        let mut names: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; max];
        let mut ctrls: Vec<[u8; 128]> = vec![[0u8; 128]; max];
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
            m.msg_hdr.msg_controllen = ctrls[i].len() as _;
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
                self.msgs[i].msg_hdr.msg_controllen = self.ctrls[i].len() as _;
                self.msgs[i].msg_len = 0;
            }
            let rc = unsafe {
                libc::recvmmsg(
                    fd,
                    self.msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    libc::MSG_WAITFORONE,
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
                    log(&format!("dns 上游 {} 查询失败: {e}", u.url));
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
    // 3) 上游 + 应答路由（对照 dae resolveDNSUpstream 的递归重查；深度上限 3）
    let router = dns_router();
    let mut resp = match up.exchange(query_send) {
        Ok(r) => r,
        Err(e) => {
            DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
            log(&format!("dns 上游 {} 查询失败: {e}", up.url));
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
                let Some(set) = upstreams() else { return None };
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

/// P3a/P3b/P4b UDP 线程（host ns）：一个透明监听同时承载
/// DNS（orig_dst port=53，解析/缓存/位图）与普通 UDP NAT（其他目的端口）。
fn dns_loop(listener: OwnedFd, tx: std::sync::mpsc::Sender<status::MainMsg>) {
    let fd = listener.as_raw_fd();
    // O7：批量收（recvmmsg）；DNS 与普通 UDP NAT 共用同一入口，按 orig_dst 分流。
    let mut batch = UdpRecvBatch::new(UDP_RECV_BATCH);
    let mut reply_sockets: std::collections::HashMap<SocketAddr, Arc<OwnedFd>> =
        std::collections::HashMap::new();
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
            DNS_STATS.queries.fetch_add(1, Ordering::Relaxed);
            // P18c+：发送方进程名（WAN egress 新 UDP DNS 流由 eBPF 写入）
            let dns_pname = lookup_dns_pname(Some(client.ip()), client.port());
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
            let Some(s) = reply_socket_for(&mut reply_sockets, orig_dst) else {
                continue;
            };
            if let Err(e) = send_to_udp(s.as_raw_fd(), client, &resp) {
                log(&format!("dns 回包 {client}: {e}"));
            }
        }
        if !nat_entries.is_empty() {
            udp_nat_handle_batch(&nat_entries, &mut reply_sockets);
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
        dm.insert(&key, &val, 0)?;
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
fn udp_session_reader(sess: Arc<UdpSession>) {
    // O8：槽走缓冲池且按需增长（空闲会话 ≈1×64KB）。
    let mut slots: Vec<bufpool::PoolBuf> = Vec::new();
    loop {
        if !sess.alive.load(Ordering::Relaxed) {
            break;
        }
        let got = match sess.relay.recv_batch(&mut slots, UDP_RECV_BATCH) {
            Ok(0) => continue,
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => {
                log(&format!("udp nat: 会话读结束（{e}）"));
                break;
            }
        };
        sess.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
        let datas: Vec<&[u8]> = slots.iter().take(got).map(|v| v.as_slice()).collect();
        let total: usize = datas.iter().map(|d| d.len()).sum();
        UDP_NAT_STATS
            .bytes_down
            .fetch_add(total as u64, Ordering::Relaxed);
        if let Err(e) = send_batch_to_udp(sess.reply.as_raw_fd(), sess.client, &datas) {
            UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
            log(&format!("udp nat: 回包 {} 失败: {e}", sess.client));
        }
    }
}

/// 取（或创建）绑定 addr 的透明回包 socket，与 DNS 回包共用同一缓存。
fn reply_socket_for(
    map: &mut std::collections::HashMap<SocketAddr, Arc<OwnedFd>>,
    addr: SocketAddr,
) -> Option<Arc<OwnedFd>> {
    if let Some(s) = map.get(&addr) {
        return Some(s.clone());
    }
    match make_transparent_udp_bound(addr) {
        Ok(fd) => {
            let a = Arc::new(fd);
            map.insert(addr, a.clone());
            Some(a)
        }
        Err(e) => {
            log(&format!("udp 回包 socket {addr}: {e}"));
            None
        }
    }
}

/// 取（或创建）一条 (client, orig_dst) 会话；创建路径含 QUIC 嗅探与拨号（不持锁）。
fn udp_nat_session(
    client: SocketAddr,
    orig_dst: SocketAddr,
    probe: &[u8],
    reply_sockets: &mut std::collections::HashMap<SocketAddr, Arc<OwnedFd>>,
) -> Option<Arc<UdpSession>> {
    let key = (client, orig_dst);
    // 快路径：已有会话（只持锁查表）
    if let Some(s) = udp_nat_shard(&key)
        .lock()
        .ok()
        .and_then(|t| t.get(&key).cloned())
    {
        return Some(s);
    }
    // P20：QUIC Initial 识别 + SNI 嗅探（解 Initial 加密；失败仅计识别数）。
    if probe.len() >= 1200 && probe[0] & 0xC0 == 0xC0 {
        SNIFF_STATS.quic_initial.fetch_add(1, Ordering::Relaxed);
        if let quicsniff::QuicSniff::Found(name) = quicsniff::sniff(probe) {
            SNIFF_STATS.quic_sni.fetch_add(1, Ordering::Relaxed);
            log(&format!(
                "quic sniff {client} → {name}（SNI，Initial 解密）"
            ));
        }
    }
    // 慢路径：先拨号（不持锁——TLS/协议拨号可能耗一个 RTT）
    let reply = match reply_socket_for(reply_sockets, orig_dst) {
        Some(r) => r,
        None => {
            UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    // P5/P19：按规则选中的组分派（conn_state 回读；回退默认组）
    let resolved = resolve_group_dialer(client, orig_dst, 17);
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
            Ok(None) => match outbound::Outbound::direct_udp(orig_dst) {
                Ok(r) => r,
                Err(e) => {
                    UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                    log(&format!("udp nat: 建出口失败: {e}"));
                    return None;
                }
            },
            Err(e) => {
                UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                log(&format!("udp nat: dial_udp {orig_dst} 失败: {e}"));
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
                    return None;
                }
            }
        }
        None => match outbound::Outbound::direct_udp(orig_dst) {
            Ok(r) => r,
            Err(e) => {
                UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                log(&format!("udp nat: 建直连出口失败: {e}"));
                return None;
            }
        },
    };
    let _ = relay.set_read_timeout(Some(Duration::from_secs(2)));
    let s = Arc::new(UdpSession {
        client,
        relay,
        reply,
        last_ns: AtomicU64::new(monotonic_now_ns()),
        alive: AtomicBool::new(true),
    });
    // 插入可能与其他线程竞争（当前只有 dns_loop 调用，但保持防御性）：
    // 已有则用已有的，新建的会话随 drop 关闭。
    match udp_nat_shard(&key).lock() {
        Ok(mut table) => match table.get(&key) {
            Some(prev) => Some(prev.clone()),
            None => {
                table.insert(key, s.clone());
                UDP_NAT_STATS.sessions_total.fetch_add(1, Ordering::Relaxed);
                let r = s.clone();
                std::thread::spawn(move || udp_session_reader(r));
                Some(s)
            }
        },
        Err(_) => None,
    }
}

/// O7：一批客户端报文——按会话聚合后批量上行（同会话顺序保持；跨会话重排不影响 UDP）。
fn udp_nat_handle_batch(
    entries: &[(&[u8], SocketAddr, SocketAddr)],
    reply_sockets: &mut std::collections::HashMap<SocketAddr, Arc<OwnedFd>>,
) {
    if entries.is_empty() {
        return;
    }
    if entries.len() == 1 {
        let &(data, client, orig_dst) = &entries[0];
        if let Some(sess) = udp_nat_session(client, orig_dst, data, reply_sockets) {
            sess.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
            match sess.relay.send_payload(data) {
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
    let mut per_sess: Vec<(Arc<UdpSession>, Vec<&[u8]>)> = Vec::new();
    for &(data, client, orig_dst) in entries {
        let Some(sess) = udp_nat_session(client, orig_dst, data, reply_sockets) else {
            continue;
        };
        sess.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
        if let Some((_, v)) = per_sess.iter_mut().find(|(s, _)| Arc::ptr_eq(s, &sess)) {
            v.push(data);
        } else {
            per_sess.push((sess, vec![data]));
        }
    }
    for (sess, datas) in per_sess {
        let orig = sess.relay.target();
        match sess.relay.send_batch(&datas) {
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

/// UDP NAT janitor：空闲超过 UDP_IDLE_SECS 的会话标记回收（reader 随之下线）。
fn udp_nat_janitor_loop() {
    let tick = Duration::from_secs(5);
    loop {
        std::thread::sleep(tick);
        let idle_ns = UDP_IDLE_SECS
            .load(Ordering::Relaxed)
            .saturating_mul(1_000_000_000);
        let now = monotonic_now_ns();
        let mut dead: Vec<((SocketAddr, SocketAddr), Arc<UdpSession>)> = Vec::new();
        for shard in UDP_NAT.iter() {
            if let Ok(t) = shard.lock() {
                dead.extend(
                    t.iter()
                        .filter(|(_, s)| {
                            now.saturating_sub(s.last_ns.load(Ordering::Relaxed)) > idle_ns
                        })
                        .map(|(k, s)| (*k, s.clone())),
                );
            }
        }
        for (k, s) in dead {
            s.alive.store(false, Ordering::Relaxed);
            UDP_NAT_STATS.evicted.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut t) = udp_nat_shard(&k).lock() {
                t.remove(&k);
            }
        }
    }
}

// ---------------------------------------------------------------- K3：子命令

fn run_subcommand(argv: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match argv[1].as_str() {
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
            let (sock, _) = parse_socket_args(argv, 2)?;
            let resp = status::client(Path::new(&sock), argv[1].as_str())?;
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
        "sysdump" => {
            let (sock, out) = parse_socket_args(argv, 2)?;
            let mut dump = serde_json::Map::new();
            dump.insert("generated_at_sec".into(), json!(unix_now_sec()));
            for key in ["status", "rules", "config", "maps"] {
                let val = match status::client(Path::new(&sock), key) {
                    Ok(resp) => serde_json::from_str(&resp).unwrap_or_else(|_| json!(resp)),
                    Err(e) => json!({"error": e.to_string()}),
                };
                dump.insert(key.into(), val);
            }
            dump.insert("system".into(), system_info_json());
            let text = serde_json::to_string_pretty(&serde_json::Value::Object(dump))?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &text)?;
                    eprintln!("sysdump -> {path}");
                }
                None => println!("{text}"),
            }
            Ok(())
        }
        "trace" => {
            let mut secs = 5u64;
            let mut it = argv.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--seconds" => secs = it.next().ok_or("--seconds 需要值")?.parse()?,
                    other => return Err(format!("未知参数 {other}").into()),
                }
            }
            let path = if Path::new("/sys/kernel/tracing/trace_pipe").exists() {
                "/sys/kernel/tracing/trace_pipe"
            } else {
                "/sys/kernel/debug/tracing/trace_pipe"
            };
            let f = std::fs::File::open(path)
                .map_err(|e| format!("打开 {path} 失败（需要 root）: {e}"))?;
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            std::thread::spawn(move || {
                use std::io::BufRead as _;
                for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        return;
                    }
                }
            });
            let deadline = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < deadline {
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(line) if line.contains("sodama") => println!("{line}"),
                    Ok(_) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => break,
                }
            }
            Ok(())
        }
        "dns-bench" => run_dns_bench(argv),
        _ => unreachable!(),
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
    for key in ["rules", "maps", "stats", "hooks", "config"] {
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
    // 索引 4 = SODAMA_STAT_PNAME_HITS（与 ebpf-rs/common.rs 对齐）
    arr.get(&4u32, 0)
        .map(|values| values.iter().copied().sum::<u64>())
        .unwrap_or(0)
}

fn read_stats(ebpf: &mut Ebpf) -> (u64, u64, u64, u64) {
    use aya::maps::PerCpuArray;
    let Some(map) = ebpf.map_mut("sodama_stats_map") else {
        return (0, 0, 0, 0);
    };
    let arr: PerCpuArray<_, u64> = match PerCpuArray::try_from(map) {
        Ok(a) => a,
        Err(_) => return (0, 0, 0, 0),
    };
    let get = |i: u32| {
        arr.get(&i, 0)
            .map(|values| values.iter().copied().sum::<u64>())
            .unwrap_or(0)
    };
    // P9：offload verdict/redirect 计数与数据面同属一个对象（索引 2/3）。
    (get(0), get(1), get(2), get(3))
}

/// P19：单个组的 JSON（status 的 `group` 与 `groups[]` 共用）。
fn group_json(g: &group::GroupRuntime, index: usize, default: bool) -> serde_json::Value {
    let snap = g.snapshot();
    json!({
        "name": g.name,
        "index": index,
        "default": default,
        "policy": format!("{:?}", g.policy),
        "members": g.member_count(),
        "alive": snap.iter().filter(|x| x.2).count(),
        "dials": g.stats.dials.load(Ordering::Relaxed),
        "failovers": g.stats.failovers.load(Ordering::Relaxed),
        "probes_ok": g.stats.probes_ok.load(Ordering::Relaxed),
        "probes_fail": g.stats.probes_fail.load(Ordering::Relaxed),
        "nodes": snap.iter().map(|(n, tag, alive, last, ema)| json!({
            "name": n, "tag": tag, "alive": alive, "last_ms": last, "ema_ms": ema
        })).collect::<Vec<_>>(),
    })
}

/// P6：状态面主查询体（status / metrics 共用数据源）。
fn status_json(ebpf: &mut Ebpf) -> serde_json::Value {
    let rules_state = LAST_RULES.lock().ok().and_then(|g| g.clone());
    let cfg_state = CONFIG_STATE.lock().ok().and_then(|g| g.clone());
    let conn_state = count_map::<SodaTuple, SodaConnState>(ebpf, "conn_state_map");
    let redirect_track = count_map::<SodaTuple, SodaRedirectEntry>(ebpf, "redirect_track");
    let domain_routing = count_map::<SodaEpochIp, SodaDomainRouting>(ebpf, "domain_routing_map");
    // P17b：cookie→pname 条目数 + 规则 VM 的 pname 命中计数
    let cookie_pid = count_map::<u64, SodaPidPname>(ebpf, "cookie_pid_map");
    let pname_hits = read_pname_hits(ebpf);
    // P7：offload 键计数（0 = 无泄漏；连接回收后必须归零）
    let fast_sock = count_fast_sock(ebpf);
    let (rebind_rejected, redirect_update_failed, offload_redirects, offload_verdicts) =
        read_stats(ebpf);
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
            "splice_fallbacks": RELAY_STATS.splice_fallbacks.load(Ordering::Relaxed),
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
            "idle_timeout_secs": UDP_IDLE_SECS.load(Ordering::Relaxed),
        },
        "hooks": HOOKS.lock().map(|h| h.clone()).unwrap_or_default(),
        "rules": rules_state.as_ref().map(|c| json!({"count": c.sets.len()})),
        "maps": {"conn_state": conn_state, "redirect_track": redirect_track, "domain_routing": domain_routing, "fast_sock": fast_sock},
        "stats": {
            "rebind_rejected": rebind_rejected,
            "redirect_update_failed": redirect_update_failed,
            "offload_redirects": offload_redirects,
            "offload_verdicts": offload_verdicts,
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
        ("sodama_dns_queries", ["dns", "queries"]),
        ("sodama_dns_responses", ["dns", "responses"]),
        ("sodama_dns_published_ips", ["dns", "published_ips"]),
        ("sodama_dns_bitmap_matched", ["dns", "bitmap_matched"]),
        ("sodama_dns_upstream_errors", ["dns", "upstream_errors"]),
        ("sodama_dns_tcp_queries", ["dns", "tcp_queries"]),
        ("sodama_dns_tcp_responses", ["dns", "tcp_responses"]),
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
        "reload" => {
            let out = do_reload(args, ebpf, false);
            json!({
                "ok": out.ok,
                "match_sets": out.match_sets,
                "slot": out.slot,
                "error": out.error,
                "at_sec": out.at_sec,
            })
            .to_string()
        }
        "suspend" => match set_suspend(ebpf, true) {
            Ok(()) => {
                SUSPENDED.store(true, Ordering::SeqCst);
                log("已挂起（no-load，全部流量 fail-open）；reload 恢复");
                json!({"ok": true, "suspended": true}).to_string()
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
            let (rebind_rejected, redirect_update_failed, offload_redirects, offload_verdicts) =
                read_stats(ebpf);
            json!({
                "conn_state": conn_state,
                "redirect_track": redirect_track,
                "domain_routing": domain_routing,
                "fast_sock": fast_sock,
                "rebind_rejected": rebind_rejected,
                "redirect_update_failed": redirect_update_failed,
                "offload_redirects": offload_redirects,
                "offload_verdicts": offload_verdicts,
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

    /// O7：会话表分片——同 key 始终同片，不同 key 能铺开（避免单锁竞争）。
    #[test]
    fn udp_nat_shard_stable_and_spread() {
        let k = (
            "10.0.0.1:1000".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
        );
        assert!(std::ptr::eq(udp_nat_shard(&k), udp_nat_shard(&k)));
        let mut set = std::collections::HashSet::new();
        for i in 0..64u16 {
            let kk = (
                SocketAddr::from(([10, 0, 0, 1], 1000 + i)),
                SocketAddr::from(([1, 1, 1, 1], 53)),
            );
            set.insert(udp_nat_shard(&kk) as *const _ as usize);
        }
        assert!(set.len() > 4, "分片过少：{}", set.len());
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
}

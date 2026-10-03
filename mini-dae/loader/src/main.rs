// SPDX-License-Identifier: GPL-2.0
/*
 * mini-dae 加载器：用 Rust + aya 复现 dae 控制面里与数据面相关的最小职责。
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
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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
mod brutal;
mod config;
mod dns;
mod dnsup;
mod geodata;
mod group;
mod hpack;
mod huffman_table;
mod hysteria2;
mod outbound;
mod quicsock;
mod rules;
mod sniffer;
mod socks5;
mod socksin;
mod ss;
mod status;
mod subscribe;
mod target;
mod tls;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod ws;

/// dae 给控制面自己的 socket 打的内部 mark（对照 so_mark_from_dae / dae_socket_mark）。
/// 副作用：避免监听 socket 的 sk_mark 为 0 时新连接继承 SYN 上的 TPROXY_MARK
/// （内核 net.ipv4.tcp_fwmark_accept=1 时的 inet_request_mark 行为）。
const DAE_SOCKET_MARK: libc::c_int = 0x233;

/// 与 ebpf-rs/src/common.rs 的 MINI_MAX_MATCH_SET_LEN 保持一致。
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
/// P15：活动节点组（状态面输出用）。
static ACTIVE_GROUP: OnceLock<std::sync::Arc<group::GroupRuntime>> = OnceLock::new();
/// relay 连接空闲回收阈值（秒）；janitor 每 5s 扫描一次。
static RELAY_IDLE_SECS: AtomicU64 = AtomicU64::new(300);
/// P11：relay 拨号超时（毫秒，默认 5000；真实节点首连可能较慢）
static RELAY_DIAL_TIMEOUT_MS: AtomicU64 = AtomicU64::new(5000);
/// P4b：UDP NAT 会话空闲阈值（秒）。
static UDP_IDLE_SECS: AtomicU64 = AtomicU64::new(60);

// ---- P14：嗅探 / dial_mode（远端域名解析）----
/// 0=ip（默认，不嗅探）| 1=domain | 2=domain+（当前同 domain）。
static DIAL_MODE: AtomicU8 = AtomicU8::new(0);
/// 嗅探等待上限（毫秒）；只在 dial_mode != ip 时生效。
static SNIFF_TIMEOUT_MS: AtomicU64 = AtomicU64::new(100);

struct SniffStats {
    attempts: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}
impl SniffStats {
    const fn new() -> Self {
        Self {
            attempts: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
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
};

/// P4c：offload 用的 fast_sock SOCKHASH（从 Ebpf 中取出后由 relay 线程共享写入）。
static RELAY_OFFLOAD: OnceLock<Mutex<SockHash<MapData, MiniTuple>>> = OnceLock::new();
/// P8：Rust/aya-ebpf offload 对象的预检镜像（HASH map，与 fast_sock 同步双写）。
static RELAY_OFFLOAD_GUARD: OnceLock<Mutex<HashMap<MapData, MiniTuple, u8>>> = OnceLock::new();

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

static UDP_NAT: std::sync::LazyLock<
    Mutex<std::collections::HashMap<(SocketAddr, SocketAddr), Arc<UdpSession>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

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

/// P3a/P6/P18a：DNS 上游（已解析的传输对象；支持 udp/tcp/tcp+udp/tls/https scheme）。
/// P6 起支持热重载（`--config` 模式下重读 dns.upstream 并重建）。
static UPSTREAM: Mutex<Option<Arc<dnsup::Upstream>>> = Mutex::new(None);

fn upstream() -> Option<Arc<dnsup::Upstream>> {
    UPSTREAM.lock().ok().and_then(|g| g.clone())
}

fn set_upstream(u: Arc<dnsup::Upstream>) {
    if let Ok(mut g) = UPSTREAM.lock() {
        *g = Some(u);
    }
}
static DOMAIN_SETS: Mutex<Vec<rules::DomainSetSpec>> = Mutex::new(Vec::new());
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
};

extern "C" fn on_sighup(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

/// P6：SIGUSR2 = suspend（对照 dae `dae suspend`），由主循环写 control_flags_map。
extern "C" fn on_sigusr2(_sig: libc::c_int) {
    SUSPEND_REQ.store(true, Ordering::SeqCst);
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct MiniConfig {
    tproxy_port: u32,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
    pad: [u8; 2],
}
unsafe impl aya::Pod for MiniConfig {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct MiniTuple {
    /// 与 ebpf-rs 同位：16 字节地址（IPv4 为 v4-mapped），is_v6 区分家族。
    sip: [u8; 16],
    dip: [u8; 16],
    sport: u16,
    dport: u16,
    l4proto: u8,
    is_v6: u8,
    pad: [u8; 2],
}
unsafe impl aya::Pod for MiniTuple {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MiniConnState {
    last_seen_ns: u64,
    mark: u32,
    outbound: u8,
    must: u8,
    has_routing: u8,
    l4proto: u8,
    is_wan_ingress_direction: u8,
    pad: [u8; 3],
}
unsafe impl aya::Pod for MiniConnState {}

/// 与 ebpf-rs/src/common.rs 的 `MiniRoutingEpochIp` 同位（20 字节）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct MiniEpochIp {
    slot: u32,
    addr: [u8; 16],
}
unsafe impl aya::Pod for MiniEpochIp {}

/// 与 ebpf-rs/src/common.rs 的 `MiniDomainRouting` 同位（MAX_MATCH_SET_LEN/32 个 u32）。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct MiniDomainRouting {
    bitmap: [u32; (MAX_MATCH_SET_LEN as usize).div_ceil(32)],
}
unsafe impl aya::Pod for MiniDomainRouting {}

impl Default for MiniDomainRouting {
    fn default() -> Self {
        Self {
            bitmap: [0; (MAX_MATCH_SET_LEN as usize).div_ceil(32)],
        }
    }
}

/// 与 ebpf-rs/src/common.rs 的 `MiniRedirectEntry` 同位（32 字节，含对齐填充）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MiniPidPname {
    /// P17b：cgroup 钩子采集的进程名（16B，NUL 补全）
    pname: [u8; 16],
    pid: u32,
    pad: [u8; 4],
    last_seen_ns: u64,
}
unsafe impl aya::Pod for MiniPidPname {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MiniRedirectEntry {
    ifindex: u32,
    smac: [u8; 6],
    dmac: [u8; 6],
    from_wan: u8,
    pad: [u8; 3],
    pad2: [u8; 4],
    last_seen_ns: u64,
}
unsafe impl aya::Pod for MiniRedirectEntry {}

struct Args {
    ebpf: String,
    /// LAN 侧接口（ingress 分流）；`--lan none` = 不挂 LAN 钩子（纯本机网关）
    lan: Vec<String>,
    /// 是否显式声明不挂 LAN 钩子（`--lan none`；阻止默认值 landae）
    no_lan: bool,
    /// WAN 侧接口（egress 分流 + ingress 状态刷新）
    wan: Vec<String>,
    /// 单臂模式：同一接口同时挂 LAN/WAN 合用程序（mini_wan_lan_ingress + mini_lan_wan_egress）
    dual: Vec<String>,
    dae0: String,
    dae0peer: String,
    daens: String,
    tproxy_port: u16,
    /// 路由规则文件（mini 语法，见 rules.rs）；缺省时用 --proxy 生成
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
    /// P11：relay 拨号超时秒数（默认 5；真实节点慢首连可调大）
    dial_timeout: Option<u64>,
    /// P14：拨号模式 ip|domain|domain+（缺省 ip；config global.dial_mode 可提供）
    dial_mode: Option<String>,
    /// P14：嗅探等待上限（毫秒，默认 100；仅 dial_mode != ip 时生效）
    sniffing_timeout_ms: Option<u64>,
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
    let line = format!("[mini-dae] {msg}");
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
        "usage: mini-dae [options]\n\
         \n\
         options:\n\
           --ebpf <path>         eBPF object（默认 ebpf-rs/target/bpfel-unknown-none/release/mini-dae-ebpf）\n\
           --lan <ifname>        LAN 侧接口，可重复（默认 landae；`--lan none` = 不挂 LAN 钩子，本机网关模式）\n\
           --wan <ifname>        WAN 侧接口，可重复（默认 wan）\n\
           --dual <ifname>       单臂模式：同一接口同时挂 LAN/WAN 合用程序，可重复\n\
           --dae0 <ifname>       控制面设备（默认 dae0）\n\
           --dae0peer <ifname>   dae netns 内对端设备（默认 dae0peer）\n\
           --daens <name>        dae netns 名字（默认 daens）\n\
           --tproxy-port <port>  tproxy 监听端口（默认 12345）\n\
           --rules <path>        路由规则文件（mini 语法，缺省时由 --proxy 生成）\n\
           --config <path>       完整 dae .dae 配置（含 include；优先于 --rules）\n\
           --strict-config       配置中有规则无法编译时直接报错（默认列 deferred 后继续）\n\
           --status-socket <path> 状态面：Unix socket 上的 JSON（status/rules/config/maps + 控制命令）\n\
           --log-file <path>     P6：日志写文件（默认 stdout；SIGHUP 时 reopen，轮转友好）\n\
           --dialer <url>        P4：代理出口拨号器（direct 或 socks5://host:port）\n\
           --relay-idle-timeout <s> P4：relay 空闲回收秒数（默认 300）
           --dial-timeout <s>       P11：relay 拨号超时秒数（默认 5；真实节点慢首连可调大）
           --dial-mode <m>          P14：ip|domain|domain+（默认 ip；域名模式嗅探 SNI/Host 后远端解析，绕 DNS 污染）
           --sniffing-timeout-ms <n> P14：嗅探等待上限毫秒（默认 100；仅 dial_mode != ip 生效）
           --subscribe <url>        P15：订阅（可重复；config subscription 段同源），与 --group 搭配
           --group <name>           P15：选用 config 中的组（默认 proxy / 唯一组）
           --geodata-dir <dir>      P17a：geoip.dat/geosite.dat 搜索目录（可重复；优先于 DAE_LOCATION_ASSET）
           --listen-socks <addr>    P12：本地 SOCKS5 入口（浏览器测试用；不加载 eBPF、不需 root）\n\
           --udp-idle-timeout <s>   P4：UDP NAT 会话空闲秒数（默认 60）\n\
           --forward <url>       旧写法：等价于 --dialer socks5://host:port\n\
           --offload             P4c：启用 TCP relay offload（内核对拼，需 --dialer）\n\
           --dns-upstream <url>  P3a：DNS 上游（host:port 或 udp://host:port）\n\
           --dump                打印编译出的 match_set / LPM 内容\n\
           --compile-dump <path> 只编译规则并按对拍格式打印（不加载 eBPF，不需要 root）\n\
           --proxy <ipv4>        无 --rules 时加入「走代理」的目的 IP，可重复\n\
         \n\
         子命令（不加载 eBPF、不需 root）：\n\
           mini-dae validate <config.dae>       解析 + schema 校验 + routing 可编译性报告\n\
           mini-dae export-config <config.dae>  合并后的配置导出为 JSON\n\
           mini-dae extract-routing <config.dae> 输出可编译规则（deferred 到 stderr）\n\
           mini-dae status [--socket <path>] [--json]  查询状态面\n\
           mini-dae reload [--socket <path>]      P6：热重载（等价 kill -HUP，同步等结果）\n\
           mini-dae suspend|resume [--socket <path>] P6：no-load 挂起 / 恢复（对照 dae suspend）\n\
           mini-dae metrics [--socket <path>]     P6：Prometheus 文本格式统计导出\n\
           mini-dae sysdump [--socket <path>] [--out <file>] P6：状态+规则+系统网络信息归档\n\
           mini-dae trace [--seconds N]           P6：过滤 mini-dae 的 ftrace 输出（需 root）\n\
         \n\
         运行中收到 SIGHUP 会重读 --rules/--config 并热重载（非活跃槽 → 切换 active），\n\
         同时清除 suspend 状态并 reopen --log-file（对照 dae reload）；SIGUSR2 = suspend。"
    );
    std::process::exit(2);
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut args = Args {
        ebpf: "ebpf-rs/target/bpfel-unknown-none/release/mini-dae-ebpf".into(),
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
        dial_timeout: None,
        dial_mode: None,
        sniffing_timeout_ms: None,
        subscribe: Vec::new(),
        geodata_dir: Vec::new(),
        group: None,
        listen_socks: None,
        udp_idle_timeout: None,
        forward: None,
        offload: false,
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
            "--subscribe" => args.subscribe.push(next()?),
            "--geodata-dir" => args.geodata_dir.push(next()?),
            "--group" => args.group = Some(next()?),
            "--listen-socks" => args.listen_socks = Some(next()?),
            "--udp-idle-timeout" => args.udp_idle_timeout = Some(next()?.parse()?),
            "--forward" => args.forward = Some(next()?),
            "--offload" => args.offload = true,
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
        ("mini_cgroup_sock_create", CgroupSockAttachType::SockCreate),
        (
            "mini_cgroup_sock_release",
            CgroupSockAttachType::SockRelease,
        ),
    ];
    let addr_specs: [(&str, CgroupSockAddrAttachType); 4] = [
        ("mini_cgroup_connect4", CgroupSockAddrAttachType::Connect4),
        ("mini_cgroup_connect6", CgroupSockAddrAttachType::Connect6),
        (
            "mini_cgroup_sendmsg4",
            CgroupSockAddrAttachType::UDPSendMsg4,
        ),
        (
            "mini_cgroup_sendmsg6",
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
            Err(e) => eprintln!("[mini-dae] accept error: {e}"),
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
                    format!("mini-dae tproxy: orig_dst={orig_dst} peer={peer}\n").as_bytes(),
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
/// 实测也可能是其它错误码），一律驻留重试；半关闭/终止由 offload_monitor
/// 的 poll(RDHUP) 判定并置 stop，本线程只在 stop 后退出（避免 socket 泄漏）。
fn pump(
    mut r: Box<dyn outbound::ReadHalf>,
    mut w: Box<dyn outbound::WriteHalf>,
    last_ns: &AtomicU64,
    bytes: &AtomicU64,
    offloaded: bool,
    stop: Option<&AtomicBool>,
) {
    let mut buf = vec![0u8; 65536];
    let mut terminal_logged = false;
    loop {
        let read_res = r.read(&mut buf);
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
            Ok(0) | Err(_) => break,
            Ok(n) => {
                last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
                bytes.fetch_add(n as u64, Ordering::Relaxed);
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = w.shutdown_write();
}

/// P7：offload 看门狗（被动观察 + 有界回收）。
/// 实测定下的规则（C 基准 + 逐级实验）：
///   - 内核重定向会自行处理 FIN，但不会把 EOF 传给对端用户态；
///   - FIN 重定向尝试会在源 socket 上留下 POLLERR——这不是错误，**绝不能**
///     在传输中 force-close（会把在途重定向数据全部切断）；
///   - 用户态主动向对端传播 FIN 也会截断排队中的数据；
/// 因此：只在两侧都 RDHUP 时干净退出；只有一侧 RDHUP 超过 10s
/// （对照 dae relayHalfCloseTimeout）才强制关闭，保证连接最终可回收。
/// 退出时置 stop，驻留的泵线程随之退出，主线程注销 fast_sock 键并回收 socket。
fn offload_monitor(client_fd: RawFd, upstream_fd: RawFd, handle: Arc<RelayHandle>) {
    const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
    fn poll_revents(fd: RawFd, timeout_ms: i32) -> i16 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLRDHUP | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            pfd.revents
        } else {
            0
        }
    }
    let mut client_closed = false;
    let mut upstream_closed = false;
    let mut first_close: Option<Instant> = None;
    let mut err_logged = false;
    loop {
        if handle.stop.load(Ordering::Relaxed) {
            break;
        }
        let ce = if client_closed {
            0
        } else {
            poll_revents(client_fd, 200)
        };
        let ue = if upstream_closed {
            0
        } else {
            poll_revents(upstream_fd, 200)
        };
        if !err_logged && (ce | ue) & (libc::POLLERR | libc::POLLHUP) != 0 {
            err_logged = true;
            log(&format!(
                "offload: 观察到 POLLERR/POLLHUP（client=0x{ce:x} upstream=0x{ue:x}），按被动策略忽略"
            ));
        }
        if ce & libc::POLLRDHUP != 0 && !client_closed {
            client_closed = true;
            log("offload: 客户端半关闭（等待对端或 10s 超时）");
        }
        if ue & libc::POLLRDHUP != 0 && !upstream_closed {
            upstream_closed = true;
            log("offload: 上游半关闭（等待对端或 10s 超时）");
        }
        if client_closed && upstream_closed {
            break;
        }
        if client_closed || upstream_closed {
            match first_close {
                None => first_close = Some(Instant::now()),
                Some(t) if t.elapsed() > HALF_CLOSE_TIMEOUT => {
                    unsafe {
                        libc::shutdown(client_fd, libc::SHUT_RDWR);
                        libc::shutdown(upstream_fd, libc::SHUT_RDWR);
                    }
                    log("offload: 半关闭超时，强制关闭两侧");
                    break;
                }
                _ => {}
            }
        }
    }
    // 通知驻留的泵线程退出（连接已终结）；主线程在泵退出后注销 fast_sock 键。
    handle.stop.store(true, Ordering::Relaxed);
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

fn mini_tuple_of(remote: SocketAddr, local: SocketAddr) -> Option<MiniTuple> {
    if remote.is_ipv4() != local.is_ipv4() {
        return None;
    }
    let (sip, v6) = addr16(remote.ip());
    let (dip, _) = addr16(local.ip());
    Some(MiniTuple {
        sip,
        dip,
        sport: remote.port().to_be(),
        dport: local.port().to_be(),
        l4proto: 6, // IPPROTO_TCP
        is_v6: v6,
        pad: [0; 2],
    })
}

fn tuple_hex(t: &MiniTuple) -> String {
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
fn log_offload_keys(up: &MiniTuple, cl: &MiniTuple) {
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
fn try_offload(client: &TcpStream, upstream: &TcpStream) -> Option<(MiniTuple, MiniTuple)> {
    let (Ok(cp), Ok(cl), Ok(up), Ok(ul)) = (
        client.peer_addr(),
        client.local_addr(),
        upstream.peer_addr(),
        upstream.local_addr(),
    ) else {
        return None;
    };
    let (Some(key_for_upstream), Some(key_for_client)) =
        (mini_tuple_of(cp, cl), mini_tuple_of(up, ul))
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
fn offload_guard_write(key: &MiniTuple) -> bool {
    match RELAY_OFFLOAD_GUARD.get() {
        None => true,
        Some(m) => match m.lock() {
            Ok(mut g) => g.insert(key, 1, 0).is_ok(),
            Err(_) => false,
        },
    }
}

/// P8：guard 镜像删除（best-effort）。
fn offload_guard_remove(key: &MiniTuple) {
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
    let Ok(orig) = client.local_addr() else {
        return;
    };
    let Some(dialer) = OUTBOUND.get() else {
        return;
    };
    // P14：dial_mode != ip 时先做用户态嗅探（MSG_PEEK 只读，不消费字节流）
    let mode = DIAL_MODE.load(Ordering::Relaxed);
    let target = if mode != 0 {
        SNIFF_STATS.attempts.fetch_add(1, Ordering::Relaxed);
        let timeout = Duration::from_millis(SNIFF_TIMEOUT_MS.load(Ordering::Relaxed));
        match sniffer::sniff_domain(&client, timeout) {
            Some(name) => {
                SNIFF_STATS.hits.fetch_add(1, Ordering::Relaxed);
                log(&format!("sniff {orig} → {name}（域名交节点远端解析）"));
                target::Target::domain(name, orig.port())
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
        socket,
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
    // P7：offload 看门狗（被动观察 RDHUP + 有界回收；见 offload_monitor）
    if offloaded {
        if let Some(up) = handle.upstream.as_ref() {
            let h = handle.clone();
            let cf = handle.client.as_raw_fd();
            let uf = up.as_raw_fd();
            std::thread::spawn(move || offload_monitor(cf, uf, h));
        }
    }
    // 客户端 → 上游
    if let Ok(c_read) = client.try_clone() {
        let h2 = handle.clone();
        std::thread::spawn(move || {
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
    pump(
        from_remote,
        Box::new(client),
        &handle.last_ns,
        &RELAY_STATS.bytes_down,
        offloaded,
        Some(&handle.stop),
    );
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
                    // 不参与空闲回收（mini 的边界；dae 另有 tcp_info 看门狗）。
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

/// 编译 + 写入非活跃槽 + 切换。返回规则条数。
fn reload_rules(args: &Args, ebpf: &mut Ebpf) -> Result<usize, Box<dyn std::error::Error>> {
    let text = rules_text(args)?;
    let geo = geodata_for(args);
    let geo = geo.lock().unwrap();
    let compiled = rules::parse_and_compile_with_geo(&text, Some(&geo))
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

/// P6：写 control_flags_map 的 suspend 位（对照 dae suspend 的 no-load 状态）。
fn set_suspend(ebpf: &mut Ebpf, on: bool) -> Result<(), Box<dyn std::error::Error>> {
    let map = ebpf
        .map_mut("control_flags_map")
        .ok_or("map control_flags_map not found（对象未包含 P6 控制位？）")?;
    let mut flags: Array<_, u32> = Array::try_from(map)?;
    flags.set(0, if on { 1u32 } else { 0u32 }, 0)?;
    Ok(())
}

/// P6：一次完整热重载（对照 dae `dae reload`）：清除 suspend → 重编译/切槽 →
/// 重建域位图 → 记录结果；失败时保留旧规则（回滚等价于不切槽，reload_rules 内部先写非活跃槽）。
fn do_reload(args: &Args, ebpf: &mut Ebpf) -> ReloadOutcome {
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
            // P6：`--config` 模式下 dns.upstream 变更热切换（--dns-upstream 显式给定时不覆盖）。
            if args.dns_upstream.is_none() {
                if let Some(path) = &args.config {
                    if let Ok(cfg) = config::load(Path::new(path)) {
                        if let Some(url) = config::dns_upstream_url(&cfg) {
                            match dnsup::Upstream::new(&url) {
                                Ok(new_up) => {
                                    let old = upstream().map(|u| u.url.clone());
                                    if old.as_deref() != Some(url.as_str()) {
                                        log(&format!(
                                            "dns upstream 切换: {old:?} -> {url} ({}, {})",
                                            new_up.spec.scheme.name(),
                                            new_up.addr()
                                        ));
                                        set_upstream(new_up);
                                    }
                                }
                                Err(e) => log(&format!("reload: {e}（保留原上游）")),
                            }
                        }
                    }
                }
            }
            // 对照 dae reconcileCurrentBpfProjections：新槽需要重建域位图。
            reconcile_domain_bits(ebpf);
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
    let mut conn_state: HashMap<_, MiniTuple, MiniConnState> = HashMap::try_from(map)?;
    let now = monotonic_now_ns();
    let mut dead: Vec<MiniTuple> = Vec::new();
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

/// P15：构建节点组（config subscription/node/group + `--subscribe`/`--group`）。
/// 订阅拉取失败/节点全部不支持时返回 None（回落为无 dialer，保持实验回显语义）。
fn build_group_outbound(args: &Args) -> Option<outbound::Outbound> {
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
    let sub_specs = cfg.as_ref().map(config::subscriptions).unwrap_or_default();
    let node_specs = cfg.as_ref().map(config::inline_nodes).unwrap_or_default();
    let group_specs = cfg.as_ref().map(config::groups).unwrap_or_default();
    if sub_specs.is_empty() && args.subscribe.is_empty() && node_specs.is_empty() {
        return None;
    }

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
    if nodes.is_empty() {
        log("未获得任何可用节点，组不启用");
        return None;
    }

    let pick = |name: &str| group_specs.iter().find(|g| g.name == name);
    let chosen = if group_specs.is_empty() {
        Some(("proxy".to_string(), None::<&config::GroupSpec>))
    } else {
        args.group
            .as_deref()
            .and_then(pick)
            .or_else(|| pick("proxy"))
            .or_else(|| group_specs.first())
            .map(|g| (g.name.clone(), Some(g)))
    };
    let Some((gname, spec)) = chosen else {
        return None;
    };
    let policy = group::parse_policy(spec.and_then(|g| g.policy.as_deref()));
    let filters = spec.map(|g| g.filters.clone()).unwrap_or_default();
    let members = group::build_members(&nodes, &filters);
    if members.is_empty() {
        log(&format!(
            "组 {gname} 没有命中的节点（filter 过严？），组不启用"
        ));
        return None;
    }

    let global_str = |key: &str| cfg.as_ref().and_then(|c| config::global_value(c, key));
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

    let rt = group::GroupRuntime::new(
        gname.clone(),
        policy,
        members,
        targets.clone(),
        interval,
        tolerance,
    );
    log(&format!(
        "节点组 {gname}: {} 个成员, policy={policy:?}, check={targets:?} 每 {interval}s, 容忍 {tolerance} 次失败",
        rt.members.len()
    ));
    rt.spawn_health_loop();
    let _ = ACTIVE_GROUP.set(rt.clone());
    Some(outbound::Outbound::Group(rt))
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
            eprintln!("[mini-dae] 无法打开日志文件 {path}，继续用 stdout");
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
    if let Some(s) = args.dial_timeout {
        RELAY_DIAL_TIMEOUT_MS.store(s.saturating_mul(1000), Ordering::SeqCst);
    }
    if let Some(s) = args.udp_idle_timeout {
        UDP_IDLE_SECS.store(s, Ordering::SeqCst);
    }

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
                eprintln!("[mini-dae] 未知 dial_mode {other}，按 ip 处理");
                0
            }
        };
        DIAL_MODE.store(m, Ordering::SeqCst);
        if let Some(ms) = args.sniffing_timeout_ms {
            SNIFF_TIMEOUT_MS.store(ms, Ordering::SeqCst);
        }
        if m != 0 {
            log(&format!(
                "dial_mode: {}（嗅探上限 {}ms；命中 SNI/Host 则域名交节点远端解析）",
                dial_mode_name(m),
                SNIFF_TIMEOUT_MS.load(Ordering::SeqCst)
            ));
        }
    }

    // P15：无 --dialer/--forward 时，用订阅/节点/组构建拨号出口（单个节点即单成员组）。
    if OUTBOUND.get().is_none() {
        if let Some(dialer) = build_group_outbound(&args) {
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
        let compiled = rules::parse_and_compile_with_geo(&text, Some(&geo))
            .map_err(|e| format!("compile rules: {e}"))?;
        print!("{}", compiled.dump_parity());
        let _ = std::io::stdout().flush();
        return Ok(());
    }

    // P12：本地 SOCKS5 入口模式（浏览器/桌面测试；不加载 eBPF、不需要 root）。
    if let Some(listen) = args.listen_socks.clone() {
        return run_socks_server(&listen);
    }

    // P3a/P18a：DNS 上游传输对象必须在 host ns 创建（上游查询走宿主路由，
    // 不经 dae0/自己的钩子）；缺省上游优先取 --config 的 dns.upstream。
    let upstream_url = args.dns_upstream.clone().unwrap_or_else(|| {
        args.config
            .as_ref()
            .and_then(|p| config::load(Path::new(p)).ok())
            .and_then(|c| config::dns_upstream_url(&c))
            .unwrap_or_else(|| "8.8.8.8:53".into())
    });
    let dns_up = dnsup::Upstream::new(&upstream_url)?;
    log(&format!(
        "dns upstream: {upstream_url} scheme={} addr={}",
        dns_up.spec.scheme.name(),
        dns_up.addr()
    ));
    set_upstream(dns_up);

    // SIGHUP = 热重载（对照 dae `dae reload`）；SIGUSR2 = suspend（对照 dae suspend）
    unsafe {
        let handler: extern "C" fn(libc::c_int) = on_sighup;
        libc::signal(libc::SIGHUP, handler as *const () as libc::sighandler_t);
        let handler2: extern "C" fn(libc::c_int) = on_sigusr2;
        libc::signal(libc::SIGUSR2, handler2 as *const () as libc::sighandler_t);
    }

    log(&format!("loading {}", args.ebpf));
    let data =
        std::fs::read(&args.ebpf).map_err(|e| format!("read eBPF object {}: {e}", args.ebpf))?;
    let mut ebpf = Ebpf::load(&data).map_err(|e| format!("Ebpf::load: {e}"))?;

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
        attach(&mut ebpf, "mini_lan_ingress", iface, TcAttachType::Ingress)?;
    }
    for iface in &args.wan {
        attach(&mut ebpf, "mini_wan_egress", iface, TcAttachType::Egress)?;
        attach(&mut ebpf, "mini_wan_ingress", iface, TcAttachType::Ingress)?;
    }
    for iface in &args.dual {
        attach(
            &mut ebpf,
            "mini_wan_lan_ingress",
            iface,
            TcAttachType::Ingress,
        )?;
        attach(
            &mut ebpf,
            "mini_lan_wan_egress",
            iface,
            TcAttachType::Egress,
        )?;
    }
    attach(
        &mut ebpf,
        "mini_dae0_ingress",
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

    attach(
        &mut ebpf,
        "mini_dae0peer_ingress",
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
        let mut config_map: Array<_, MiniConfig> = Array::try_from(map)?;
        config_map.set(
            0,
            MiniConfig {
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

    let initial = do_reload(&args, &mut ebpf);
    if !initial.ok {
        return Err(format!("初始规则下发失败: {}", initial.error.unwrap_or_default()).into());
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
            let sh: SockHash<MapData, MiniTuple> = SockHash::try_from(map_data)?;
            let fd = sh.fd().try_clone()?;
            {
                let prog: &mut SkSkb = ebpf
                    .program_mut("mini_tcp_offload")
                    .ok_or("program mini_tcp_offload not found")?
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
        log("relay 线程池已启动（host ns）");
    }

    // P4b：UDP NAT janitor（无论是否启用 dialer 都在跑；只清扫非 DNS 的代理 UDP 会话）
    std::thread::spawn(udp_nat_janitor_loop);

    // 主循环：状态查询 + 检查重载标志 + 定期清扫 conn_state
    let mut ticks: u64 = 0;
    let tick = Duration::from_millis(200);
    let janitor_ticks = (JANITOR_INTERVAL.as_millis() / tick.as_millis()).max(1) as u64;
    loop {
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
            do_reload(&args, &mut ebpf);
        }
        ticks += 1;
        if ticks % janitor_ticks == 0 {
            match sweep_conn_state(&mut ebpf) {
                Ok(0) => {}
                Ok(n) => log(&format!("conn_state janitor: 清理 {n} 条过期状态")),
                Err(e) => log(&format!("conn_state janitor 失败: {e}")),
            }
        }
    }
}

// ---------------------------------------------------------------- P3a：DNS（UDP 接管）

const IP_TRANSPARENT_OPT: libc::c_int = 19;
/// IP_ORIGDSTADDR 与 IP_RECVORIGDSTADDR 同值（linux/in.h）。
const IP_ORIGDSTADDR_OPT: libc::c_int = 20;

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

fn sockaddr_in_of(addr: SocketAddr) -> libc::sockaddr_in {
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = addr.port().to_be();
    if let std::net::IpAddr::V4(v4) = addr.ip() {
        sin.sin_addr.s_addr = u32::from(v4).to_be();
    }
    sin
}

fn sockaddr_to_std(st: &libc::sockaddr_storage) -> Option<SocketAddr> {
    if st.ss_family as libc::c_int != libc::AF_INET {
        return None;
    }
    let sin = unsafe { &*(st as *const _ as *const libc::sockaddr_in) };
    Some(SocketAddr::from(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
        u16::from_be(sin.sin_port),
    )))
}

fn new_udp_socket() -> std::io::Result<OwnedFd> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_int_opt(fd.as_raw_fd(), libc::IPPROTO_IP, IP_TRANSPARENT_OPT, 1)?;
    set_int_opt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    Ok(fd)
}

fn bind_udp(fd: &OwnedFd, addr: SocketAddr) -> std::io::Result<()> {
    let sin = sockaddr_in_of(addr);
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
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
    let fd = new_udp_socket()?;
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

/// 回包 socket：绑定原始目的地址（IP_TRANSPARENT），源地址/端口与客户端预期一致。
fn make_transparent_udp_bound(addr: SocketAddr) -> std::io::Result<OwnedFd> {
    let fd = new_udp_socket()?;
    bind_udp(&fd, addr)?;
    Ok(fd)
}

fn send_to_udp(fd: RawFd, to: SocketAddr, data: &[u8]) -> std::io::Result<()> {
    let sin = sockaddr_in_of(to);
    let rc = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 收一个 UDP 报文，返回 (长度, 客户端地址, 原始目的地址)。
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
    let mut orig: Option<SocketAddr> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let c = &*cmsg;
            if c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == IP_ORIGDSTADDR_OPT {
                let sa = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let a4 = &*sa;
                orig = Some(SocketAddr::from(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from(u32::from_be(a4.sin_addr.s_addr)),
                    u16::from_be(a4.sin_port),
                )));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    let orig =
        orig.ok_or_else(|| std::io::Error::other("缺少 IP_ORIGDSTADDR（setsockopt 未生效？）"))?;
    Ok((n as usize, client, orig))
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

/// 查询处理（UDP/TCP 共用）：缓存命中 → 直接回；否则上游 → 发布位图 → 回填缓存。
/// UDP 最终应答按客户端公布尺寸截断（TCP 不截断）；位图从**完整**应答发布。
/// 上游经 `dnsup::Upstream`（P18a：udp/tcp/tcp+udp/tls/https）。
fn resolve_dns(
    query: &[u8],
    proto: ClientProto,
    upstream: &dnsup::Upstream,
    tx: &std::sync::mpsc::Sender<status::MainMsg>,
) -> Option<Vec<u8>> {
    let parsed = dns::parse_query(query);
    let edns = dns::query_edns(query);
    if let Some(q) = &parsed {
        let hit = DNS_CACHE
            .lock()
            .ok()
            .and_then(|mut c| c.answer_from_cache(query, q, &edns, Instant::now()));
        if let Some(resp) = hit {
            DNS_STATS.responses.fetch_add(1, Ordering::Relaxed);
            publish_live(q, &resp, tx, true);
            return Some(serve_response(query, resp, proto));
        }
    }
    let resp = match upstream.exchange(query) {
        Ok(r) => r,
        Err(e) => {
            DNS_STATS.upstream_errors.fetch_add(1, Ordering::Relaxed);
            log(&format!("dns 上游 {} 查询失败: {e}", upstream.url));
            return None;
        }
    };
    DNS_STATS.responses.fetch_add(1, Ordering::Relaxed);
    if let Some(q) = &parsed {
        publish_live(q, &resp, tx, false);
        if let Ok(mut c) = DNS_CACHE.lock() {
            c.insert(q, &edns, &resp, Instant::now());
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

/// P3a/P3b/P4b UDP 线程（host ns）：一个透明监听同时承载
/// DNS（orig_dst port=53，解析/缓存/位图）与普通 UDP NAT（其他目的端口）。
fn dns_loop(listener: OwnedFd, tx: std::sync::mpsc::Sender<status::MainMsg>) {
    let fd = listener.as_raw_fd();
    let mut buf = vec![0u8; 2048];
    let mut reply_sockets: std::collections::HashMap<SocketAddr, Arc<OwnedFd>> =
        std::collections::HashMap::new();
    loop {
        let (n, client, orig_dst) = match recv_with_orig_dst(fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                log(&format!("udp recv: {e}"));
                continue;
            }
        };
        if orig_dst.port() != 53 {
            // P4b：普通 UDP 代理流量 → NAT 会话表
            udp_nat_handle(&buf[..n], client, orig_dst, &mut reply_sockets);
            continue;
        }
        DNS_STATS.queries.fetch_add(1, Ordering::Relaxed);
        let Some(up) = upstream() else {
            continue;
        };
        // panic 隔离：单次查询（含第三方 QUIC 栈）出 panic 不应杀死整个 DNS 线程
        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resolve_dns(&buf[..n], ClientProto::Udp, &up, &tx)
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
        let Some(up) = upstream() else { break };
        let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resolve_dns(&query, ClientProto::Tcp, &up, &tx)
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
    let mut dm: HashMap<_, MiniEpochIp, MiniDomainRouting> = HashMap::try_from(map)?;
    for u in updates {
        let key = MiniEpochIp {
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
    let mut dm: HashMap<_, MiniEpochIp, MiniDomainRouting> = HashMap::try_from(map)?;
    let keys: Vec<MiniEpochIp> = dm
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

/// 上游回包 → 客户端（每会话一个 reader 线程）。
fn udp_session_reader(sess: Arc<UdpSession>) {
    let mut buf = vec![0u8; 65536];
    loop {
        if !sess.alive.load(Ordering::Relaxed) {
            break;
        }
        match sess.relay.recv_payload(&mut buf) {
            Ok(payload) => {
                sess.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
                UDP_NAT_STATS
                    .bytes_down
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                if let Err(e) = send_to_udp(sess.reply.as_raw_fd(), sess.client, &payload) {
                    UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                    log(&format!("udp nat: 回包 {} 失败: {e}", sess.client));
                }
            }
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

/// 一条客户端 UDP 报文：按 (client, orig_dst) 复用/创建会话并上行。
fn udp_nat_handle(
    data: &[u8],
    client: SocketAddr,
    orig_dst: SocketAddr,
    reply_sockets: &mut std::collections::HashMap<SocketAddr, Arc<OwnedFd>>,
) {
    let key = (client, orig_dst);
    // 快路径：已有会话（只持锁查表）
    let existing = UDP_NAT.lock().ok().and_then(|t| t.get(&key).cloned());
    let sess = match existing {
        Some(s) => s,
        None => {
            // 慢路径：先拨号（不持锁——TLS/协议拨号可能耗一个 RTT）
            let Some(reply) = reply_socket_for(reply_sockets, orig_dst) else {
                UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                return;
            };
            // P5：有 dialer 且协议支持 UDP → 走代理；否则直连回退
            let relay = match OUTBOUND.get() {
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
                            return;
                        }
                    },
                    Err(e) => {
                        UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                        log(&format!("udp nat: dial_udp {orig_dst} 失败: {e}"));
                        return;
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
                            return;
                        }
                    }
                }
                None => match outbound::Outbound::direct_udp(orig_dst) {
                    Ok(r) => r,
                    Err(e) => {
                        UDP_NAT_STATS.errors.fetch_add(1, Ordering::Relaxed);
                        log(&format!("udp nat: 建直连出口失败: {e}"));
                        return;
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
            match UDP_NAT.lock() {
                Ok(mut table) => match table.get(&key) {
                    Some(prev) => prev.clone(),
                    None => {
                        table.insert(key, s.clone());
                        UDP_NAT_STATS.sessions_total.fetch_add(1, Ordering::Relaxed);
                        let r = s.clone();
                        std::thread::spawn(move || udp_session_reader(r));
                        s
                    }
                },
                Err(_) => return,
            }
        }
    };
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

/// UDP NAT janitor：空闲超过 UDP_IDLE_SECS 的会话标记回收（reader 随之下线）。
fn udp_nat_janitor_loop() {
    let tick = Duration::from_secs(5);
    loop {
        std::thread::sleep(tick);
        let idle_ns = UDP_IDLE_SECS
            .load(Ordering::Relaxed)
            .saturating_mul(1_000_000_000);
        let now = monotonic_now_ns();
        let dead: Vec<((SocketAddr, SocketAddr), Arc<UdpSession>)> = match UDP_NAT.lock() {
            Ok(t) => t
                .iter()
                .filter(|(_, s)| now.saturating_sub(s.last_ns.load(Ordering::Relaxed)) > idle_ns)
                .map(|(k, s)| (*k, s.clone()))
                .collect(),
            Err(_) => continue,
        };
        for (k, s) in dead {
            s.alive.store(false, Ordering::Relaxed);
            UDP_NAT_STATS.evicted.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut t) = UDP_NAT.lock() {
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
                .ok_or("用法: mini-dae validate|export-config|extract-routing <config.dae>")?;
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
            let mut sock = "/tmp/mini-dae-status.sock".to_string();
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
                    Ok(line) if line.contains("mini-dae") => println!("{line}"),
                    Ok(_) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => break,
                }
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}

/// P6：解析 `--socket <path>` / `--out <path>`（子命令公用）。
fn parse_socket_args(
    argv: &[String],
    start: usize,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let mut sock = "/tmp/mini-dae-status.sock".to_string();
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
    println!("mini-dae status");
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
        if let Ok(sh) = SockHash::<_, MiniTuple>::try_from(map) {
            return Some(sh.iter().count());
        }
    }
    let mutex = RELAY_OFFLOAD.get()?;
    let guard = mutex.lock().ok()?;
    Some(guard.iter().count())
}

fn read_pname_hits(ebpf: &mut Ebpf) -> u64 {
    use aya::maps::PerCpuArray;
    let Some(map) = ebpf.map_mut("mini_stats_map") else {
        return 0;
    };
    let arr: PerCpuArray<_, u64> = match PerCpuArray::try_from(map) {
        Ok(a) => a,
        Err(_) => return 0,
    };
    // 索引 4 = MINI_STAT_PNAME_HITS（与 ebpf-rs/common.rs 对齐）
    arr.get(&4u32, 0)
        .map(|values| values.iter().copied().sum::<u64>())
        .unwrap_or(0)
}

fn read_stats(ebpf: &mut Ebpf) -> (u64, u64, u64, u64) {
    use aya::maps::PerCpuArray;
    let Some(map) = ebpf.map_mut("mini_stats_map") else {
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

/// P6：状态面主查询体（status / metrics 共用数据源）。
fn status_json(ebpf: &mut Ebpf) -> serde_json::Value {
    let rules_state = LAST_RULES.lock().ok().and_then(|g| g.clone());
    let cfg_state = CONFIG_STATE.lock().ok().and_then(|g| g.clone());
    let conn_state = count_map::<MiniTuple, MiniConnState>(ebpf, "conn_state_map");
    let redirect_track = count_map::<MiniTuple, MiniRedirectEntry>(ebpf, "redirect_track");
    let domain_routing = count_map::<MiniEpochIp, MiniDomainRouting>(ebpf, "domain_routing_map");
    // P17b：cookie→pname 条目数 + 规则 VM 的 pname 命中计数
    let cookie_pid = count_map::<u64, MiniPidPname>(ebpf, "cookie_pid_map");
    let pname_hits = read_pname_hits(ebpf);
    // P7：offload 键计数（0 = 无泄漏；连接回收后必须归零）
    let fast_sock = count_fast_sock(ebpf);
    let (rebind_rejected, redirect_update_failed, offload_redirects, offload_verdicts) =
        read_stats(ebpf);
    let cache = match DNS_CACHE.lock() {
        Ok(c) => (c.len(), c.hits, c.misses, c.inserts, c.evictions, c.expired),
        Err(_) => (0, 0, 0, 0, 0, 0),
    };
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
        },
        "sniffing": {
            "dial_mode": dial_mode_name(DIAL_MODE.load(Ordering::Relaxed)),
            "timeout_ms": SNIFF_TIMEOUT_MS.load(Ordering::Relaxed),
            "attempts": SNIFF_STATS.attempts.load(Ordering::Relaxed),
            "hits": SNIFF_STATS.hits.load(Ordering::Relaxed),
            "misses": SNIFF_STATS.misses.load(Ordering::Relaxed),
        },
        // P17b：pname 采集面（cgroup2 钩子 + cookie→pname map）
        "pname": {
            "driver": "cgroup2",
            "enabled": HOOKS.lock().map(|h| h.iter().any(|x| x.starts_with("mini_cgroup_"))).unwrap_or(false),
            "hooks": HOOKS.lock().map(|h| h.iter().filter(|x| x.starts_with("mini_cgroup_")).count()).unwrap_or(0),
            "map_entries": cookie_pid,
            "hits": pname_hits,
        },
        "group": match ACTIVE_GROUP.get() {
            Some(g) => {
                let snap = g.snapshot();
                json!({
                    "name": g.name,
                    "policy": format!("{:?}", g.policy),
                    "members": g.members.len(),
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
            None => serde_json::Value::Null,
        },
        "udp_nat": {
            "sessions_active": UDP_NAT.lock().map(|t| t.len()).unwrap_or(0),
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
            "queries": DNS_STATS.queries.load(Ordering::Relaxed),
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
        "mini_dae_uptime_seconds",
        get(v, &["uptime_sec"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_active_slot",
        get(v, &["active_slot"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_suspended",
        b(v.get("suspended")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_reload_success",
        b(v.get("reload")
            .and_then(|r| r.get("ok"))
            .and_then(|x| x.as_bool())
            .unwrap_or(true)),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_reload_match_sets",
        get(v, &["reload", "match_sets"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_relay_conns_total",
        get(v, &["relay", "conns_total"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_relay_conns_active",
        get(v, &["relay", "conns_active"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_relay_bytes_up",
        get(v, &["relay", "bytes_up"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_relay_bytes_down",
        get(v, &["relay", "bytes_down"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_relay_dial_errors",
        get(v, &["relay", "dial_errors"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_relay_evicted",
        get(v, &["relay", "evicted"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_offloaded_total",
        get(v, &["relay", "offloaded_total"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_offload_failures",
        get(v, &["relay", "offload_failures"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_udp_nat_sessions_active",
        get(v, &["udp_nat", "sessions_active"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_udp_nat_sessions_total",
        get(v, &["udp_nat", "sessions_total"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_udp_nat_sessions_proxied",
        get(v, &["udp_nat", "sessions_proxied"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_udp_nat_direct_fallback",
        get(v, &["udp_nat", "direct_fallback"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_udp_nat_bytes_up",
        get(v, &["udp_nat", "bytes_up"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_udp_nat_bytes_down",
        get(v, &["udp_nat", "bytes_down"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_udp_nat_evicted",
        get(v, &["udp_nat", "evicted"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_udp_nat_errors",
        get(v, &["udp_nat", "errors"]),
    );
    for (name, path) in [
        ("mini_dae_dns_queries", ["dns", "queries"]),
        ("mini_dae_dns_responses", ["dns", "responses"]),
        ("mini_dae_dns_published_ips", ["dns", "published_ips"]),
        ("mini_dae_dns_bitmap_matched", ["dns", "bitmap_matched"]),
        ("mini_dae_dns_upstream_errors", ["dns", "upstream_errors"]),
        ("mini_dae_dns_tcp_queries", ["dns", "tcp_queries"]),
        ("mini_dae_dns_tcp_responses", ["dns", "tcp_responses"]),
        ("mini_dae_dns_cache_hits", ["dns", "cache_hits"]),
        ("mini_dae_dns_cache_misses", ["dns", "cache_misses"]),
        ("mini_dae_dns_cache_inserts", ["dns", "cache_inserts"]),
        ("mini_dae_dns_cache_evictions", ["dns", "cache_evictions"]),
    ] {
        emit(&mut s, "counter", name, get(v, &path));
    }
    emit(
        &mut s,
        "gauge",
        "mini_dae_dns_cache_entries",
        get(v, &["dns", "cache_entries"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_dns_domain_sets",
        get(v, &["dns", "domain_sets"]),
    );
    // P17b：pname（cgroup2）
    emit(
        &mut s,
        "gauge",
        "mini_dae_pname_hooks",
        get(v, &["pname", "hooks"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_pname_map_entries",
        get(v, &["pname", "map_entries"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_pname_hits",
        get(v, &["pname", "hits"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_map_conn_state",
        get(v, &["maps", "conn_state"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_map_redirect_track",
        get(v, &["maps", "redirect_track"]),
    );
    emit(
        &mut s,
        "gauge",
        "mini_dae_map_domain_routing",
        get(v, &["maps", "domain_routing"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_rebind_rejected",
        get(v, &["stats", "rebind_rejected"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_redirect_update_failed",
        get(v, &["stats", "redirect_update_failed"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_offload_redirects",
        get(v, &["stats", "offload_redirects"]),
    );
    emit(
        &mut s,
        "counter",
        "mini_dae_offload_verdicts",
        get(v, &["stats", "offload_verdicts"]),
    );
    let dialer = v
        .get("dialer")
        .and_then(|x| x.as_str())
        .unwrap_or("none")
        .replace(['"', '\\', '\n'], "_");
    s.push_str(&format!(
        "# TYPE mini_dae_info gauge\nmini_dae_info{{dialer=\"{dialer}\"}} 1\n"
    ));
    s
}

fn handle_status_query(cmd: &str, ebpf: &mut Ebpf, args: &Args) -> String {
    match cmd {
        "status" => status_json(ebpf).to_string(),
        "reload" => {
            let out = do_reload(args, ebpf);
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
            let conn_state = count_map::<MiniTuple, MiniConnState>(ebpf, "conn_state_map");
            let redirect_track = count_map::<MiniTuple, MiniRedirectEntry>(ebpf, "redirect_track");
            let domain_routing =
                count_map::<MiniEpochIp, MiniDomainRouting>(ebpf, "domain_routing_map");
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

//! sodama 面板：前后端共享 DTO。
//!
//! 后端把引擎 `status` JSON 裁剪为这里的稳定视图；前端只依赖本 crate，
//! 引擎内部字段变化不会直接泄漏到 UI。

use serde::{Deserialize, Serialize};

/// 引擎状态总览（面板主视图）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusView {
    /// 采样时间（Unix 秒，后端注入）。
    pub sampled_at: u64,
    pub version: String,
    pub kernel: String,
    pub pid: u32,
    pub uptime_sec: u64,
    pub suspended: bool,
    pub active_slot: u64,
    pub tproxy_port: u16,
    pub dialer: String,
    pub hooks: Vec<String>,
    pub config: ConfigView,
    pub reload: ReloadView,
    pub relay: RelayView,
    pub dns: DnsView,
    pub sniffing: SniffView,
    pub group: GroupView,
    pub nodes: Vec<NodeView>,
    pub rule_sets: Vec<RuleSetView>,
    /// P0（2026-10-11）：订阅源状态（tag/最近拉取/结果/节点数；不含 URL/token）。
    pub subscriptions: Vec<SubSourceView>,
    pub maps: MapsView,
    pub pname: PnameView,
    pub config_watch: WatchView,
    /// v2.0：UDP NAT 会话面（含 GSO 聚合与 full-cone/raw_udp 回退）
    pub udp_nat: UdpNatView,
    /// v2.0：数据面错误/丢弃计数 + 卸载记账 + XDP 计量
    pub stats: StatsView,
    /// v2.0：内核 trace 会话（A2 #3）
    pub trace: TraceView,
    /// v2.0：sysctl 期望监控（watched/rewrites）
    pub sysctl: SysctlView,
    /// v2.0：域名确认集（dial_mode=domain 的远端解析决策面）
    pub real_domain: RealDomainView,
    /// v2.0：1h 流量历史摘要（引擎侧对账口径）
    pub traffic: TrafficView,
    /// v2.0：引擎构建（`sodama --version`；不可得为 None）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_build: Option<EngineBuildView>,
    /// P-AI：域名维度统计（「AI 流量」卡片；按流量 Top，最多 30 条）。
    pub domain_stats: Vec<DomainStatView>,
    /// 进程运行时（面板本地读 `/proc/<pid>`；引擎状态面不提供）
    pub runtime: RuntimeView,
}

/// 面板本地采的进程运行时参数（`/proc/<pid>`；读不到则为 0）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeView {
    /// 常驻内存 VmRSS（KB）
    pub rss_kb: u64,
    /// 峰值常驻 VmHWM（KB）
    pub hwm_kb: u64,
    /// 虚拟内存 VmSize（KB）
    pub vmsize_kb: u64,
    /// 线程数
    pub threads: u64,
    /// 进程累计 CPU 时间（秒，utime+stime）
    pub cpu_secs: f64,
    /// 相对采样区间的 CPU 占用（%，由前后两次采样差分；首点为 0）
    pub cpu_pct: f64,
    /// 子进程累计 CPU 时间（秒；RLIMIT/内核旁路等外部工具）
    pub cpu_child_secs: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigView {
    pub entry: String,
    pub fallback: String,
    pub sections: Vec<String>,
    pub routing_supported: u64,
    pub routing_deferred: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReloadView {
    pub at_sec: u64,
    pub ok: bool,
    pub error: Option<String>,
    pub slot: u64,
    pub match_sets: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayView {
    pub conns_active: u64,
    pub conns_total: u64,
    pub dial_errors: u64,
    pub evicted: u64,
    pub limit_rejected: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub fds_used: u64,
    pub fds_soft_limit: u64,
    pub max_conns: u64,
    pub idle_timeout_secs: u64,
    pub splice_enabled: bool,
    pub splice_fallbacks: u64,
    pub offload_enabled: bool,
    pub offloaded_total: u64,
    // ---- v2.0：数据面记账补充（引擎 `relay.*`）----
    /// fast_sock 卸载失败次数（非零 = 卸载路径有问题，回退拷贝泵）
    pub offload_failures: u64,
    /// splice 零拷贝会话数（累计）
    pub splice_total: u64,
    /// reactor codec 会话数（累计；AEAD 协议走 reactor 时）
    pub reactor_codec_sessions: u64,
    /// splice 保留的 fd 预算
    pub splice_fd_budget: u64,
    /// 管道池：创建/复用/归还/丢弃（泄漏看 `创建-归还`）
    pub pipe_created: u64,
    pub pipe_reused: u64,
    pub pipe_released: u64,
    pub pipe_discarded: u64,
}

/// UDP NAT（引擎 `status.udp_nat`）：会话面 + full-cone/负缓存/raw_udp 回退 + **GSO 聚合**。
///
/// GSO 三段计数（v2.19 交付 + 2026-10-17 修复）：
/// `gso_sends`/`gso_datagrams` = 实际聚合发送的调用数 / 用户数据包数；
/// `gso_unsupported` = 内核/协议不支持时的逐包回退数。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpNatView {
    pub sessions_active: u64,
    pub sessions_total: u64,
    /// 其中走了代理出口（其余为 direct 回退）
    pub sessions_proxied: u64,
    pub direct_fallback: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub evicted: u64,
    pub errors: u64,
    pub reply_sockets_evicted: u64,
    /// full-cone 端点池会话数
    pub cone_sessions: u64,
    /// 负缓存命中（上次失败目标的快速失败）
    pub negcache_hits: u64,
    /// raw_udp 回退数（协议侧不能承载 UDP 时）
    pub raw_udp_fallbacks: u64,
    pub gso_sends: u64,
    pub gso_datagrams: u64,
    pub gso_unsupported: u64,
    pub idle_timeout_secs: u64,
}

/// 数据面错误/丢弃计数（引擎 `status.stats`）+ 卸载记账（`offload_sent`/`offload_fuse`）+ XDP。
///
/// 口径：这些值**正常应恒为 0**（丢包/溢出/发布失败才是异常），面板以「错误面」呈现，
/// 非零时提示；`domain_publish_*` 与 `offload_*` 为 2026-10-16/17 新增的观测面。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsView {
    pub udp_conn_overflow: u64,
    pub tcp_conn_overflow: u64,
    pub redirect_overflow: u64,
    pub redirect_update_failed: u64,
    pub rebind_rejected: u64,
    pub syn_rebind_rejected: u64,
    pub stateless_tcp_passthrough: u64,
    pub frag_tail_passed: u64,
    pub parse_unsupported_l4: u64,
    pub unsolicited_udp_seen: u64,
    pub sockmark_fallback: u64,
    pub rebind_rerouted: u64,
    pub event_drops: u64,
    /// DNS 域位图投递重试/丢弃（v2.19 投影重试堆）
    pub domain_publish_retries: u64,
    pub domain_publish_dropped: u64,
    // ---- 卸载记账（offload_sent）----
    /// 用户态已收回的卸载字节（对账用）
    pub offload_reclaimed_bytes: u64,
    /// 内核侧记账的卸载送达字节
    pub offload_kernel_bytes: u64,
    /// 记账丢包（探针键不符等）
    pub offload_account_drops: u64,
    // ---- 背压 fuse（offload_fuse）----
    pub fuse_engages: u64,
    pub fuse_lifts: u64,
    pub fuse_failures: u64,
    pub fuse_threshold: u64,
    // ---- XDP 计量探针（未挂载 = None）----
    pub xdp_packets: Option<u64>,
    pub xdp_bytes: Option<u64>,
}

/// 内核 trace 会话（引擎 `status.trace`；A2 #3）+ 面板可发起短时抓取。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceView {
    pub active: bool,
    pub file: String,
    pub events: u64,
    pub write_errors: u64,
}

/// sysctl 期望监控（引擎 `status.sysctl`）：watched = 受管键数，rewrites = 被改回次数。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SysctlView {
    pub watched: u64,
    pub rewrites: u64,
}

/// 域名确认集（引擎 `status.real_domain`；`dial_mode=domain` 的远端解析决策面）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RealDomainView {
    pub confirmed: u64,
    pub negative: u64,
    pub inflight: u64,
    pub capacity: u64,
    pub probes: u64,
    pub confirmed_total: u64,
    pub negative_total: u64,
    pub hits: u64,
}

/// 1h 流量历史摘要（引擎 `status.traffic`；A2 #13）。
/// 面板曲线仍用自有环形缓冲；本段用于「引擎侧累计/速率/窗口」对账与首屏回填。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrafficView {
    pub window_sec: u64,
    pub points: u64,
    pub samples_total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub active_conns: u64,
    pub udp_sessions: u64,
}

/// 引擎构建信息（`sodama --version`，A2 #1；缓存 10 分钟）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineBuildView {
    /// “0.1.0-g9f1179a769f6-dirty”
    pub full: String,
    /// 版本号
    pub version: String,
    /// git 短 sha（解析不到为空）
    pub git_sha: String,
    /// 工作区是否 dirty
    pub dirty: bool,
    /// “rust release linux/x86_64”
    pub toolchain: String,
    /// 原始多行文本（弹窗/复制用）
    pub raw: String,
}

/// 控制动作参数（reload/suspend/resume 共用的可选载荷）。
/// `drain_secs` > 0 = 旧代在飞会话排空预算（A2：`--drain=N`）；`abort` = 中断在飞会话。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActionReq {
    pub drain_secs: Option<u64>,
    pub abort: Option<bool>,
}

/// `POST /api/v1/engine/trace`：短时抓取参数（映射 `sodama trace`；A2 #3）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceReq {
    /// 保持秒数（1..=30）
    pub seconds: Option<u64>,
    /// 仅 IPv4 / 仅 IPv6（互斥）
    pub ipv4: Option<bool>,
    pub ipv6: Option<bool>,
    /// tcp | udp | 空
    pub l4: Option<String>,
    pub port: Option<u16>,
    /// 只看被判丢弃的会话
    pub drop_only: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceResult {
    pub ok: bool,
    pub seconds: u64,
    /// 抓取到的行（服务端已截断到上限）
    pub lines: Vec<String>,
    pub total_lines: u64,
    pub truncated: bool,
    pub file: String,
    pub message: String,
}

/// P0（2026-10-11）：单个订阅源最近一次拉取状态（引擎 `status.subscriptions[]`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SubSourceView {
    pub tag: String,
    pub rank: u64,
    /// 拉取时刻（Unix 秒）
    pub at_sec: u64,
    /// 本次是否可用（含磁盘缓存回退）
    pub ok: bool,
    /// 失败原因 / 回退说明（成功时为 None 或上一次错误）
    pub error: Option<String>,
    /// 可用节点数
    pub nodes: u64,
    /// net / disk / memory / cooldown
    pub source: String,
}

/// P-AI：单个域名的连接/流量统计（引擎 `status.domain_stats[]`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainStatView {
    pub domain: String,
    /// 是否 AI 服务域名（引擎侧后缀表标记）。
    pub ai: bool,
    /// 累计连接数 / 当前活跃连接。
    pub conns: u64,
    pub active: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// 最近一次活动距今秒数。
    pub last_seen_secs_ago: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsView {
    pub queries: u64,
    pub responses: u64,
    pub upstream: String,
    pub upstream_errors: u64,
    pub cache_entries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_expired: u64,
    pub cache_evictions: u64,
    pub bitmap_matched: u64,
    pub published_ips: u64,
    pub rejects: u64,
    pub stale_hits: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SniffView {
    pub dial_mode: String,
    pub timeout_ms: u64,
    pub attempts: u64,
    pub hits: u64,
    pub misses: u64,
    pub quic_sni: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GroupView {
    pub name: String,
    pub active_tag: String,
    pub policy: String,
    /// 点名锁定的节点名（未锁定为空；`fixed('名称')`）
    pub pinned: String,
    /// 锁定名是否命中了当前成员（false = 订阅变更/节点下线，已兜底自动）
    pub pinned_ok: bool,
    /// 当前优选成员索引（select_order 首位 = 新连接优先走它；无成员为 None）
    pub current: Option<u64>,
    /// 健康探测节奏（秒；空闲退避时变大）
    pub probe_interval_secs: u64,
    /// 是否处于活跃探测（有人看状态或有流量）
    pub probe_active: bool,
    pub members: u64,
    pub alive: u64,
    pub dials: u64,
    pub failovers: u64,
    pub probes_ok: u64,
    pub probes_fail: u64,
    pub subscription_failover: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeView {
    /// 成员索引（与引擎 `group.current` 对齐）
    pub index: u64,
    pub name: String,
    pub tag: String,
    pub alive: bool,
    pub ema_ms: f64,
    pub last_ms: u64,
    /// 协议（vless/vmess/shadowsocks/trojan/tuic/hysteria2/anytls/…）
    pub protocol: String,
    /// 传输：tcp / ws / quic / h2
    pub transport: String,
    /// 安全：tls / reality / shadowtls / none
    pub security: String,
    /// 该协议能否承载 UDP（能力；路由当前把 UDP 送 direct）
    pub udp: bool,
    /// 服务器地址 host:port
    pub addr: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleSetView {
    pub tag: String,
    pub entries: u64,
    pub remote: bool,
    pub from_cache: bool,
    pub updated_secs_ago: u64,
    pub suffix: u64,
    pub full: u64,
    pub keyword: u64,
    pub regex: u64,
    /// 全局刷新周期（秒；0 = 每次 reload 刷新）
    pub interval_secs: u64,
    /// 距离下次自动刷新的秒数（0 = 即将/已过）
    pub next_update_secs: u64,
    /// 本次加载的软失败原因（None = 正常）。
    /// 引擎侧已改为「单个规则集失败不阻塞整体 reload」，失败者置空并在此上报。
    pub error: Option<String>,
}

// ---------------------------------------------------------------- 配置页（订阅导入 / 规则集 / 分流文件）

/// 解析预览里的单条节点。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SubNode {
    pub name: String,
    pub protocol: String,
    pub addr: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtoCount {
    pub name: String,
    pub count: u64,
}

/// `POST /api/v1/config/inspect`：订阅拉取 + 解析结果（只读，不落盘）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InspectView {
    pub ok: bool,
    pub tag: String,
    pub source: String,
    pub bytes: u64,
    /// `base64` | `plain`
    pub format: String,
    pub count: u64,
    pub protocols: Vec<ProtoCount>,
    pub nodes: Vec<SubNode>,
    pub truncated: bool,
    pub errors: Vec<String>,
    pub elapsed_ms: u64,
    /// 启发式：疑似订阅头信息（运行时会被 group.filter 排除）
    pub info_entries: u64,
}

/// 单个规则集（本地文件可直接编辑条目，远程只读）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainFileView {
    pub tag: String,
    /// 配置里的值（远程 URL 脱敏）
    pub target: String,
    pub remote: bool,
    /// routing 里是否有 `ruleset: <tag>` 引用
    pub referenced: bool,
    pub path: String,
    pub exists: bool,
    pub count: u64,
    /// 尾部条目（最多 500）
    pub entries: Vec<String>,
    pub bytes: u64,
    /// 引擎侧本次加载的软失败原因（None = 正常）。
    /// 引擎改为「单个规则集失败不阻塞整体 reload」后，失败原因经此透出到配置页。
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainsView {
    pub files: Vec<DomainFileView>,
}

// ---------------------------------------------------------------- 单节点详情

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodePoint {
    pub t: u64,
    pub alive: bool,
    pub ema_ms: f64,
    pub last_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeDetail {
    pub tag: String,
    pub name: String,
    pub alive: bool,
    pub ema_ms: f64,
    pub last_ms: u64,
    pub samples: Vec<NodePoint>,
    // 协议事实（与列表同行；详情页展示）
    pub protocol: String,
    pub transport: String,
    pub security: String,
    pub udp: bool,
    pub addr: String,
}

// ---------------------------------------------------------------- 会话登录

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginReq {
    pub token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginResp {
    pub ok: bool,
    pub message: String,
    /// 会话有效期（秒）
    pub session_ttl_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MapsView {
    pub conn_state: u64,
    pub domain_routing: u64,
    pub fast_sock: u64,
    pub redirect_track: u64,
    /// v2.0：首包路由交接表（eBPF 余项批次）
    pub routing_handoff: u64,
    /// v2.0：出口连通性判定为「死」的组数（>0 则这些组的新流被数据面阻断）
    pub connectivity_dead_groups: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PnameView {
    pub driver: String,
    pub enabled: bool,
    pub hooks: u64,
    pub map_entries: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchView {
    pub enabled: bool,
    pub transport: String,
    pub debounce_ms: u64,
    pub interval_secs: u64,
}

/// 日志尾。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogsView {
    pub lines: Vec<String>,
}

/// 操作结果（reload/suspend/resume）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionResult {
    pub ok: bool,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

// ---------------------------------------------------------------- M1：曲线

/// 单个采样点（后端定期采样引擎状态）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Sample {
    /// Unix 秒
    pub t: u64,
    pub conns_active: u64,
    /// 上行/下行速率（B/s，由累计字节差分）
    pub up_bps: u64,
    pub down_bps: u64,
    /// WAN 接口整机速率（B/s；直连 + 代理合计，面板本地读 `/proc/net/dev`；不可用为 0）
    pub wan_up_bps: u64,
    pub wan_down_bps: u64,
    pub alive: u64,
    pub members: u64,
    pub ema_min: f64,
    pub ema_avg: f64,
    /// DNS 查询速率（次/秒）
    pub dns_qps: f64,
    /// SNI 嗅探命中率（%）
    pub sniff_pct: f64,
    pub fds_used: u64,
    /// 常驻内存（KB，面板本地读 /proc）
    pub rss_kb: u64,
    /// 线程数
    pub threads: u64,
    /// CPU 占用（%，区间差分）
    pub cpu_pct: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SeriesView {
    pub step_secs: u64,
    pub points: Vec<Sample>,
}

// ---------------------------------------------------------------- M1：订阅源

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceInfo {
    pub tag: String,
    /// 脱敏后的订阅 URL
    pub url: String,
    /// 声明顺序（0 = 主源）
    pub order: u64,
    pub nodes: u64,
    pub alive: u64,
    pub active: bool,
    /// P0（2026-10-11）：引擎最近一次拉取状态（None = 尚无记录）。
    pub pull_ok: Option<bool>,
    pub pull_error: Option<String>,
    /// 距上次拉取的秒数（无记录 = 0）
    pub pull_ago_secs: u64,
    /// 可用节点数（拉取结果）
    pub pull_nodes: u64,
    /// net / disk / memory / cooldown（空 = 无记录）
    pub pull_source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SourcesView {
    pub active_tag: String,
    pub sources: Vec<SourceInfo>,
}

// ---------------------------------------------------------------- M3：配置/规则编辑

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub mtime: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FileContent {
    pub name: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SaveResult {
    pub ok: bool,
    pub message: String,
    /// 保存后引擎热重载是否成功（等待 inotify/reload 回执）
    pub reload_ok: Option<bool>,
}

// ---------------------------------------------------------------- 内核参数（配置页「参数」区）

/// 参数控件类型（前端据此选控件）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamKind {
    /// 开关（true/false）
    Bool,
    /// 整数（可带单位，单位见 `unit`）
    Int,
    /// 自由文本
    Str,
    /// 枚举（候选项见 `options`，首项常为「引擎默认」）
    Enum,
    /// 时长（秒；也接受 `300s` / `5min` 写法）
    Duration,
    /// 表达式（如节点 filter：`!name(keyword: 'x') && name(subtag: y)`）——
    /// **原样写回**（内含引号是语法的一部分，不能整体加引号）
    Expr,
}

/// 一条可视化内核参数：位置（段/键）+ 展示元信息 + 默认值。
#[derive(Debug, Clone, Copy)]
pub struct ParamSpec {
    /// `global` / `dns` / `group`
    pub section: &'static str,
    pub key: &'static str,
    /// UI 分组标题
    pub group: &'static str,
    pub label: &'static str,
    /// 一行说明（怎么理解 / 什么时候要改）
    pub help: &'static str,
    pub kind: ParamKind,
    /// 引擎默认值（空 = 未注明；UI 只显示「未设置 = 引擎默认」）
    pub default: &'static str,
    /// 单位（`s` / `ms` / `个` / `字节` …）
    pub unit: &'static str,
    /// `kind = Enum` 时的候选项（第一项为「未设置」）
    pub options: &'static [&'static str],
}

/// 面板可视化的内核参数清单（与引擎 `config.rs` 的 KEY 白名单一致）。
///
/// 设计口径：
/// - 只收录**用户真会动**的旋钮；调试类（utls/pprof 等）不进首版；
/// - `default` 仅在与引擎代码核对过时填写，宁缺毋滥；
/// - 段内平铺键（`global`/`dns`）；`group` 段写入第一个组。
pub const PARAMS: &[ParamSpec] = &[
    // ---- 转发与连接 ----
    ParamSpec {
        section: "global",
        key: "max_conns",
        group: "转发与连接",
        label: "并发连接上限",
        help: "0 = 不限；超限的新连接直接关闭并计数",
        kind: ParamKind::Int,
        default: "0",
        unit: "条",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "dial_timeout",
        group: "转发与连接",
        label: "拨号超时",
        help: "拨上游节点的最长等待（超时即失败切换）",
        kind: ParamKind::Duration,
        default: "5s",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "relay_idle_timeout",
        group: "转发与连接",
        label: "TCP 空闲回收",
        help: "转发会话空闲超时后强制回收（含长连接；客户端会自动重连）",
        kind: ParamKind::Duration,
        default: "300s",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "udp_idle_timeout",
        group: "转发与连接",
        label: "UDP 会话回收",
        help: "UDP NAT 会话空闲多久回收",
        kind: ParamKind::Duration,
        default: "60s",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "dial_mode",
        group: "转发与连接",
        label: "域名解析位置",
        help: "domain+ = 尽量把域名交给节点远端解析（绕 DNS 污染）",
        kind: ParamKind::Enum,
        default: "",
        unit: "",
        options: &["", "ip", "domain", "domain+", "domain++"],
    },
    ParamSpec {
        section: "global",
        key: "sniffing_timeout",
        group: "转发与连接",
        label: "嗅探等待",
        help: "首包等待 TLS SNI / HTTP Host 的时间（超时按 IP 走）",
        kind: ParamKind::Int,
        default: "100",
        unit: "ms",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "auto_sniff_punt",
        group: "转发与连接",
        label: "嗅探后重判出口",
        help: "嗅探到域名后按规则重选出口（direct/block/组）",
        kind: ParamKind::Bool,
        default: "",
        unit: "",
        options: &[],
    },
    // ---- v2.0（引擎 A1/A2 生效面补齐）----
    ParamSpec {
        section: "global",
        key: "so_mark_from_dae",
        group: "转发与连接",
        label: "控制面 SO_MARK",
        help: "控制面自身 socket 的标记；数据面按同值跳过自环（一般不动）",
        kind: ParamKind::Int,
        default: "0x233",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "allow_insecure",
        group: "转发与连接",
        label: "跳过证书验证",
        help: "全局默认；仅用于自签名/测试节点（节点参数优先）",
        kind: ParamKind::Bool,
        default: "false",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "udphop_interval",
        group: "转发与连接",
        label: "hysteria2 端口跳跃",
        help: "全局默认跳跃间隔；节点 URL 里的 udphop-interval 优先",
        kind: ParamKind::Duration,
        default: "30s",
        unit: "",
        options: &[],
    },
    // ---- 探测与选路 ----
    ParamSpec {
        section: "group",
        key: "policy",
        group: "探测与选路",
        label: "选路策略",
        help: "新连接优先走哪个节点；可被面板「锁定节点」覆盖",
        kind: ParamKind::Enum,
        default: "min_moving_avg",
        unit: "",
        options: &["", "min", "min_moving_avg", "min_avg10", "random", "fixed"],
    },
    ParamSpec {
        section: "group",
        key: "check_interval",
        group: "探测与选路",
        label: "健康探测间隔",
        help: "有人看面板/有流量时按此间隔探测；空闲会指数退避",
        kind: ParamKind::Int,
        default: "30",
        unit: "s",
        options: &[],
    },
    ParamSpec {
        section: "group",
        key: "check_tolerance",
        group: "探测与选路",
        label: "失败容忍",
        help: "连续失败几次才把节点标死（切换需谨慎，太小会抖）",
        kind: ParamKind::Int,
        default: "1",
        unit: "次",
        options: &[],
    },
    ParamSpec {
        section: "group",
        key: "tcp_check_url",
        group: "探测与选路",
        label: "TCP 探测地址",
        help: "健康检查用的 URL（建议默认，别指向自己的规则集域名）",
        kind: ParamKind::Str,
        default: "http://cp.cloudflare.com",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "group",
        key: "tcp_check_http_method",
        group: "探测与选路",
        label: "探测 HTTP 方法",
        help: "探测请求的方法；部分节点/CF 对 HEAD 与 GET 可用性不同（空 = 引擎默认 HEAD）",
        kind: ParamKind::Enum,
        default: "",
        unit: "",
        options: &["", "HEAD", "GET", "CONNECT"],
    },
    ParamSpec {
        section: "group",
        key: "udp_check_dns",
        group: "探测与选路",
        label: "UDP 探测 DNS",
        help: "UDP 连通性探测用的 DNS（域名:端口；留空则不做 UDP 检查）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "group",
        key: "filter",
        group: "探测与选路",
        label: "节点筛选",
        help: "keyword:/regex:/subtag: 等；只留想用的节点参与选路（表达式原样写回）",
        kind: ParamKind::Expr,
        default: "",
        unit: "",
        options: &[],
    },
    // ---- 订阅与规则集 ----
    ParamSpec {
        section: "global",
        key: "subscription_failover",
        group: "订阅与规则集",
        label: "订阅顺序回退",
        help: "开 = 按声明顺序优先，首源全死才切下一源（pacman 镜像风格）",
        kind: ParamKind::Bool,
        default: "true",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "sub_cache_ttl",
        group: "订阅与规则集",
        label: "订阅缓存 TTL",
        help: "reload 时多久内不重复拉订阅（省流量、加快重载）",
        kind: ParamKind::Duration,
        default: "60s",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "subscription_update_interval",
        group: "订阅与规则集",
        label: "订阅读周期刷新",
        help: "零人工维护的节点刷新（0 = 关闭）；失败源按 sub_fail_ttl 负缓存",
        kind: ParamKind::Duration,
        default: "21600s",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "sub_fail_ttl",
        group: "订阅与规则集",
        label: "失败源负缓存",
        help: "窗口内失败源不再打网（0 = 关）；与订阅顺序回退配套",
        kind: ParamKind::Duration,
        default: "600s",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "watch_config",
        group: "订阅与规则集",
        label: "配置热驱动",
        help: "inotify 事件 + 兜底扫描秒数（0 = 关；改配置即自动重载）",
        kind: ParamKind::Duration,
        default: "0",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "rule_set_update_interval",
        group: "订阅与规则集",
        label: "规则集刷新间隔",
        help: "远程规则集多久自动拉一次（0 = 每次 reload 都拉）",
        kind: ParamKind::Duration,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "rule_set_cache_dir",
        group: "订阅与规则集",
        label: "规则集缓存目录",
        help: "远程规则集落盘位置（重启后可直接用缓存）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "geodata_dir",
        group: "订阅与规则集",
        label: "geodata 搜索目录",
        help: "geoip.dat/geosite.dat 搜索目录（逗号分隔；含 XDG 默认）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    // ---- 性能与内核 ----
    ParamSpec {
        section: "global",
        key: "probe_idle_cap",
        group: "性能与内核",
        label: "空闲探测上限",
        help: "无人看面板且无流量时，探测间隔指数退避到此上限（0 = 不退避）",
        kind: ParamKind::Duration,
        default: "600s",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "disable_thp",
        group: "性能与内核",
        label: "禁用透明大页",
        help: "THP 会让 RSS 虚高、回收变慢；路由器上建议关闭",
        kind: ParamKind::Bool,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "tproxy_port",
        group: "性能与内核",
        label: "tproxy 端口",
        help: "透明代理监听端口（改错会导致断网，改后确认）",
        kind: ParamKind::Int,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "lan_interface",
        group: "性能与内核",
        label: "LAN 接口",
        help: "逗号分隔；支持 glob（如 br-*）与 auto；1s 轮询热插拔（改造网络前先确认）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "wan_interface",
        group: "性能与内核",
        label: "WAN 接口",
        help: "逗号分隔；auto = 跟随默认路由接口（pppoe 重拨会自动跟）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "mptcp",
        group: "性能与内核",
        label: "MPTCP",
        help: "拨号 socket 用 IPPROTO_MPTCP；内核不支持时自动回落 TCP（需两端支持）",
        kind: ParamKind::Bool,
        default: "false",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "disable_waiting_network",
        group: "性能与内核",
        label: "不等待网络就绪",
        help: "默认启动会等到默认路由+DNS 可达（或 30s 超时）；开机早于网络时可保持默认",
        kind: ParamKind::Bool,
        default: "false",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "enable_local_tcp_fast_redirect",
        group: "性能与内核",
        label: "本机 TCP 快速重定向",
        help: "宿主自身流量的快速路径（真网关模式建议开）",
        kind: ParamKind::Bool,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "auto_config_kernel_parameter",
        group: "性能与内核",
        label: "自动配置内核参数",
        help: "启动时按需写 sysctl（转发/缓冲/拥塞）",
        kind: ParamKind::Bool,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "auto_config_firewall_rule",
        group: "性能与内核",
        label: "自动配置防火墙",
        help: "启动时插入所需 nftables/iptables 规则",
        kind: ParamKind::Bool,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "bpf_conn_state_map_size",
        group: "性能与内核",
        label: "连接状态表容量",
        help: "eBPF conn_state map 上限（万级并发才需要调）",
        kind: ParamKind::Int,
        default: "",
        unit: "条",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "bandwidth_max_tx",
        group: "性能与内核",
        label: "上行带宽上限",
        help: "如 100 mbps；用于 brutal/QUIC 类协议的带宽声明",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "bandwidth_max_rx",
        group: "性能与内核",
        label: "下行带宽上限",
        help: "如 500 mbps；同上",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    // ---- v2.0：TLS 指纹与分片（引擎 A2；仅自实现 TLS/REALITY 路径）----
    ParamSpec {
        section: "global",
        key: "tls_fragment",
        group: "TLS 与抗封锁",
        label: "ClientHello 分片",
        help: "把 TLS ClientHello 拆段发送（对抗按 CH 特征识别）；仅自实现 TLS/REALITY 路径生效",
        kind: ParamKind::Bool,
        default: "false",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "tls_fragment_length",
        group: "TLS 与抗封锁",
        label: "分片长度区间",
        help: "形如 50-100（字节）；非法或倒置会回落默认",
        kind: ParamKind::Str,
        default: "",
        unit: "字节",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "tls_fragment_interval",
        group: "TLS 与抗封锁",
        label: "分片间隔",
        help: "分片之间的发送间隔（过大拖慢握手）",
        kind: ParamKind::Duration,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "utls_imitate",
        group: "TLS 与抗封锁",
        label: "uTLS 指纹",
        help: "ClientHello 指纹族（当前仅 chrome 口径；rustls 出站不受影响）",
        kind: ParamKind::Str,
        default: "chrome",
        unit: "",
        options: &[],
    },
    // ---- DNS ----
    ParamSpec {
        section: "dns",
        key: "ipversion_prefer",
        group: "DNS",
        label: "首选 IP 版本",
        help: "双栈域名优先解析 v4 还是 v6",
        kind: ParamKind::Enum,
        default: "",
        unit: "",
        options: &["", "4", "6"],
    },
    ParamSpec {
        section: "dns",
        key: "bind",
        group: "DNS",
        label: "DNS 监听",
        help: "接管 DNS 的监听地址（默认 0.0.0.0:53）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "bootstrap_resolver",
        group: "DNS",
        label: "bootstrap 解析器",
        help: "启动期解析器（DoH/DoT URL；解析上游域名时用）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "fallback_resolver",
        group: "DNS",
        label: "兜底解析器",
        help: "bootstrap 之后、系统解析器之前；节点域名解析失败时兜底",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "dns",
        key: "max_cache_size",
        group: "DNS",
        label: "缓存条数上限",
        help: "DNS 缓存最多存多少条",
        kind: ParamKind::Int,
        default: "",
        unit: "条",
        options: &[],
    },
    ParamSpec {
        section: "dns",
        key: "fixed_domain_ttl",
        group: "DNS",
        label: "固定 TTL",
        help: "非零时所有域名缓存统一用该 TTL（秒）",
        kind: ParamKind::Int,
        default: "",
        unit: "s",
        options: &[],
    },
    ParamSpec {
        section: "dns",
        key: "optimistic_cache",
        group: "DNS",
        label: "乐观缓存",
        help: "缓存过期先回旧值再后台刷新（更快，可能短暂陈旧）",
        kind: ParamKind::Bool,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "dns",
        key: "optimistic_cache_ttl",
        group: "DNS",
        label: "乐观缓存窗口",
        help: "过期后仍可回旧值的时间窗",
        kind: ParamKind::Duration,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "dns",
        key: "optimistic_stale_reply_ttl",
        group: "DNS",
        label: "陈旧应答 TTL",
        help: "乐观缓存回包时告诉客户端的 TTL（秒）",
        kind: ParamKind::Int,
        default: "",
        unit: "s",
        options: &[],
    },
    // ---- 日志与调试 ----
    ParamSpec {
        section: "global",
        key: "log_level",
        group: "日志与调试",
        label: "日志级别",
        help: "debug 会明显增加日志量与 CPU（排障后调回 info）",
        kind: ParamKind::Enum,
        default: "",
        unit: "",
        options: &["", "error", "warn", "info", "debug"],
    },
    ParamSpec {
        section: "global",
        key: "log_file",
        group: "日志与调试",
        label: "日志文件",
        help: "留空 = 交给 procd/日志系统；SIGHUP 会 reopen（配合 logrotate）",
        kind: ParamKind::Str,
        default: "",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "disable_timestamp",
        group: "日志与调试",
        label: "日志不带时间戳",
        help: "交给 syslog/procd 收日志时可关（省一点日志体积）",
        kind: ParamKind::Bool,
        default: "false",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "pprof_port",
        group: "日志与调试",
        label: "诊断端口",
        help: "只绑 127.0.0.1；`/` 文本摘要、`/json` 结构化（0 = 关）",
        kind: ParamKind::Int,
        default: "0",
        unit: "",
        options: &[],
    },
    ParamSpec {
        section: "global",
        key: "status_socket",
        group: "日志与调试",
        label: "状态面 socket",
        help: "面板/脚本读写状态的 Unix socket 路径（与面板 panel.conf 的 socket 要一致）",
        kind: ParamKind::Str,
        default: "/tmp/sodama-status.sock",
        unit: "",
        options: &[],
    },
];

/// 参数当前值（只回传**配置文件里显式写了**的键；未设置 = 引擎默认）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ParamsView {
    /// `"<section>.<key>"` → 原文值
    pub values: std::collections::BTreeMap<String, String>,
}

/// 写参数请求：`value` 为空 = 从配置里移除该键（回到引擎默认）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ParamSetReq {
    pub section: String,
    pub key: String,
    pub value: String,
}

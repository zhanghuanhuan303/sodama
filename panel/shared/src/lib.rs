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
    pub maps: MapsView,
    pub pname: PnameView,
    pub config_watch: WatchView,
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

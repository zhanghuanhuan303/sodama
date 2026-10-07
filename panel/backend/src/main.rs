//! sodama 面板后端：把引擎的 CLI/socket 能力包成 HTTP API，并托管前端静态资源。
//!
//! - 与引擎**零协议耦合**：数据来自执行 `sodama` 子命令（命令模板可覆盖，便于本机开发走 SSH）。
//! - M1 采样曲线（内存环形缓冲）+ **CSV 按需导出（不落盘）** + 订阅源调序。
//! - M2 控制动作（reload/suspend/resume）+ **token 会话**（HttpOnly Cookie）。
//! - M3 配置/规则在线编辑（先 `validate` 再落盘，等 inotify 重载回执）。
//! - 单节点详情：每节点延迟/健康历史（内存环形缓冲）。

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

mod configapi;

use shared::{
    ConfigView, DnsView, DomainStatView, FileContent, FileInfo, GroupView, LoginReq, LoginResp,
    MapsView, NodeDetail, NodePoint, NodeView, PnameView, RelayView, ReloadView, RuleSetView,
    Sample, SaveResult, SeriesView, SniffView, SourceInfo, SourcesView, StatusView, WatchView,
};

// ---------------------------------------------------------------- 配置

pub(crate) struct GlobalCfg {
    bind: String,
    token: Option<String>,
    static_dir: PathBuf,
    timeout: Duration,
    actions_enabled: bool,
    sample_secs: u64,
    /// 无人看面板时也持续采样（默认 false：只在有人看的时候采，好让引擎空闲退避）
    sample_when_idle: bool,
    series_cap: usize,
    node_cap: usize,
    session_ttl: u64,
    tls: bool,
    tls_bind: String,
    tls_cert: PathBuf,
    tls_key: PathBuf,
}

pub(crate) struct Engine {
    pub(crate) sodama: String,
    /// 状态面 unix socket（未被 `status_cmd` 显式覆盖时，面板直连它，不 fork 子进程）
    pub(crate) socket: Option<PathBuf>,
    status_cmd: String,
    metrics_cmd: String,
    logs_cmd: String,
    /// 默认 `tail` 形式时的日志文件路径（面板直接读尾，不 fork 子进程）
    pub(crate) log_file: Option<PathBuf>,
    pub(crate) reload_cmd: String,
    suspend_cmd: String,
    resume_cmd: String,
    pub(crate) engine_config: PathBuf,
    pub(crate) rules_dir: PathBuf,
    series: SeriesStore,
    nodes: NodeStore,
    latest: Mutex<Option<StatusView>>,
    /// `/proc/<pid>` CPU 差分用（上次采样时刻, 累计 CPU 秒, 上次百分数）
    proc_prev: Mutex<Option<(std::time::Instant, f64, f64)>>,
}

#[derive(Clone)]
pub(crate) struct Ctx {
    pub(crate) cfg: Arc<GlobalCfg>,
    pub(crate) engine: Arc<Engine>,
    sessions: Arc<Mutex<HashMap<String, u64>>>,
}

#[derive(Default)]
struct SeriesStore {
    inner: Mutex<SeriesInner>,
}

#[derive(Default)]
struct SeriesInner {
    points: VecDeque<Sample>,
    prev: Option<(u64, u64, u64, u64)>, // t, bytes_up, bytes_down, dns_queries
}

impl SeriesStore {
    fn push(&self, s: Sample, cap: usize) {
        let mut g = self.inner.lock().unwrap();
        g.points.push_back(s);
        while g.points.len() > cap {
            g.points.pop_front();
        }
    }
    fn tail(&self, n: usize) -> Vec<Sample> {
        let g = self.inner.lock().unwrap();
        let skip = g.points.len().saturating_sub(n);
        g.points.iter().skip(skip).cloned().collect()
    }
    fn prev(&self) -> Option<(u64, u64, u64, u64)> {
        self.inner.lock().unwrap().prev
    }
    fn set_prev(&self, p: (u64, u64, u64, u64)) {
        self.inner.lock().unwrap().prev = Some(p);
    }
}

/// 每节点历史（key = `tag|name`）。
#[derive(Default)]
struct NodeStore {
    inner: Mutex<HashMap<String, VecDeque<NodePoint>>>,
}

impl NodeStore {
    fn push(&self, key: String, p: NodePoint, cap: usize) {
        let mut g = self.inner.lock().unwrap();
        let q = g.entry(key).or_default();
        q.push_back(p);
        while q.len() > cap {
            q.pop_front();
        }
    }
    fn get(&self, key: &str) -> Vec<NodePoint> {
        self.inner
            .lock()
            .unwrap()
            .get(key)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    // 兼容两种写法：`--status_cmd`（键原样）与 `--status-cmd`（连字符）。
    // 脚本里习惯写连字符（见 scripts/dev-local.sh），不再因拼写差异被静默忽略。
    let dashed = key.replace('_', "-");
    args.iter()
        .position(|a| a == key || a == &dashed)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// 极简 key = value 配置（# 注释、空行忽略）——避免为面板引入额外依赖。
fn load_kv(path: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
        }
    }
    out
}

fn parse_cfg() -> (GlobalCfg, Arc<Engine>) {
    let args: Vec<String> = std::env::args().collect();
    let cfg_path = arg_value(&args, "--config").or_else(|| {
        let p = "/etc/sodama-panel/panel.conf".to_string();
        Path::new(&p).exists().then_some(p)
    });
    let file: Vec<(String, String)> = cfg_path
        .as_deref()
        .map(|p| load_kv(Path::new(p)))
        .unwrap_or_default();
    let file_get = |key: &str| file.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let get = |key: &str| arg_value(&args, &format!("--{key}")).or_else(|| file_get(key));
    let flag = |key: &str| {
        args.iter().any(|a| a == &format!("--{key}"))
            || matches!(
                file_get(key).as_deref(),
                Some("1") | Some("true") | Some("yes") | Some("on")
            )
    };

    let g = GlobalCfg {
        bind: get("bind").unwrap_or_else(|| "0.0.0.0:8080".into()),
        token: get("token").filter(|t| !t.is_empty()),
        static_dir: PathBuf::from(
            get("static_dir").unwrap_or_else(|| "/usr/share/sodama-panel/dist".into()),
        ),
        timeout: Duration::from_secs(get("timeout").and_then(|v| v.parse().ok()).unwrap_or(20)),
        actions_enabled: flag("enable_actions"),
        sample_secs: get("sample_secs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(5)
            .max(1),
        sample_when_idle: flag("sample_when_idle"),
        series_cap: get("series_points")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1440),
        node_cap: get("node_points")
            .and_then(|v| v.parse().ok())
            .unwrap_or(720),
        session_ttl: get("session_ttl")
            .and_then(|v| v.parse().ok())
            .unwrap_or(7 * 86400),
        tls: flag("tls"),
        tls_bind: get("tls_bind").unwrap_or_else(|| "0.0.0.0:8443".into()),
        tls_cert: PathBuf::from(
            get("tls_cert").unwrap_or_else(|| "/etc/sodama-panel/tls/cert.pem".into()),
        ),
        tls_key: PathBuf::from(
            get("tls_key").unwrap_or_else(|| "/etc/sodama-panel/tls/key.pem".into()),
        ),
    };

    // 引擎即本机：只认平铺键（`engine.*` 已随多引擎一并移除）
    let sodama = get("sodama").unwrap_or_else(|| "/usr/bin/sodama".into());
    let socket = get("socket").unwrap_or_else(|| "/var/run/sodama.sock".into());
    let log_file = get("log_file").unwrap_or_else(|| "/var/log/sodama.log".into());
    let engine_config = get("engine_config").unwrap_or_else(|| "/etc/sodama/config.dae".into());
    let rules_dir = get("rules_dir").unwrap_or_else(|| "/etc/sodama/rules".into());
    let status_cmd =
        get("status_cmd").unwrap_or_else(|| format!("{sodama} status --socket {socket} --json"));
    let metrics_cmd =
        get("metrics_cmd").unwrap_or_else(|| format!("{sodama} metrics --socket {socket}"));
    let logs_cmd = get("logs_cmd").unwrap_or_else(|| format!("tail -n {{n}} {log_file}"));
    let reload_cmd =
        get("reload_cmd").unwrap_or_else(|| format!("{sodama} reload --socket {socket}"));
    let suspend_cmd =
        get("suspend_cmd").unwrap_or_else(|| format!("{sodama} suspend --socket {socket}"));
    let resume_cmd =
        get("resume_cmd").unwrap_or_else(|| format!("{sodama} resume --socket {socket}"));
    let logs_cmd_overridden = get("logs_cmd").is_some();
    let status_cmd_overridden = get("status_cmd").is_some();
    let engine = Arc::new(Engine {
        sodama,
        socket: (!status_cmd_overridden).then(|| PathBuf::from(&socket)),
        log_file: (!logs_cmd_overridden).then(|| PathBuf::from(&log_file)),
        status_cmd,
        metrics_cmd,
        logs_cmd,
        reload_cmd,
        suspend_cmd,
        resume_cmd,
        engine_config: PathBuf::from(engine_config),
        rules_dir: PathBuf::from(rules_dir),
        series: SeriesStore::default(),
        nodes: NodeStore::default(),
        latest: Mutex::new(None),
        proc_prev: Mutex::new(None),
    });

    (g, engine)
}

// ---------------------------------------------------------------- 工具

pub(crate) async fn run_cmd(cfg: &GlobalCfg, cmd: &str) -> Result<(i32, String, String), String> {
    let fut = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::null())
        .output();
    match tokio::time::timeout(cfg.timeout, fut).await {
        Err(_) => Err(format!("命令超时（{}s）: {cmd}", cfg.timeout.as_secs())),
        Ok(Err(e)) => Err(format!("命令执行失败: {e}")),
        Ok(Ok(out)) => Ok((
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn err_json(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({"error": msg.into()}))).into_response()
}

/// 会话 id（/dev/urandom；不可用时退回时间+PID 混合）。
fn new_session_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !ok {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mix = t ^ ((std::process::id() as u128) << 64);
        buf[..16].copy_from_slice(&mix.to_le_bytes());
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// token 校验：空 token = 放行；否则 Bearer / ?token= / 会话 Cookie 任一命中。
pub(crate) fn auth(ctx: &Ctx, headers: &HeaderMap, uri: &Uri) -> Result<(), Response> {
    // 任何一次带鉴权的访问都算「有人在看」（面板空闲自我停机 / 引擎探测节奏的信号）
    note_ui();
    let Some(want) = ctx.cfg.token.as_deref() else {
        return Ok(());
    };
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    let query_token = uri.query().and_then(|q| {
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "token")
            .map(|(_, v)| v)
    });
    if bearer == Some(want) || query_token == Some(want) {
        return Ok(());
    }
    if let Some(sid) = cookie_value(headers, "panel_session") {
        let mut g = ctx.sessions.lock().unwrap();
        g.retain(|_, exp| *exp > now_secs());
        if g.get(&sid).is_some_and(|exp| *exp > now_secs()) {
            return Ok(());
        }
    }
    Err(err_json(StatusCode::UNAUTHORIZED, "需要登录（token）"))
}

pub(crate) fn require_actions(ctx: &Ctx, headers: &HeaderMap, uri: &Uri) -> Result<(), Response> {
    auth(ctx, headers, uri)?;
    if !ctx.cfg.actions_enabled {
        return Err(err_json(
            StatusCode::FORBIDDEN,
            "控制动作未启用（panel.conf: enable_actions = 1）",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- JSON → DTO

fn u64_of(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}
fn f64_of(v: &Value) -> f64 {
    v.as_f64().unwrap_or(0.0)
}
fn str_of(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}
fn bool_of(v: &Value) -> bool {
    v.as_bool().unwrap_or(false)
}
fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        a as f64 * 100.0 / b as f64
    }
}

/// 从引擎配置文本里取 `global.rule_set_update_interval`（秒）。
fn rule_set_interval(text: &str) -> u64 {
    let mut inside_global = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("global") && t.contains('{') {
            inside_global = true;
            continue;
        }
        if inside_global {
            if t.starts_with('}') {
                break;
            }
            if let Some((k, v)) = t.split_once(':') {
                if k.trim() == "rule_set_update_interval" {
                    return v
                        .trim()
                        .trim_matches('\'')
                        .trim_matches('"')
                        .trim()
                        .parse()
                        .unwrap_or(0);
                }
            }
        }
    }
    0
}

fn to_view(root: &Value, engine: &Engine) -> StatusView {
    let group = &root["group"];
    let nodes: Vec<NodeView> = group["nodes"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .enumerate()
                .map(|(i, n)| NodeView {
                    index: i as u64,
                    name: str_of(&n["name"]),
                    tag: str_of(&n["tag"]),
                    alive: bool_of(&n["alive"]),
                    ema_ms: f64_of(&n["ema_ms"]),
                    last_ms: u64_of(&n["last_ms"]),
                    protocol: str_of(&n["protocol"]),
                    transport: str_of(&n["transport"]),
                    security: str_of(&n["security"]),
                    udp: bool_of(&n["udp"]),
                    addr: str_of(&n["addr"]),
                })
                .collect()
        })
        .unwrap_or_default();
    let interval = std::fs::read_to_string(&engine.engine_config)
        .map(|t| rule_set_interval(&t))
        .unwrap_or(0);
    let rule_sets = root["rule_sets"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|r| {
                    let ago = u64_of(&r["updated_secs_ago"]);
                    RuleSetView {
                        tag: str_of(&r["tag"]),
                        entries: u64_of(&r["entries"]),
                        remote: bool_of(&r["remote"]),
                        from_cache: bool_of(&r["from_cache"]),
                        updated_secs_ago: ago,
                        suffix: u64_of(&r["suffix"]),
                        full: u64_of(&r["full"]),
                        keyword: u64_of(&r["keyword"]),
                        regex: u64_of(&r["regex"]),
                        interval_secs: interval,
                        next_update_secs: if interval == 0 {
                            0
                        } else {
                            interval.saturating_sub(ago)
                        },
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let hooks = root["hooks"]
        .as_array()
        .map(|a| a.iter().map(str_of).collect())
        .unwrap_or_default();
    let sections = root["config"]["sections"]
        .as_array()
        .map(|a| a.iter().map(str_of).collect())
        .unwrap_or_default();

    StatusView {
        sampled_at: now_secs(),
        version: str_of(&root["version"]),
        kernel: str_of(&root["kernel"]),
        pid: u64_of(&root["pid"]) as u32,
        uptime_sec: u64_of(&root["uptime_sec"]),
        suspended: bool_of(&root["suspended"]),
        active_slot: u64_of(&root["active_slot"]),
        tproxy_port: u64_of(&root["tproxy_port"]) as u16,
        dialer: str_of(&root["dialer"]),
        hooks,
        config: ConfigView {
            entry: str_of(&root["config"]["entry"]),
            fallback: str_of(&root["config"]["fallback"]),
            sections,
            routing_supported: u64_of(&root["config"]["routing_supported"]),
            routing_deferred: u64_of(&root["config"]["routing_deferred"]),
        },
        reload: ReloadView {
            at_sec: u64_of(&root["reload"]["at_sec"]),
            ok: bool_of(&root["reload"]["ok"]),
            error: root["reload"]["error"].as_str().map(str::to_string),
            slot: u64_of(&root["reload"]["slot"]),
            match_sets: u64_of(&root["reload"]["match_sets"]),
        },
        relay: RelayView {
            conns_active: u64_of(&root["relay"]["conns_active"]),
            conns_total: u64_of(&root["relay"]["conns_total"]),
            dial_errors: u64_of(&root["relay"]["dial_errors"]),
            evicted: u64_of(&root["relay"]["evicted"]),
            limit_rejected: u64_of(&root["relay"]["limit_rejected"]),
            bytes_up: u64_of(&root["relay"]["bytes_up"]),
            bytes_down: u64_of(&root["relay"]["bytes_down"]),
            fds_used: u64_of(&root["relay"]["fds_used"]),
            fds_soft_limit: u64_of(&root["relay"]["fds_soft_limit"]),
            max_conns: u64_of(&root["relay"]["max_conns"]),
            idle_timeout_secs: u64_of(&root["relay"]["idle_timeout_secs"]),
            splice_enabled: bool_of(&root["relay"]["splice_enabled"]),
            splice_fallbacks: u64_of(&root["relay"]["splice_fallbacks"]),
            offload_enabled: bool_of(&root["relay"]["offload_enabled"]),
            offloaded_total: u64_of(&root["relay"]["offloaded_total"]),
        },
        domain_stats: root["domain_stats"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|d| DomainStatView {
                        domain: str_of(&d["domain"]),
                        ai: bool_of(&d["ai"]),
                        conns: u64_of(&d["conns"]),
                        active: u64_of(&d["active"]),
                        bytes_up: u64_of(&d["bytes_up"]),
                        bytes_down: u64_of(&d["bytes_down"]),
                        last_seen_secs_ago: u64_of(&d["last_seen_secs_ago"]),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        dns: DnsView {
            queries: u64_of(&root["dns"]["queries"]),
            responses: u64_of(&root["dns"]["responses"]),
            upstream: str_of(&root["dns"]["upstream"]),
            upstream_errors: u64_of(&root["dns"]["upstream_errors"]),
            cache_entries: u64_of(&root["dns"]["cache_entries"]),
            cache_hits: u64_of(&root["dns"]["cache_hits"]),
            cache_misses: u64_of(&root["dns"]["cache_misses"]),
            cache_expired: u64_of(&root["dns"]["cache_expired"]),
            cache_evictions: u64_of(&root["dns"]["cache_evictions"]),
            bitmap_matched: u64_of(&root["dns"]["bitmap_matched"]),
            published_ips: u64_of(&root["dns"]["published_ips"]),
            rejects: u64_of(&root["dns"]["routing"]["rejects"]),
            stale_hits: u64_of(&root["dns"]["stale_hits"]),
        },
        sniffing: SniffView {
            dial_mode: str_of(&root["sniffing"]["dial_mode"]),
            timeout_ms: u64_of(&root["sniffing"]["timeout_ms"]),
            attempts: u64_of(&root["sniffing"]["attempts"]),
            hits: u64_of(&root["sniffing"]["hits"]),
            misses: u64_of(&root["sniffing"]["misses"]),
            quic_sni: u64_of(&root["sniffing"]["quic_sni"]),
        },
        group: GroupView {
            name: str_of(&group["name"]),
            active_tag: str_of(&group["active_tag"]),
            policy: str_of(&group["policy"]),
            pinned: str_of(&group["pinned"]),
            pinned_ok: bool_of(&group["pinned_ok"]),
            current: group["current"].as_u64(),
            probe_interval_secs: u64_of(&group["probe_interval_secs"]),
            probe_active: bool_of(&group["probe_active"]),
            members: u64_of(&group["members"]),
            alive: u64_of(&group["alive"]),
            dials: u64_of(&group["dials"]),
            failovers: u64_of(&group["failovers"]),
            probes_ok: u64_of(&group["probes_ok"]),
            probes_fail: u64_of(&group["probes_fail"]),
            subscription_failover: bool_of(&group["subscription_failover"]),
        },
        nodes,
        rule_sets,
        maps: MapsView {
            conn_state: u64_of(&root["maps"]["conn_state"]),
            domain_routing: u64_of(&root["maps"]["domain_routing"]),
            fast_sock: u64_of(&root["maps"]["fast_sock"]),
            redirect_track: u64_of(&root["maps"]["redirect_track"]),
        },
        pname: PnameView {
            driver: str_of(&root["pname"]["driver"]),
            enabled: bool_of(&root["pname"]["enabled"]),
            hooks: u64_of(&root["pname"]["hooks"]),
            map_entries: u64_of(&root["pname"]["map_entries"]),
            hits: u64_of(&root["pname"]["hits"]),
        },
        config_watch: WatchView {
            enabled: bool_of(&root["config_watch"]["enabled"]),
            transport: str_of(&root["config_watch"]["transport"]),
            debounce_ms: u64_of(&root["config_watch"]["debounce_ms"]),
            interval_secs: u64_of(&root["config_watch"]["interval_secs"]),
        },
        runtime: proc_runtime(u64_of(&root["pid"]) as u32, engine),
    }
}

/// 读 `/proc/<pid>`（面板与引擎同机）：RSS / 峰值 / 虚拟内存 / 线程 / CPU 时间。
/// 读不到（权限/不存在）则全 0，不影响其他指标。
fn read_proc(pid: u32) -> shared::RuntimeView {
    let mut rt = shared::RuntimeView::default();
    if pid == 0 {
        return rt;
    }
    if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in text.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let first = v.split_whitespace().next().unwrap_or("0");
            match k {
                "VmRSS" => rt.rss_kb = first.parse().unwrap_or(0),
                "VmHWM" => rt.hwm_kb = first.parse().unwrap_or(0),
                "VmSize" => rt.vmsize_kb = first.parse().unwrap_or(0),
                "Threads" => rt.threads = first.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    // CPU：/proc/<pid>/stat 在 `)` 之后依次 state→…→utime(11)/stime(12)/cutime(13)/cstime(14)
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        if let Some((_, rest)) = stat.rsplit_once(')') {
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() > 14 {
                let get = |i: usize| f[i].parse::<i64>().unwrap_or(0);
                // clock tick：Linux 常规 HZ=100（仅用于人读展示，不参与任何控制逻辑）
                let hz = 100.0;
                rt.cpu_secs = (get(11) + get(12)) as f64 / hz;
                rt.cpu_child_secs = (get(13).max(0) + get(14).max(0)) as f64 / hz;
            }
        }
    }
    rt
}

/// `/proc` 采样 + CPU 区间差分。
///
/// 窗口下限 2s：`/proc/<pid>/stat` 的 tick 只有 10ms 精度（USER_HZ=100），
/// 窗口过短时 ±1 tick 就能把百分数放大成噪声（实测 2ms 窗口会报 80% 而真实 7%），
/// 所以短窗口直接沿用上次结果。
fn proc_runtime(pid: u32, engine: &Engine) -> shared::RuntimeView {
    let mut rt = read_proc(pid);
    if let Ok(mut g) = engine.proc_prev.lock() {
        match *g {
            Some((pt, pc, last_pct)) => {
                let dt = pt.elapsed().as_secs_f64();
                if dt >= 2.0 {
                    rt.cpu_pct = if rt.cpu_secs >= pc {
                        (rt.cpu_secs - pc) / dt * 100.0
                    } else {
                        last_pct
                    };
                    *g = Some((std::time::Instant::now(), rt.cpu_secs, rt.cpu_pct));
                } else {
                    rt.cpu_pct = last_pct;
                }
            }
            None => {
                *g = Some((std::time::Instant::now(), rt.cpu_secs, 0.0));
            }
        }
    }
    rt
}

/// 最近一次有浏览器/客户端访问面板的时间（unix 秒）。
///
/// 用来让面板自己在“无人看”时停下来：引擎的健康探测会按「有人查状态 / 有流量」退避，
/// 如果面板还盲轮询，引擎就永远不会进入空闲——这与“优雅空闲”目标矛盾。
static LAST_UI: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn note_ui() {
    LAST_UI.store(now_secs(), std::sync::atomic::Ordering::Relaxed);
}

fn ui_recently_active(within: u64) -> bool {
    let t = LAST_UI.load(std::sync::atomic::Ordering::Relaxed);
    t > 0 && now_secs().saturating_sub(t) < within
}

/// 读文件尾部 `n` 行（最多回看 512KB；日志轮转/截断时不报错，返回空）。
fn tail_lines(path: &Path, n: u32) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let back = len.min(512 * 1024);
    f.seek(SeekFrom::Start(len - back))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    let mut lines: Vec<String> = buf.lines().map(str::to_string).collect();
    if lines.len() > n as usize {
        lines.drain(..lines.len() - n as usize);
    }
    Ok(lines)
}

/// 直连状态面：unix socket 上写一行命令，读到 EOF（与 `sodama status` 同一协议）。
/// 比每次 fork 一个 7.4MB 的 CLI 子进程便宜得多（面板轮询 2s 一次）。
pub(crate) fn socket_query(sock: &Path, cmd: &str) -> std::io::Result<String> {
    use std::io::{Read, Write};
    let mut s = std::os::unix::net::UnixStream::connect(sock)?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.write_all(cmd.as_bytes())?;
    s.write_all(b"\n")?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out.trim_end().to_string())
}

/// 查询状态面：优先直连 socket，失败/未配置时回退到 CLI 子进程。
async fn engine_query(ctx: &Ctx, engine: &Arc<Engine>, cmd: &str) -> Result<String, String> {
    if let Some(sock) = engine.socket.clone() {
        let c = cmd.to_string();
        if let Ok(Ok(text)) = tokio::task::spawn_blocking(move || socket_query(&sock, &c)).await {
            return Ok(text);
        }
    }
    let cli = match cmd {
        "status" => engine.status_cmd.clone(),
        "metrics" => engine.metrics_cmd.clone(),
        other => return Err(format!("未知引擎查询 {other}")),
    };
    match run_cmd(&ctx.cfg, &cli).await {
        Ok((0, out, _)) => Ok(out),
        Ok((code, _o, err)) => {
            Err(format!("引擎查询 {cmd} 退出码 {code}: {err}").replace("\n", " "))
        }
        Err(e) => Err(e),
    }
}

async fn fetch_view(ctx: &Ctx, engine: &Arc<Engine>) -> Result<StatusView, String> {
    match engine_query(ctx, engine, "status").await {
        Ok(out) => match serde_json::from_str::<Value>(&out) {
            Ok(v) => {
                let view = to_view(&v, engine);
                *engine.latest.lock().unwrap() = Some(view.clone());
                Ok(view)
            }
            Err(e) => Err(format!("status JSON 解析失败: {e}")),
        },
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------- 采样（M1）

fn make_sample(v: &StatusView, prev: &mut Option<(u64, u64, u64, u64)>) -> Sample {
    let (up, down, q) = (v.relay.bytes_up, v.relay.bytes_down, v.dns.queries);
    let (up_bps, down_bps, dns_qps) = match *prev {
        Some((pt, pu, pd, pq)) if v.sampled_at > pt => {
            let dt = (v.sampled_at - pt) as f64;
            (
                (up.saturating_sub(pu) as f64 / dt) as u64,
                (down.saturating_sub(pd) as f64 / dt) as u64,
                q.saturating_sub(pq) as f64 / dt,
            )
        }
        _ => (0, 0, 0.0),
    };
    *prev = Some((v.sampled_at, up, down, q));
    let emas: Vec<f64> = v
        .nodes
        .iter()
        .filter(|n| n.alive && n.ema_ms > 0.0)
        .map(|n| n.ema_ms)
        .collect();
    let ema_min = emas.iter().cloned().fold(f64::MAX, f64::min);
    let ema_avg = if emas.is_empty() {
        0.0
    } else {
        emas.iter().sum::<f64>() / emas.len() as f64
    };
    Sample {
        t: v.sampled_at,
        conns_active: v.relay.conns_active,
        up_bps,
        down_bps,
        alive: v.group.alive,
        members: v.group.members,
        ema_min: if ema_min == f64::MAX { 0.0 } else { ema_min },
        ema_avg,
        dns_qps,
        sniff_pct: pct(v.sniffing.hits, v.sniffing.attempts),
        fds_used: v.relay.fds_used,
        rss_kb: v.runtime.rss_kb,
        threads: v.runtime.threads,
        cpu_pct: v.runtime.cpu_pct,
    }
}

async fn sampler(ctx: Ctx, engine: Arc<Engine>) {
    loop {
        // 无人看面板时不自转：否则引擎永远被“盯着”，空闲退避永远不会生效。
        // （`sample_when_idle = 1` 可恢复旧行为：无条件持续采样。）
        if !ctx.cfg.sample_when_idle && !ui_recently_active(15) {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        if let Ok(v) = fetch_view(&ctx, &engine).await {
            let mut prev = engine.series.prev();
            let s = make_sample(&v, &mut prev);
            if let Some(p) = prev {
                engine.series.set_prev(p);
            }
            engine.series.push(s, ctx.cfg.series_cap);
            for n in &v.nodes {
                engine.nodes.push(
                    format!("{}|{}", n.tag, n.name),
                    NodePoint {
                        t: v.sampled_at,
                        alive: n.alive,
                        ema_ms: n.ema_ms,
                        last_ms: n.last_ms,
                    },
                    ctx.cfg.node_cap,
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(ctx.cfg.sample_secs)).await;
    }
}

// ---------------------------------------------------------------- 配置文本（M1/M3）

pub(crate) fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("token=") {
        out.push_str(&rest[..pos + 6]);
        rest = &rest[pos + 6..];
        let end = rest
            .find(|c: char| c == '\'' || c == '"' || c.is_whitespace() || c == '&' || c == '}')
            .unwrap_or(rest.len());
        out.push_str("***");
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// 通用 `block { tag: 'value' }` 提取（subscription / rule_set / node 同构）。
pub(crate) fn block_kv(text: &str, block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if !inside {
            if t.starts_with('#') {
                continue;
            }
            if let Some(rest) = t.strip_prefix(block) {
                if rest.trim_start().starts_with('{') {
                    inside = true;
                    // 单行形式 `block { a: 'b' }`
                    if let Some((_, inner)) = t.split_once('{') {
                        if let Some((kv, _)) = inner.split_once('}') {
                            if let Some((k, v)) = kv.split_once(':') {
                                let k = k.trim().to_string();
                                let v = v.trim().trim_matches(['\'', '"']).trim().to_string();
                                if !k.is_empty() && !v.is_empty() {
                                    out.push((k, v));
                                }
                            }
                            inside = false;
                        }
                    }
                }
            }
            continue;
        }
        if t.starts_with('}') {
            break;
        }
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if let Some((k, v)) = t.split_once(':') {
            let tag = k.trim().to_string();
            let url = v
                .trim()
                .split('#') // 行尾注释
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['\'', '"'])
                .trim()
                .to_string();
            if !tag.is_empty() && !url.is_empty() {
                out.push((tag, url));
            }
        }
    }
    out
}

fn parse_subscription(text: &str) -> Vec<(String, String)> {
    block_kv(text, "subscription")
}

fn reorder_subscription(text: &str, tag: &str) -> Result<String, String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut start = None;
    let mut end = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if start.is_none() && t.starts_with("subscription") && t.contains('{') {
            start = Some(i);
            continue;
        }
        if start.is_some() && t.starts_with('}') {
            end = Some(i);
            break;
        }
    }
    let (start, end) = match (start, end) {
        (Some(s), Some(e)) => (s, e),
        _ => return Err("配置里找不到 subscription 块".into()),
    };
    let mut entry_idx = Vec::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    for i in start + 1..end {
        let t = lines[i].trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if let Some((k, v)) = t.split_once(':') {
            let k = k.trim().to_string();
            let url = v
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .trim()
                .to_string();
            if !k.is_empty() && !url.is_empty() {
                entry_idx.push(i);
                entries.push((k, lines[i].to_string()));
            }
        }
    }
    let pos = entries
        .iter()
        .position(|(k, _)| k == tag)
        .ok_or_else(|| format!("subscription 里没有 tag={tag}"))?;
    if pos == 0 {
        return Ok(text.to_string());
    }
    let mut order: Vec<usize> = vec![pos];
    order.extend((0..entries.len()).filter(|&i| i != pos));
    let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    for (slot, &src) in entry_idx.iter().zip(order.iter()) {
        new_lines[*slot] = entries[src].1.clone();
    }
    let mut out = new_lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

pub(crate) fn write_preserving(path: &Path, text: &str) -> Result<(), String> {
    let mode = std::fs::metadata(path).ok().map(|m| m.permissions());
    std::fs::write(path, text).map_err(|e| format!("写入 {} 失败: {e}", path.display()))?;
    #[cfg(unix)]
    if let Some(p) = mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(p.mode() & 0o777));
    }
    Ok(())
}

pub(crate) fn deferred_count(out: &str) -> u64 {
    for line in out.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("routing:") {
            if let Some(pos) = rest.find("条 deferred") {
                let head = rest[..pos].trim_end();
                let num: String = head
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                return num.parse::<u64>().unwrap_or(0);
            }
        }
    }
    0
}

pub(crate) async fn wait_reload(
    ctx: &Ctx,
    engine: &Arc<Engine>,
    prev_at: u64,
    secs: u64,
) -> Option<bool> {
    let deadline = now_secs() + secs;
    loop {
        if now_secs() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(600)).await;
        if let Ok(v) = fetch_view(ctx, engine).await {
            if v.reload.at_sec != prev_at {
                return Some(v.reload.ok);
            }
        }
    }
}

pub(crate) async fn current_reload_at(ctx: &Ctx, engine: &Arc<Engine>) -> u64 {
    if let Ok(v) = fetch_view(ctx, engine).await {
        return v.reload.at_sec;
    }
    engine
        .latest
        .lock()
        .unwrap()
        .as_ref()
        .map(|v| v.reload.at_sec)
        .unwrap_or(0)
}

fn editable_files(engine: &Engine) -> Vec<FileInfo> {
    let mut out = Vec::new();
    let cfg_name = engine
        .engine_config
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.dae".into());
    if let Ok(md) = std::fs::metadata(&engine.engine_config) {
        out.push(FileInfo {
            name: cfg_name.clone(),
            size: md.len(),
            mtime: md
                .modified()
                .ok()
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
    }
    let cfg_dir = engine
        .engine_config
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    for (dir, prefix) in [(&engine.rules_dir, "rules/"), (&cfg_dir, "")] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_rule = prefix == "rules/"
                && (name.ends_with(".txt") || name.ends_with(".list") || name.ends_with(".md"));
            let is_blocklist = prefix.is_empty() && name.starts_with("blocklist");
            if !(is_rule || is_blocklist) || (prefix.is_empty() && name == cfg_name) {
                continue;
            }
            if let Ok(md) = e.metadata() {
                out.push(FileInfo {
                    name: format!("{prefix}{name}"),
                    size: md.len(),
                    mtime: md
                        .modified()
                        .ok()
                        .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                });
            }
        }
    }
    out
}

fn resolve_editable(engine: &Engine, name: &str) -> Option<PathBuf> {
    if name.contains("..") || name.starts_with('/') {
        return None;
    }
    let cfg_dir = engine
        .engine_config
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let cfg_name = engine
        .engine_config
        .file_name()?
        .to_string_lossy()
        .into_owned();
    if name == cfg_name {
        return Some(engine.engine_config.clone());
    }
    if let Some(rest) = name.strip_prefix("rules/") {
        if rest.is_empty() {
            return None;
        }
        return Some(engine.rules_dir.join(rest));
    }
    if name.starts_with("blocklist") {
        return Some(cfg_dir.join(name));
    }
    None
}

/// 纪元秒 → `YYYY-MM-DD HH:MM:SSZ`（UTC，不引入 chrono）。
fn iso_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant civil_from_days
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}

/// 载入或生成自签证书（`tls = 1` 时；生成结果落在 tls_cert/tls_key）。
fn load_or_gen_tls(
    cfg: &GlobalCfg,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    String,
> {
    if cfg.tls_cert.exists() && cfg.tls_key.exists() {
        let mut cr = std::io::BufReader::new(
            std::fs::File::open(&cfg.tls_cert).map_err(|e| format!("读证书失败: {e}"))?,
        );
        let certs: Vec<_> = rustls_pemfile::certs(&mut cr)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("证书 PEM 解析失败: {e}"))?;
        let mut kr = std::io::BufReader::new(
            std::fs::File::open(&cfg.tls_key).map_err(|e| format!("读私钥失败: {e}"))?,
        );
        let key = rustls_pemfile::private_key(&mut kr)
            .map_err(|e| format!("私钥 PEM 解析失败: {e}"))?
            .ok_or("私钥文件里没有可用私钥")?;
        return Ok((certs, key));
    }
    let names = vec![
        "sodama-panel".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let ck =
        rcgen::generate_simple_self_signed(names).map_err(|e| format!("生成自签证书失败: {e}"))?;
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();
    if let Some(dir) = cfg.tls_cert.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&cfg.tls_cert, &cert_pem).map_err(|e| format!("写证书失败: {e}"))?;
    std::fs::write(&cfg.tls_key, &key_pem).map_err(|e| format!("写私钥失败: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cfg.tls_key, std::fs::Permissions::from_mode(0o600));
    }
    println!(
        "[panel] 已生成自签证书：{} / {}",
        cfg.tls_cert.display(),
        cfg.tls_key.display()
    );
    let certs = vec![rustls::pki_types::CertificateDer::from(
        ck.cert.der().to_vec(),
    )];
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::io::Cursor::new(
        key_pem.as_bytes(),
    )))
    .map_err(|e| format!("私钥解析失败: {e}"))?
    .ok_or("私钥解析为空")?;
    Ok((certs, key))
}

// ---------------------------------------------------------------- 处理器

async fn api_health(State(ctx): State<Ctx>) -> impl IntoResponse {
    note_ui();
    Json(json!({"ok": true, "auth_required": ctx.cfg.token.is_some()}))
}

async fn api_login(State(ctx): State<Ctx>, Json(req): Json<LoginReq>) -> Response {
    let Some(want) = ctx.cfg.token.as_deref() else {
        return Json(LoginResp {
            ok: true,
            message: "未启用 token（LAN 免认证）".into(),
            session_ttl_secs: 0,
        })
        .into_response();
    };
    if req.token.trim() != want {
        return err_json(StatusCode::UNAUTHORIZED, "token 不正确");
    }
    let sid = new_session_id();
    let exp = now_secs() + ctx.cfg.session_ttl;
    ctx.sessions.lock().unwrap().insert(sid.clone(), exp);
    let cookie = format!(
        "panel_session={sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        ctx.cfg.session_ttl
    );
    (
        [(header::SET_COOKIE, cookie)],
        Json(LoginResp {
            ok: true,
            message: "登录成功".into(),
            session_ttl_secs: ctx.cfg.session_ttl,
        }),
    )
        .into_response()
}

async fn api_logout(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_value(&headers, "panel_session") {
        ctx.sessions.lock().unwrap().remove(&sid);
    }
    (
        [(
            header::SET_COOKIE,
            "panel_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        )],
        Json(json!({"ok": true})),
    )
        .into_response()
}

async fn api_status(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    match fetch_view(&ctx, &engine).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err_json(StatusCode::BAD_GATEWAY, e),
    }
}

async fn api_status_raw(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    match engine_query(&ctx, &engine, "status").await {
        Ok(out) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            out,
        )
            .into_response(),
        Err(e) => err_json(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct LogQuery {
    tail: Option<u32>,
}

async fn api_logs(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<LogQuery>,
) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let n = q.tail.unwrap_or(300).clamp(10, 3000);
    // 默认日志命令就是 `tail`：直接读文件尾（避免每 4s fork 一个进程）
    if let Some(log) = engine.log_file.clone() {
        let lines = tokio::task::spawn_blocking(move || tail_lines(&log, n))
            .await
            .unwrap_or_else(|_| Err(std::io::Error::other("tail 任务失败")));
        return match lines {
            Ok(lines) => Json(shared::LogsView { lines }).into_response(),
            Err(e) => err_json(StatusCode::BAD_GATEWAY, format!("读日志失败: {e}")),
        };
    }
    let cmd = engine.logs_cmd.replace("{n}", &n.to_string());
    match run_cmd(&ctx.cfg, &cmd).await {
        Ok((0, out, _)) => {
            let lines: Vec<String> = out.lines().map(str::to_string).collect();
            Json(shared::LogsView { lines }).into_response()
        }
        Ok((code, _o, err)) => err_json(
            StatusCode::BAD_GATEWAY,
            format!("日志命令退出码 {code}: {}", err.trim()),
        ),
        Err(e) => err_json(StatusCode::BAD_GATEWAY, e),
    }
}

async fn api_metrics(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    match engine_query(&ctx, &engine, "metrics").await {
        Ok(out) => Json(json!({"text": out})).into_response(),
        Err(e) => err_json(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct SeriesQuery {
    points: Option<u32>,
}

async fn api_series(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<SeriesQuery>,
) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let n = q.points.unwrap_or(360).clamp(10, 5000) as usize;
    Json(SeriesView {
        step_secs: ctx.cfg.sample_secs,
        points: engine.series.tail(n),
    })
    .into_response()
}

/// CSV 导出：**按需生成，不落盘**（浏览器直接下载）。
async fn api_series_csv(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<SeriesQuery>,
) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let n = q
        .points
        .unwrap_or(ctx.cfg.series_cap as u32)
        .clamp(10, 20000) as usize;
    let points = engine.series.tail(n);
    let mut csv = String::from(
        "t,time_utc,conns_active,up_bps,down_bps,up_kBps,down_kBps,alive,members,ema_min_ms,ema_avg_ms,dns_qps,sniff_pct,fds_used,rss_kb,rss_mb,threads,cpu_pct\n",
    );
    for p in &points {
        csv.push_str(&format!(
            "{},{},{},{},{},{:.1},{:.1},{},{},{:.1},{:.1},{:.2},{:.1},{},{},{:.1},{},{:.1}\n",
            p.t,
            iso_utc(p.t),
            p.conns_active,
            p.up_bps,
            p.down_bps,
            p.up_bps as f64 / 1024.0,
            p.down_bps as f64 / 1024.0,
            p.alive,
            p.members,
            p.ema_min,
            p.ema_avg,
            p.dns_qps,
            p.sniff_pct,
            p.fds_used,
            p.rss_kb,
            p.rss_kb as f64 / 1024.0,
            p.threads,
            p.cpu_pct
        ));
    }
    let fname = format!(
        "sodama-series-{}.csv",
        iso_utc(now_secs()).replace([':', ' '], "-")
    );
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{fname}\""),
            ),
        ],
        csv,
    )
        .into_response()
}

async fn api_node(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<NodeQuery>,
) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let key = format!("{}|{}", q.tag, q.name);
    let cached = { engine.latest.lock().unwrap().clone() };
    let view = match cached {
        Some(v) => Some(v),
        None => fetch_view(&ctx, &engine).await.ok(),
    };
    let cur = view.as_ref().and_then(|v| {
        v.nodes
            .iter()
            .find(|n| n.tag == q.tag && n.name == q.name)
            .cloned()
    });
    Json(NodeDetail {
        tag: q.tag.clone(),
        name: q.name.clone(),
        alive: cur.as_ref().map(|n| n.alive).unwrap_or(false),
        ema_ms: cur.as_ref().map(|n| n.ema_ms).unwrap_or(0.0),
        last_ms: cur.as_ref().map(|n| n.last_ms).unwrap_or(0),
        samples: engine.nodes.get(&key),
        protocol: cur.as_ref().map(|n| n.protocol.clone()).unwrap_or_default(),
        transport: cur
            .as_ref()
            .map(|n| n.transport.clone())
            .unwrap_or_default(),
        security: cur.as_ref().map(|n| n.security.clone()).unwrap_or_default(),
        udp: cur.as_ref().map(|n| n.udp).unwrap_or(false),
        addr: cur.as_ref().map(|n| n.addr.clone()).unwrap_or_default(),
    })
    .into_response()
}

#[derive(Deserialize)]
struct NodeQuery {
    tag: String,
    name: String,
}

async fn api_sources(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = std::fs::read_to_string(&engine.engine_config).unwrap_or_default();
    let entries = parse_subscription(&text);
    let cached = { engine.latest.lock().unwrap().clone() };
    let view = match cached {
        Some(v) => Some(v),
        None => fetch_view(&ctx, &engine).await.ok(),
    };
    let (active_tag, nodes) = match &view {
        Some(v) => (v.group.active_tag.clone(), v.nodes.clone()),
        None => (String::new(), Vec::new()),
    };
    let sources = entries
        .iter()
        .enumerate()
        .map(|(i, (tag, url))| {
            let ns: Vec<&NodeView> = nodes.iter().filter(|n| &n.tag == tag).collect();
            SourceInfo {
                tag: tag.clone(),
                url: redact(url),
                order: i as u64,
                nodes: ns.len() as u64,
                alive: ns.iter().filter(|n| n.alive).count() as u64,
                active: *tag == active_tag,
            }
        })
        .collect();
    Json(SourcesView {
        active_tag,
        sources,
    })
    .into_response()
}

#[derive(Deserialize)]
struct PromoteReq {
    tag: String,
}

async fn api_source_promote(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<PromoteReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let path = engine.engine_config.clone();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_GATEWAY, format!("读取配置失败: {e}")),
    };
    let new_text = match reorder_subscription(&text, &req.tag) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    if new_text == text {
        return Json(SaveResult {
            ok: true,
            message: format!("订阅源 {} 已在第一顺位，无需调整", req.tag),
            reload_ok: None,
        })
        .into_response();
    }
    let prev_at = current_reload_at(&ctx, &engine).await;
    if let Err(e) = write_preserving(&path, &new_text) {
        return err_json(StatusCode::BAD_GATEWAY, e);
    }
    let reload_ok = wait_reload(&ctx, &engine, prev_at, 15).await;
    Json(SaveResult {
        ok: true,
        message: format!("已把订阅源 {} 设为第一顺位", req.tag),
        reload_ok,
    })
    .into_response()
}

#[derive(Deserialize)]
struct RawQuery {
    raw: Option<u8>,
}

async fn api_config_get(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<RawQuery>,
) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let path = engine.engine_config.clone();
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let raw = q.raw.unwrap_or(0) == 1;
            Json(json!({
                "name": path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
                "path": path.display().to_string(),
                "redacted": !raw,
                "text": if raw { text } else { redact(&text) },
            }))
            .into_response()
        }
        Err(e) => err_json(StatusCode::BAD_GATEWAY, format!("读取配置失败: {e}")),
    }
}

#[derive(Deserialize)]
struct SaveTextReq {
    name: String,
    text: String,
}

/// 引擎 validate 护栏：临时 `.dae`（0600）→ 「退出码 0 且 deferred == 0」才算通过。
/// 引擎对不可编译规则退出码仍为 0，只在 `routing: N 条可编译, M 条 deferred` 列出 M。
pub(crate) async fn validate_dae(ctx: &Ctx, engine: &Engine, text: &str) -> Result<(), String> {
    let path = &engine.engine_config;
    let tmp = path.with_file_name(format!(
        ".{}.panel-new.dae",
        path.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".into())
    ));
    if let Err(e) = std::fs::write(&tmp, text) {
        return Err(format!("写临时文件失败: {e}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    let cmd = format!("{} validate '{}'", engine.sodama, tmp.display());
    let res = run_cmd(&ctx.cfg, &cmd).await;
    let _ = std::fs::remove_file(&tmp);
    match res {
        Err(e) => Err(e),
        Ok((code, out, err)) => {
            if code != 0 || deferred_count(&out) > 0 {
                Err(format!(
                    "配置未通过校验（未落盘）：\n{}{}",
                    out.trim(),
                    if err.trim().is_empty() {
                        String::new()
                    } else {
                        format!("\n{}", err.trim())
                    }
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// 配置类改动的统一入口：validate → 落盘 → 等 inotify 热重载回执。
pub(crate) async fn apply_config_text(
    ctx: &Ctx,
    engine: &Arc<Engine>,
    text: &str,
    ok_msg: String,
) -> Response {
    if let Err(e) = validate_dae(ctx, engine, text).await {
        return Json(SaveResult {
            ok: false,
            message: e,
            reload_ok: None,
        })
        .into_response();
    }
    let prev_at = current_reload_at(ctx, engine).await;
    if let Err(e) = write_preserving(&engine.engine_config, text) {
        return err_json(StatusCode::BAD_GATEWAY, e);
    }
    let reload_ok = wait_reload(ctx, engine, prev_at, 20).await;
    Json(SaveResult {
        ok: true,
        message: ok_msg,
        reload_ok,
    })
    .into_response()
}

async fn api_file_save(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<SaveTextReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let Some(path) = resolve_editable(&engine, &req.name) else {
        return err_json(StatusCode::BAD_REQUEST, "不允许编辑该文件");
    };
    if path == engine.engine_config {
        return apply_config_text(
            &ctx,
            &engine,
            &req.text,
            format!("已保存 {}（引擎热重载）", req.name),
        )
        .await;
    }
    let prev_at = current_reload_at(&ctx, &engine).await;
    if let Err(e) = write_preserving(&path, &req.text) {
        return err_json(StatusCode::BAD_GATEWAY, e);
    }
    let reload_ok = wait_reload(&ctx, &engine, prev_at, 15).await;
    Json(SaveResult {
        ok: true,
        message: format!("已保存 {}（引擎热重载）", req.name),
        reload_ok,
    })
    .into_response()
}

async fn api_files(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    Json(json!({"files": editable_files(&engine)})).into_response()
}

#[derive(Deserialize)]
struct NameQuery {
    name: String,
}

async fn api_file_get(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<NameQuery>,
) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let Some(path) = resolve_editable(&engine, &q.name) else {
        return err_json(StatusCode::BAD_REQUEST, "不允许访问该文件");
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => Json(FileContent { name: q.name, text }).into_response(),
        Err(e) => err_json(StatusCode::BAD_GATEWAY, format!("读取失败: {e}")),
    }
}

async fn action(ctx: &Ctx, headers: &HeaderMap, uri: &Uri, cmd: &str) -> Response {
    if let Err(r) = require_actions(ctx, headers, uri) {
        return r;
    }
    match run_cmd(&ctx.cfg, cmd).await {
        Ok((code, out, err)) => Json(shared::ActionResult {
            ok: code == 0,
            code,
            stdout: out,
            stderr: err,
        })
        .into_response(),
        Err(e) => err_json(StatusCode::BAD_GATEWAY, e),
    }
}

async fn api_reload(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let prev_at = current_reload_at(&ctx, &engine).await;
    let cmd = engine.reload_cmd.clone();
    let (code, out, err) = match run_cmd(&ctx.cfg, &cmd).await {
        Ok(v) => v,
        Err(e) => return err_json(StatusCode::BAD_GATEWAY, e),
    };
    let reload_ok = wait_reload(&ctx, &engine, prev_at, 20).await;
    let ok = reload_ok.unwrap_or(code == 0);
    Json(shared::ActionResult {
        ok,
        code,
        stdout: out,
        stderr: err,
    })
    .into_response()
}

async fn api_suspend(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    let engine = ctx.engine.clone();
    let cmd = engine.suspend_cmd.clone();
    action(&ctx, &headers, &uri, &cmd).await
}

async fn api_resume(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    let engine = ctx.engine.clone();
    let cmd = engine.resume_cmd.clone();
    action(&ctx, &headers, &uri, &cmd).await
}

fn mime_of(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

async fn serve_static(cfg: &GlobalCfg, path: &str) -> Option<Response> {
    let rel = if path == "/" {
        "index.html".to_string()
    } else {
        path.trim_start_matches('/').to_string()
    };
    if rel.contains("..") {
        return None;
    }
    let full = cfg.static_dir.join(&rel);
    match tokio::fs::read(&full).await {
        Ok(bytes) => Some(([(header::CONTENT_TYPE, mime_of(&rel))], bytes).into_response()),
        Err(_) => None,
    }
}

async fn static_or_spa(State(ctx): State<Ctx>, uri: Uri) -> Response {
    let path = uri.path().to_string();
    if path.starts_with("/api/") {
        return err_json(StatusCode::NOT_FOUND, "未知 API");
    }
    if let Some(r) = serve_static(&ctx.cfg, &path).await {
        return r;
    }
    match serve_static(&ctx.cfg, "/").await {
        Some(r) => r,
        None => err_json(
            StatusCode::NOT_FOUND,
            format!("静态目录为空：{}", ctx.cfg.static_dir.display()),
        ),
    }
}

// ---------------------------------------------------------------- main

#[tokio::main]
async fn main() {
    let (g, engine) = parse_cfg();
    println!(
        "[panel] 启动：bind={} static={} actions={} token={} 采样={}s/{}点",
        g.bind,
        g.static_dir.display(),
        g.actions_enabled,
        if g.token.is_some() {
            "已设置（会话 Cookie）"
        } else {
            "无（LAN 免认证）"
        },
        g.sample_secs,
        g.series_cap,
    );
    println!("[panel] 内核命令：{}", engine.status_cmd);
    let bind = g.bind.clone();
    let gcfg = Arc::new(g);
    let ctx = Ctx {
        cfg: gcfg.clone(),
        engine: engine.clone(),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    tokio::spawn(sampler(ctx.clone(), engine.clone()));

    let app = Router::new()
        .route("/api/v1/health", get(api_health))
        .merge(configapi::routes())
        .route("/api/v1/login", post(api_login))
        .route("/api/v1/logout", post(api_logout))
        .route("/api/v1/status", get(api_status))
        .route("/api/v1/status/raw", get(api_status_raw))
        .route("/api/v1/logs", get(api_logs))
        .route("/api/v1/metrics", get(api_metrics))
        .route("/api/v1/series", get(api_series))
        .route("/api/v1/series.csv", get(api_series_csv))
        .route("/api/v1/node", get(api_node))
        .route("/api/v1/sources", get(api_sources))
        .route("/api/v1/sources/promote", post(api_source_promote))
        .route("/api/v1/config", get(api_config_get))
        .route("/api/v1/files", get(api_files))
        .route(
            "/api/v1/files/content",
            get(api_file_get).post(api_file_save),
        )
        .route("/api/v1/actions/reload", post(api_reload))
        .route("/api/v1/actions/suspend", post(api_suspend))
        .route("/api/v1/actions/resume", post(api_resume))
        .fallback(static_or_spa)
        .with_state(ctx);

    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[panel] 监听 {bind} 失败: {e}");
            std::process::exit(1);
        }
    };

    // 可选：HTTPS 与 HTTP 并存（tls = 1）
    if gcfg.tls {
        match load_or_gen_tls(&gcfg) {
            Ok((certs, key)) => {
                let _ = rustls::crypto::ring::default_provider().install_default();
                match rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                {
                    Ok(tls_cfg) => {
                        let tls_bind = gcfg.tls_bind.clone();
                        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
                        let tls_app = app.clone();
                        tokio::spawn(async move {
                            let l = match tokio::net::TcpListener::bind(&tls_bind).await {
                                Ok(l) => l,
                                Err(e) => {
                                    eprintln!("[panel] HTTPS 监听 {tls_bind} 失败: {e}");
                                    return;
                                }
                            };
                            println!("[panel] 监听 https://{tls_bind}/（自签证书，浏览器会提示不受信任）");
                            loop {
                                let (stream, _) = match l.accept().await {
                                    Ok(v) => v,
                                    Err(e) => {
                                        eprintln!("[panel] HTTPS accept 失败: {e}");
                                        continue;
                                    }
                                };
                                let acceptor = acceptor.clone();
                                let app = tls_app.clone();
                                tokio::spawn(async move {
                                    match acceptor.accept(stream).await {
                                        Ok(tls) => {
                                            let io = hyper_util::rt::TokioIo::new(tls);
                                            let svc =
                                                hyper_util::service::TowerToHyperService::new(app);
                                            let _ = hyper_util::server::conn::auto::Builder::new(
                                                hyper_util::rt::TokioExecutor::new(),
                                            )
                                            .serve_connection(io, svc)
                                            .await;
                                        }
                                        Err(e) => eprintln!("[panel] TLS 握手失败: {e}"),
                                    }
                                });
                            }
                        });
                    }
                    Err(e) => eprintln!("[panel] TLS 配置失败（继续 HTTP）：{e}"),
                }
            }
            Err(e) => eprintln!("[panel] TLS 初始化失败（继续 HTTP）：{e}"),
        }
    }

    println!("[panel] 监听 http://{bind}/");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("[panel] 服务退出: {e}");
    }
}

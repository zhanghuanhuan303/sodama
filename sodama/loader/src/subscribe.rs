//! P15：订阅拉取（HTTP/HTTPS/file）与节点链接解析。
//!
//! 对照 dae `control/subscription`：拉取订阅 URL → base64（或明文）→ 逐行链接。
//! 边界（如实）：不支持 gzip/br 压缩体（报错提示）；只跟随绝对/同站绝对路径重定向
//! （最多 3 跳）；TLS 用 webpki 根（订阅站证书需公开可信）。

use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::time::Duration;

use base64::Engine as _;

use crate::outbound;

/// 一条订阅/内联节点解析结果。
#[derive(Clone)]
pub struct ParsedNode {
    pub name: String,
    pub tag: String,
    /// P34：来源顺序（0 = 最高优先；`subscription_failover` 按此分层回退）。
    pub rank: u32,
    pub outbound: outbound::Outbound,
}

const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;

/// 能力缺口 #2：dae 的 `http-file://` / `https-file://` scheme（`dae/common/subscription/
/// subscription.go:171-179`）——去掉 `-file` 后按普通 http(s) 拉取。持久化/回退语义在
/// sodama 里对所有 http(s) 源统一生效（成功落盘 `sub-cache/<tag>.bin`、失败回退，
/// 见 `fetch_one_sub`），是 dae `-file` 语义的超集；但**不识别该 scheme 时**旧版会把
/// `https-file://…` 当本地文件路径去读（ENOENT），dae 风格配置直接失效。
pub fn normalize_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https-file://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("http-file://") {
        format!("http://{rest}")
    } else {
        url.to_string()
    }
}

/// P34：订阅 URL 文件——文件内容只有一行 http(s)（含 `-file://` 变体）URL 时，按该
/// URL 抓取（一层间接）。空文件/多行/非 http(s) 一律当作普通订阅正文（节点列表）。
fn url_file_target(body: &[u8]) -> Option<String> {
    if body.is_empty() || body.len() > 4096 {
        return None;
    }
    let t = std::str::from_utf8(body).ok()?.trim();
    if t.is_empty() || t.contains('\n') || t.contains('\r') {
        return None;
    }
    let t = normalize_url(t);
    if t.starts_with("http://") || t.starts_with("https://") {
        Some(t)
    } else {
        None
    }
}

/// 拉取订阅正文：支持 `file://`、裸路径、`http://`、`https://`（含 dae 风格的
/// `http-file://`/`https-file://`，见 `normalize_url`）。
pub fn fetch(url: &str, timeout: Duration) -> io::Result<Vec<u8>> {
    let url = normalize_url(url);
    let mut cur = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        match fetch_once(&cur, timeout, false)? {
            Fetch::Body(b) => return Ok(b),
            Fetch::Redirect(loc) => cur = resolve_location(&cur, &loc)?,
        }
    }
    Err(io::Error::other(format!("订阅重定向过多: {url}")))
}

/// P0（2026-10-11）：**截断宽容模式**（最后手段）。
///
/// 严格模式（`fetch`）对正文完整性把关（CL/超时/换行），但首次部署且无磁盘缓存时，
/// 持续截断的链路会让引擎“零节点启动”（生产实测：15:35 双源截断 → dialer=none）。
/// 本函数仅在上游全部失败且无缓存可用时作为最后手段，接受不完整正文——
/// 解出的部分节点仍会经健康探测自我验证。调用方必须记警告日志。
pub fn fetch_lenient(url: &str, timeout: Duration) -> io::Result<Vec<u8>> {
    let url = normalize_url(url);
    let mut cur = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        match fetch_once(&cur, timeout, true)? {
            Fetch::Body(b) => return Ok(b),
            Fetch::Redirect(loc) => cur = resolve_location(&cur, &loc)?,
        }
    }
    Err(io::Error::other(format!("订阅重定向过多: {url}")))
}

#[derive(Debug)]
enum Fetch {
    Body(Vec<u8>),
    Redirect(String),
}

fn fetch_once(url: &str, timeout: Duration, lenient: bool) -> io::Result<Fetch> {
    if let Some(path) = url.strip_prefix("file://") {
        let body = std::fs::read(path)?;
        if let Some(target) = url_file_target(&body) {
            return fetch(&target, timeout).map(Fetch::Body);
        }
        return Ok(Fetch::Body(body));
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        // 裸路径也当文件（lab 测试方便）；P34：内容为单行 http(s) URL 时按「订阅 URL 文件」处理
        // （便于把 token 单独放 ~/.config/sodama/subN.url，config 只写文件名）。
        let body = std::fs::read(url)?;
        if let Some(target) = url_file_target(&body) {
            return fetch(&target, timeout).map(Fetch::Body);
        }
        return Ok(Fetch::Body(body));
    }
    let (use_tls, host, port, path) = parse_http_url(url)?;
    // P23：配置了 bootstrap resolver 时，订阅主机名也直连解析（对照 dae：
    // 订阅/节点服务器主机名在内部 DNS 路由下走 bootstrap）。
    let addrs: Vec<std::net::SocketAddr> =
        if crate::bootstrap::enabled() && host.parse::<std::net::IpAddr>().is_err() {
            crate::bootstrap::resolve_host(&host)
                .map_err(|e| io::Error::other(format!("bootstrap 解析 {host} 失败: {e}")))?
                .into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, port))
                .collect()
        } else {
            (host.as_str(), port).to_socket_addrs()?.collect()
        };
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("解析 {host} 失败")))?;
    let sock = crate::outbound::marked_tcp_connect(addr, timeout)?;
    // H2 修复：拉取结束时解除拨号看门狗（避免拉取完成后到点误 shutdown）。
    let _wg = crate::outbound::DialWatchdogGuard::new();
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let host_header = if port == 80 || port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: sodama/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    let mut buf_reader: Box<dyn Read>;
    let mut writer: Box<dyn Write>;
    if use_tls {
        let (tr, tw) = crate::tls::connect(sock, &host, false, &[], timeout)?;
        tr.set_read_timeout(Some(timeout))?;
        buf_reader = Box::new(tr);
        writer = Box::new(tw);
    } else {
        buf_reader = Box::new(sock.try_clone()?);
        writer = Box::new(sock);
    }
    writer.write_all(req.as_bytes())?;
    writer.flush()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    let mut timed_out = false;
    loop {
        match buf_reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BODY {
                    return Err(io::Error::other("订阅正文超过 8MB 上限"));
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // 读超时不再当作「正文正常结束」——交给 parse_http_response 结合
                // Content-Length/换行收尾判定是否截断（P0，2026-10-11：截断曾静默通过）。
                timed_out = true;
                break;
            }
            Err(e) => return Err(e),
        }
    }
    parse_http_response(&raw, timed_out, lenient)
}

fn parse_http_url(url: &str) -> io::Result<(bool, String, u16, String)> {
    let (use_tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("不支持的订阅 URL: {url}"),
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("订阅 URL 非法: {url}"),
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("端口非法: {e}"))
            })?,
        ),
        None => (authority.to_string(), if use_tls { 443 } else { 80 }),
    };
    if host.is_empty() || host.starts_with('[') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("订阅主机非法（IPv6 字面量不支持）: {url}"),
        ));
    }
    Ok((use_tls, host, port, path.to_string()))
}

fn resolve_location(base: &str, loc: &str) -> io::Result<String> {
    if loc.starts_with("http://") || loc.starts_with("https://") || loc.starts_with("file://") {
        return Ok(loc.to_string());
    }
    if let Some(path) = loc.strip_prefix('/') {
        let (use_tls, host, port, _) = parse_http_url(base)?;
        let scheme = if use_tls { "https" } else { "http" };
        let authority = if port == 80 || port == 443 {
            host
        } else {
            format!("{host}:{port}")
        };
        return Ok(format!("{scheme}://{authority}/{path}"));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("相对重定向不支持: {loc}"),
    ))
}

fn parse_http_response(raw: &[u8], timed_out: bool, lenient: bool) -> io::Result<Fetch> {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP 响应头不完整"))?;
    let head = String::from_utf8_lossy(&raw[..pos]);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("状态行非法: {status}"))
        })?;
    let mut location = None;
    let mut chunked = false;
    let mut gzip = false;
    let mut content_length: Option<usize> = None;
    let mut retry_after: Option<String> = None;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "location" => location = Some(v.to_string()),
            "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => chunked = true,
            "content-encoding" if v.to_ascii_lowercase().contains("gzip") => gzip = true,
            "content-length" => content_length = v.parse().ok(),
            "retry-after" => retry_after = Some(v.to_string()),
            _ => {}
        }
    }
    if (300..400).contains(&code) {
        let loc = location.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("重定向 {code} 但缺少 Location"),
            )
        })?;
        return Ok(Fetch::Redirect(loc));
    }
    if !(200..300).contains(&code) {
        // 429（限流）带 Retry-After 原样透传，供上层做冷却与诊断（P1，2026-10-11）。
        let extra = retry_after
            .map(|r| format!("；Retry-After: {r}"))
            .unwrap_or_default();
        return Err(io::Error::other(format!("订阅 HTTP 状态 {code}{extra}")));
    }
    if gzip {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "订阅正文为 gzip（暂不支持压缩体；可让服务端返回 plain/base64）",
        ));
    }
    let body = &raw[pos + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        // P0（2026-10-11）：截断完整性——旧实现把 EOF/读超时都当正文正常结束，
        // 半截订阅会被静默当成功（生产实测 50 节点被截成 22）。
        // ① 有 Content-Length：必须精确匹配；
        // ② 无 CL 且因读超时结束、且正文无换行收尾 —— 高度可疑的截断。
        // `lenient`（最后手段）时不做①②，正文原样返回（调用方记警告）。
        if !lenient {
            if let Some(cl) = content_length {
                if body.len() != cl {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("HTTP 正文不完整（{}/{} 字节，疑似截断）", body.len(), cl),
                    ));
                }
            } else if timed_out && !body.is_empty() && !body.ends_with(b"\n") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "HTTP 正文读取超时且无换行收尾（{} 字节，疑似截断）",
                        body.len()
                    ),
                ));
            }
        }
        body.to_vec()
    };
    Ok(Fetch::Body(body))
}

fn decode_chunked(mut body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find_crlf(body)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunked: 缺长度行"))?;
        let size_str = String::from_utf8_lossy(&body[..line_end]);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("chunked 长度: {e}"))
        })?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked: 正文截断",
            ));
        }
        out.extend_from_slice(&body[..size]);
        if &body[size..size + 2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked: 缺 CRLF",
            ));
        }
        body = &body[size + 2..];
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// 正文解码：优先 base64（标准 / URL-safe / 无 padding），失败时按明文。
pub fn decode_body(body: &[u8]) -> io::Result<String> {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    for eng in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(dec) = eng.decode(&compact) {
            if let Ok(s) = String::from_utf8(dec) {
                if s.contains("://") {
                    return Ok(s);
                }
            }
        }
    }
    // 全是 base64 字母表但解不出来 → 多半是**截断/损坏**的正文（慢链路/半截响应实测遇到）。
    // 此时绝不能按明文处理：整段会被当成「一行不支持」而静默得到 0 个节点，
    // 用户看到的现象是「订阅可用但没节点」。直接报错，让上层按失败处理。
    let looks_b64 = !compact.is_empty()
        && compact
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    if looks_b64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "订阅正文疑似 base64 但解码失败（{} 字节，可能是截断/损坏）",
                body.len()
            ),
        ));
    }
    String::from_utf8(body.to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("订阅正文非 UTF-8: {e}")))
}

// ---------------------------------------------------------------- P0（2026-10-11）
// 订阅源状态 / 磁盘缓存 / 限流冷却——均**不含 URL/token**，供状态面与面板展示。

/// 单个订阅源最近一次拉取的状态。
#[derive(Clone)]
pub struct SourceStatus {
    pub tag: String,
    pub rank: u32,
    pub at_sec: u64,
    pub ok: bool,
    pub error: Option<String>,
    pub nodes: usize,
    /// 连续失败次数（成功清零；自愈重试的退避依据）。
    pub fails: u32,
    /// net（网络）/ disk（磁盘缓存回退）/ memory（内存缓存）/ cooldown（限流冷却）
    pub source: &'static str,
    // ---- P37（2026-10-13）C1：订阅请求计数（额度自证）----
    /// 累计实际打网次数（含成功与失败；memory/disk 命中不计）。
    pub fetches_total: u64,
    /// 累计打网失败次数。
    pub fetch_fail_total: u64,
    /// 最近一次打网时刻（unix 秒；0 = 从未打网）。
    pub last_fetch_at: u64,
}

fn source_status_map() -> &'static std::sync::Mutex<Vec<SourceStatus>> {
    static S: std::sync::OnceLock<std::sync::Mutex<Vec<SourceStatus>>> = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

pub fn record_source_status(mut st: SourceStatus) {
    let mut m = match source_status_map().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    // C1：打网计数只由 net 来源推进；memory/disk 命中沿用前值（保留“服务器真被请求几次”语义）。
    let is_net = st.source == "net";
    if let Some(prev) = m.iter().find(|x| x.tag == st.tag).cloned() {
        // 连续失败计数：失败叠加（success/disk 回退均视为“拿到数据”，归零）。
        st.fails = if st.ok {
            0
        } else {
            prev.fails.saturating_add(1)
        };
        if is_net {
            st.fetches_total = prev.fetches_total.saturating_add(1);
            st.fetch_fail_total = prev.fetch_fail_total + u64::from(!st.ok);
            st.last_fetch_at = st.at_sec;
        } else {
            st.fetches_total = prev.fetches_total;
            st.fetch_fail_total = prev.fetch_fail_total;
            st.last_fetch_at = prev.last_fetch_at;
        }
        if let Some(slot) = m.iter_mut().find(|x| x.tag == st.tag) {
            *slot = st;
        }
    } else {
        st.fails = if st.ok { 0 } else { 1 };
        st.fetches_total = u64::from(is_net);
        st.fetch_fail_total = u64::from(is_net && !st.ok);
        st.last_fetch_at = if is_net { st.at_sec } else { 0 };
        m.push(st);
    }
}

/// P1（2026-10-11）：自愈重试判据——返回**按退避到期**的失败源 tag 列表。
/// 退避：300s · 2^(fails-1)，封顶 3600s（首次失败 5 分钟后重试）。
/// P37（2026-10-13 / B3）：从 bool 改为列表——调用方只对这些源定向重拉，
/// 不再连带健康源（旧行为：任一失败源到期 → 全部源重打）。
pub fn sources_due_for_retry(now_sec: u64) -> Vec<String> {
    let m = match source_status_map().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    m.iter()
        .filter(|s| {
            if s.ok {
                return false;
            }
            let shift = s.fails.saturating_sub(1).min(4);
            let backoff = (300u64 << shift).min(3600);
            now_sec >= s.at_sec.saturating_add(backoff)
        })
        .map(|s| s.tag.clone())
        .collect()
}

/// 配置里已不存在的来源从状态表移除（删源后不留幽灵条目）。
pub fn prune_source_status(keep: &[String]) {
    let mut m = match source_status_map().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    m.retain(|s| keep.iter().any(|k| k == &s.tag));
}

pub fn source_status_json() -> serde_json::Value {
    let m = match source_status_map().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    serde_json::Value::Array(
        m.iter()
            .map(|s| {
                serde_json::json!({
                    "tag": s.tag,
                    "rank": s.rank,
                    "at_sec": s.at_sec,
                    "ok": s.ok,
                    "error": s.error,
                    "nodes": s.nodes,
                    "fails": s.fails,
                    "source": s.source,
                    // C1：订阅服务器请求计数（额度自证）
                    "fetches_total": s.fetches_total,
                    "fetch_fail_total": s.fetch_fail_total,
                    "last_fetch_at": s.last_fetch_at,
                })
            })
            .collect(),
    )
}

/// 限流冷却：收到 429 后短期不再打网络（回退内存/磁盘缓存），避免火上浇油。
const COOLDOWN_429_SECS: u64 = 15 * 60;

fn cooldown_map() -> &'static std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>
{
    static C: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 记录一次拉取错误；429（含 Retry-After 文本）触发本 URL 的冷却。
/// P37（B2）：同时登记「最近失败时刻」——配置热重载（Fast）对负缓存窗口内的源不打网。
pub fn note_fetch_error(url: &str, err: &str) {
    {
        let mut m = match fetch_fail_map().lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        m.insert(url.to_string(), std::time::Instant::now());
    }
    if err.contains("429") {
        let mut m = match cooldown_map().lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        m.insert(url.to_string(), std::time::Instant::now());
    }
}

/// 冷却剩余秒数（None = 未冷却）。
pub fn cooldown_remaining(url: &str) -> Option<u64> {
    let m = match cooldown_map().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    let at = m.get(url)?;
    let elapsed = at.elapsed().as_secs();
    if elapsed >= COOLDOWN_429_SECS {
        return None;
    }
    Some(COOLDOWN_429_SECS - elapsed)
}

// ---------------------------------------------------------------- P37（2026-10-13）
// 对照研究（devlog §13）：dae 的订阅只在启动/SIGHUP 拉取；mihomo 的 fetcher 以 hash 不变
// 跳过、失败走 backoff。同类均不会因「配置热重载」反复打订阅服务器——本区块补上两条记忆：
//   * `sub_seen`：曾成功拉取过该 URL → 配置热重载（Fast）不再打网（磁盘缓存兜底）；
//   * `fetch_fail`：最近一轮打网失败 → 负缓存窗口内不再打网（自愈/手动/周期仍然放行）。

/// 曾成功拉取过的 URL 集合（B1）——「URL 未变」的判定依据。
fn sub_seen_set() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

pub fn mark_sub_seen(url: &str) {
    let mut m = match sub_seen_set().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    // 上限保护（URL 集合规模 = 源数量级，32 足矣；超出淘汰最旧不可得，直接限容）。
    if m.len() >= 64 && !m.contains(url) {
        m.clear();
    }
    m.insert(url.to_string());
}

pub fn sub_seen(url: &str) -> bool {
    let m = match sub_seen_set().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    m.contains(url)
}

/// 最近一次打网失败时刻（B2 负缓存）。
fn fetch_fail_map(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>> {
    static F: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    F.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 负缓存剩余秒数（None = 不在负缓存窗口内或 ttl=0 关闭）。
pub fn fetch_fail_remaining(url: &str, ttl_secs: u64) -> Option<u64> {
    if ttl_secs == 0 {
        return None;
    }
    let m = match fetch_fail_map().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    let at = m.get(url)?;
    let elapsed = at.elapsed().as_secs();
    if elapsed >= ttl_secs {
        return None;
    }
    Some(ttl_secs - elapsed)
}

/// 打网成功后清除负缓存（下次失败重新计时）。
pub fn clear_fetch_fail(url: &str) {
    let mut m = match fetch_fail_map().lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    m.remove(url);
}

/// 磁盘缓存路径：`<配置目录>/sub-cache/<tag>.bin`。
pub fn disk_cache_path(cfg_dir: &std::path::Path, tag: &str) -> std::path::PathBuf {
    let safe: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    cfg_dir.join("sub-cache").join(format!("{safe}.bin"))
}

/// 落盘最近一次成功拉取的**原始正文**（含 base64；目录 0700、文件 0600——含凭据）。
pub fn disk_store(cfg_dir: &std::path::Path, tag: &str, body: &[u8]) -> io::Result<()> {
    let path = disk_cache_path(cfg_dir, tag);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    f.write_all(body)?;
    f.sync_all().ok();
    Ok(())
}

/// 读磁盘缓存；返回（原始正文, 距写入秒数）。
pub fn disk_load(cfg_dir: &std::path::Path, tag: &str) -> Option<(Vec<u8>, u64)> {
    let path = disk_cache_path(cfg_dir, tag);
    let body = std::fs::read(&path).ok()?;
    if body.is_empty() {
        return None;
    }
    let age = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| std::time::SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some((body, age))
}

/// P38：SIP008（shadowsocks 官方 JSON 订阅）解析——对照 dae `ResolveSubscriptionAsSIP008`。
/// 判定与原版一致：JSON 可解析且 `version == 1 && servers != null`；每台服务器映射为
/// `ss://` 链接后复用既有链接解析器（userinfo = base64url(method:password)，不做必填校验）。
/// 返回 `(remarks, link)`；remarks 可能为空（调用方用 tag-序号 兑底命名）。
pub fn parse_sip008(text: &str) -> Option<Vec<(String, String)>> {
    let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    if v.get("version").and_then(|x| x.as_i64()) != Some(1) {
        return None;
    }
    let servers = v.get("servers")?.as_array()?;
    let mut out = Vec::with_capacity(servers.len());
    for s in servers {
        let server = s.get("server").and_then(|x| x.as_str()).unwrap_or("");
        let port = s.get("server_port").and_then(|x| x.as_u64()).unwrap_or(0);
        let method = s.get("method").and_then(|x| x.as_str()).unwrap_or("");
        let password = s.get("password").and_then(|x| x.as_str()).unwrap_or("");
        let remarks = s
            .get("remarks")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let userinfo =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
        let mut link = format!("ss://{userinfo}@{server}:{port}");
        if let Some(plugin) = s
            .get("plugin")
            .and_then(|x| x.as_str())
            .filter(|p| !p.is_empty())
        {
            let opts = s.get("plugin_opts").and_then(|x| x.as_str()).unwrap_or("");
            let full = if opts.is_empty() {
                plugin.to_string()
            } else {
                format!("{plugin};{opts}")
            };
            link.push_str(&format!(
                "?plugin={}",
                percent_encoding::utf8_percent_encode(&full, percent_encoding::NON_ALPHANUMERIC)
            ));
        }
        if !remarks.is_empty() {
            link.push_str(&format!(
                "#{}",
                percent_encoding::utf8_percent_encode(&remarks, percent_encoding::NON_ALPHANUMERIC)
            ));
        }
        out.push((remarks, link));
    }
    Some(out)
}

/// P38：正文是否为 SIP008（供 `sub-parse` 的格式展示）。
pub fn is_sip008(text: &str) -> bool {
    parse_sip008(text).is_some()
}

/// 解析订阅正文为节点列表（`(nodes, errors)`；错误逐行报告，不中断）。
pub fn parse_subscription(text: &str, tag: &str) -> (Vec<ParsedNode>, Vec<String>) {
    // P38：SIP008（JSON）优先；不匹配再按 base64 行解析（对照 dae 的识别顺序）。
    if let Some(servers) = parse_sip008(text) {
        let mut nodes = Vec::new();
        let mut errors = Vec::new();
        for (i, (remarks, link)) in servers.into_iter().enumerate() {
            let name = if remarks.is_empty() {
                format!("{tag}-{}", i + 1)
            } else {
                remarks
            };
            match outbound::parse(&link) {
                Ok(o) => nodes.push(ParsedNode {
                    name,
                    tag: tag.to_string(),
                    rank: 0,
                    outbound: o,
                }),
                Err(e) => errors.push(format!("SIP008 第 {} 台服务器不支持: {e}", i + 1)),
            }
        }
        return (nodes, errors);
    }
    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let name = match line.split_once('#') {
            Some((_, frag)) if !frag.is_empty() => percent_encoding::percent_decode_str(frag)
                .decode_utf8_lossy()
                .to_string(),
            _ => format!("{tag}-{}", i + 1),
        };
        match outbound::parse(line) {
            Ok(o) => nodes.push(ParsedNode {
                name,
                tag: tag.to_string(),
                // P34：来源顺序由调用方（fetch_nodes）按订阅声明顺序覆写。
                rank: 0,
                outbound: o,
            }),
            Err(e) => errors.push(format!("第 {} 行不支持: {e}", i + 1)),
        }
    }
    (nodes, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- P37（2026-10-13 / B1・B2・B3・C1）----

    fn mk_status(tag: &str, ok: bool, source: &'static str, at: u64) -> SourceStatus {
        SourceStatus {
            tag: tag.into(),
            rank: 1,
            at_sec: at,
            ok,
            error: if ok { None } else { Some("x".into()) },
            nodes: 0,
            fails: 0,
            source,
            fetches_total: 0,
            fetch_fail_total: 0,
            last_fetch_at: 0,
        }
    }

    #[test]
    fn sip008_maps_to_ss_nodes() {
        let text = r#"{"version":1,"servers":[
          {"id":"a","remarks":"香港-01","server":"1.1.1.1","server_port":8388,"method":"chacha20-ietf-poly1305","password":"pw1"},
          {"server":"2.2.2.2","server_port":443,"method":"chacha20-ietf-poly1305","password":"pw2","plugin":"shadow-tls","plugin_opts":"host=bing.com;password=secret"}
        ],"bytes_used":1,"bytes_remaining":2}"#;
        let servers = parse_sip008(text).expect("SIP008 应识别");
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].0, "香港-01");
        assert!(servers[0].1.starts_with("ss://"));
        assert!(servers[1].1.contains("?plugin="), "{}", servers[1].1);
        let (nodes, errors) = parse_subscription(text, "sub");
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "香港-01");
        // 无 remarks → tag-序号 兑底
        assert_eq!(nodes[1].name, "sub-2");
        assert!(is_sip008(text));
        // 非 SIP008：version 不为 1 / servers 为 null / 非 JSON
        assert!(parse_sip008(r#"{"version":2,"servers":[]}"#).is_none());
        assert!(parse_sip008(r#"{"version":1,"servers":null}"#).is_none());
        assert!(parse_sip008("ss://a@1.1.1.1:1").is_none());
        // 行式订阅不被误判
        assert!(!is_sip008("ss://YWVzLTEyODpwdw==@1.1.1.1:1#n1"));
    }

    #[test]
    fn b2_fail_negative_cache_window() {
        let url = "https://t.example/b2-unique";
        assert!(fetch_fail_remaining(url, 600).is_none());
        note_fetch_error(url, "连接超时");
        let remain = fetch_fail_remaining(url, 600).expect("负缓存应命中");
        assert!(remain > 0 && remain <= 600);
        // ttl=0 = 关闭负缓存
        assert!(fetch_fail_remaining(url, 0).is_none());
        clear_fetch_fail(url);
        assert!(fetch_fail_remaining(url, 600).is_none());
    }

    #[test]
    fn b1_seen_set_roundtrip() {
        let url = "https://t.example/b1-unique";
        assert!(!sub_seen(url));
        mark_sub_seen(url);
        assert!(sub_seen(url));
    }

    #[test]
    fn b3_due_for_retry_only_failed_sources() {
        // 独特 tag，避免与并行测试的全局状态表互扰；只做包含断言。
        record_source_status(mk_status("t_b3_ok", true, "net", 100));
        record_source_status(mk_status("t_b3_fail", false, "net", 100));
        // 首次失败退避 300s：now=200 未到期，now=400 到期。
        let due_now = sources_due_for_retry(200);
        assert!(!due_now.iter().any(|t| t == "t_b3_fail"));
        let due_later = sources_due_for_retry(400);
        assert!(due_later.iter().any(|t| t == "t_b3_fail"));
        assert!(!due_later.iter().any(|t| t == "t_b3_ok"));
    }

    #[test]
    fn c1_fetch_counters_only_advance_on_net() {
        let tag = "t_c1_net";
        record_source_status(mk_status(tag, false, "net", 10)); // 打网失败 #1
        record_source_status(mk_status(tag, true, "disk", 11)); // 磁盘兜底：不计打网
        record_source_status(mk_status(tag, true, "net", 12)); // 打网成功 #2
        record_source_status(mk_status(tag, true, "memory", 13)); // 内存命中：不计
        let m = source_status_map()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let s = m.iter().find(|s| s.tag == tag).expect("状态应存在");
        assert_eq!(s.fetches_total, 2);
        assert_eq!(s.fetch_fail_total, 1);
        assert_eq!(s.last_fetch_at, 12);
    }

    #[test]
    fn decode_plain_and_base64() {
        let plain = b"ss://a@1.1.1.1:1#n1\nvless://b@2.2.2.2:2\n";
        assert!(decode_body(plain).unwrap().contains("ss://"));
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        let dec = decode_body(b64.as_bytes()).unwrap();
        assert!(dec.contains("vless://b@2.2.2.2:2"));
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plain);
        assert!(decode_body(b64u.as_bytes()).unwrap().contains("ss://"));
    }

    #[test]
    fn parse_links_names_and_errors() {
        let text = "# comment\n\nss://chacha20-ietf-poly1305:pass@1.1.1.1:8388#%E9%A6%99%E6%B8%AF-01\nbogus://x\n";
        let (nodes, errors) = parse_subscription(text, "sub");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "香港-01");
        assert_eq!(nodes[0].tag, "sub");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn url_file_target_detects_single_http_url() {
        // P34：subN.url 这类「URL 文件」——只有一行 http(s) URL 才当间接；其余当普通正文
        assert_eq!(
            url_file_target(b"https://example.com/sub?token=x\n"),
            Some("https://example.com/sub?token=x".to_string())
        );
        assert_eq!(
            url_file_target(b"http://1.2.3.4:8080/a"),
            Some("http://1.2.3.4:8080/a".to_string())
        );
        // 能力缺口 #2：dae 风格的 `-file://` 变体也当间接，并归一化为普通 http(s)
        assert_eq!(
            url_file_target(b"https-file://example.com/sub?token=x\n"),
            Some("https://example.com/sub?token=x".to_string())
        );
        assert_eq!(url_file_target(b"https://a\nhttps://b\n"), None);
        assert_eq!(url_file_target(b"ss://a@1.1.1.1:1#n"), None);
        assert_eq!(url_file_target(b""), None);
    }

    #[test]
    fn normalize_url_maps_dae_file_schemes() {
        // 能力缺口 #2：`http-file://`/`https-file://` ≡ 去掉 `-file`（dae patch 同义）
        assert_eq!(
            normalize_url("https-file://sub.example.com/x?token=t"),
            "https://sub.example.com/x?token=t"
        );
        assert_eq!(
            normalize_url("http-file://127.0.0.1:9/sub"),
            "http://127.0.0.1:9/sub"
        );
        // 其余形态原样（含 file://、裸路径、普通 http(s)）
        assert_eq!(normalize_url("file:///tmp/a"), "file:///tmp/a");
        assert_eq!(normalize_url("/tmp/a"), "/tmp/a");
        assert_eq!(normalize_url("https://a/b"), "https://a/b");
    }

    #[test]
    fn http_response_plain_and_chunked() {
        let resp = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        match parse_http_response(resp, false, false).unwrap() {
            Fetch::Body(b) => assert_eq!(b, b"abc"),
            _ => panic!("expect body"),
        }
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        match parse_http_response(resp, false, false).unwrap() {
            Fetch::Body(b) => assert_eq!(b, b"abc"),
            _ => panic!("expect body"),
        }
    }

    #[test]
    fn http_response_redirect_and_gzip() {
        let resp = b"HTTP/1.1 302 Found\r\nLocation: https://x.example/sub\r\n\r\n";
        match parse_http_response(resp, false, false).unwrap() {
            Fetch::Redirect(l) => assert_eq!(l, "https://x.example/sub"),
            _ => panic!("expect redirect"),
        }
        let resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8b";
        assert!(parse_http_response(resp, false, false).is_err());
    }

    #[test]
    fn http_response_truncation_rejected() {
        // P0（2026-10-11）：截断完整性——声明 10 字节只到 3，必须报错（
        // 旧实现会静默当 3 字节正文——生产实测 50 节点被截成 22）。
        let resp = b"HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        assert!(parse_http_response(resp, false, false).is_err());
        // 无 CL + 读超时结束 + 无换行收尾 —— 疑似截断，报错。
        let resp = b"HTTP/1.0 200 OK\r\n\r\nss://YWVzLTEyOA==";
        assert!(parse_http_response(resp, true, false).is_err());
        // 无 CL + EOF 结束 —— 无法判定，放行（上层有节点数骤降告警适配）。
        let resp = b"HTTP/1.0 200 OK\r\n\r\nss://YWVzLTEyOA==";
        assert!(parse_http_response(resp, false, false).is_ok());
        // lenient（最后手段）：同样输入放行，正文原样返回。
        let resp = b"HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        match parse_http_response(resp, false, true).unwrap() {
            Fetch::Body(b) => assert_eq!(b, b"abc"),
            _ => panic!("expect lenient body"),
        }
    }

    #[test]
    fn http_response_429_retry_after_passthrough() {
        // P1：429 限流带 Retry-After——错误信息透传，供冷却逻辑识别。
        let resp = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\n\r\n";
        let e = parse_http_response(resp, false, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("429") && e.contains("120"), "{e}");
    }

    #[test]
    fn fetch_over_http_local() {
        // 本地假服务器：固定响应
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            use std::io::Read as _;
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .unwrap();
        });
        let body = fetch(
            &format!("http://127.0.0.1:{port}/sub"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(body, b"hello");
        h.join().unwrap();
    }

    #[test]
    fn url_parse_cases() {
        let (tls, host, port, path) = parse_http_url("https://a.example:8443/x/y?z=1").unwrap();
        assert!(tls);
        assert_eq!(host, "a.example");
        assert_eq!(port, 8443);
        assert_eq!(path, "/x/y?z=1");
        let (tls, host, port, path) = parse_http_url("http://b.example").unwrap();
        assert!(!tls);
        assert_eq!((host.as_str(), port, path.as_str()), ("b.example", 80, "/"));
        assert!(parse_http_url("ftp://x").is_err());
    }
}

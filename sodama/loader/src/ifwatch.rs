// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! 能力缺口 #3：接口懒绑定/热插拔（对照 dae `component/interface_manager.go` +
//! `control/control_plane_core_bind.go:487+` 的 pattern 注册 + `cmd/run_config.go:144-157`
//! 的 `wan_interface: auto`）。
//!
//! dae 用 netlink `LinkSubscribeWithOptions`（RTM_NEWLINK/RTM_DELLINK）事件驱动；
//! sodama 用**周期扫描**（主循环 tick 读 `/sys/class/net` 目录名）：行为等价
//! （新出现的匹配接口即挂、消失即记账），代价是 ≤1 个扫描间隔的延迟，换来零依赖与
//! 零 netlink 消息解析。接口消失时内核随 netdev 注销回收 TCX 钩子（bpf_link 归内核管理），
//! 本模块只做记账与 `l3_ifindex_map` 清理（防 ifindex 复用被错认成 L3）。
//!
//! 语义对齐 dae：
//! - 模式用 glob（`path.Match` 同族：`*` / `?` / `[a-z]` / `[!a-z]`）；
//! - 一个接口可同时命中多个角色（lan 与 wan 模式都命中时两组钩子都挂，
//!   对照 `interface_manager.go:58-72` 的 `matchingCallbacksLocked` 注释）；
//! - 显式名字不存在不报错——「懒绑定」等它出现（dae `Register` 同语义）。

use std::collections::HashMap;

/// 接口角色（= CLI `--lan`/`--wan`/`--dual` 对应的挂载集合）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    Lan,
    Wan,
    Dual,
}

impl Role {
    pub fn tag(self) -> &'static str {
        match self {
            Role::Lan => "lan",
            Role::Wan => "wan",
            Role::Dual => "dual",
        }
    }
}

/// 一条注册（模式 + 角色）。
#[derive(Clone, Debug)]
pub struct Spec {
    pub role: Role,
    pub pattern: String,
}

/// path.Match 风格的 glob 匹配：`*` 任意串、`?` 单字符、`[a-z]`/`[!a-z]` 字符类。
/// 未闭合/非法的 `[...]` 按字面处理（dae 在注册期报错；这里宽松，不影响正常模式）。
pub fn pattern_matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    // 最近一次 `*` 的回撤点
    let mut star_p: Option<usize> = None;
    let mut star_n = 0usize;
    while ni < n.len() {
        let mut advanced = false;
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star_p = Some(pi);
                    star_n = ni;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    ni += 1;
                    continue;
                }
                '[' => {
                    if let Some((hit, next_pi)) = match_class(&p, pi, n[ni]) {
                        if hit {
                            pi = next_pi;
                            ni += 1;
                            advanced = true;
                        }
                    } else if n[ni] == '[' {
                        pi += 1;
                        ni += 1;
                        advanced = true;
                    }
                }
                c => {
                    if c == n[ni] {
                        pi += 1;
                        ni += 1;
                        advanced = true;
                    }
                }
            }
        }
        if advanced {
            continue;
        }
        match star_p {
            Some(sp) => {
                star_n += 1;
                pi = sp + 1;
                ni = star_n;
            }
            None => return false,
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 匹配字符类 `[...]`；返回（是否命中, `]` 之后的位置）。非法（未闭合）返回 None。
fn match_class(p: &[char], start: usize, c: char) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let negate = matches!(p.get(i), Some('!') | Some('^'));
    if negate {
        i += 1;
    }
    let mut hit = false;
    let mut first = true;
    while i < p.len() && (p[i] != ']' || first) {
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if p[i] <= c && c <= p[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if p[i] == c {
                hit = true;
            }
            i += 1;
        }
    }
    if i >= p.len() {
        return None;
    }
    Some((hit != negate, i + 1))
}

/// 扫描当前 netns 的接口名（读 `/sys/class/net`），排序保证稳定。
pub fn list_interfaces() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// `/proc/net/route`（v4）中默认路由（Destination/Mask 全 0）的接口名。
pub fn parse_default_v4(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000" && !f[0].is_empty() {
            out.push(f[0].to_string());
        }
    }
    out
}

/// `/proc/net/ipv6_route` 中默认路由（dest/plen 全 0）的接口名。
pub fn parse_default_v6(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // dest(32 hex) dest_plen src src_plen nh metric refcnt use flags ifname
        if f.len() >= 10 && f[0].len() == 32 && f[0].chars().all(|c| c == '0') && f[1] == "00" {
            out.push(f[9].to_string());
        }
    }
    out
}

/// `wan_interface: auto`：默认路由接口（v4+v6），去重保序。
/// 对照 dae `GetDefaultIfnames`（`common/utils.go:298`：带默认路由的 up 接口）。
pub fn default_route_ifaces() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
        for i in parse_default_v4(&t) {
            if !out.contains(&i) {
                out.push(i);
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for i in parse_default_v6(&t) {
            if !out.contains(&i) {
                out.push(i);
            }
        }
    }
    out
}

/// `auto` 展开（对照 dae `preprocessWanInterfaceAuto`）：把列表里的 `auto` 替换为
/// 启动时刻的默认路由接口名（也作为精确模式注册——懒绑定语义下接口后出现也命中）。
/// 返回（展开后列表, 说明行）。
pub fn expand_auto(patterns: &[String]) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let mut resolved: Option<Vec<String>> = None;
    for p in patterns {
        if p == "auto" {
            let ifs = resolved.get_or_insert_with(default_route_ifaces);
            if ifs.is_empty() {
                notes.push("auto：未找到默认路由接口（懒绑定：出现后自动挂载）".to_string());
            } else {
                notes.push(format!("auto → {}", ifs.join(", ")));
                for i in ifs {
                    if !out.contains(i) {
                        out.push(i.clone());
                    }
                }
            }
        } else if !out.contains(p) {
            out.push(p.clone());
        }
    }
    (out, notes)
}

/// 接口监听器：维护「模式 → 角色」注册与「已挂载接口」集合，供主循环周期驱动。
pub struct IfWatch {
    specs: Vec<Spec>,
    mounted: HashMap<String, Vec<Role>>,
}

impl IfWatch {
    pub fn new(specs: Vec<Spec>) -> Self {
        Self {
            specs,
            mounted: HashMap::new(),
        }
    }

    /// 命中某接口的全部角色（保序去重；同一接口可被 lan/wan/dual 同时命中）。
    pub fn roles_for(&self, name: &str) -> Vec<Role> {
        let mut roles = Vec::new();
        for s in &self.specs {
            if pattern_matches(&s.pattern, name) && !roles.contains(&s.role) {
                roles.push(s.role);
            }
        }
        roles
    }

    /// 启动/周期扫描：返回（新增挂载清单, 消失的接口名）。
    pub fn poll(&mut self) -> (Vec<(String, Vec<Role>)>, Vec<String>) {
        let cur = list_interfaces();
        let mut added = Vec::new();
        for name in &cur {
            if self.mounted.contains_key(name) {
                continue;
            }
            let roles = self.roles_for(name);
            if !roles.is_empty() {
                self.mounted.insert(name.clone(), roles.clone());
                added.push((name.clone(), roles));
            }
        }
        let removed: Vec<String> = self
            .mounted
            .keys()
            .filter(|n| !cur.contains(n))
            .cloned()
            .collect();
        for n in &removed {
            self.mounted.remove(n);
        }
        (added, removed)
    }

    /// 启动阶段首次展开（= `poll` 的首次调用语义）。
    pub fn initial(&mut self) -> Vec<(String, Vec<Role>)> {
        self.poll().0
    }

    /// 当前已挂载的接口（诊断/状态面预留）。
    #[allow(dead_code)]
    pub fn mounted(&self) -> Vec<(String, Vec<Role>)> {
        let mut v: Vec<(String, Vec<Role>)> = self
            .mounted
            .iter()
            .map(|(k, r)| (k.clone(), r.clone()))
            .collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_literal_and_glob() {
        assert!(pattern_matches("landae", "landae"));
        assert!(!pattern_matches("landae", "landae3"));
        assert!(pattern_matches("lan*", "landae"));
        assert!(pattern_matches("lan*", "lanclient"));
        assert!(!pattern_matches("lan*", "wan"));
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("eth?", "eth0"));
        assert!(!pattern_matches("eth?", "eth10"));
        assert!(pattern_matches("en*", "ens18"));
        assert!(pattern_matches("veth[a-c]x", "vethbx"));
        assert!(!pattern_matches("veth[a-c]x", "vethdx"));
        assert!(pattern_matches("veth[!a-c]x", "vethdx"));
        assert!(pattern_matches("a*b*c", "aXXbYYc"));
        assert!(!pattern_matches("a*b*c", "aXXbYY"));
        // 未闭合字符类按字面 `[` 处理
        assert!(pattern_matches("a[", "a["));
        assert!(!pattern_matches("a[", "ab"));
    }

    #[test]
    fn default_route_parsing() {
        let v4 =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                  wan0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_default_v4(v4), vec!["eth0".to_string()]);
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
                  00000000000000000000000000000000 00000100 00000001 00000000 00000003 eth0\n\
                  fe800000000000000000000000000000 40 00000000000000000000000000000000 00 \
                  00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n";
        assert_eq!(parse_default_v6(v6), vec!["eth0".to_string()]);
    }

    #[test]
    fn ifwatch_roles_and_poll() {
        let mut w = IfWatch::new(vec![
            Spec {
                role: Role::Lan,
                pattern: "tlan*".into(),
            },
            Spec {
                role: Role::Wan,
                pattern: "tw*".into(),
            },
        ]);
        assert_eq!(w.roles_for("tlan0"), vec![Role::Lan]);
        assert_eq!(w.roles_for("twlan0"), vec![Role::Wan]);
        assert!(w.roles_for("other").is_empty());
        // mounted 记账（poll 依赖真实 /sys/class/net，此处直接检查集合语义）
        w.mounted.insert("tlan0".into(), vec![Role::Lan]);
        assert_eq!(w.mounted().len(), 1);
    }
}

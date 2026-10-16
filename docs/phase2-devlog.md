# 第二阶段 · 开发记录（devlog）

> **第一阶段**（K0–K3 内核攻坚 / P14–P36 生态接入 / M1–M4 性能专项 / 内存与资源边界终测）
> 的成果综述见 [`sodama-atlas.html`](./sodama-atlas.html)。
> 本文件是**第二阶段**（生产实战轮）的逐条记录。
>
> 记录约定：**问题 → 侦查证据 → 结论 → 动作 → 验收**。每条在解决之后追加，
> 不改写历史；未解决的条目保留并标注状态。

- 记录起点：2026-10-08
- 生产环境：OpenWrt Kwrt x86_64（2 核 / 4 GB），`root@192.0.2.10`
- 基线代码：`main@d99a349`（Atlas v1.0 对应版本）

## 目录

| # | 日期 | 问题 | 状态 |
|---|---|---|---|
| 1 | 2026-10-08 | 面板"更新规则集"失败 | ✅ 已定位（非引擎故障）+ 发现 1 个隐患 |
| 2 | 2026-10-08 | Reactor 未接管生产会话（组拨号绕过） | ✅ 已确证 + **已修复**（§8.3）并持续实测 |
| 3 | 2026-10-08 | 引擎内存随运行时长上升（40 MB → 75 MB） | 🕐 观察中（已排除泄漏，追踪器在跑） |
| 4 | 2026-10-08 | 日志体系：无时间戳 / 无轮转 / 在 tmpfs | 🟡 归档+轮转已部署；时间戳需引擎改动 |
| 5 | 2026-10-08 | 订阅源重复（`subA` 与 `3` 同一 URL） | ✅ 已删除（成员 226 → 163） |
| 6 | 2026-10-09 | 节点入口 IP 漂移 + 拨号失败率 40% | ✅ 根因已定位（**探测线程卡死**）并已修复 + 加看门狗 |
| 7 | 2026-10-09 | 处置轮：清理遗留物 / 日志归档 / 探测复活 | ✅ 已执行（§7） |
| 8 | 2026-10-09 | 修复轮：四项引擎侧修复 + 部署 | ✅ 已交付并实测（§8） |
| 9 | 2026-10-10 | **事故复盘：探测线程泄漏（§8 引入的回归）** | ✅ 已根治（握手硬超时 + 墙钟看门狗，stragglers 归零） |
| 10 | 2026-10-11 | 节点看护侦查：粘滞 IP 永不重解析（subA 6/63 存活） | ✅ 已实施 + 已验收（§11.7） |
| 11 | 2026-10-11 | 面板「热重载失败」侦查 + 25h 生产复盘 | ✅ 已实施 + 已验收（§11.7） |
| 12 | 2026-10-11 | **72h 生产测试**（第二阶段收口验证） | 🕐 进行中（§12） |

---

## 1 · 面板"更新规则集"失败（2026-10-08）

### 侦查

| 证据 | 值 |
|---|---|
| `status.reload` | `ok: true`、`error: null`、`slot 1` |
| 引擎日志 | `rules reloaded: 20 match_sets -> slot 0 (was 1)` —— 重载成功 |
| `rule_sets[user_proxy]` | `entries: 0`，`suffix/full/keyword/regex = 0/0/0/0` |
| `rule_sets[user_direct]` | `entries: 0` |
| `/etc/sodama/rules/user_proxy.txt` | 534 字节，**16 行全部是注释**（`grep -vc "^#"` = 0） |
| `/etc/sodama/rules/user_direct.txt` | 332 字节，同样只有注释 |
| `config.dae` 的 `rule_set` 段 | 只有两个本地文件；远程 URL 是**注释掉的示例** |
| 引擎每次 reload 的告警 | `geoexp: domain(ruleset:user_proxy) 为空（规则不匹配任何域；列表文件只有注释？）` |
| 同批日志 | `订阅 subA 拉取失败: Resource temporarily unavailable (os error 11)` |

### 结论

**不是引擎的"更新规则集"坏了**，是三重叠加：

1. **没有可更新的对象** —— `rule_set` 段里没有任何启用的远程 URL；
2. **本地名单是空模板** —— 两个 `.txt` 全是注释示例，有效条目 0 条
   （面板上"规则集"页显示 0 条是**如实反映**，不是失败）；
3. **同批的订阅拉取抖动** —— 日志里真正报错的是 `订阅 subA 拉取失败`。

面板对 `reload_ok=false` 的文案是「**热重载未确认**」，而本次 `reload.ok=true`，
所以用户看到的"失败"更可能来自 ③ 的订阅报错或 ② 的空名单观感。

### 附带发现（**隐患，需要修**）

远程规则集的失败语义（`sodama/loader/src/ruleset.rs:165`）：

```
刷新失败回退旧缓存（日志警示）；无缓存可用则【硬失败】
→ Err("规则集 {tag}: 拉取失败且无可用缓存: {e}（源: {src}）")
```

而面板落盘路径 `apply_config_text`（`panel/backend/src/main.rs:1651`）是
**先写盘、再等 reload 回执，失败不回滚**。

⟹ **一次「首次拉取就失败的远程规则集」会把坏条目永久留在 `config.dae` 里，
导致之后每一次 reload 都失败**。当前生产配置里没有坏条目，说明已被移除。

### 动作（待做）

- [ ] 面板侧：`reload_ok=false` 时提示"配置已写入但未生效"，并给出**一键回滚**（写回上一版文本）
- [ ] 引擎侧：把「远程规则集首拉失败」与「配置语法错」区分开——建议降级为**软失败**
      （该规则集标记为空 + 告警，其余照常 reload），或至少在 status 里把这条规则集标红
- [ ] 文档：把"首次使用远程规则集必须先在路由器上验证 URL 可达"写进 `docs/deploy.md`

---

## 2 · Reactor 未接管生产会话（组拨号绕过）

### 侦查

**代码路径**（`sodama/loader/src/`）：

```
outbound.rs:990  Outbound::codec_reactor_capable()
                   match 只列 Trojan / Vless / Vmess / Shadowsocks / Ssr / AnyTls
                   → Group 落 `_ => false`
main.rs:2892     let wire_codec = !splice && !offloaded && dialer.codec_reactor_capable();
main.rs:2901     let reactor_codec = !splice && !offloaded && wire_codec && reactor::codec_available();
main.rs:2984     if reactor_codec { reactor::submit_codec(...) }
```

生产 dialer 是 `group:proxy` ⟹ `wire_codec = false` ⟹ `reactor_codec = false`
⟹ 连接**退回传统双泵线程路径**（`main.rs:2993+`）。

**现场定量取证**（`/root/reactor-probe.sh`，16 轮 × 10 s，生产实例）：

```
样本 16 点，conns_active 范围 5..8
拟合：线程 = 15.9 + 2.39 × 活跃连接
```

- 截距 **15.9** ≈ Reactor 池的 16 个 worker —— **池子建起来了，但没接到活**；
- 斜率 **2.39** ≈ 每条代理连接 2 个 OS 线程（双泵路径，1 MiB 栈 + 64 KiB 缓冲）。

**旁证**：`splice_total = 0`、`pipe_created = 0`、`pipe_reused = 0`（全时段）。

**对照**：实验室内 M4 是用**单 outbound** 验证的（`vless-tls` 2000 长连接 = 27 线程 / 61 MB），
所以"Reactor 可用"与"Reactor 在生产被使用"是两件事。

### 结论

`Outbound::Group` 是唯一未声明 reactor 能力的常用出站类型，而它恰好是
**生产配置里覆盖率 100% 的那一种**。影响随并发线性放大：
2 核软路由上并发到 100 条代理连接时，就是 200 个线程 / 200 MiB 栈。

### 动作（✅ 已选型并实施，见 §8.3）

> 历史：本项最初按用户指示**不改引擎**，先在路由器上用测试脚本量化
>（`/root/reactor-probe.sh`，只读）。下方面向决策曾列出三个方向；
> 实测数据到位后选了 **②+③**（保守放行 + 计数器），并在 §8.3 落地。
>
> **选型依据（实测）**：
> | 候选 | 取舍 |
> |---|---|
> | ① 选定成员后交回 reactor（语义最准） | 需要在 `DialedStream` 上带回“实际选中成员”，改动在 relay 主路径 —— 收益与②相同、风险更大，**暂不做** |
> | ② **保守放行**（全成员 capable 才放行） | **已选**：改动最小、语义可证；真实订阅下组内同质（vless+anytls），收益完整 |
> | ③ 先补 `reactor_codec_sessions` 计数器 | **已选**：永久可观测，且是验证②是否生效的唯一直接证据 |

#### 实测结论（数据已充足，两次独立重启复核）

| 采样窗口 | `conns_total` | `reactor_codec_sessions` | 占比 | `dial_errors` |
|---|---|---|---|---|
| 部署后 12 min | 12 | 12 | **100%** | 0 |
| 部署后 45 min | 339 | 339 | **100%** | 0 |
| 再部署后 1 min | 28 | 28 | **100%** | 0 |

斜率拟合：`+2.39 → −0.11`（≈ 0）；线程构成中 `relay` 从 36 → **0**。

#### 已知边界（保守放行的代价，已加限流告警）

组内**混入任一个**不支持成员（tuic / hysteria2 / juicity / naive / 带 shadow-tls 的 ss）
⟹ 整组退回线程泵路径（**正确但昂贵**的性能悬崖）。生产上这个降级曾经是静默的，
现已在 `main.rs` 加 `warn_group_not_reactor_once()`：
同一进程每 10 分钟最多一条日志，直说“组里混了不支持的协议”。

> 若将来要吃掉这个悬崖，就回到候选①（按实际选中成员判定）——
> 前提是把成员身份从 `GroupRuntime::dial_tcp` 带回 relay。

---

以下为当初的三个候选（保留作决策历史）：

1. **组内选定成员后交回 reactor**：`GroupRuntime::dial_tcp` 返回后，由 relay 侧
   用**实际选中成员**的 `codec_reactor_capable()` 重新判定（语义最准，改动在 relay 主路径）；
2. **保守放行**：`Group` 若其全部成员都是 reactor-capable 则返回 true（改动最小，
   但组内混协议时会误判）；
3. **维持现状**：先补齐可观测（`reactor_codec_sessions` 计数器），再决定。

---

## 3 · 引擎内存随运行时长上升（观察中）

### 侦查

| 时点 | RSS | RssAnon | 线程 | 备注 |
|---|---|---|---|---|
| reload 后（用户观察） | ~40 MB | — | — | 生产配置启动水位 |
| 22:38（up 17.3 h） | 68.8 MB | 62.7 MB | 53 | |
| 23:38（up 18.3 h） | 75.4 MB | 69.2 MB | 52 | 1 小时 +6.6 MB |
| 23:47（up 18.4 h） | **69.7 MB** | 63.5 MB | 30 | **回落 5.8 MB** —— 非单调 |
| 23:49（up 18.4 h） | 71.2 MB | 64.9 MB | 32 | |

> **首个反证**：RSS 在 23:38→23:47 之间**回落了 5.8 MB**，且线程数同步从 52 降到 30。
> 单调泄漏不会出现回落 ⟹ 强烈支持「**分配器高水位 + 随负载涨落**」而非真泄漏。
> （同时段 `map_conn_state` 562 → 62、`redirect_track` 1030 → 54，是连接收敛后的正常回落。）

**"启动 40 MB"是合理的**：生产配置比实验室重得多 —— 208–226 个节点、
4 个订阅源、`geosite:cn` 5718 + `geoip:cn` 14719 + `category-ads-all` 879 条规则、
DNS 位图与域名统计。实验室空闲基线 11–12 MB 是"50 节点单订阅"口径，两者不可直接比。

**已排除的泄漏候选**：

| 候选 | 实测 | 结论 |
|---|---|---|
| `domain_stats` | 30 条 | 有界 ✅ |
| DNS 缓存 | `cache_entries: 137` | 有界 ✅ |
| `published_ips` | 81409 | 是**累计计数器**（`fetch_add`），非集合 ✅ |
| `pname.map_entries` | 62 | 有界 ✅ |
| `redirect_track` / `conn_state` | 1030 / 562（事故时曾满 65536） | janitor 在清 ✅ |

**主要嫌疑：分配器高水位 + 高频大块分配**

1. **musl 下 `malloc_trim` 是空实现**（本项目已记录的经验）——空闲页**不会**还给内核；
   RSS 只会爬到历史峰值水位，然后停在那里；
2. **每 2 秒一次的大块分配**：面板 `REFRESH_MS = 2000`（`panel/frontend/src/lib.rs:26`）
   → 引擎每次 `status_json()` **全量构建**一棵 `serde_json::Value`
   （生产约 81 KB，含 208+ 节点数组）→ 一天 4.3 万次申请/释放；
3. **连接 churn**：累计 11 862 条连接，每条 2 个 64 KiB 泵缓冲 + 2 个 1 MiB 栈。

### 结论（待验证）

倾向判定为**分配器高水位 / 碎片**（可停在高位不再增长），而**非单调泄漏**。
判据：**空闲期（无流量、无人看面板）观察 RSS 是否平台化**。

### 动作

- [x] 部署只读追踪器 `/root/sodama-mem-track.sh`（每分钟采样 →
      `/root/sodama-mem-track.tsv`：RSS / RssAnon / 线程 / FD / conns / dial_errors /
      bytes / DNS / 两个 eBPF map 水位）
- [ ] 观察 24–48 h，把 RSS 与 `conns_total`、`dns_queries` 做相关性；
      **若空闲段平台化 → 高水位结论成立；若空闲段仍上升 → 真泄漏，转专项**
- [ ] 若确认是高水位：评估在**返回前调用 `malloc_trim` 的替身**
      （musl 下无效 → 考虑 arena 复用/对象池，或把 status JSON 改为**复用缓冲**增量序列化）

---

## 4 · 日志体系（待处理）

| 问题 | 现状 | 影响 |
|---|---|---|
| **在 tmpfs 上** | `/var` 是 `/tmp` 的符号链接（`/var -> tmp`），日志实体是 `/tmp/log/sodama.log` | **重启即丢**，17 h 的日志无法追溯 |
| **无轮转** | 单文件 12.5 MB / 150 062 行，无任何 logrotate 配置 | overlay 只剩 386 MB |
| **无时间戳** | 行格式 `[sodama] ...` | 事后取证只能靠行号推断 |
| 面板无独立日志 | stdout → procd → logd 环形缓冲（`logread`） | 已被冲刷，查不到面板侧错误 |

### 动作（待做）

- [ ] 引擎：日志行加 ISO8601 时间戳前缀
- [ ] 部署：`/etc/logrotate.d/sodama` 或按大小自截断（保留副本到 `/overlay`）
- [ ] 部署：cron 定期把 `/tmp/log/sodama.log` 归档到 `/overlay`（持久分区）

---

## 5 · 订阅源重复（待处理）

`/api/v1/sources` 实测：

```
order 0  subA  https://sub1.example.com/sub?token=REDACTED   63 节点  ← 活动
order 1  2     https://sub2.example.com/sub?token=REDACTED       50 节点
order 2  1     https://sub3.example.com/sub?token=REDACTED      29 节点
order 3  3     https://sub1.example.com/sub?token=REDACTED   63 节点  ← 与 subA 完全相同
```

`subA` 与 `3` 是**同一个 URL 配了两遍**，226 个成员里有 63 个是重复的，
白付一份健康探测与槽位。**动作**：删掉 `3`。

---

## 6 · 节点入口 IP 漂移 → 拨号失败率 40%（待决策）

### 侦查

| 证据 | 值 |
|---|---|
| 最近 4000 行日志 | `RELAY established` **778** vs `失败（group` **519** → 失败率 **40%** |
| 失败原因 | **100% 是 `connect timeout`**（`tail -4000 \| grep 失败 \| sed 's/: .*//'` 全部同一类） |
| `metrics` | `dial_errors` 334（22:38）→ **853**（23:38），1 小时 +519 |
| `group.failovers` | 533（22:38）→ **1571**（23:38） |
| `group` 成员数 | 149 → 205 → **208 → 226**（订阅持续刷新，名单不稳定） |
| 节点地址 | subA 的 `香港01` 从 `203.0.113.252:28537` 变为 `203.0.113.243:28537`（**端口不变，IP 变**） |
| 订阅原文 | 节点 server 是**域名** `node-a.example.com:28537`（base64 解码后可见），SNI `sni.example.com` |
| 路由器侧解析 | `node-a.example.com` → `203.0.113.119` / `203.0.113.48`（**与引擎显示的 IP 不同**） |
| 健康探测结果 | **208/208 个成员 `last_ms`、`ema_ms` 全为 `null`** —— 自上次订阅刷新后**没有一次探测成功** |
| 节点存活 | 166 alive / 42 dead |

### 结论（机理）

三条链路叠加，互相放大：

1. **入口域名的 A 记录在漂移**（18.139.x → 15.168.x → 13.208/13.229），
   机场在轮换入口；
2. **引擎的粘滞 IP 会把解析结果钉住**（日志：`sticky: node-a.example.com:28537 → 203.0.113.252:28537（粘滞 IP 已固定）`）
   —— 钉住的入口一旦失效，该节点持续 `connect timeout`，直到「3 次失败作废」或 reload 重置；
3. **健康探测 100% 失败 ⟹ `ema_ms` 全空 ⟹ `MinMovingAvg` 无值可排**
   —— 组选不出"最健康"的成员，退化为按索引顺序取，**继续命中坏入口**，形成自锁。

> 注：探测失败究竟是"节点真不可达"还是"探测路径本身的问题"，尚未分离。
> 探测目标是 `cp.cloudflare.com:80`（`GET /generate_204`），需要经节点连通。

### 动作（待决策）

- [ ] **先分离**：抓一次探测的完整过程（`SODAMA_REACTOR_DEBUG` 不覆盖这里，
      需要临时开更细的日志或手工用同一路径复现一次拨号）
- [ ] 节点看护策略（用户此前已提出该问题）：
      ① 粘滞 IP 加"失败即失效"的更快判据（当前 3 次）
      ② 探测失败与节点不可达分开记账（区分"经节点连不通"与"目标本身不通"）
      ③ 组内至少保留一个"最后可用"成员，避免全组漂到坏入口
- [ ] 订阅刷新时对**入口 IP 变更**给出显式日志（现在只有 sticky 固定日志）

---

## 7 · 处置轮（2026-10-09 00:00–00:25）

> 按「全部做一下」一次性执行 A/B/C/D。全程两次引擎重启（各 ~10 s），
> 改动前均已备份到 `/root/backup-<stamp>/`；配置改后经 `sodama validate` 自检通过。

### 7.1 C · 遗留物清理

| 项 | 处置 |
|---|---|
| `/var/sodama`（7.7 MB 误拷二进制） | 已删 |
| `/tmp/{sodama-new,sodama-udpfix,sodama-ebpf}`（16 MB 旧构建） | 已删 |
| `/tmp/*.dae`（测试配置 ×5）、`panel.conf.new`、`reload-timing.sh`、`*.log` ×4 | 已删 |
| `/tmp/sodama-diag{,.tar.gz}`（旧诊断包） | 已删 |
| 遗留进程 `tail -f /var/log/sodama.log`（PID 3420）+ `trace.sh` | 已 kill |

**效果**：`/tmp` 占用 **61.3 MB → 29.6 MB**（tmpfs 直接吃内存，等于回收 ≈32 MB RAM）；overlay 回收 7.7 MB。

### 7.2 根因 · 健康探测线程卡死（**本次最重要的发现**）

| 证据 | 值 |
|---|---|
| `probes_ok` / `probes_fail`（引擎 status，权威） | **双双冻结** 在 21549 / 5123，连续 3 次采样（跨 2 分钟）不动 |
| `probe_interval_secs` / `probe_active` | 30s / true（自述在跑，实际不动） |
| 有 `last_ms` 的节点数 | **0 / 226** |
| 线程现场 | TID 32585：`syscall=45`（recvfrom）、`wchan=wait_woken` —— **阻塞在无超时的 socket 读** |

**机理**：`group.rs:710` 的探测批用 `std::thread::scope` + `s.spawn(move || probe(j))`，
而 `thread::scope` **会等待批内全部线程结束**。只要有一个探测线程卡死，
整轮永不返回 → 健康循环彻底停摆。卡死点在 `probe()` 的末尾读取：

```rust
let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));  // ← 返回值被丢弃
...
let read_ok = matches!(d.from_remote.read(&mut buf), Ok(n) if n > 0);
```

`set_read_timeout` 的失败被 `let _ =` 吞掉；一旦其未生效（或协议层内部的读路径不受该超时约束），
这个 `read` 就永久阻塞。

**因果链**：探测停摆 → `ema_ms` 全空 → `MinMovingAvg` 无值可排 → 组退化为按索引取成员
→ 命中失效入口 → **拨号失败率 40%**（成功 778 / 失败 519，全是 `connect timeout`）。

**双重旁证**：① 入口 IP 实际可达（`curl` 得 `Empty reply from server` = TCP 握手成功）；
② `dial_errors` 在 853 后**停涨**——说明那一波是瞬时的，而探测停摆是**持续**的。

**运行时兜底已部署**：`/root/sodama-watchdog.sh`（每 5 min 检查，`probes_ok` 冻结 ≥1800 s
则自动 `restart`）。窗口取 1800 s 为了避开空闲退避时的 600 s 探测间隔。

> **待做的引擎侧修法**（本阶段不改代码）：
> ① `probe()` 改为**总有硬超时**（`set_read_timeout` 失败不再静默）；
> ② 批处理不用 `thread::scope`（改为独立线程 + 全局 deadline），单个探测卡死不应拖垮整轮；
> ③ 状态面加 `probes_last_ok_secs_ago`，让“探测停了”能被直接观测。

### 7.3 A · Reactor 确实被绕过（确证）

方法：临时向 `/etc/init.d/sodama` 注入 `export SODAMA_REACTOR_DEBUG=1` → 重启 →
跑 90 s 真实流量 → 数日志里的 `reactor-dbg: codec 投递`。

| 观察项 | 结果 |
|---|---|
| 启动自述 | `M4 reactor 已启动（2 workers，epoll/splice+codec，每连接 0 线程）` |
| **`reactor-dbg` 行数** | **0** |
| 对照（斜率法，重启前） | `线程 = 15.9 + 2.39 × 活跃连接` |

⟹ **Reactor 建起来了、自述已启用，但在生产（组拨号）下一条会话也没收到**。
调试变量已从 init 脚本移除并再次重启复原（残留检查：0 行）。

### 7.4 B · 节点看护（已恢复）

重启后：

| 指标 | 重启前 | 重启后 |
|---|---|---|
| `probes_ok` 增速 | **0 / 2 min**（冻结） | **+181 / 45 s** |
| `probes_fail` | 5123（冻结） | 40（本世代） |
| 有延迟数据的节点 | **0 / 226** | 282 |
| 成员存活 | 163 / 226 | **163 / 163** |

### 7.5 D · 去重复订阅源（已完成）

删除与 `subA` 同 URL 的 `3` 号源，热重载后：

```
订阅 subA: 拉取成功，66 个节点（来源顺序 #1）
订阅 2:   拉取成功，50 个节点（来源顺序 #2）
订阅 1:   拉取成功，50 个节点（来源顺序 #3）
订阅热更新：组 proxy 163 成员（继承 163 健康）
config-watch: 自动 reload 完成（ok=true match_sets=20 error=null）
```

成员 **226 → 163**（去掉 63 个重复），健康探测负担同步下降 ≈ 28%。

### 7.6 C · 日志归档与轮转（已部署）

| 项 | 处置 |
|---|---|
| 持久化归档 | `/root/sodama-log-archive.sh`：日志 > 8 MiB 时 `cp` 到 `/root/logs/sodama-<ts>.log`（保留最近 12 份） |
| 安全截断 | 已核实引擎日志 fd 带 **O_APPEND**（flags `0x88401`）⟹ 截断安全，写入会从新 EOF 继续 |
| 定时 | crontab：`*/30` 归档、`*/5` 看门狗 |
| ⚠️ 未解 | **日志行仍无时间戳** —— 需引擎侧改动（`crate::log` 加 ISO8601 前缀），本阶段未动代码 |

### 7.7 内存基线（重启后实测）

| 指标 | 重启后 90 s | 重启前（up 18 h） |
|---|---|---|
| RSS | **39.0 MB** | 75.4 MB |
| 线程 | **21** | 52 |

⟹ 印证了用户观察的「重启后 40 多 MB」：**这是生产配置（163–226 节点 / 4 订阅 /
geosite 5.7k + geoip 14.7k）的自然启动水位**，不是异常。
18 h 后涨到 75 MB 的那部分，倾向为分配器高水位（见 §3），追踪器继续采样。

### 7.8 本轮后的待办

- [x] 引擎：探测硬超时 + 批处理不卡死（§7.2） → **见 §8**
- [x] 引擎：远程规则集首拉失败改软失败 + 面板自动回滚（§1） → **见 §8**
- [x] 引擎：`Group` 接入 reactor + `reactor_codec_sessions` 计数器（§2 / §7.3） → **见 §8**
- [x] 引擎：日志行加时间戳（§7.6） → **见 §8**
- [ ] 观察 24–48 h：内存曲线（平台化 vs 持续上升）+ 看门狗日志
- [ ] 面板：`reload_ok=false` 的文案与回滚入口 → **已随 §8.2 自动回滚一并处理**

---

## 8 · 修复轮（2026-10-09 00:25–01:00）

> 四项引擎侧修复 + 部署 + 单测。改动共 9 个文件 / +404 行。
> 单测：**271 passed / 0 failed**（含新增 3 条）；OpenWrt x86_64 构建 → 部署实测。

### 8.1 ① 探测不再卡死（`group.rs`）

| 修法 | 说明 |
|---|---|
| **硬超时必判** | `probe()` 不再 `let _ = set_read_timeout(..)`；设置失败即判本次探测失败并返回错误，**绝不进入无超时的读** |
| **补写超时** | 同时 `set_write_timeout(3s)` |
| **批处理不再卡** | 探测批由 `std::thread::scope`（等全部子线程）改为 **独立 spawn + 带超时收集**（`PROBE_BATCH_DEADLINE = 30s`）；超时未回的线程被放弃，主循环必定继续 |
| **可观测** | 新增 `probes_stragglers` 计数器 + 超时日志一行 |
| 顺带 | 探测线程栈 512 KiB（原默认 8 MiB），`thread::Builder::name("probe")` 便于 /proc 辨认 |

### 8.2 ② 远程规则集不再自锁（`ruleset.rs` + 面板）

- **引擎**：新增 `RuleSet::error`；`load_one` 拆为 `load_one_inner` + **软失败包装** ——
  任一规则集失败只把自己置空并记录原因，**不阻塞其它集合与整体 reload**；状态面 `rule_sets[].error` 上报。
- **面板**：`apply_config_text` 加 **失败自动回滚** —— 写盘前保留上一版；
  若 `reload_ok == Some(false)` 则自动回写上一版并再等一次回执，回报里明说“已自动回滚”。
- **面板**：配置页规则集行新增“加载失败”提示（经 `DomainFileView.error` 透出）。

### 8.3 ③ 组拨号不再绕过 Reactor（`outbound.rs` + `group.rs`）

```rust
Self::Group(g) => g.codec_reactor_capable_all(),   // 逐成员实算，保守放行
```

语义：组内**全部**成员都是 reactor-capable（vless/anytls/vmess/trojan/ss非shadowtls/ssr）才放行；
混入 tuic/hy2/juicity/naive/QUIC 任一个则整组退回双泵线程路径 —— 慢但正确。
新增 `reactor_codec_sessions` 计数器（metrics: `sodama_relay_reactor_codec_sessions`）作为永久可观测。

### 8.4 ④ 日志时间戳（`main.rs`）

日志行变为 `[sodama] 2026-10-09 00:45:10 <msg>`。

时区三级兜底（首次部署踩到“差 8 小时”）：

1. `TZ` 已设 → `localtime_r`（两端 libc 都尊重完整 TZ 库）；
2. 否则读 `/etc/TZ` 的简单形式（OpenWrt 为 `CST-8`）→ 自实现 `parse_posix_tz` + `epoch_to_civil`；
3. 都不可用 → `localtime_r` 兜底（glibc 会读 `/etc/localtime`）。

新增单测：`posix_tz_simple_forms`（含 `CST-8` / `UTC0` / `EST5` / `<+08>-8` / 带 DST 规则的形式 / 非法输入）、
`epoch_to_civil_matches_known_instants`（含闰日与负 epoch）。

### 8.5 部署后实测（前后对照）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 斜率拟合（Δ线程/Δ连接） | **+2.39** | **−0.11**（≈ 0） |
| `reactor_codec_sessions` | 计数器不存在；`reactor-dbg` 行数 **0** | **12 / 12 连接**（100% 走 Reactor） |
| 线程构成中的 `relay` | **36** | **0** |
| 总线程（同量级负载） | 52 | **30**（15 sodama + 14 probe + 1 gc） |
| `probes_stragglers` | 计数器不存在 | **1**（新机制真的抓到一次卡死探测，且未拖垮整轮） |
| 日志行 | `[sodama] msg`（无时间） | `[sodama] 2026-10-09 00:45:10 msg` |
| `codec_reactor_capable` | 字段不存在 | `true` |
| 单测 | 268 | **271** |

> 线程数在负载下仍有 17–40 的波动，来自探测批（并发 24）+ 短命线程，
> **不再与并发连接数线性相关** —— 这正是 Reactor 接管的定义。

### 8.6 本轮的边界与遗留

- **已补**（收尾）：`warn_group_not_reactor_once()` —— 组因含不受支持成员而退回线程
  路径时，**限流**（同进程 10 分钟一条）地报一次，把“静默性能悬崖”变成可见。
  部署后验证：日志中该告警出现 **0 次**（当前组能力为 true，符合预期）。
- **未验证**：探测硬超时的“写超时”分支未在真实卡死场景复现（`probes_stragglers=1` 是
  自然发生的一次）；下一轮若再出现 stragglers，应到 `/proc/<pid>/task/*/syscall` 采一次现场。
- **未做**：`reactor_codec` 对 **Vision/WS 组合** 的长期稳定性验证（实验室逐字节过，生产未持续观察）。
- **未做**：规则集软失败只在代码层验证，**未在生产造一次“首拉失败”**（怕干扰网络）。
- **已知观测瑕疵**：订阅热更新重建组对象时，`probes_ok/fail` 归零（计数器按“组世代”而非进程）。
  不影响功能，但跨热更新读速率时需要留意。
- 72 h soak 仍未做，`bounded-memory` 表述仍不启用。

---

## 9 · 事故复盘：探测线程泄漏（2026-10-09 22:10 / 2026-10-10 13:30）

> **性质：§8 修复引入的回归。** 诚实记录：第一轮"修好探测卡死"的做法本身制造了新的泄漏。

### 9.1 现象

用户在面板上看到内存到 100+ MB、虚拟内存 400+ MB，13:30 前后突涨。

| 时点 | VmRSS | VmSize | 线程 | fd | `probe` 线程 |
|---|---|---|---|---|---|
| 2026-10-09 22:10（发现时） | **104.7 MB** | **432 MB** | **566** | 1821 | **553** |
| 2026-10-10 13:29（修复前） | 66.7 MB | 164 MB | 141 | 562 | 123 |

### 9.2 根因（两层）

**第一层：探测线程被放弃后不退出。**
§8.1 把探测批从 `thread::scope`（等全部子线程）改成"独立 spawn + 带超时收集"，
解决了"一个卡死拖垮整轮"，但**被放弃的线程仍在后台阻塞** —— 如果它永不退出，
就是纯粹泄漏。

**第二层（真正的根因）：协议握手读不受任何超时约束。**
线程现场（修复前采样）：**553 个 probe 线程全部** `syscall=45 (recvfrom)` /
`wchan=wait_woken`，其中 470 个已存活 > 1 小时。

追到 `outbound.rs::marked_tcp_connect`：

```rust
let rc = libc::connect(...);
if rc != 0 {  /* EINPROGRESS → poll(POLLOUT, timeout_ms)  ← 超时只盖到这里 */ }
...
let flags = libc::fcntl(fd, F_GETFL);
libc::fcntl(fd, F_SETFL, flags & !O_NONBLOCK);   // ← 清掉非阻塞后**没设 SO_RCVTIMEO**
```

即：**TCP 连接超时被遵守，但握手阶段的读没有超时**。碰上"端口开、能建连、
但不回包"的节点（这批机场里大量存在），VLESS 应答头 / anytls settings 的
`recvfrom` 就**永久阻塞**。

> 这也解释了为什么 §8.1 的 `set_read_timeout` 修复没用：那个超时设在
> **dial 成功之后**（probe 自己的读），而卡死发生在 **dial 内部**。

### 9.3 修复（本轮）

| # | 修法 | 位置 |
|---|---|---|
| 1 | `marked_tcp_connect` 建连后立即设 `SO_RCVTIMEO = SO_SNDTIMEO = timeout` | `outbound.rs` |
| 2 | `Outbound::dial_tcp` **握手完成后清除**两者（否则残留超时会把"安静但正常"的长空闲连接误判为超时；reactor 路径会置非阻塞、本就忽略它） | `outbound.rs` |
| 3 | **安全网**：`PROBE_LIVE` 存活计数 + `PROBE_MAX_LIVE = 96`；撞顶则跳过本轮并告警。即使还有别的卡死路径，线程数也不再有界增长 | `group.rs` |

新增回归测试 `handshake_timeout_set_then_cleared`（helper 设/清语义 + dup 共享 +
root 下验 `marked_tcp_connect` 真的设上；注意内核会把 `SO_*TIMEO` 向上取整到
时钟粒度，断言用容差）。单测 **272 passed**。

### 9.4 修复后实测（部署 13:30:18，观测 13:38–13:43）

| 指标 | 修复前（旧版跑 15h） | 修复后（观测 5 min） |
|---|---|---|
| `probe` 线程 | **123**（持续累积） | **18–38 波动**（流失，非单调累积） |
| 总线程 | 141 | 34–53 |
| VmRSS | 66.7 MB | 42.4 → 46.0 MB（跟着当前线程数走） |
| `probes_stragglers` | 773 | +14 → +28（≈170/h，仍在产生） |

**判读**：线程数从"单调累积到 553"变成"在 18–38 之间波动" ⟹ 修复**确实生效**
（线程现在会退出了）。但探测仍频繁超 30 s。

### 9.5 ~~尚未关闭的部分~~ → **已关闭**（14:01 墙钟看门狗）

**补修（10 日 14:01 部署）**：`socket` 级超时只把「永久阻塞」降级为「有界重试」，
握手总时长仍无上界。加一层**墙钟看门狗**：

- `marked_tcp_connect` 建连后 `arm_dial_watchdog(fd, timeout)`：起一个 64 KiB 栈的
  `dial-wd` 线程，分片睡眠（20 ms）等待取消标志；到点仍未取消就 `shutdown(fd, SHUT_RDWR)`
  —— **任何阻塞中的 recvfrom 立刻返回**，整个拨号被硬性截断。
- `Outbound::dial_tcp` 在 inner 返回后立刻 `disarm_dial_watchdog()`（成败都要）。
  用**线程局部**保存标志：组拨号嵌套成员拨号时，内层 armed→disarm 后外层拿到空值，互不干扰。
- dup 一份 fd 给看门狗，保证 shutdown 时 fd 有效。
- 代价：每次拨号多一个短命线程（正常路径 20 ms 内退出）。以生产 ~20 dials/min 计可忽略。

**效果对比（同一实例，连续 7 次采样）**：

| 指标 | 加看门狗前 | 加看门狗后 |
|---|---|---|
| `probes_stragglers` | +14 / 5 min（持续增长） | **0（全程 7 次采样）** |
| `dial-wd` 线程 | — | 1–13（短命，按设计） |
| 总线程 | 34–53 | 18–43（波动） |
| RSS | 42.4 → 46.0 MB | 38.8 → 44.4 MB |
| `超过 30s 未回` 告警 | 持续产生 | **14:01 之后 0 条**（最后一条 14:00:41，早于新二进制启动） |
| 上限封顶告警 | — | 0 次（从未撞到 96） |

功能面同时正常：`reactor_codec_sessions` 167/167（100%）、`dial_errors` 0。

新增测试：`dial_watchdog_shuts_down_after_deadline`（到点确实掐断、阻塞读立即返回）、
`dial_watchdog_cancel_keeps_socket_alive`（取消后连接仍可用 —— 防止误杀成功连接）。
单测 **274 passed**。

### 9.5b 修复后的剩余如实说明

- **未完全修好**：`stragglers` 仍以 ≈170/h 产生，说明握手路径里还有"超时后重试"
  的循环（每次 `recvfrom` 被 5 s 超时打断，但外层循环继续重试）——
  socket 级超时只把"永久阻塞"降级为"有界重试"，**没有整体 deadline**。
- **因此**：本次修复的实质是「把无界泄漏降级为有界流失 + 上限封顶（96）」，
  **不是**根治。真正该做的是给 `dial_tcp` 的握手加一个**墙钟 deadline**
  （例如把 `timeout` 贯穿到握手循环的每次重试判定），已列入下阶段待办。
- **未验证**：96 上限在长跑中是否会被撞到（当前峰值 38）；若撞到，探测会暂停
  直到线程退出——这本身是设计意图，但需要一次长跑确认它不会长期锁死探测。
- `probes_stragglers` 仍随组对象重建而归零（同 §8.6 的观测瑕疵）。

### 9.6 方法论教训

1. **"放弃等待"不等于"终止线程"** —— 把阻塞式 I/O 放进可放弃的批处理时，
   必须同时回答"被放弃的线程怎么结束"。
2. **超时要设在最内层**：`marked_tcp_connect` 的 `timeout` 参数名字像"整次拨号超时"，
   实际只覆盖 `poll(POLLOUT)` —— 命名与语义不符会误导后续所有调用方。
3. **现场证据先于重启**：本次在重启前抓到了 553 个线程的 syscall/wchan 分布，
   直接定位到 `recvfrom`；若先重启，这条线索就没有了。
4. **累积型回归必须长跑才看得见**：§8 部署后 1 小时的观测完全正常（线程 18），
   泄漏在 15–20 小时后才到 100+ MB。

---

## 10 · 节点看护侦查：入口轮换与「永不重解析」的粘滞 IP（2026-10-11）

### 10.1 症状

用户在面板上发现主订阅源 `subA` 的节点大面积显示为 dead：

| 观测 | 值 |
|---|---|
| 组 `proxy` 成员 | 113（subA 63 + 源 2 50） |
| subA 存活 | **6/63** |
| 源 2 存活 | 35/50（正常，CF anycast 不受入口轮换影响） |
| 源 1（subC） | 14:01 拉取失败后 0 节点（次日凌晨实测已恢复，见 10.2-⑦） |
| 活动源 | subA（rank 1）——活着的 6 个节点 EMA 592–736 ms，显著快于源 2 的 1.5–2.4 s |

死节点按「钉住的入口 IP」聚类（63 节点、8 个入口 IP）：

| 钉住的入口 IP | 存活/总数 | | 钉住的入口 IP | 存活/总数 |
|---|---|---|---|---|
| 203.0.113.42 | 5/32 | | 203.0.113.6 | 0/5 |
| 203.0.113.11 | 1/6 | | 203.0.113.18 | 0/4 |
| 203.0.113.153 | 0/7 | | 203.0.113.150 | 0/1 |
| 203.0.113.245 | 0/7 | | 203.0.113.107 | 0/1 |

同一 `IP:端口` 上兄弟节点一活一死（如 `node-a.example.com:17985` 的新加坡 01 活 /
02 死）——症状不是「入口失联」，而是「钉错入口」。

### 10.2 侦查证据

1. **subA 全部节点共用同一域名** `node-a.example.com`（仅端口不同，`sticky` 日志可见）。
   该域名的 DNS 应答**随时间轮换**：14:00 两次启动解析时 63 个节点散落在 8 个 IP；
   01:04 查得 `203.0.113.11`；01:07 连续 4 次均为 `203.0.113.132`（AWS 新加坡，
   不在 14:00 的钉选集合里）→ 机场「轮换入口」。
2. 从路由器对 8 个入口 IP 逐个做 TCP 连通测试（节点端口 28877/17985/28537）：
   **全部可连**——入口 IP 并没有整体失联。
3. TLS 层探测：旧 IP 普遍超时 / 握手期 EOF（`curl` 报 `unexpected eof while reading` /
   timeout），行为参差 → 旧入口已不再按旧端口完整服务，但仍有残余服务（6 个活节点在其上）。
4. **sticky 日志时间分布**：「粘滞 IP 已固定」只有 3 组时间戳——13:29:56（58 条）、
   14:00:56/57（29+29 条），即**全部发生在引擎启动（解析）时刻**；
   而「作废粘滞 IP」共 85 条分布在 11:31–00:34 全程。**作废后没有任何「已固定」**。
5. 代码佐证：`Outbound` 在 `parse_*`（→ `sticky::resolve`）把节点域名解析成**固定
   `SocketAddr`** 存储；`sticky::note_dial` 第 3 次失败时删缓存项并打日志「下次重新解析」，
   但**没有任何运行时路径再调用 `sticky::resolve`**（`ssr.rs:280` 是例外：它存域名、
   每次拨号重解析）→「下次重新解析」是空头承诺（第一阶段 P23 的移植偏差）。
6. **死亡时间线**与「节点钉住的入口停止服务时死掉」吻合：11:31 起零星、11:43–44
   一批 24 个（首次大轮换）、14:02–14:08 一批约 17 个（②重启后重掷骰子仍落旧池）、
   之后 16:07、17:01、17:30、19:21、21:27、22:14 零星，23:45–23:47 一批 7 个，
   00:34:35 一个（与用户当夜感知的「短暂断网」时刻接近）。
7. **订阅端点侧变化（外部因素）**：subA URL 的两个前端（198.51.100.10:36666/sub1 与
   198.51.100.11:9000/sub1b，同一 token）现在对非浏览器 UA 间歇 403/429，
   浏览器 UA 得到 **956 字节 / 5 个 ss 节点**（入口 203.0.113.102 的
   「香港/台湾/日本/新加坡/美国 IEPL」）——与 14:01 拉到的 66 个 anytls/reality
   是两套完全不同的内容。源 1（subC）14:01 拉取失败（627 字节截断），
   但次日凌晨实测返回 200 / 22,980 字节 / **50 个 vless(CF) 节点**——源 1 已恢复可拉。

### 10.3 结论

- **引擎侧缺陷（根因，确定）**：粘滞 IP 只「作废」不「重解析」。节点在整个进程
  生命周期内永远钉在解析期那一次 DNS 应答上；机场轮换入口后，钉到旧入口的节点
  永久死亡，直到下次配置热更新 / 进程重启重掷骰子才可能复活。
  这与 dae `StickyIpDialer`（每次拨号过缓存、失效即重解析）的语义不符。
- **订阅侧变化（外部）**：subA 端点交付内容已变（新套餐 = 5 个 ss/IEPL 节点）。
  这部分不可由引擎修复，需要新订阅 URL / 确认套餐。旧套餐是否完全退役无法从外部确证——
  6 个存活节点仍工作在旧入口上，说明**旧套餐尚未完全退役**；重解析修复后应能复活一部分节点。
- **「顺序回退」策略表现良好**：11 小时 12,522 次成员拨号、仅 8 次 failover、4 次 dial 错误；
  活动层（subA）的 6 个存活节点延迟最低。**不建议**改成「按存活率排序」
  （会把低延迟活节点让位给高延迟源 2）。

### 10.4 处置（本阶段）

> **→ 2026-10-11 下午：本表 1–4 均随 §11 修复批次落地（见 §11.7）。**

| # | 动作 | 落点 | 规模 |
|---|---|---|---|
| 1 | **拨号时重解析**：`marked_tcp_connect` 入口加 `sticky::resolve_for_dial(addr)`（缓存命中零开销；失效/TTL 过期即重新解析）；`note_dial` 改为按域名记失败；日志只在实际换 IP 时打印 | `sticky.rs` + `outbound.rs` 1 行 | 小 |
| 2 | **订阅磁盘缓存**：拉取成功即落盘，拉取失败 / 启动时回退到磁盘缓存（告警「stale」）；重启不再因端点抖动丢源 | `main.rs` 订阅路径 | 小 |
| 3 | **订阅读周期刷新**：`global.subscription_update_interval`（默认 6h、错峰抖动、失败退避、识别 429）；复用 SIGHUP 热更新的「按名继承健康」 | `main.rs` | 中 |
| 4 | 观测补强：status 每个订阅源输出 `alive/total`；面板订阅卡片显示来源存活 | status/main.rs + panel | 小 |

### 10.5 用户侧事项

- [ ] 从机场获取**新的订阅 URL/token**（两个旧前端现在都只给 5 个 ss IEPL 节点）；
      或确认现套餐就是这批 IEPL。
- [ ] 处置 2/3 部署前**避免重启引擎**：内存里的 66 节点列表是旧套餐最后的完整副本；
      重启会按新订阅内容重建（subA 变成 5 个 ss）或因端点再抖而丢源。
- [ ] 本轮排查把 subA 端点打进了限流（429）——今后人工测试该端点要克制。

### 10.6 验收（部署后回填）

- [ ] 运行中出现 sticky「已固定」重解析日志（且只在实际换 IP 时打印）
- [ ] subA 死节点存活数回升 / `probes_fail` 增速回落
- [ ] 引擎重启（含模拟 403）不再丢源（磁盘缓存生效）

---

## 11 · 面板「热重载失败」侦查 + 25h 生产复盘（2026-10-11）

### 11.1 症状

- 面板操作（切换节点 / 添加订阅 / 移动源）显示「热重载失败 / 未确认」；
  用户实测「切换节点」**确实未生效**（不只是提示问题）。
- 组从 113 → 22 成员：subA 整源消失、源 2 从 50 → 22。

### 11.2 侦查证据

1. **引擎日志**：今日仅三次 config-watch reload（13:14:30 / 13:41:02 / 13:50:17），
   全部 `ok=true`，但耗时 **19 s / 20 s / 34 s**。
2. **三次重载的完整时间线**：

   | 操作 | subA | 源 2 | 源 1 | 热更新结果 |
   |---|---|---|---|---|
   | 13:14:30→49 | 403 | 「成功」22 节点 | 未拉取 | 全量替换：113→22（subA 63 成员被清空） |
   | 13:41:02→22 | 403 | 响应头不完整 | 未拉取 | 全失败：保留旧成员（**policy 等本地变更也未应用——早退**） |
   | 13:50:17→51 | 403 | 响应头不完整 | unexpected EOF | 同上 |

3. **面板回执窗口**（读码）：配置写入 `wait_reload` 20 s、文件保存 15 s、源 promote 15 s、
   手动 reload 20 s（`sodama reload` CLI 同步等待 + 面板命令超时同为 20 s）。
   19–34 s 的重载全部踩线/超时 → 前端失败文案（部署 dist 内含「热重载失败」「热重载未确认」）。
4. **「切换节点」功能性失效链**：`reload_group_members` 在 `nodes.is_empty()` 时**早退**
   （“保留旧成员”），其后的 policy 应用（`main.rs:4284`）被一并跳过——配置写入了
   `fixed('X')` 但引擎不应用（13:41/13:50 无 `policy ->` 日志）。旁证：no-op 演练
   `POST config/group/policy {"policy":"auto"}` 返回「策略已是 min_moving_avg，无需修改」——链路本身正常。
5. **`2-22` 之谜**：无 `#` 片段的行自动命名 `{tag}-{行号}`；13:14 的“22 节点”是
   **截断响应被当成功**。源 2 现在实测健康：50 节点 / 13.8 KB / 2.5 s。
   根因：`subscribe::fetch_once` 读循环把 EOF 与读超时都当正文正常结束，**不校验 Content-Length**。
6. 源 1 在 13:14/13:41 未被拉取 → 推断为用户编辑中间态里订阅块暂缺源 1（13:50 已回）。
7. **25h 健康曲线**（1486 采样，10-10 14:15 → 10-11 15:11）：RSS 平台 **50–53 MB**
   （12 时段峰值 58.9 为 ws 风暴瞬时）；**stragglers 0/1486**；fd 峰值 504（同风暴）；
   线程 16–66；watchdog 从未触发；三次 reload 前后内存无跳变。
8. **ws 帧截断风暴**：按小时 08h 12 → 11h 588 → 12h 846 → 15h 51，与 13 时前后
   网络劣化窗口（订阅拉取同窗口失败）吻合；暂判「网络扰动 + 客户端中断」叠加，观察项。

### 11.3 结论

- **误报链**（用户看到的「失败」）：reload 同步拉取全部订阅（慢、可达 34 s）→
  面板回执窗口 15/20 s 超时 → 前端显示失败；引擎实际 ok=true。
- **功能性失效链**（切换节点真的不生效）：全源拉取失败时热更新早退 → 本地变更（policy）也不应用。
- **丢源链**：部分源失败时全量替换成员 → 失败源被静默清空（subA 63 → 0）。
- **数据完整性**：截断正文静默通过（22 节点假成功 + `2-22`）。
- 25 h 运行稳定（无泄漏、无 straggler、无看门狗触发）；subA 403 与 §10 结论一致（端点侧）。

### 11.4 处置提案（本阶段）

> **→ 2026-10-11 下午全部实施并验收（见 §11.7）。**

| # | 优先级 | 动作 | 落点 | 规模 |
|---|---|---|---|---|
| 1 | P0 | **reload 与订阅拉取解耦**：配置热重载只做本地部分（规则/参数/组结构/policy），回执毫秒级；订阅刷新异步进行，完成后热更新成员并记录订阅状态 | `main.rs` reload 路径 | 中 |
| 2 | P0 | **按源保留成员**：某源拉取失败时保留该源旧成员；仅成功源替换；全空才保留全部 | `reload_group_members` | 小 |
| 3 | P0 | **本地变更不随拉取早退**：policy/参数应用不受 `nodes.is_empty()` 影响（随 #1 自然成立） | 同上 | 小 |
| 4 | P0 | **正文完整性**：强制 Content-Length；读超时≠EOF；无 CL 时要求正文以换行收尾；成功且节点数骤降（如 <上次 50%）告警/拒绝 | `subscribe.rs` | 小 |
| 5 | P0 | **sticky 拨号重解析**（§10.4-1，仍未批） | `sticky.rs`+`outbound.rs` | 小 |
| 6 | P1 | **订阅磁盘缓存**：成功正文落盘；拉取失败/重启回退（告警 stale） | `main.rs` | 小 |
| 7 | P1 | **周期刷新 + 429/退避**：`subscription_update_interval`（默认 6h、抖动）+ 识别 429/Retry-After | `main.rs` | 中 |
| 8 | P1 | **面板回执语义**：超时文案改「已保存；回执超时，稍后刷新」；手动 reload 不依赖 CLI 退出码；窗口适当拉长（配合 #1 后基本不需要） | `panel/backend` | 小 |
| 9 | P2 | 观测：per-source `last_pull_at/ok/error/count` + per-tag `alive/total`；面板订阅卡展示 | status/main.rs + panel | 小 |
| 10 | P2 | 面板文案「死亡自动兑底」应为「兜底」（typo） | `configapi.rs` | 微 |

### 11.5 验收

- [ ] 面板任一操作 < 2 s 返回成功回执；订阅刷新在后台完成且状态可见
- [ ] 构造截断响应（本地脚本）→ 拉取被判失败/告警，不静默
- [ ] 单源失败时该源成员保留（用本机实例演练）
- [ ] 引擎重启不丢源（磁盘缓存生效）
- [ ] 切换节点 1 s 内生效（不依赖任何网络拉取）

### 11.6 用户侧事项

- [ ] 拿新 subA 订阅 URL 或弃用 subA；当前服务正常（22 节点 / 14 活，均源 2）
- [ ] 修复部署前，避免再触发写操作（可能触发全量替换 + 长拉取；subA 已空，但源 1 有
      同样被清空的风险）；如想立刻回血，可在确认网络好的时段手动热重载一次（会显示失败=误报）
- [ ] 观察项：ws 帧截断风暴（§11.2-8）随下次网络劣化对比

### 11.7 实施与验收（2026-10-11 下午，全部落地）

处置表逐项落地与验收证据：

| # | 实施位置 | 验收证据（实机） |
|---|---|---|
| 1 | `main.rs`：`request_sub_refresh`（mpsc 合并的后台 `sub-refresh` 线程）+ `do_reload` 不再同步拉取 | 面板文件保存回执 **0.74s**（旧：19–34s 超时误报）；日志链「后台开始拉取→拉取完成→组 N 成员→本轮结束」 |
| 2 | `fetch_sources`（按源结果）+ `group::clone_members_by_tag`（失败源继承旧成员；删源自然丢弃） | 16:13 热更新「组 proxy 100 成员（继承 100 健康）」 |
| 3 | `apply_group_policy_local`（reload 同步应用 policy，不依赖网络） | 实机链路演练正常（`auto` 无变更路径） |
| 4 | `subscribe.rs`：CL 精确校验 / 读超时≠EOF / 无 CL 需换行收尾 | **实战捕获截断×2**：16:04:25（8754/13852）、16:12:31（1909/13848）——旧实现会静默接受 |
| 5 | `sticky.rs`：`resolve_for_dial`（origin 映射 + 按域名计失败；仅实际换 IP 时打日志） | 单测×4（保持/失效重解析/TTL/IP 直通） |
| 6 | 订阅磁盘缓存 `/etc/sodama/sub-cache/<tag>.bin`（0600/0700） | 实机落盘：`1.bin`/`2.bin` |
| 7 | `sub-timer`：周期刷新（默认 6h±10%）+ 429 冷却（15min）+ **失败源自愈重试**（5min→1h 退避，60s 扫描） | 重试实战：3 次尝试内化解截断（16:04/16:06/16:12 各例） |
| 8 | 截断宽容（最后手段）：`fetch_lenient`，仅当严格×3 + 磁盘均失败；警告日志；不写磁盘 | 16:05:39 救回 50 节点（缺口 8 字节）——避免“零节点启动” |
| 9 | 面板回执语义：wait 20→60 / 15→30；超时文案「已保存；回执超时…」；手动 reload 以回执为准 | 0.74s 回执 ✓；「热重载失败」误报路径消除 |
| 10 | status `subscriptions[]`（tag/rank/at/ok/error/nodes/fails/source）+ 面板订阅表「拉取状态」列 | `/api/v1/sources` 含 `pull_*` 字段；面板显示“✓ 50 节点·3m 前拉取” |

**部署事故插曲（如实）**：15:35 首次部署后，15:40 reload **未触发后台拉取**（`sub-refresh` 线程停摆于 futex；原因未定），同时在 15:34–15:37 链路对 CF 主机**持续截断**（多 vantage 同时）、首跑无磁盘缓存 → 一度 `dialer:none`（约 35 分钟对外无出口）。重试版（16:04）部署后自愈：

- 16:04:43 源 2 第 3 次尝试成功（50 节点）→ 组 50；
- 16:05:39 源 1 宽容救回（50 节点）→ **组 100 / 活动源 2**；
- 16:11 复检：重启后启动拉取两源均一次成功 → 组直接 100。

worker 停摆现象加诊断日志后未再复现；全链路日志（“后台开始拉取/拉取完成/本轮结束”）已在位，若再现按日志定位。

**配置与运维**：

- 路由器配置：删除 `subA`（备份 `/root/backup-20261011-1534`）；新增 `subscription_update_interval: 21600`（含 schema 注册）。
- 部署产物：引擎（16:04 / 16:11 两次）、面板（16:09）；旧二进制备份在 `/root/binbak-*`。
- 内存：稳态 RSS **39.4 MB** / VmSize 80.9 MB / 20 线程（重启后瞬时值）。

---

## 12 · 72h 生产测试（2026-10-11 启动，进行中）

### 12.1 目的与判据

在真实生产环境（软路由）上连续运行 72 h，验证 §8–§11 修复批次后的稳态**有界**——这是
「bounded-memory / predictable resource consumption」表述的生产侧最后一关（I4 判据的生产侧执行；
实验室侧 `lab/perf/soak-curve.sh`（`SOAK_SECS=259200`）保持独立口径）。

| 检查点 | 判据（相对 1 h 基线） |
|---|---|
| 24 h / 48 h / 72 h | RSS / FD 漂移 ≤ 5%；失败指标（`dial_errors`、`probes_fail`）零增长 |
| 全程 | `stragglers` 恒 0；探测看门狗（cron）不触发；线程不单调上升 |

> 基线取值口径：生产负载与实验室不同（有启动爬坡段），1 h 基线的具体取法在 24 h 回填时校准并注明。

### 12.2 运行协议（测试期间操作纪律）

- **不重启引擎、不在面板触发写操作**——订阅热更新会归零 `probes_*` / `stragglers`（附 B5 已知瑕疵）
- 探测看门狗（`/root/sodama-watchdog.sh`）一旦动作（重启引擎）→ 本测试作废、重新起算
- 采样：软路由侧 60 s 写 `/root/sodama-health.tsv`；开发机
  `sh sodama/lab/prod/health-track.sh pull` 拉取、`plot` 生成 SVG（判据线内建）
- 外部扰动（网络劣化、ws 截断风暴再现、订阅端点抖动）按事件记入 12.5

### 12.3 起点与基线

- 起点：2026-10-11（引擎为 §11.7 修复批次部署后的运行世代；确切启动时刻以健康曲线首点校准）
- 1 h 基线（重启后瞬时，§11.7）：RSS 39.4 MB / VmSize 80.9 MB / 20 线程
- 组：100 成员（源 1 + 源 2）；订阅周期刷新 `subscription_update_interval = 21600`（6 h ± 10%）

### 12.4 记分板（按检查点回填）

| 检查点 | 时刻 | RSS | VmSize | 线程 | fd | stragglers | dial_errors | 看门狗 | 判定 |
|---|---|---|---|---|---|---|---|---|---|
| 基线（1 h） | 10-11 ~17:11 | 39.4 MB* | 80.9 MB | 20* | — | 0 | — | 未触发 | — |
| 24 h | 10-12 ~16:11 | | | | | | | | |
| 48 h | 10-13 ~16:11 | | | | | | | | |
| 72 h | 10-14 ~16:11 | | | | | | | | |

> `*` 为重启后瞬时值；漂移基线按 12.1 注记的口径在 24 h 回填时标定。

### 12.5 观察项（按事件追加）

- ws 帧截断风暴（§11.2-8）若再现：记录时段与规模，与 10-11 的窗口对比
- 订阅周期刷新的边界行为（6 h 抖动、429 冷却、失败源自愈重试）日志实录
- 源 1（subC）与源 2 的拉取稳定性（subA 已退役）

---

## 13 · 探测/订阅频率研究：dae 与同类内核策略对照 + 修复提案（2026-10-13）

> 背景：生产观察「订阅服务器一直被请求 + 节点延迟一直被测」（面板首页探测计数快速上涨、订阅端点 429），疑耗订阅额度与节点握手预算。本节为**纯代码研究**（无实测——路由器 SSH 当刻不可达，见 13.6）。
>
> 方法：sodama 源头审计（本仓库）+ dae 上游 clone（较新线）；同类内核**离线精读源码**：mihomo v1.19.32、sing-box v1.14.2、Xray v1.260327.0、v2ray v5.54.2（经 goproxy.cn 拉出 module zip 存 `/tmp/refproj`，未入库）。

### 13.1 sodama 现状（审计结论，全部有行号）

**订阅拉取触发点**（`loader/src/main.rs`）：

| 触发 | 位置 | fast | 每源请求量 | 频率 |
|---|---|---|---|---|
| 进程启动 | `build_groups`→`fetch_nodes` | false | ≤×3（重试） | 每次启动 |
| 配置/规则文件变更（inotify+10s 兜底） | `do_reload`→`request_sub_refresh`（L4438） | true | 60s 缓存命中=0；否则 ×3 | 每次保存后（距上次 >60s） |
| 手动 reload / 面板热重载 | `sodama reload` | false | 强制 ×3 | 手动 |
| 周期刷新 | `sub-timer` | false | ×3 | `subscription_update_interval`=21600s（6h±10%） |
| 失败源自愈 | `subscribe.rs:432 sources_need_retry`（5m→1h 退避） | false | 全部源 ×3（**缺陷**：不只失败源） | 退避节律 |

磁盘缓存 `sub-cache/*.bin` 写入**不**触发重载（`watch.rs` 逐文件名过滤，只关心 config/include/rule_set）；内存缓存 TTL `SUB_CACHE_TTL_SECS`（L197，默认 60s）；**失败源无负缓存**（缓存只在成功时写 `cache_put_sub`，L4099 `cache_get_sub`）→ 持续失败的源被每次配置保存 ×3 重打。

**延迟探测节奏**（`group.rs:720 spawn_health_loop`）：

- 每轮：`watched = watched_recently(20)` / `busy = traffic_active(base.max(30))`；
- `probe_interval_for(base=check_interval(默认 30s), cap=probe_idle_cap(默认 600s), watched, busy, idle_rounds)`（L234）：`watched||busy`→全速 base 并清零退避，否则 ×2 指数退避到 cap；
- **退避几乎永不生效**：`note_watch()`（L3787）被 `status_json()`（L7564，函数首行）打点——面板秒级轮询 + `health-track`（每分钟）+ watchdog（每 5min）+ 任何 CLI 查询；`note_traffic()`（L3791）每次 relay 建连打点，且 `conns_active>0` 直接算 busy（家庭网微流量常驻）。
- ⇒ **7×24 以 30s 全速探测全部（含死）节点**；100 成员 ≈ 28.8 万次/天经节点握手。
- 探测并发 24（L764 注记）；`check_interval`/`probe_idle_cap` 均可配置，路由器配置未显式写。

### 13.2 dae 原版怎么做（上游 clone，较新线）

1. **默认 `check_interval: 30s` + `check_tolerance: 50ms`**（`config/config.go:30-31`；tolerance 是**选路迟滞**非失败计数；全局与组级可 override）。
2. **「无消费不探测」**（`submitCheckTasks`：`if !d.hasAliveDialerSets(...)` 跳过——没有任何策略引用该 latent 就不探）；只对 routing 引用的 outbound 激活探测（`control_plane_dialtarget.go:24 ActivateCheck: referencedOutbounds` 检查）。
3. **每节点独立 timer + 冷启动随机相位**（`connectivity_check.go:829-929`：cold-start 后 `nextDelay = fastrand.Int63n(cycle)` 打散，之后按 interval）。
4. 全局探测 worker 池（ants，`calcPoolSize = clamp(40+ceil(sqrt(n)*10),40,256)`，非阻塞）。
5. **定向唤醒**：`NotifyCheck*`（checkCh/checkDnsUdpCh/checkTcpCh），带 **2s 冷却**。
6. 恢复机制（`recovery_state.go`）：`backoffLevel`+`StableSuccessCount`；`HandleNoAliveDialer`（仅错误路径）→`Resuscitate`（按 MinCheckInterval 限流）→定向唤醒；「stability-based wash white」——某协议族**有失败且无成功**才重置其评分。
7. **订阅只在启动 + SIGHUP 拉取**（`cmd/run_controlplane.go:250-330`），**无周期刷新**；`http-file` scheme 拉取成功才落盘到 `persist.d/<tag>.sub`，失败回退读缓存；失败语义 `resolvingfailed`，若「全失败且 0 节点」则**不整体替换**（保留旧状态）。

### 13.3 同类内核对照表（代码出处已核）

| 维度 | sodama 现状 | dae | mihomo 1.19.32 | sing-box 1.14.2 | Xray 26.x | v2ray 5.54 |
|---|---|---|---|---|---|---|
| 探测默认间隔 | 30s（退避 cap 600s） | 30s | **300s**（组 `groupOption.Interval=300`，`outboundgroup/parser.go:171`；provider health-check 亦默认 300，`provider/parser.go:67`） | **3min**（`constant/timeout.go:14 DefaultURLTestInterval`） | **10s**（`observer.go:74` `sleepTime := 10s`） | 1min×10 采样=10min/轮（`burst/healthping.go:57,64`） |
| 空闲是否探测 | **是（退避被污染失效）** | 否（无引用不探） | lazy 默认 **true**：轮次内无 touch 则跳过（`healthcheck.go:52`；`groupOption{Lazy:true}` `outboundgroup/parser.go:52`） | **无 Touch 不建 ticker**；idle_timeout 30min 后停探（`urltest.go Touch/loopCheck`；`DefaultURLTestIdleTimeout=30min`）；启动先探一轮 | 否（一直探） | 随 balancer 启动 scheduler（消费才探） |
| 「活跃/touch」来源 | status 查询（面板/CLI/watchdog/health-track **任何**查询）+relay 建连+conns_active>0 | 每节点 timer；定向唤醒 | 拨号路径 `Unwrap(metadata,touch=true)`/`GetProxies(true)`；**状态 API `tunnel.Proxies()` 不 touch**（`tunnel/tunnel.go:215`） | 新连接 `DialContext/ListenPacket` 首行 `Touch()`；**status 不算** | — | — |
| 死节点处理 | 无区别 | 无降频（recovery 只走错误路径） | 无区别 | 非 force 时跳过 `now-last_test < interval` 的节点（`urlTestBatch.test` history 时间戳） | 无区别 | 无区别 |
| 探测并发 | 24 | ants 40–256 | errgroup limit 10 | batch 并发 10 | 串行（EnableConcurrency 默认 false；每节点间隔 sleep） | doCheck 采样 |
| 订阅刷新 | 启动+变更+6h+自愈 | 无周期（启动+SIGHUP） | `interval` 未显式配=0=**不自动刷新**（`fetcher.go:239` `else if f.interval > 0`）；官方示例 3600；启动时缓存过旧 force 拉一次；失败 backoff（`NewFetcher`：Min=min(10s,interval)、Max=interval、×2）→**失败快重试**；hash 不变→跳过 | 无订阅 | 无订阅 | 无订阅 |
| 失败语义 | 磁盘缓存兜底；自愈重拉**全部**源 | 全失败且 0 节点不替换 | 失败保留旧内容+backoff | — | — | — |
| 手动触发 | `sodama reload` 全量 | NotifyCheck* 定向 | `/proxies/:name/delay` 单点 | urltest API(force) | observatory API | Check(tags) |
| 默认测试 URL | （路由器 config 定） | — | `https://www.gstatic.com/generate_204`（`constant/adapters.go:65`） | 用户配 | `https://www.google.com/generate_204`（`observer.go:162`） | `https://connectivitycheck.gstatic.com/generate_204` |

### 13.4 结论

1. **确认两个真缺陷（sodama 独有）**：①「看着/流量」信号被 status 查询击穿（对照：mihomo 状态 API 不 touch、sing-box Touch 只在新连接）→ 退避机制形同虚设；②订阅失败源无负缓存 + 自愈重拉全部源。
2. **「空闲即不探/少探」是主流**（mihomo lazy 默认 true、sing-box idle 停 ticker、dae 无引用不探、v2ray 随 balancer 消费）——我们的「指数退避」方向一致，但信号源不对。**「状态查询 ≠ 活跃」是最该抄的一条**。
3. 主流**都不做「死节点慢车道」**（dae 的 recovery 也只在错误路径限流）——原 A1「死节点降频」降级为可选，先修信号源。
4. 订阅 6h 周期相比 dae（无周期）偏激进但可接受；真正要修的是变更触发与失败路径（0 请求提升空间最大）。
5. sing-box 的「history 时间戳跳过」可顺手借鉴：同节点被多组共享时避免一轮内重复探测（评估项 D1）。
6. 各家测试 URL 均为 generate_204 类——无需变更。

### 13.5 修订提案（等拍板）

**P-A 探测节奏**

- **A1（核心，最小改动）**：把 `note_watch()` 从 `status_json()`（`main.rs:7564`）移除——状态查询不再视为「有人看」。`watched` 信号保留给未来的显式面板心跳；当前效果 = 探测活跃度只由 `note_traffic` + `conns_active` 驱动，安静家庭网夜间退避到 600s。
- A2（配套）：`busy` 口径评估——维持 `conns_active>0` 算忙（折衷，防误杀挂机长连用户），先不动。
- A3：路由器 config 显式写 `check_interval`、`probe_idle_cap`，配置即文档。
- **验收**：空闲夜 8h 内日志出现「空闲退避」且稳定于 cap；`probes_total` 增速昼/夜比 ≥3×；面板打开/关闭不改变探测节奏。

**P-B 订阅拉取**

- **B1**：变更触发（fast=true）只对「URL 新增/变更」的源打网；未变的源延长内存缓存 TTL 至 30min（或直接读磁盘缓存）。
- **B2**：失败源负缓存：记录 `failed_at`，`sub_fail_ttl`（默认 600s）内不重试。
- **B3**：自愈重试只拉失败源（`sources_need_retry` 传集合过滤）。
- **验收**：连续编辑 config 10 次 → 订阅端点请求数 ≤（增量源数×3）；失败源在 TTL 内 0 请求。

**P-C 观测**

- C1：`status.subscriptions[]` 增 `fetches_total`/`fetch_fail_total`/`last_fetch_at`；探测侧沿用 `probes_*`。面板可展示「今日订阅请求数」供额度自证。

**P-D 评估项（先不做）**

- D1 跨组共享成员的单轮去重（sing-box history 思路）；D2 每节点相位抖动（dae 思路）——两者都要先有 A1 落地后的真实基线再评估。

### 13.6 阻碍与待办

- 路由器 SSH 当刻不可达（`connect refused` 于 22，ping 通）——**实测验证与部署待路由器恢复**；本节的「现状」均为代码结论，无生产实测佐证。
- 拍板后实施顺序：A1 →（面板如需配合）→ B1–B3 → C1；`cargo test` + 构建部署（`lab/build-openwrt.sh` + `docs/notes/deploy-engine.sh`）。

### 13.7 实施与验证（用户拍板 a1+b+c，2026-10-13）

**落地内容**（ADR-0064）：

| 项 | 改动 | 文件 |
|---|---|---|
| A1 | `status_json()` 删 `note_watch()`；活跃度只由流量驱动；`note_watch` 降为显式心跳预留（`#[allow(dead_code)]`）；日志措辞更新 | `main.rs`（~L7683）/ `group.rs` 注释 |
| B1 | `SubFetchMode::{Full,Fast,Heal}`；`SUB_CACHE_TTL_SECS` 默认 60→**1800**；seen 集合（`mark_sub_seen`/`sub_seen`）+ Fast 走内存→磁盘、0 请求 | `main.rs` + `subscribe.rs` |
| B2 | `SUB_FAIL_TTL_SECS` 默认 **600**（global `sub_fail_ttl`）；`note_fetch_error` 记失败时刻；Fast 负缓存内不打网 | `subscribe.rs` + `config.rs` |
| B3 | `sources_need_retry()->bool` → `sources_due_for_retry()->Vec<String>`；sub-timer 发 `Heal(set)` 定向重拉 | `subscribe.rs` + `main.rs` |
| 队列 | `SubFetchMode::merge`（Full 优先；Heal 并集；Fast 最窄） | `main.rs` |
| C1 | `subscriptions[]` 增 `fetches_total`/`fetch_fail_total`/`last_fetch_at`（只由 net 推进）；status `config_watch` 增 `sub_fail_ttl_secs` | `subscribe.rs` + `main.rs` |

**验证**：

- `cargo test` **285/285**（新增：B1 seen 往返、B2 负缓存窗口、B3 定向列表、C1 计数只由 net 推进、`merge` 语义；
  注：`sticky::tests::dial_time_reresolves_after_invalidation` 存在既有并行 flaky——与其它测试共用全局 DNS mock，
  单独/串行均通过，与本轮改动无关）；
- OpenWrt 构建：`lab/build-openwrt.sh --arch x86_64` → `sodama 7.6M · sodama-ebpf 494K`；
- **部署前基线**（旧引擎，20.6h 世代）：`probes_ok=89886 / probes_fail=220057`（71% 打向死节点）、
  `probe_active=true`、`probe_interval_secs=30` 恒定；`sub_cache_ttl_secs=60`；
- **部署后**：6s 就绪，50 节点正常；`subscriptions[]` C1 字段可见（`fetches_total=1`=启动拉取）；
- **B1 实测**：`touch /etc/sodama/config.dae` → `reload-fast` → 日志 `订阅 2: 命中缓存（44.7s 前抓取，50 个节点）`，
  `fetches_total` 保持 **1**（0 网络请求）✓
- **待观察判据**：夜间无流量窗口出现「空闲退避」且 `probe_interval_secs` 稳定于 cap；
  失败源出现时日志「订阅自动重试：N 个失败源到退避窗口（…），定向重拉」且 `fetches_total` 只对失败源 +1。

## 14 · CF 额度事故：探测循环「叫醒」缺陷（2026-10-13 晚）

> 报告人：用户。现象：自建 CF EdgeTunnel Worker（Workers 免费版 100k 请求/天）当日请求
> **68,370 / 100,000**，疑为 sodama 所致；要求同时评估「是否被人盗用」与「是否我们的请求」。

### 14.1 取证

1. **节点归属**（拉回 `/etc/sodama/sub-cache/*.bin` 解析）：三个源共 116 节点全部是
   `vless+ws+tls` 指向 Cloudflare IP；当前生效的源 3（16 节点）为用户自建的 CF 线，
   源 1/2（各 50 节点）为机场 CF 系（不消耗本 Worker 额度）。
2. **量级对账**：源 3 启用后 6.0h 世代内 `probes_ok=67,619 / fail=1,895` ——
   与 CF 面板当日 68,370 **同量级吻合**（差值 ≈ 真实流量 + 少量前时段流量）。
   ⇒ CF 请求几乎 100% 是健康探测。
3. **速率异常**：16 成员 / `check_interval=30s` 的设计速率是 **0.53 探测/s**；
   实测 `(67,619+1,895)/21,695s = 3.20/s`，**6 倍超标**。

### 14.2 根因（两个叠加缺陷）

1. `traffic_active()` 包含 `conns_active > 0`（`main.rs:3822`）——家庭环境挂机长连接
   （推送保活/下载/SSH）使 `busy` **恒真**；
2. 探测循环的分片睡眠**无条件**允许「有流量就 break」（`group.rs:849-856`）：
   旧语义为“退避期间被叫醒提前恢复”，但未限制仅在退避态生效 →
   正常节奏下也每睡 1s 就 break → 探测循环变成“探完一轮喘 1 秒再来”
   （每轮 ~5s × 16 成员 → 3.2/s）。
   ⇒ 两缺陷叠加：只要家里有活跃连接，探测就以 ~6 倍设计速率 7×24 轮回。

### 14.3 修复（P37b）

1. `traffic_active` 去掉 `conns_active>0` 分支——对齐 dae/sing-box 的「活跃 = 新连接」
   （`note_traffic` 仍在新连接时打点；长连接本身不续期）。影响面只有探测节奏。
2. 分片睡眠的「叫醒」判定抽为纯函数 `probe_sleep_should_wake`（`group.rs`）：
   **仅退避态（`interval > base`）且未睡满**才允许提前唤醒；正常节奏必须睡满 `interval`。
   （新增回归单测 `probe_sleep_wake_only_while_idle`。）

### 14.4 验证（23:41 部署后）

- 240s 窗口：`dOk=112` → **0.47 探测/s**（回到设计值 0.53 ±退避交叉）——较修复前降 **6.6 倍**；
- 日志双向切换正常：`23:41:50 60s（空闲退避）→ 23:41:56 30s（活跃）→ 23:44:36 60s→ 23:45:29 30s`；
  （另：A1 的独立佐证—— 17:51:05 旧 bin 上已出现 `600s（空闲退避；无流量（状态查询不计））`，
   A1 对“状态查询不计”确实生效。）
- `cargo test` **286/286**；OpenWrt 构建 + 部署（4s 就绪，16 节点）。
- **预期额度**：活跃浏览时探测 ≈ 0.53/s → ~46k/day；空闲退避后 < 5k/day；
  加真实流量（测段 `conns_total` 增量 0.1/s ≈ 9k/day）→ 全天活跃 ~55k/100k，安全线内。

### 14.5 遗留与建议

- **盗用排查**：修复后观察 1–2h（CF 面板速率应≈探测+流量）；若仍偏高，用
  `npx wrangler tail` 看请求 IP/UA/路径定位外部来源；新 Worker 建议改强随机路径/自定义域名。
- 可选降额：`check_interval` 60–120s（配置热驱动，46k→23k→11.5k/day）。
- backlog（D 系列评估项）：对 CF/WS 类节点的周期性探测可降级为 **L4 探针**
  （TCP+TLS 握手不发 HTTP → 不 invoke Worker、不计额度），低频再做完整 L7 校准。

## 15 · AF_XDP 预研（2026-10-14，调研否决）

- 触发：新一轮 72h 生产测试数据等待期（§16）的技术预研。专文：`docs/af-xdp-research.md`。
- **结论：否决（条件性）**——三条独立理由：
  1. **硬件层**：软路由 4× Intel I211（igb 驱动）未接入 AF_XDP 的 xsk 缓冲池路径
     （`/proc/kallsyms` 中 igb 仅有 `igb_xmit_xdp_ring`，无任何 xsk 符号）→ 只能回退 `XDP_SKB`
     generic 慢路径，**比现架构（TC 分流 + 内核 TCP + splice）更慢**；
  2. **瓶颈层**：既有实测（`docs/benchmark-report.html`）瓶颈是加密与拷贝（rustls `rep_movs 46.8%`），
     非收包；该设备实际需求（<0.1 Mpps）距内核栈能力（~1 Mpps/核）两个数量级，且已在同一架构
     跑出 16.9 Gbps / 26k conn/s（远超 1GbE 物理线速）；
  3. **架构层**：代理 = 两段 TCP 终结拼接，AF_XDP 只提供“帧→用户态”，收益需配套用户态 TCP 栈
     （月级重写 + 与现有 TC/eBPF 钩子位冲突），端到端收益无法证明；生态上无一家主流代理内核采用。
- **重新评估判据**（见专文 §7）：10G+ 且驱动支持 XDP ZC / softirq 持续饱和 / 纯 L4 转发定位 /
  端到端 PoC 优于现架构 20%+——至少满足三条再立项。
- 替代优化优先级（若遇数据面瓶颈）：kTLS → io_uring/批量化 → 连接复用 → GRO/GSO/RSS 微调。

## 16 · 新一轮 72h 生产测试（2026-10-14 启动，进行中）

- 引擎：P37/P37b 修复批次（main@330225e）；订阅源 3（16 成员，自建 CF 线）。
- 重点观察项：
  1. **探测节奏（A1/P37b）**：日志「健康探测节奏 Xs（空闲退避 ↔ 活跃）」双向切换；
     `probe_interval_secs` 空闲时应爬向 cap（600s）；
  2. **CF Worker 额度**：探测设计速率 0.53/s（16 成员×30s，活跃期）；退避后 <0.1/s；
     用户侧从 CF 面板对账「探测 + 真实流量」——若显著高于此，再查外部盗用；
  3. **订阅请求（C1）**：`fetches_total` 只在启动/周期刷新（6h）/失败源自愈时增长；
  4. **内存/线程 bounded**（口径同 §12 记分板）。
- 数据回填：按 §12 协议；本轮结末时出验收记录。

## 17 · 审计修复批次 + 2d5h39m 生产数据比对（2026-10-16）

> 触发：`docs/memory-safety-audit.html` v1.0（unsafe 专项审计）产出后，用户要求「把 2d5h37m 真实运行数据调下来比对得出结论」，并拍板「直接修复」。

### 17.1 取证（引擎世代 2026-10-13 23:41:53 起，2d5h39m）

- 样本：`health.tsv` 3210 行 + `mem-track.tsv` 3215 行（1 分钟粒度）、status/metrics 快照、日志全史、socket/fd/线程现场解剖、`/proc/<pid>/net/tcp` 逐秒扫描；原始数据在开发机 `docs/notes/prod-audit-2026-10-16/`（不入库）。
- 基线：RSS 47.2 均值 / 53.5 峰 MB；线程常态 17–19；fd 随活跃连接（≈2/条 + ≈100 基座）；stragglers 全程 0；probes 110,240 / fail 140；订阅 2.2 天 10 次拉取、0 失败；UDP NAT 全零；conns 36,019 = reactor codec 36,019、splice 0。

### 17.2 审计发现 × 实况结论

| 发现 | 判定 | 关键证据 |
|---|---|---|
| H2 拨号看门狗未解除 | **实锤** | DoH 连接恰好 3s 生命周期（逐秒扫描 5/5 条）+ 端口每次更换；≈1.4 万次重连/天；`exchange_https` 重试静默吞掉失败（日志无痕）|
| M4 退出残留 | **证伪降级** | aya ≥5.7 走 `bpf_link_create`（进程退出自动解绑）；3 世代 6/6 挂载、零 EEXIST；<5.7 fallback 才成立 |
| H1/H3 | 零暴露 | splice_total=0、pipe 计数全 0（ws 负载 100% codec）|
| M1 组世代线程 | 未触发 | 日志全史无「组集合变更」；16→36 成员走 replace_members（不新建线程）|
| M2/M3 UDP 表 | 零暴露 | udp_nat 全零（无 UDP 代理会话）|

- 事件窗：00:56–01:10 上游网络事件（dial_errors 全部 1072 集中于此；线程峰 154、fd 峰 455；~15min 自愈）——顺带复核 §9（探测线程硬超时）修复持续成立、无卡死线程累积。
- P37b 达标：16 节点 32 次/分 / 36 节点 68 次/分 = 设计值；「空闲退避」仅 3 次 60s（家庭网 busy 近乎恒真，「夜间退避 600s」验收判据本环境不适用）。
- 新观察：ws 帧截断（CF 线抖动，~30 条/200 行）；DoH「400」风暴与网络事件同窗（成因未定）。

### 17.3 修复批次（已实施未部署；报告 §9 有逐文件清单）

| 条目 | 修法 |
|---|---|
| H1 | reactor `destroy` 回收改 `recycle_pipe`（pending>0 直接关闭不入缓存）+ `pipe_discarded` 计数 + 回归测试 |
| H2 | `DialWatchdogGuard`（作用域自动解除）+ `dial_udp` 对称解除 + dnsup/subscribe/bootstrap 接入 |
| H3 | 上方向线程改持 `handle.upstream` 的 fd（RELAY_CONNS 保活至双泵结束）|
| M1 | `GroupRuntime.stop` 世代停止位 + 重建前停旧世代（日志「已停止 N 个旧世代健康探测线程」）|
| M2 | `udp_nat_retire` 共用退役（reader 致命退出即摘表）|
| M3 | 回包 socket 表上限 128 + 逐出计数 |
| L1/L2/L5 | 对齐缓冲（CtlBuf/EvBuf）；recvmmsg 容量守卫；kTLS 密钥早退清理 |

### 17.4 验证

- `cargo test` **287/287**（286 基线 + 新增 1）；`cargo clippy` 无新增（余 3 条 correctness 为既有）；
- OpenWrt x86_64 交叉构建通过：`sodama 7.6M · sodama-ebpf 496K`（即部署产物）；
- 部署后判据（报告 §9）：DoH 连接生命周期 >3s、空闲 `dial-wd` 归零、`pipe_discarded≈0`、组删除后线程回落、UDP NAT 计数联动。

### 17.5 待办

- [x] 部署本批次（2026-10-16 05:44，dev@171e7e6 → main 并推送；就绪 6s，36 节点，md5 `a5aa0d09…`）；收口数据 `status-closeout.json`（conns 36,294 / probes 111,896 / stragglers 0）；回验与新一轮 72h 见 §18；
- [x] H1/H3 虽生产零暴露，已随批上线（一旦启用可 splice 链路/UDP NAT 即进入暴露面）；
- [ ] 新观察两项（ws 帧截断、DoH 400 风暴）另立观察项。

## 18 · 新一轮 72h 生产测试（2026-10-16 05:44 启动 · 审计修复批上线）

- 引擎：审计修复批次（dev@171e7e6，OpenWrt x86_64 产物 md5 `a5aa0d09…`）；部署即重启（就绪 6s，36 节点，pname 6/6）。
- **启动即回验（部署后 60s 内实测）**：
  1. **H2 修复生效（实锤对照）**：223.5.5.5:443 连接 40s 逐秒扫描——端口全程不变（修复前：恰好 3s 一换、≈1.4 万次重连/天）；
  2. 空闲 `dial-wd` 线程 = **0**（修复前常态 ≥1）；
  3. 新观测计数在位：`pipe_discarded=0`、`reply_sockets_evicted=0`。
- 新世代基线（启动 77s）：RSS 42.5 MB / HWM 43.6 MB / 线程 19 / fd 127；追踪器（health/mem-track）持续采样、计数随进程重置（B5 已知）。
- 本轮重点观察项：
  1. **H2 长稳**：DoH 连接 ≥30s 生命周期常态、`upstream_errors` 不再因重连产生；启用 UDP-over-stream 时连接不再 5s 被断；
  2. **H1/H3 前提**：splice_total 持续 0（未来启用可 splice 链路时 `pipe_discarded` 仅零星出现、无跨会话串流）；
  3. **M1 回验**：组集合变更（改名/增删组）后线程回落 + 日志「已停止 N 个旧世代健康探测线程」；
  4. **M2/M3 回验**（若启用 UDP NAT）：reader 退出即摘表；`reply_sockets_evicted` 随目的地址多样性增长而有界；
  5. 常规判据（同 §16）：探测节奏/CF 额度、订阅计数、内存与线程有界、stragglers=0。
- 数据回填：按 §12 协议；本代起点 2026-10-16 05:44（health/mem-track 持续运行）。

## 19 · 数据面对标批次：L3 变体 · ringbuf 事件 · skb_send_sock 记账 · XDP 计量（2026-10-16）

对应 `docs/backlog.md` C1/C3/C4 与 `docs/parity-status.md` 域 1 的余项；决策与偏离清单见 ADR-0065。

### 侦查（源码实测，均有行号）

1. **dae 的 L2/L3 语义**：同一逻辑传不同 `link_h_len`（以太 14 / 无链路头 0），程序成对存在
   （`SEC("tc/lan_ingress_l2")` / `_l3`）；选择逻辑在 Go 侧 `linkHdrLen()`
   （`dae/control/control_plane_core_bind.go:61-77`：netlink `EncapType` 的
   `none`/`ipip`/`ppp`/`tun` → 0，`ether` → 14，其它告警后按 14），再在 `:256-273` 选程序变体。
   L3 的 v4/v6 判定用 `skb->protocol`（`kern/tproxy.c:1103`），送控制面前补以太头
   （`rewrite_packet_for_control_plane:2253-2279`），redirect_track 不记 MAC
   （`fill_redirect_entry_from_forward_packet:2151-2164`）。
2. **dae 的事件通道**：`event_ringbuf` 256KiB + `struct dae_event` 72B +
   `send_dae_event`（reserve 写、败则 `BPF_STATS_EVENT_DROP`）+ `blocked_event_rate_limited`
   （全局 ARRAY、CAS 抢槽、读后取时、1s 窗口、键 256/257/258）——`kern/tproxy.c:611-875`。
3. **dae 的 offload 记账**：fentry 与 kprobe 双形态挂 `skb_send_sock`（非 `_locked`；后者只有
   xfrm/espintcp 调用），按 skb 的 `network_header`/`transport_header`/`tail`/`head` 重建重定向前
   四元组；键布局与 verdict 的 `peer_key` 同构，Go 侧用同一对键做背压 fuse；fentry 在无
   `CONFIG_DYNAMIC_FTRACE` 或被直接调用/trampoline 占用时会 EBUSY → kprobe 回退
   （`kern/tproxy.c:4360-4393`、`kern/include/tcp_offload.h`、`control/tcp_offload_hook.go`）。
4. **aya 生态的硬约束**（逐个源码核实）：aya-ebpf 无 `bpf_core_read`/`BpfCoreAccessors`；
   bpf 目标无 `target_has_atomic="64"`（`rustc +nightly --print cfg --target bpfel-unknown-none`
   实测只有 `target_has_atomic_load_store`）→ Rust 侧做不了 dae 的 CAS 限速；
   `RingBuf::reserve/output`、`FEntry/KProbe/Xdp::attach`、`PerCpuHashMap::get/remove` 等 API 齐备。

### 实施

- **数据面（`sodama/ebpf-rs/src/`）**：新增 `event.rs`（事件+限速）、`trace.rs`（fentry+kprobe 记账）、
  `xdp.rs`（计量探针）；`parse.rs` 拆为 `parse_ip_at(ctx, link_h_len)`（L2 读以太类型、L3 读
  `skb->protocol`，MAC 置 0）；`flow.rs` 的 `split_flow`/`redirect_to_control_plane`/
  `publish_redirect_track` 带 `link_h_len`（L3 补头 + MAC 置 0）；`progs.rs` 落 5 个 `*_l3` 变体
  + 回程按 `l3_ifindex_map` 剥头；`maps.rs` 新增 4 map、`sodama_stats_map` 容量 5→16（键 5 event_drops
  / 6 offload_sent_bytes / 7 conn_overflow / 8 account_drops）。
- **用户态（`sodama/loader/src/`）**：新增 `btfoff.rs`（纯 std BTF 解析，输出 `sk_buff` 字段偏移；
  匿名 struct/union 递归）；`main.rs` 增 `--link-hdr auto|l2|l3`（默认 auto，按
  `/sys/class/net/<if>/type` 判定 → 选 `_l3` 变体 + 写 `l3_ifindex_map`）、`--xdp`（可选挂载）、
  `attach_offload_accounting`（BTF → `trace_param_map` → fentry→kprobe 回退）、
  事件消费线程（poll+排空、1 条/秒/类型日志限速）、`offload_sent_reclaim`（键摘除时汇总）、
  status 新增 `events`/`offload_sent`/`xdp` 三块 + 9 个 metrics 计数。
- **回显夹具（loader `handle_tproxy_conn`）**：移除「最多读 8 次（≈32KB）」上限，改为读到对端关闭。
  旧上限对 >32KB 的流 shutdown(Both) → 残余数据触发 RST，现象酷似「大流被中间设备 reset」
  （曾把 L3 排障引向 MTU/隧道方向）；夹具只服务无 dialer 的 lab 会话，生产必有 dialer。
- **lab 工具链**：新增 `lab/net_offload.py`（SIOCETHTOOL 关 csum/tso/gso/gro，免 ethtool；
  解决「veth+隧道 内层校验和 PARTIAL → 对端静默丢包」；含设后回读证据）、
  `lab/tproxy_stream_probe.py`（banner 容忍的大流探针：无 dialer 会话回显夹 banner，
  用「期望载荷=已发字节」消歧剥掉 banner 后逐字节比对）。

### 验收（本机已实测）

| 项 | 结果 |
|---|---|
| 数据面构建 | `cargo +nightly build --release` 通过；section `fentry/skb_send_sock`/`kprobe/skb_send_sock`/`xdp` 均在（`llvm-readelf`）；5 个 `*_l3` 符号在（`llvm-nm`） |
| map 容量与结构 | `bpftool btf dump`：`event_ringbuf`=262144、`event_rate_map`=259、`l3_ifindex_map`=64、`offload_sent`=8192、`xdp_stats_map`=8、`sodama_stats_map`=16；`SodaEvent`=72B、`SodaTraceParam`=16B |
| BTF 解析 | 302 tests passed（含 `btfoff` 14 项）；真机 `/sys/kernel/btf/vmlinux` 解出 `network_header=184, transport_header=182, tail=188, head=200`，与 `pahole` 逐项一致 |
| 构建与 CLI | musl 交叉（x86_64）通过：`sodama 7.7M · sodama-ebpf 772K`；`--help`/`--link-hdr bogus` 行为正确；clippy 无新增 error |

### 内核级验收（QEMU 内核矩阵，内核 7.2.8-arch1-2，已实测）

按仓库既有入口 `lab/matrix.sh vm`（宿主用户即可，无需 root：QEMU 内以 root 跑 `lab.sh up && verify`）复跑，
并把本批次的三件事加进门禁/诊断项：

| 项 | 结果 | 证据 |
|---|---|---|
| 回归门禁 | **verify=PASS：12 项全绿**（原 9 项 + `l3-attach` + `l3` + `xdp`） | `lab/matrix/out/vm-kernel-7.2.8-arch1-2.log` 的 `MATRIX-RESULT`、逐项 PASS 行 |
| L3 变体选择/挂载 | ✅ 自动判定 + 挂载成功 | 日志 `link-hdr: landae3 登记为 L3（ifindex=5）`、`attached sodama_lan_ingress_l3 to landae3`，`bpftool net show` 显示 `landae3 tcx/ingress sodama_lan_ingress_l3` |
| L3 端到端 | ✅ **已过并入门禁**：`test-l3` —— 小连接（`orig_dst=1.1.1.1:8080` 证明经隧道进 tproxy）+ 512KB 逐字节一致回显（双向经 ipip 隧道），`verify` 的 `l3 : PASS` | `lab/matrix/out/vm-l3only-7.2.8-arch1-2.log`：`stream-ok bytes=524288`；`MATRIX-RESULT l3_attach=0 l3=0` |
| fentry 探针 | ✅ 挂载成功；偏移由运行内核 BTF 解出（7.2.8 与 6.18 同值 184/182/188/200）；`probe_calls` 随流量增长 | 日志 `offload 记账: fentry/skb_send_sock 已挂载`、`status.offload_sent.probe_calls` |
| 记账链路 | ✅ `kernel_bytes`/`reclaimed_bytes` 均随 offload 会话增长并释出：实测单轮 `kernel_bytes=1050069` 且 `reclaimed_bytes=1050069`；6 轮累计 `kernel_bytes=5289555`、`probe_parse_fail=0` | `status.offload_sent`（debug3 运行记录） |
| XDP 计量 | ✅ 挂载并计数：`packets=6 bytes=488 ipv4=4 ipv6=1 other=1`（quiet 时）→ 验证运行中 `packets>0 && ipv4>0` 均过 | `status.xdp`；`test-xdp` 用例 |
| L3 前向补头 helper | ✅ 内核里逐次成功：`L3 push eth change_head=0 proto=0x8`（M1 `--ebpf-debug` 采样） | trace_pipe 采样（VM） |
| `head+nh` 缺陷 | ✅ **测试抓到并已修**：探针误读 `head+0` 当版本字节（采到 `v=0x0/0x52` 即以太目的 MAC 首字节）→ 100% 解析失败；改为 `head+nh` 后 `parse_fail=0` | debug2/debug4 采样对照；`trace.rs` 注释 |
| 回程「多剥 14B」缺陷 | ✅ **抓包十六进制抓到并已修**：redirect 到 L3 设备时内核自己会去 L2 头，再 `adjust_room(-14)` 会多剥——外层 `total_length=66`（应为 80）且载荷从内层 IP 头第 14 字节起；改为「只 redirect、不手工剥头」后 512KB 回显逐字节一致 | `progs.rs::dae0_ingress_l3_reply` 注释；`vm-l3rst` 抓包（已删，结论入库） |
| 隧道 MTU/校验和治理 | ✅ 三层修复后大流稳定：ipip MTU 1466（封装 34B → 外层 ≤1500）+ 专用 underlay veth（10.30.0.0/24）+ 两端关 offload（`lab/net_offload.py`） | `lab.sh` L3 段注释；net_offload 回读行（`rx-csum=off tx-csum=off tso=off gso=off gro=off`） |
| 回显夹具上限缺陷 | ✅ **定位并已修**：`handle_tproxy_conn` 限读 8 次（≈32KB）→ 之后 shutdown 使残余数据变 RST，曾误诊为「MTU/隧道问题」；改为读至对端关闭 + 新增 banner 容忍探针 `tproxy_stream_probe.py` | `loader/src/main.rs`；本地仿真 3 场景（正常/分开发/中途关）5+1+1 次全过 |
| `net_offload.py` 段错误缺陷 | ✅ **修**：`id(buf)` 当 `ifr_data` 指针指向 CPython 对象头，内核写回直接写坏解释器堆（VM 内 4 处调用全 SIGSEGV，被 `|| true` 掩盖）；改 ctypes 取地址 + `struct.pack_into` | `net_offload.py` 头注；宿主 GET/SET 路径验证（EPERM 而非 EFAULT/段错） |

### 未通过 / 待办（诚实边界）

1. **offload 用例在本 QEMU 环境有既有抖动，今日显著加剧**：2026-10-16 重启后同机实测——
   全矩阵一轮 3 次尝试全挂（失败点：第二连 `stream_probe` 前缀读超时），
   随即做四组对照（`l3` 全配 / `NO_L3=1` / `SKIP_NET_OFFLOAD=1` / **基线 5092723 stash 后重编译**）：
   **全部 9/9 失败**（基线失败更早：首连即不通）。⇒ 与本批改动（关 offload/MTU/夹具）**无关**，
   是宿主重启后的环境因素；基线前期（会话内）记录为「记账开 4/6、记账关 5/6 通过」，
   可见通过率随宿主状态大幅波动。`offload=` 仍为信息项（不计入 PASS/FAIL 判定），
   但**下一批应把 offload 路径的「drain→注册」交接竞态列入调查**：本轮拿到两种签名——
   ①首/次连问候超时（疑似交接期丢段或核内管道未流动）；②`offload_failures=1` +
   `offloaded_total=1`（首连降级用户态泵，转发无感但背离「两连接都内核拼接」的断言）。
2. **仍属推断**：verifier 在 6.12（生产内核）上的行为、kprobe 回退路径（VM 上 fentry 直接成功，未触发回退）、
   以及 L3 在生产 tun/ppp 接口上的实际表现（lab 侧 ipip 已端到端过关）。

---

---

## 附 A · 路由器侧工具清单（**不入库**，仅存在于软路由）

| 路径 | 用途 | 部署时间 |
|---|---|---|
| `/root/reactor-probe.sh` | Reactor 接管情况取证（斜率法；只读） | 2026-10-08 |
| `/root/sodama-mem-track.sh` | 内存追迹器（每分钟采样 → `/root/sodama-mem-track.tsv`） | 2026-10-08 |
| `/root/sodama-log-archive.sh` | 日志归档 + 安全截断（cron `*/30`） | 2026-10-09 |
| `/root/sodama-watchdog.sh` | 探测停摆看门狗（cron `*/5`，冻结 ≥1800s 则重启） | 2026-10-09 |
| `/root/backup-<stamp>/` | 配置与 init 脚本改动前的备份 | 2026-10-09 |
| `/root/logs/` | 归档日志与 `watchdog.log`（持久分区） | 2026-10-09 |
| `docs/notes/deploy-engine.sh`（开发机侧） | 引擎二进制部署：备份→停服→就位→起服→就绪等待→自检 | 2026-10-09 |

> 按约定：这些脚本**不提交到项目**，只在软路由上运行；仓库内 `docs/notes/`
> 留有一份副本用于记录（该目录已在 `.git/info/exclude` 中，不会入库）。
> 对照：**实验室**脚本（`sodama/lab/**`）才是入库的可复现工件。

---

## 附 B · 遗留监控台账（截至 2026-10-11 01:30）

| # | 事项 | 现状/数据 | 建议 |
|---|---|---|---|
| B1 | 健康曲线 | 652 采样 / 10.9 h：RSS 每小时均值 48.3 → 52.8 → 51.1 MB（平台期，非单调上升）；VmSize ~93 MB 平；线程 16–66 波动；**stragglers 0/652**；fd ~160 稳定；dial_errors 4（早期后不增） | 维持采集；这是 §9.5b「残余担忧」的关闭证据 |
| B2 | 看门狗 | 从未触发（无 watchdog.log）✓；注意其动作是「重启引擎」 | 在处置 2/3 完成前，若触发重启会按新端点内容重建组，需知悉 |
| B3 | 开机自启采集 | crontab `@reboot` 行是注释；`/etc/rc.local` 存在且为空 | 把 `sh /root/sodama-health-track.sh start` 加进 rc.local |
| B4 | 日志归档 | cron */30 正常（两份归档 12.9 / 8.4 MB）；当前日志在 tmpfs | 保持 |
| B5 | 计数重置瑕疵 | `probes_ok/fail/stragglers` 随订阅热更新归零 | 已知；跨世代看进程级指标 |
| B6 | 72h 生产测试 | **已启动**（2026-10-11，§12）；判据/脚本就绪 | 按 §12 记分板回填 24/48/72 h；bounded-memory 表述待通过后启用 |
| B7 | Vision/WS 长跑 | `reactor_codec_sessions` 100%；泵失败均为客户端 RST | 继续观察 |
| B8 | P37 待验收（dev 分支已提交） | ADR-0064（A1/B1/B2/B3/C1）已部署生产；B1 实测 0 请求✓；待观察：夜间「空闲退避」日志、失败源 `Heal` 定向重拉 | **稳定观察 ≥1 晚后提醒用户合并 dev → main** |

# ADR-0064：P37——探测活跃度信号修正（A1）与订阅拉取三修（B1/B2/B3）+ 请求计数（C1）

- **状态**：已采纳（2026-10-13）
- **对应**：用户决策「a1+b+c」（先研究 dae 与同类内核策略、按修订提案实施；研究记录见 `docs/phase2-devlog.md` §13）
- **相关**：ADR-0062（fast reload / `sub_cache_ttl` 默认 60s——本 ADR 修订其默认值与缓存优先语义）、ADR-0061（P34 多订阅顺序回退）、ADR-0031/0042（订阅热更新语义）

## 背景

1. **探测退避被状态查询击穿**（生产实测基线，2026-10-13 部署前）：
   `status_json()` 首行 `note_watch()` 把**每次状态面查询**（面板秒级轮询 / health-track 每分钟 /
   watchdog 每 5 分钟 / 任何 CLI）都算作「有人在看」→ `probe_interval_for` 的空闲退避几乎永不生效。
   证据：引擎连续运行 20.6h，`probe_active=true`、`probe_interval_secs=30` 恒定；
   世代内 `probes_ok=89886`、`probes_fail=220057`（**71% 的探测打在死节点上**，约 4.2 次/秒持续探测）。
2. **订阅拉取的三个浪费**：失败源无负缓存（持续失败的源被每次配置保存 ×3 重打）；
   自愈重试触发全量拉取（连带健康源）；配置热重载（fast）全量走网络（仅 60s 内存缓存兜短窗口）。
3. **同类惯例（`docs/phase2-devlog.md` §13 源码级对照）**：
   - dae：订阅仅在启动 + SIGHUP 拉取，**不随配置热重载**；探测「无策略引用不探」；
   - mihomo：组/provider 的 `lazy` **默认 true**（无 touch 的轮次跳过探测）；状态 API `tunnel.Proxies()`
     **不 touch**；provider 未写 interval = 不自动刷新、失败走 backoff、hash 不变跳过；
   - sing-box：**无 Touch 不建 ticker**（空闲 30min 停探）；Touch 只发生在新连接；
   - Xray/v2ray：observatory 随消费方（balancer）或独立周期运行，无状态面耦合。
   ⇒ 「状态查询 ≠ 活跃」「配置热重载 ≠ 订阅拉取」是主流共识；本 ADR 将 sodama 对齐之。

## 决策

1. **A1（探测活跃度信号）**：`status_json()` 不再调用 `note_watch()`；探测节奏只由
   `note_traffic()`（relay 建连打点）+ `conns_active` 决定，安静时段指数退避到 `probe_idle_cap`。
   `note_watch()`/`watched_recently()` 机制保留（`#[allow(dead_code)]`），供未来的**显式**面板心跳使用；
   当前无任何自动打点来源。状态面新增日志措辞「无流量（状态查询不计）」。
2. **B1（配置热重载不打订阅服务器）**：引入 `SubFetchMode::{Full, Fast, Heal(set)}`：
   - `Fast`（watch 触发的 `reload-fast`）：对 `sub_seen`（曾成功拉取过的 URL）的源走
     内存缓存（`sub_cache_ttl` **默认 60s → 1800s**）→ 磁盘缓存，**0 网络请求**；
     URL 新增/变更（token 更换）自然打网；磁盘缓存缺失时兜底打网（最终一致性）。
   - 语义对齐 dae：**内容更新职责交给周期刷新（6h±10%）与手动 reload/SIGHUP（Full）**。
3. **B2（失败源负缓存）**：新增 `sub_fail_ttl`（`global` 可配，**默认 600s**）。
   `note_fetch_error` 记录最近失败时刻；`Fast` 模式对负缓存窗口内的源不打网（磁盘兜底）；
   自愈/手动/周期（Full/Heal 命中）不受限。与既有机制互补：自愈退避 300s·2^n（多久后再试）、
   429 冷却 15min（被限流后的硬冷却）。
4. **B3（自愈定向重拉）**：`sources_need_retry() -> bool` 改为 `sources_due_for_retry() -> Vec<String>`
   （到期失败源 tag 列表）；sub-timer 以 `SubFetchMode::Heal(set)` 触发——**只有失败源打网**，
   其余源走缓存；健康源不再被连带重打。
5. **队列合并**：`SubFetchMode::merge` 取更宽语义——任一 `Full` → `Full`；`Heal` 之间取并集；
   `Fast` 与 `Heal` 混合 → `Heal`（打网集合更大者胜）。
6. **C1（请求计数）**：`status.subscriptions[]` 新增 `fetches_total` / `fetch_fail_total` /
   `last_fetch_at`——只由 **net** 打网推进（memory/disk 命中不计数），用于「订阅额度自证」。

## 理由

- 把「探测成本」与「运维观测行为」解耦：看面板不再等于在用网络；这消除了家族网络中
  「面板常开 → 探针永不退避」的结构性浪费（mihomo/sing-box 同款设计）。
- 配置热重载的目标是「让配置尽快生效」，与「订阅内容是否更新」正交；dae 的分工（SIGHUP=手动拉取）
  与 mihomo 的 hash/interval 分工都指向：**热重载只做本地重编译**，网络拉取按自己的节律走。
- 失败源负缓存 + 定向重拉让订阅额度消耗与「失败面」成正比，而不是与「配置编辑次数」成正比
  （旧行为：编辑 10 次配置 = 失败源被打 30 次）。
- C1 是观测闭环：用户对「订阅服务器被请求了多少次」有可审计的数据，而不是凭感觉。

## 后果

- **正面（实测，2026-10-13）**：
  - 部署后 `status.subscriptions` 即含 C1 字段（`fetches_total=1`——启动一次）；
  - **B1 实测**：`touch /etc/sodama/config.dae` → `reload-fast` → 日志
    `订阅 2: 命中缓存（44.7s 前抓取，50 个节点）`，`fetches_total` 保持 1（**0 网络请求**）；
  - `cargo test` **285/285**（新增：B1 seen 往返、B2 负缓存窗口、B3 定向列表、
    C1 计数只由 net 推进、`SubFetchMode::merge` 语义）；
  - 修复前基线（留存对照）：20.6h 世代 `probes_ok=89886 / probes_fail=220057`、`probe_active` 恒 true。
- **代价/边界**：
  - `Fast` 在 seen 后依赖磁盘缓存：磁盘缓存被清且内存缓存过期时兜底打网（可接受）；
  - 「无流量才退避」意味着**挂机长连接场景仍保持全速探测**（`conns_active>0` 即 busy——A2 折衷，
    本轮明确维持既有语义）；
  - `Heal` 轮不刷新健康源（既定语义：内容更新由周期/手动负责）；
  - 探测计数器随订阅热更新归零的已知瑕疵（devlog 附 B5）本轮未处理。
- **待生产观察（判据）**：
  - 夜间无流量窗口出现 `健康探测节奏 60s/120s/…/600s（空闲退避；无流量（状态查询不计））`
    且 `probe_interval_secs` 稳定于 cap；
  - 失败源出现时日志 `订阅自动重试：N 个失败源到退避窗口（…），定向重拉` 且 `fetches_total`
    只对失败源 +1。

## 验证方式

- 单测：`cd sodama && cargo test` → 285 passed / 0 failed（含上述新增用例）。
- 生产：`sh docs/notes/deploy-engine.sh` 部署；`touch` 配置 → 日志 + `fetches_total` 不变（B1 实测）；
  夜间巡检 `健康探测节奏` 日志（A1 验收，见上）。
- 回归：手动 `sodama reload` / SIGHUP 仍为 `Full`（强制重拉）——不受本 ADR 影响。

# ADR-0063：P36——用户分流名单、标准格式规则集（URL 自动更新）、订阅置顶的可读配置

- **状态**：已采纳（2026-10-05）
- **对应**：用户决策「订阅配置放最前/配置像 i3wm 一样可读」「用户自己加走代理或直连的域名（默认分流覆盖不到的）」「分流规则独立成文件、支持标准格式、配置里填更新地址自动下载（像其他客户端）」
- **相关**：ADR-0005（.dae 语法兼容）、ADR-0031（订阅/组）、ADR-0037（`qname(file:)` 名单与「缺失硬失败」口径）、ADR-0062（inotify 热驱动——名单文件一并在监听集合内）

## 背景

1. **配置可读性**：网关模板/用户配置此前以解析顺序堆放（global 在首、订阅未必在最前），
   不利于「从上往下读」的运维习惯；用户希望像 i3wm 配置那样分区带注释、一眼看清。
2. **用户自定分流**：默认分流（私网/UDP/兜底）覆盖不到长尾域名；用户需要最小成本的
   「强制走代理 / 强制直连（eBPF real-direct）」名单，且改完立即生效。
3. **规则集生态**：Clash/sing-box 用户习惯从 URL 拉取标准格式规则集（rule-provider /
   rule-set），本仓库此前只有内联 dae 规则 + `geosite:`（v2ray .dat）+ `qname(file:)`；
   缺少独立的规则文件与自动更新。

## 决策

1. **配置布局（i3wm 风格）**：模板与用户配置统一为六段带标题注释、**订阅置顶**：
   ① subscription（顺序=优先级）→ ② rule_set → ③+④ routing（用户自定义在最前，默认分流在后）
   → ⑤ dns → ⑥ global（运行参数）。reload 顺序即分词顺序：用户名单先命中先用。
2. **`rule_set { tag: 'url|路径' }`**（config 新 section）：
   - **标准格式自动识别**：Clash rule-provider YAML（`payload:` 下 `DOMAIN,`/`DOMAIN-SUFFIX,`/
     `DOMAIN-KEYWORD,`/`DOMAIN-REGEX,`；classical 三列列表同解析，只取前两列）、
     sing-box rule-set JSON v1（`domain`/`domain_suffix`/`domain_keyword`/`domain_regex`）、
     纯文本域名列表（`#`/`//` 注释；`full:`/`suffix:`/`keyword:`/`regex:` 前缀；裸条目=suffix）；
   - 非域名条目（IP-CIDR/GEOIP/PROCESS-NAME…）**如实计数**（日志 + `status.rule_sets[].ignored`），
     不静默丢弃；
   - **远程 URL 自动下载 + 本地缓存**：缓存目录 `global.rule_set_cache_dir`
     （缺省 XDG cache → `~/.cache` → `/var/cache` → `/tmp`）；按
     `global.rule_set_update_interval`（缺省 86400s）刷新，**0 = 每次 reload 都刷新**；
     刷新失败回退旧缓存（日志警示），无缓存则**硬失败**（保持「缺失不静默降级」口径）；
   - 路由引用：`domain(ruleset: tag)`（编译期展开为 full/suffix/keyword/regex 域名集合，
     与 `domain(geosite:)` 同机制）；**空名单**（只有注释）编译为「永不匹配」哨兵
     （`sodama-empty.invalid`）并记 note，避免刚建文件就打断 reload。
3. **用户名单文件**：随附 `rules/user_proxy.txt` 与 `rules/user_direct.txt`（纯文本、
   带语法注释），配置里以相对路径引用；**加入 inotify 监听集合**（`RULESET_FILES`）——
   编辑名单文件即触发热重载（毫秒级），无需改 config。
4. **部署一致性**：gateway.sh 的默认配置发现不变；模板 `lab/gateway.dae` 同步新布局与
   用户名单引用（`rules/*.txt` 相对配置目录解析）。

## 理由

- 规则集是「数据」而不是「语法」：把标准格式解析收敛在一个模块（`ruleset.rs`），
  编译器只消费（full/suffix/keyword/regex）四元组，规则引擎零改动即可复用 geosite 的成熟路径。
- 「URL + 间隔 + 回退旧缓存 + 无缓存硬失败」把在线更新（类 Clash/sing-box）与
  离线/断网可用性平衡在同一策略里；缓存目录链保证无 home 的软路由也能找到可写位置。
- 用户名单加入 inotify 让「加域名」与「改配置」体验一致（保存即生效，不重启、不断网）；
  空名单哨兵避免「刚创建文件就硬失败」这种反直觉行为。

## 后果

- **正面（实测，2026-10-05）**：
  - lab `ruleset-up`/`test-ruleset`：三种格式端到端生效（与 fallback 相反的判定：
    clash→direct 能到 WAN、json→proxy 产生 `RELAY <ip>:9999` 日志、plain→direct）；
    状态面 `rule_sets` 计数与 `ignored` 断言（Clash/sing-box 各 1 条 IP-CIDR 被忽略）；
    **URL 内容更新**（interval=0 + SIGHUP 重拉）后 `plain.test` 判定从直连翻转为代理；
    **未知规则集** `domain(ruleset: nope)` → reload `ok=false` 且旧槽保留（端到端仍通）；
  - 真网关：配置重排后 `sudo lab/gateway.sh up` 零行为参数启动、`gateway.sh test` PASS；
    向 `~/.config/sodama/rules/user_proxy.txt` 追加 `openai.com` → **1s 内**日志出现
    `检测到配置变更（inotify）→ 自动 reload` + `规则集 user_proxy: 1 条域名` +
    `geoexp: domain(ruleset:user_proxy) → 1 条域名`（订阅缓存命中，fast reload）；删除同样生效；
  - `cargo test` **264/264**（新增 Clash/JSON/纯文本三解析用例）。
- **代价/边界**：
  - 规则集仅覆盖**域名**维度（IP/端口/进程等仍写在 routing；非域名条目只计数不生效）；
  - SRS（sing-box 二进制 rule-set）未支持（JSON 形态同源，可先用 JSON）；
  - 空名单哨兵会在 `note` 里出现（如实标注，不影响匹配）；
  - 远程规则集的缓存写入失败只警示（本次仍可用），刷新受 interval 限制（0 时每次 reload 重拉）。
- **文档化的边界**：`qname(ruleset:)`（DNS 侧）未实现——DNS 路由继续用 `qname(file:)`/`geosite:`。

## 验证方式

- `cargo test --release` **264/264**；
- lab：`sudo lab/lab.sh ruleset-up && sudo lab/lab.sh test-ruleset`（三格式/计数/URL 刷新/未知集硬失败）；
- 真网关：编辑 `rules/user_proxy.txt` 观察 1s 内热生效（日志证据）；`gateway.sh test` PASS；
- 回归：`test-subscribe`、`test-sub-order`、`test-domain`、`test-config-reload`（规则/订阅路径不变）。

## 相关

- 实现：`loader/src/ruleset.rs`（新增）、`loader/src/rules.rs`（`parse_and_compile_full` +
  `domain(ruleset:)` + 空名单哨兵）、`loader/src/config.rs`（`rule_set` 段校验/提取、
  `GLOBAL_KEYS` 增 `rule_set_update_interval`/`rule_set_cache_dir`、translate `ruleset` key）、
  `loader/src/main.rs`（`RULESET_STORE`/`RULESET_FILES`、状态面 `rule_sets`、inotify 监听名单文件）；
- 部署/夹具：`lab/gateway.dae`（新布局）、`lab/rules/user_{proxy,direct}.txt`、
  `lab/lab.sh`（`ruleset-up`/`test-ruleset`）、`lab/sub_server.py`（`SUB_EXTRA_ROUTES`）、
  `lab/fake_dns.py`（`plain.test`）。

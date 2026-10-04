# ADR-0033：P17 规则语言收尾——geoip/geosite 展开（.dat）+ pname（cgroup2）

- **状态**：已采纳（2026-10-04）
- **对应**：P17（对标表缺口 #4「geoip/geosite/pname」）；P17a geodata、P17b pname
- **相关**：ADR-0011（配置子集/deferred）、ADR-0014（domain regex）、ADR-0030（嗅探/Target）、
  ADR-0032（IPv6）、NOTES §11.24；上游对照 `pkg/geodata`、`component/routing/optimizer.go`、
  `control/tproxy.c`（cgroup 六钩子 / `cookie_pid_map` / `match_set.pname`）

## 背景

- 对标表缺口 #4：dae 支持 `dip(geoip:cn)`、`domain(geosite:cn[@attr])`、`ext:file:code`、
  `pname(curl)`；sodama 此前把带 key 参数与 `pname()` 整条列入 deferred（覆盖度规则引擎 ≈75%）。
- 上游机制（研究结论，见 NOTES §11.24 证据行）：
  - geodata 是 v2ray protobuf `.dat`（`GeoIPList/GeoSiteList`），由
    `DatReaderOptimizer` 在规则归一化链中展开；`geoip:cn` ≈15,357 CIDR（v4+v6）、
    `geosite:cn` ≈6,623 域（suffix/full/keyword/regex 四类）；搜索目录含
    `DAE_LOCATION_ASSET`；缺文件/缺 code/inverse_match 都是硬错误；
  - pname 由 **6 个 cgroup2 钩子**（sock_create/release、connect4/6、sendmsg4/6）按
    socket cookie 采集 `{pname, pid, last_seen}` 写入 `cookie_pid_map`；TC 侧只在
    **WAN egress 新连接**（TCP SYN / UDP 首包）用 `bpf_get_socket_cookie(skb)` 反查，
    16 字节定长精确比较；LAN 方向没有 `skb->sk`，正规则不命中、`!pname` 命中；
  - `MergeAndSortRulesOptimizer` 对非 ip/sip 函数参数按 (key, val) **字符串序**排序，
    `DeduplicateParamsOptimizer` 去重——对拍可见。

## 决策

### A. geoip/geosite（P17a）

1. **数据读取**（`loader/src/geodata.rs`，手写极简 protobuf，无新依赖）：
   `GeoIPList/GeoSiteList` 整文件遍历、按 code 命中即返回；code 大小写不敏感；
   `geosite:code@attr` 按 `Domain.attribute.key` 大小写不敏感过滤；`ext:<file>[:<code>]`
   （文件名缺 `.dat` 自动补）；`inverse_match` 硬错误（与 dae 一致）。
   搜索目录：`--geodata-dir`（sodama 扩展）> `$DAE_LOCATION_ASSET` > 配置文件目录 >
   `/etc/dae` > `/usr/local/share/dae` > `/usr/share/dae`。文件/展开结果按
   (dir, code) 进程内缓存，懒加载（无 geo 规则不碰磁盘）。
2. **编译期展开**（`rules.rs`）：`dip/sip` 的 `geoip:`/`ext:` 参数展开为裸前缀
   （v4 → v4-mapped+96，v6 原样；前缀长度校验），**排序 + 去重**后再插 LPM；
   `domain` 的 `geosite:`/`ext:` 展开为域名参数，按类型映射
   Plain→keyword、RootDomain→suffix、Full→full、Regex→regex（dae 同），
   首次出现顺序分组、组内去重。
3. **容量**：LPM 内层模板 `max_entries` 1024 → **2,048,000**（对齐 dae `tproxy.c:75`；
   NO_PREALLOC 下无预分配开销）；超过上限在编译期报错（不截断）。
4. **匹配执行**：域位图的字符串匹配改为编译期预计算索引——suffix/full 用 Hash 集合
   （suffix 按 qname 的点后缀枚举，O(labels)）、**支持前导点语义**（`.example.com`
   只匹配子域，dae ahocorasick 同义）；keyword/regex 维持线性（模式数通常小）。
5. **配置语法**：`.dae` 提取器透传 `geoip:/geosite:/ext:` 参数；值允许 `file:code`
   多段冒号；词法把词内 `!` 当普通字符（`geolocation-!cn`）；`ipversion(6)` 解禁
   （P16 数据面已支持，提取器此前仍在 deferred）。
6. **对拍**：Go harness 接入 `assets.NewLocationFinder`；`parity.sh` 生成夹具并设置
   `DAE_LOCATION_ASSET`，新增 `rules.geoip.dae`（v4+v6、多 code）。

### B. pname（P17b）

7. **eBPF**（`ebpf-rs/src/cgroup.rs`）：6 个 cgroup 程序（section `cgroup/sock_create`、
   `sock_release`、`connect4/6`、`sendmsg4/6`），全部返回 1（放行，绝不阻断业务）；
   按 `bpf_get_socket_cookie(ctx)` 写/刷新/删除 `cookie_pid_map`
   （`SodaPidPname{pname[16],pid,last_seen}`；HASH + `BPF_F_NO_PREALLOC` + 65536，dae 同）。
   **pname 取 `bpf_get_current_comm`**（≤15 字节）；dae 优先读 argv[0] basename
   （CO-RE + `bpf_loop`）——见差异。
8. **TC 侧**（`flow.rs` + `route.rs`）：仅在 `is_wan && new_flow` 时反查 cookie →
   pname 存入规则上下文；新增 match 类型 `Pname = 8`（= dae `MatchType_ProcessName`），
   值区即 16 字节进程名（dae `match_set` union 同布局），`is_wan && 16B 相等`
   才置命中；`!pname` 在 pname 为空（LAN/降级）时命中（dae 同）。
9. **控制面**：`pname(curl)` 支持多值 OR 与 NOT；16 字节截断（记 note，dae 记日志）；
   装载时挂 cgroup2 钩子（第一个 cgroup2 挂载点；`CgroupAttachMode::Single`），
   任何失败只告警继续（规则不命中，dae 同）；状态面新增
   `pname{driver,enabled,hooks,map_entries,hits}`，metrics 加
   `sodama_pname_{hooks,map_entries,hits}`；命中计数在规则 VM（`SODAMA_STAT_PNAME_HITS=4`）。
10. **对拍**：harness 增加 `ProcessName` 分支（16B NUL 截断渲染）与
    `rules.pname.dae`（单值/多值排序/NOT）。

## 理由

- geodata 展开放在**编译期**：数据面零改动（复用 LPM 与域位图机制），与 dae 的
  optimizer 链位置一致；整文件解析对 MB 级文件 <50ms，换来实现极小、可单测。
- pname 复用 dae 的「cgroup 采集 → cookie 反查」链路而不是在 TC 里读 current：
  qdisc/softirq 上下文里 current 不保证是发包进程；cookie 是内核保证的归属。
- 所有能力保持「**不静默丢失**」：能编译的编译，不能编译的 deferred（未知函数），
  能展开但数据缺失的**硬失败**（保持旧规则/拒绝启动），绝不部分执行语义。

## 与 dae 的差异（如实）

- **pname 来源**：comm（15 字符）vs dae 的 argv[0] basename（CO-RE 读 `mm->arg_start`，
  可绕过 setuid/线程改 comm 的场景）。常见进程（curl/python3/docker-proxy）一致；
  对 comm 被改写或多名字进程（如 chrome 子进程）可能不同。需要时按修订条件扩展。
- **geodata 解析**：整文件遍历（有 256MiB 级内存保护的必要性低；单 entry 解析后即丢弃），
  dae 为按 code 流式 seek；无 XDG 搜索目录；`--geodata-dir` 为 sodama 扩展。
- **domain 组顺序**：dae 对 domain 参数按 (key,val) 排序，sodama 按「首次出现顺序」分组。
  位下标在两边各自自洽（域位图与规则 VM 同源），端到端语义一致；仅内部下标不同
  （对拍不比较 domain 负载）。
- **geosite 未纳入逐字节对拍**（对拍格式只覆盖 LPM/pname 等负载；域集合由单测 +
  真实数据计数 + 端到端验证，见验证方式）。
- cgroup2 钩子挂根 cgroup（系统级），与 dae 相同；容器/自定义 cgroup 层级的可见性
  受 cgroup namespace 影响。

## 后果

- **正面（实测）**：
  - `cargo test --release` **131/131**（新增 geodata 解析/展开、索引语义、pname 编译用例）；
  - 规则对拍 `parity.sh` **5/5 逐字节一致**（含 `rules.geoip.dae`：v4+v6/multi-code；
    `rules.pname.dae`：多值排序与 NOT）；
  - lab：`geo-up`+`test-geo`（geoip LPM 集合内直连/集合外代理；geosite 经 DNS 位图
    走代理）；`pname-up`+`test-pname`（python3 命中直连、curl 走 fallback 代理、
    `cookie_pid_map` 可见进程名、状态面 hooks=6/hits≥1）；
  - 真实数据：`geoip:cn` **15,357** 前缀、`geosite:cn` **6,576+44+3** 域、
    `geolocation-!cn` **25,024** 域，编译 ~40ms（与上游数据清点一致）；
  - 回归：`verify` 9/9、DNS 6/6、订阅 3/3、config 7+1、`test-v6` 3/3；
  - 真机网关：cgroup2 钩子 6/6、v4 204 / v6 200 不回归。
- **负面/代价**：cgroup2 钩子为系统级（每 socket 一次采集 + 30 字节/条目，LRU 无；
  由 `sock_release` 删除）；geoip 大集合（`geoip:us` ≈29 万前缀）会放大编译与
  reload 时间（一次性，~百 ms 级）。
- **风险**：cgroup attach 失败是静默降级（有日志/状态面），排障时先看
  `status .pname.hooks`；comm 与 argv 差异见上。

## 验证方式（实测）

1. 单测：protobuf 读写（测试编码器）、attr 过滤、类型映射、ext/搜索目录/缓存、
   `split_ext`；展开→编译（LPM 排序去重、域集 key 顺序、notes）；domain 索引
   （前导点/裸域/子域/大小写）；pname 编译（单值/多值排序/NOT/截断/非法输入）。
2. 对拍：`lab/parity.sh`（5 个规则集，含 geoip 与 pname）。
3. lab：`geo-up`+`test-geo`；`pname-up`+`test-pname`（cgroup2 钩子需 root）。
4. 真实数据清点：`--compile-dump` + `/usr/share/v2ray/{geoip,geosite}.dat`
   （见「正面」数字）。
5. 全量回归 + 真机网关（见「正面」）。

## 修订条件

- pname 对齐 argv[0] basename（CO-RE/`bpf_loop` 可用时）、或需要 cgroup 路径过滤
  （只对某些进程树生效）时，新写 ADR 扩展。
- geosite 需要纳入逐字节对拍、或需要 XDG 搜索目录/流式解析/XDG 大文件保护时。
- 需要 `dip(geoip:...)` 的 inverse_match、geodata 热更新（订阅式）时。

# ADR-0014：P3b-2a 范围与边界——`domain(regex:)` 与 EDNS 处理（DO 位缓存键 / UDP 按客户端尺寸截断）

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 P3（DNS）第三阶段（P3b-2a）；细化 ADR-0013 第 2、7 条
- **相关**：ADR-0013（P3b-1 缓存/TCP DNS）、ADR-0012（P3a 域位图）

## 背景

ADR-0013 把 P3b-2 的边界列为「DoH/DoQ、`domain(regex:)`、嗅探 punt、`dns.routing` 分流、
EDNS 参数区分、乐观/陈旧缓存」。其中有两项不需要等协议栈依赖、且直接关系到配置语义与
协议正确性，先做（P3b-2a）：

1. `domain(regex: …)` 目前整条规则进 deferred（规则级原子），是配置兼容性的缺口；
2. 缓存命中时按 qname/qtype 取应答、忽略客户端 EDNS 参数，会出现两类问题：
   - DNSSEC：DO=1 的查询会拿到不带 RRSIG 的缓存应答（或反之）；
   - 大应答：no-EDNS 客户端（512 上限）可能收到超过 512 的 UDP 报文。

## 决策

1. **regex 域名规则照 dae 语义实现**（对照 `component/routing/domain_matcher/ahocorasick_slimtrie.go`）：
   - 模式在**编译期**编译（Rust `regex` 1.x，RE2 语法系，与 Go `regexp` 对齐；
     对照 dae `regexp.Compile`），编译错误是**硬失败**（不是 deferred）；
   - 匹配对象是**小写化、去尾点**的 qname；模式保持原大小写、非锚定匹配
     （对照 dae `MatchString`）——即大写模式在 dae 语义下永不命中，mini-dae 保持一致；
   - 数据面不需要认识 regex：位图位下标照旧 = match_set 位置，匹配发生在用户态。
2. **EDNS 解析与缓存键**：`query_edns()` 解析 OPT（payload size / DO 位 / options）。
   DO 位入缓存键（DO=1 与 DO=0 分属不同条目）；**带 EDNS options（ECS 等）的查询不入
   缓存、也不命中缓存**（选项会改变上游应答；我们不解析 ECS，宁可不缓存）。
3. **UDP 截断**：发给客户端的最终 UDP 应答按客户端公布尺寸截断——无 EDNS = 512
   （RFC 1035），有 EDNS = 公布值（下限 512）。截断 = 清空 answer/authority/additional、
   置 TC=1、保留 question，若原应答带 OPT 则在尺寸允许时一并保留。**缓存与位图始终基于
   完整应答**；TCP 不截断。
4. **细化 ADR-0013 第 2 条**：命中应答的 TTL 递减覆盖 answer/authority/additional 的
   普通 RR（对照 dae `setRecordTTL`：只跳过 OPT，OPT 的 TTL 字段是扩展 rcode/flags）。
   ADR-0013 写的「additional 与 OPT 不动」收窄为「仅 OPT 不动」。
5. **配置栈同步**：`config.rs` 的 `translate_function` 接受 `domain(regex: …)` 并透传给
   mini 规则编译器；非法正则在加载器编译规则时**硬失败**（启动或热重载报错）。
   注意：`validate` 阶段只做规则翻译不编译正则（与 dip/dport 等标量在翻译期做格式检查
   不同），正则合法性以加载器编译为准。
6. **边界（剩余 P3b-2，留待后续 ADR）**：DoH/DoQ、嗅探 punt（`ROUTE_STATE_DNS_QUERY`）、
   `dns.routing` 请求/应答分流、ECS 等 options 的独立解析与缓存分区、乐观/陈旧缓存。
7. **验收口径**：regex 端到端（命中走 tproxy、不命中直转）+ EDNS 端到端（no-EDNS 被
   截断 TC=1、EDNS 4096 完整、缓存命中仍按客户端尺寸截断、TCP 完整、上游只查一次）+
   单测（regex 位图/大小写语义、EDNS 解析、截断、DO 位键分离、options 不缓存、
   additional TTL 递减但 OPT 不动）。

## 理由

- regex 与 EDNS 都不依赖新协议栈，却分别补上「配置能写但跑不了」与「缓存引入的协议
  错误」两个实质缺口；先落地能把 P3b-2 剩余项收窄为纯协议栈工作。
- 与 dae 逐条对齐（匹配语义、硬失败、OPT 跳过），避免日后对拍出现行为漂移。
- 截断与缓存解耦（缓存完整、出站裁剪）保证 TCP 与 EDNS 客户端拿到完整数据，同一份
  缓存条目服务所有尺寸。

## 后果

- 正面：`domain(regex:)` 不再 deferred，配置兼容面完整覆盖四种 domain key；
  DNSSEC 客户端不会被错误缓存污染；小 buffer 客户端收到合法的 TC=1 并回退 TCP；
  `big.test`（60 条 A）在三类客户端上行为可验证。
- 负面/代价：带 EDNS options 的查询永远直连上游（未做 ECS 分区缓存），
  高频 ECS 场景损失缓存命中；truncate 会丢弃 additional 里的非 OPT 记录（合法，
  但客户端需重试 TCP 才能拿到）。
- 风险：Rust `regex` 与 Go `regexp` 在极端模式（如 `\p{…}`、回溯引用不支持）上仍有
  细节差异；两边都不支持回溯引用，常用的字符类/量词/分组均已覆盖。未来若发现差异，
  按「规则编译对拍」的方式补语料。

## 验证方式（实测）

- `cargo test --release`：28/28（新增 5 个：regex 位图与大小写语义、EDNS 解析与尺寸下限、
  UDP 截断置 TC/清 answer/保留 OPT、DO 位键分离与 options 不缓存、additional TTL 递减
  而 OPT 不动；config 测试增加 regex 规则翻译断言）。
- `lab.sh regex-up && test-domain-regex`：`api1.regex.test → 10.9.10.21` 走 tproxy、
  `web.regex.test → 10.9.10.23` 内核直转；`domain_sets=1 bitmap_matched=1
  domain_routing=1`。
- `lab.sh dns-up && test-dns-edns`：no-EDNS（512）得到 `tc=1 ancount=0`；`--edns 4096`
  得到 `tc=0 ancount=60`；再查一次 no-EDNS 仍截断（缓存存完整应答）；`--tcp` 得到
  `ancount=60`；假上游 `QUERY big.test` 仅 1 次。
- 回归：`lab/parity.sh` 逐字节一致；标准拓扑 verify 9/9；
  `config-up + test-config + test-status` 通过（`real-user.dae` supported 6 / deferred 1）。

## 修订条件

剩余 P3b-2 项（DoH/DoQ、嗅探 punt、`dns.routing` 分流、ECS 分区、乐观缓存）落地时，
新写 ADR 取代本条第 6 条；若 Rust/Go 正则语义差异在真实规则上被观察到，需在 `lab/parity/`
增加 regex 语料对拍并修订第 1 条。

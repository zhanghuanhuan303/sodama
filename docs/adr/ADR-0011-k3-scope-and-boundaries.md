# ADR-0011：K3 范围与边界——全量解析、子集编译（显式 deferred）、只读状态面、过渡一跳

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 K3（生态接入）
- **相关**：ADR-0005（配置 100% 兼容）、ADR-0004（协议栈梯度）、ADR-0008（部署形态）

## 背景

K3 要求「全量 `.dae` 解析 + 只读状态面 +（可选）Go 后端过渡一跳」，验收是「拿一份真实
用户配置与节点跑通」。推进时有三处必须先定义清楚，否则会把「跑通」变成语义错误：

1. **全量解析 ≠ 全量编译。** 真实用户的路由规则大量使用 `domain(geosite:…)`、
   `dip(geoip:…)`、`pname(…)`，而这些依赖域位图（P3）、geodata、进程归因（未实现）。
   若为了「跑通」静默删掉这些规则，本该走代理的域会落到 fallback——这是最危险的
   失败模式（不报错、只表现为行为错误）。
2. **只读状态面不能引入新的并发/写路径。** `Ebpf` 与全部 map 由主循环独占。
3. **过渡一跳不能污染配置语言。** ADR-0005 要求 100% 兼容 `.dae`，因此后端出口
   不能表现为新增配置键。

## 决策

1. **解析全量，schema 与 dae 对齐**：词法/语法对照 `pkg/config_parser` 与
   `dae_config.tokens`；include 对照 `config_merger.go`（仅 `.dae`、必须在入口目录下、
   权限 `mode & 0o037 == 0`、同一文件重复包含即报循环、glob、父在前子在后）；
   schema 对照 `config.go`/`parser.go`（未知 section/key 报错、`global`/`routing` 必填、
   `group.policy` 必填、`dns.routing.{request,response}.fallback` 必填）。
   诊断一律带 `文件:行号`。
2. **子集编译 + deferred 显式上报**：`routing` 段逐条翻译；**任何一条规则含未实现能力
   就整条列入 `deferred`**（绝不部分编译），并在启动日志与状态面列出（文件:行号、规则
   原文、原因）。`--strict-config` 可把 deferred 变成硬失败。K3 阶段用户组统一映射
   `proxy = 0x02`（单用户组模型），`fallback` 同映射。
3. **状态面只读**：`--status-socket <path>` 暴露 Unix socket；每连接一行命令、一行 JSON。
   只接受 `status` / `rules` / `config` / `maps` 四个查询；请求经 mpsc 交给主循环
   （唯一持有 `Ebpf` 的线程）执行，服务线程不触碰任何 map，不存在并发与写路径。
4. **过渡一跳用 CLI flag**：`--forward socks5://host:port`，tproxy 接受连接后以
   SOCKS5 CONNECT 原始目的地址交给后端并双向拷贝；不新增任何配置键。
   注意 accept 线程生活在 daens，后端必须**从 daens 可达**（实验里跑在 daens 的
   `127.0.0.1`；真实部署可以是 daens 能路由到的任何 SOCKS5）。
5. **验收口径**：「跑通」= 真实用户风格配置（`global`/`subscription`/`node`/`group`/
   `dns`/`routing`）全量解析与校验通过；可编译子集在 lab 数据面生效；
   deferred 显式上报；状态面可查询；节点协议执行仍属 P5（本阶段节点仅解析与展示）。

## 理由

- 显式 deferred 把「未实现」变成可观测事实，而不是行为差异；这也是后续 P3/P5 的待办清单。
- 状态面走 channel 串行化，复用了「主循环独占 Ebpf」的现有事实，零锁、零并发风险。
- 一跳用 CLI flag 是唯一不动配置语言的做法；同时它就是 P5 原生协议栈的替换点
  （换成 `Dialer` 后删除 flag 即可）。

## 后果

- 正面：真实配置可直接喂给工具链（`validate`/`export-config`/`extract-routing`）；
  `example.dae` 一次通过；状态面为后续运维面（P6）提供最小雏形；一跳证明了
  「内核侧保留 orig_dst + 协议出口外置」这一过渡形态可行。
- 负面/代价：`geoip` 规则目前必然 deferred（无 geodata），K3 的「真实配置」在纯
  geo 场景下可编译规则可能很少；组名→`proxy` 的塌缩在多组策略下会丢失区分度
  （P5 引入 Dialer 梯度后消解）。状态面协议未做鉴权（Unix socket 本地文件权限兜底），
  公网暴露不在范围内。
- 风险：把 deferred 规则当「已支持」使用会造成流量落 fallback；缓解是日志/状态面
  显式计数 + `--strict-config`。

## 验证方式（实测）

- `mini-dae validate lab/real-user.dae`：6 个 section 全解析、schema 通过；
  routing 7 条规则 → 5 条可编译、2 条 deferred（domain/geoip，带行号与原因）。
- `mini-dae validate`（dae 官方 `example.dae`，chmod 640）：schema 通过；
  6 条规则 → 1 条可编译、5 条 deferred（pname / 含 IPv6 的 dip / geoip×2 / domain）。
- `lab.sh config-up && test-config && test-status`：配置驱动 proxy 生效；
  状态面返回 rules=11、conn_state≥1、hooks=5、deferred=2、fallback=proxy；
  未知命令被拒绝（只读语义）。
- `lab.sh forward-up && test-forward`：客户端收到
  `socks5-backend: target=1.1.1.1:8080`，SOCKS5 侧日志含 `CONNECT 1.1.1.1:8080`，
  orig_dst 一跳保留。
- 标准与单臂拓扑全量回归：各 9/9 PASS（新增 status 用例）。

## 修订条件

P3 完成域位图后，`domain` 规则应从 deferred 转为可编译（届时 `extract_routing` 的
deferred 列表变化需要新 ADR 记录域位图语义）；P5 原生 Dialer 落地后，`--forward`
转为兼容/调试用途。若将来需要多用户组语义，另行 ADR 定义组→outbound 的映射。

# 规则编译对拍工具（dae ↔ mini-dae）

用 **dae 自己的 Go 编译器** 编译 mini-dae 的 `.dae` 规则子集，输出与 mini-dae 侧
相同格式的 match_set dump，用于逐行 diff 验证 `loader/src/rules.rs` 的编译结果
与 dae 原版最终写进 BPF map 的数组完全一致。

## 怎么跑

```sh
# 参数是规则文件（mini 语法，见下），输出契约格式的 dump 到 stdout
mini-dae/lab/parity/run.sh mini-dae/lab/rules.dae
mini-dae/lab/parity/run.sh mini-dae/lab/rules.reload.dae
# P16：IPv6 前缀（quoted mini 语法）也逐字节对拍
mini-dae/lab/parity/run.sh mini-dae/lab/rules.v6.dae

# 自检（expected/ 下是本机已验证的黄金输出）
mini-dae/lab/parity/run.sh mini-dae/lab/rules.dae \
    | diff -u mini-dae/lab/parity/expected/rules.dae.dump -
```

`run.sh` 做的事：

1. 若 `dae-work/` 不存在（或 `PARITY_RESYNC=1`），把 `DAE_SRC`
   （默认为本仓库同级的 `dae/`，即 `mini-dae/lab/parity/../../../dae`）整树复制到 `dae-work/`，**排除 `.git`**；
   原始 clone 全程只读。可用 `DAE_SRC=/path/to/dae` 覆盖。
2. 把 `zz_parity_dump_test.go` 同步进 `dae-work/control/`。
3. 在副本里跑
   `PARITY_RULES=<file> PARITY_OUT=<tmp> go test -tags dae_stub_ebpf -count=1 -run '^TestParityDump$' ./control`，
   成功则把 `PARITY_OUT` 的内容（纯 dump，无 go test 杂音）打到 stdout。

环境：go 1.27.1；首次运行需要从 `proxy.golang.org` 拉依赖（见「注意事项」）。
`dae_stub_ebpf` 构建标签让 `control` 包用未提交的 `control/bpf_stub.go`
替代 bpf2go 生成物，因此**不需要 eBPF 工具链、不需要 root**。

## 输出契约

每行一条 match_set，按数组顺序，无标题、无空行：

```
slot <i> type=<Type> not=<0|1> outbound=0x<两位hex> mark=0x<hex> must=<0|1><payload>
```

- type 名与 mini 的 `type_name` 一致（`loader/src/rules.rs:641-654`）：
  IpSet, SourceIpSet, Mac, Port, SourcePort, L4Proto, IpVersion, Dscp, Fallback。
- LPM 类（IpSet/SourceIpSet/Mac）：` prefixes=<p1>,<p2>`，前缀来自
  `simulatedLpmTries[lpm_index]`；渲染按 16 字节 BPF key：`data[10]=data[11]=0xff`
  时为 IPv4 `a.b.c.d/<plen-96>`（`data[12..15]`），否则为 MAC
  `xx:xx:xx:xx:xx:xx/<plen>`（`data[10..15]`）；同集合内先按 plen 升序、再按
  地址字节升序。无前缀时输出 `prefixes=`。
- 端口类：` port=<start>-<end>`（u16 本机序）。
- L4Proto/IpVersion：` mask=0x<hex>`（union 前 4 字节按本机序读成 u32）。
- Dscp：` dscp=<n>`；Fallback 无 payload。

## 调用链与数据来源（dae clone `main@e3fee8f`）

测试文件 `zz_parity_dump_test.go`（package control）完整模仿生产构建路径：

| 步骤 | dae 源码位置 |
| --- | --- |
| `fallback -> X` 改写为 routing 段内 `fallback: X`（mini 语法 vs dae 语法） | `config/config.go:151-154`（`Routing.Rules/Fallback`）；`pkg/config_parser/config_parser.go:14-43`；`config/parser.go:174-184` |
| `config_parser.Parse` + `config.New` | `config/decode.go:23-30`；`config/config.go:179-235` |
| 生产优化器链（Alias/DatReader/MergeAndSort/Deduplicate） | `control/control_plane.go:728-733` |
| `dip`/`dport` 别名 → `ip`/`port`（必须，否则 unknown function） | `component/routing/optimizer.go:45-72` |
| 规则/参数排序、合并 | `component/routing/optimizer.go:74-139` |
| `routing.NewNormalizedProgram` + `Lower` | `component/routing/normalize.go:14-35,37-56` |
| 每个 match_set 的 outbound 编码（LogicalOr 0xFE / LogicalAnd 0xFF / 真实 outbound）与 mark/must | `component/routing/matcher_builder.go:44-91,104-130` |
| `NewRoutingMatcherBuilderFromProgram`（`bpf=nil`） | `control/routing_matcher_builder.go:145-169` |
| IpSet/SourceIpSet 编译（多前缀折叠、LPM 去重） | `control/routing_matcher_builder.go:440-477,508-545` |
| Mac 编译（16 字节 key 放在 data[10..15]，plen=128） | `control/routing_matcher_builder.go:406-438` |
| Port/SourcePort | `control/routing_matcher_builder.go:479-506,547-574` |
| L4Proto/IpVersion/Dscp/Fallback | `control/routing_matcher_builder.go:576-612,640-689` |
| 取「最终写进 map 的数组」 | `KernspaceSnapshot`：`control/routing_matcher_builder.go:728-737`；测试用法样例 `control/sniff_punt_routing_test.go:67-79` |
| map 写入路径（需要活 bpf，stub 下跳过） | `buildRoutingKernspaceForSlot`：`control/routing_matcher_builder.go:759+` |
| `BuildUserspace` 校验（fallback 必须最后；随后置空 b.rules） | `control/routing_matcher_builder.go:1086-1184`（校验 1154-1158，置空 1175-1182） |

BPF key 编码细节（LPM trie 的 16 字节 key）：

- 真实实现 `control/bpf_utils.go:96-119`（`cidrToBpfLpmKey`，IPv4 加 96 偏移、
  4-in-6 先 unmap）在 `dae_stub_ebpf` 下被排除（`bpf_utils.go:1` 的构建标签）。
- stub 里的同名函数返回空 key（`control/bpf_stub.go:447-449`），所以对拍测试在
  `parityBpfKey` 里逐行复刻了真实实现，保证 dump 的是会写进 map 的字节。
- struct 布局：`bpfMatchSet` `control/bpf_stub.go:55-63`；`_bpfLpmKey`
  `control/bpf_stub.go:388-391`；本机序标量编解码 `control/bpf_host_abi.go:21-55`。

mini 侧对照点：`loader/src/rules.rs`（`MatchSet` 76-92、常量 41-59、`dump`
669-708、`type_name` 641-654）；lab 规则文件注释里也标注了每种语义的覆盖目的。

## 已验证的本机命令与输出

```sh
cd mini-dae/lab/parity
chmod +x run.sh            # 已提交可执行位

./run.sh ../rules.dae | diff -u expected/rules.dae.dump - && echo IDENTICAL
./run.sh ../rules.reload.dae | diff -u expected/rules.reload.dae.dump - && echo IDENTICAL
```

两条 diff 均 **IDENTICAL**（逐字节一致）。实际输出（`out/` 下留存）：

`rules.dae`：

```
slot 0 type=IpSet not=0 outbound=0xff mark=0x0 must=0 prefixes=1.1.1.1/32
slot 1 type=Port not=0 outbound=0x02 mark=0x0 must=0 port=8080-8080
slot 2 type=IpSet not=0 outbound=0xff mark=0x0 must=0 prefixes=10.9.9.0/24,10.9.10.0/24
slot 3 type=Port not=0 outbound=0x00 mark=0x0 must=0 port=9999-9999
slot 4 type=Port not=1 outbound=0xff mark=0x0 must=0 port=9999-9999
slot 5 type=SourceIpSet not=0 outbound=0x01 mark=0x0 must=0 prefixes=10.0.0.0/24
slot 6 type=L4Proto not=0 outbound=0xff mark=0x800 must=1 mask=0x1
slot 7 type=Port not=0 outbound=0x00 mark=0x800 must=1 port=443-443
slot 8 type=Fallback not=0 outbound=0x02 mark=0x0 must=0
```

`rules.reload.dae` 与上表完全相同，唯一的差异在 slot 1：`outbound=0x01`
（`dip(1.1.1.1/32) && dport(8080) -> block`），与规则文件名/注释所述的热重载
变化点一致。

## 注意事项

- **构建步骤取舍**：生产在 `KernspaceSnapshot()` 之后调用
  `buildRoutingKernspaceForSlot` 把数组写进 BPF map；该步骤需要活的
  `*bpfObjects`，stub 构建不可用。测试改为「snapshot 后调用 `BuildUserspace`」：
  它执行同样的校验（fallback 必须最后、所有 LPM trie 可构建）且不碰 bpf，
  失败时对拍直接报错。snapshot 持有的切片就是 map 写入的数据源。
- **必须用生产优化器链**，而不是 `NewNormalizedProgram(rules, fallback)` 裸调用：
  没有 `AliasOptimizer` 时 `dip`/`dport` 根本不被 dae 识别；`MergeAndSortRulesOptimizer`
  会按函数名排序规则内的 `AndFunctions`（mini 保留书写顺序）。对 `lab/` 里的两个
  文件两种顺序恰好一致；未来若输入依赖书写顺序，diff 会暴露 dae 优化器的重排，
  这是真实行为差异，不应在本工具里掩盖。
- **`fallback -> X` 是 mini 写法**，不是 dae 语法；测试把它改写成 routing 段的
  `fallback: X` 参数（`fallback` 缺省为 `direct`）。原生 `fallback: X` 写法可留在
  规则文件里，由 dae 配置解析器直接处理。
- **网络**：首次 `go test` 会拉模块；本机到 `proxy.golang.org` 的请求偶发 EOF
  （curl 同样复现，IPv4 通、IPv6 不通所致）。模块是逐个缓存的，重跑
  `go mod download` 直至成功即可；本机用如下循环完成预热：
  `for i in $(seq 10); do go mod download && break; sleep 2; done`。
- **原始 clone 保持干净**：所有编译、复制、测试都在 `dae-work/` 内发生；
  `git -C ../dae status --porcelain` 无输出（见最终报告）。
- `zz_parity_dump_test.go` 依赖 `dae_stub_ebpf` 标签和 `control` 包内未导出字段，
  只能放在 `dae-work/control/` 里编译；直接把它当普通 Go 文件看会报缺包错误。
- mini-dae 自带的 `--dump` 需要先加载 eBPF object（`loader/src/main.rs`），无根
  环境跑不了；`expected/*.dump` 即 mini 侧验收基准，本工具负责在无 eBPF 环境下
  复现同一份数据。

## 文件

```
lab/parity/
├── README.md                  # 本文件
├── run.sh                     # 入口
├── zz_parity_dump_test.go     # dae 侧测试（会同步进 dae-work/control/）
├── expected/
│   ├── rules.dae.dump         # 验收基准（rules.dae）
│   └── rules.reload.dae.dump  # rules.reload.dae 基准（与上者仅 slot1 outbound 不同）
├── out/                       # 本机验证时 run.sh 的实际输出
└── dae-work/                  # dae 源码副本（自动生成，可删；PARITY_RESYNC=1 重建）
```

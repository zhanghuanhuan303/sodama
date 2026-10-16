# K2 内核矩阵：执行汇总（最近复跑 2026-10-16，eBPF 余项批次）

同一份 sodama（**唯一 Rust/aya-ebpf 数据面对象 + Rust 加载器**，C 对象已移除，见 ADR-0025）
在不同内核上跑同一套用例：`lab.sh verify`（**12 个用例**：proxy / direct / block / host / reload /
rebind / status / fault-reload / l3-attach / l3 / xdp / fault-kill）+ cap 阶段
（**9 个用例**：test-must / test-sub-file / test-hotplug / test-rules-cap / test-domain /
test-gaps / test-alive / test-fuse / test-pinning）。

| 内核 | 获取方式 | 结果 | 证据 |
|---|---|---|---|
| 6.18.54-2-lts（宿主） | `lab/matrix.sh run`（privileged 容器 + chroot） | **9/9 PASS**（旧轮次，未含对标批新项） | [`out/host-kernel-6.18.54-2-lts.log`](./out/host-kernel-6.18.54-2-lts.log) |
| 7.2.8-arch1-2 | `lab/matrix.sh vm`（QEMU + virtio-9p root + 自制 initramfs） | **9/9 PASS**（旧轮次） | [`out/vm-kernel-7.2.8-arch1-2.log`](./out/vm-kernel-7.2.8-arch1-2.log) |
| 7.2.8-arch1-2（数据面对标批次，2026-10-16） | 同上 | **12/12 PASS**（原 9 项 + `l3-attach` + `l3` + `xdp`）；仅 `offload=` 为信息项（QEMU 环境既有抖动，随宿主状态大幅波动且基线同环境同样失败，见 `docs/phase2-devlog.md` §19） | [`out/vm-kernel-7.2.8-arch1-2.log`](./out/vm-kernel-7.2.8-arch1-2.log)（`MATRIX-RESULT … verify=PASS`） |
| 7.2.8-arch1-2（能力缺口批次 #1–#4，2026-10-16） | 同上 | **12/12 + 5/5 PASS**（`verify=PASS cap=PASS`；`offload=` 仍为信息项，同因） | [`out/vm-kernel-7.2.8-arch1-2.log`](./out/vm-kernel-7.2.8-arch1-2.log)（`MATRIX-RESULT kernel=7.2.8-arch1-2 verify=PASS offload=FAIL cap=PASS`） |
| 7.2.8-arch1-2（eBPF 余项批次，2026-10-16） | 同上 | **12/12 + 9/9 PASS**（`verify=PASS cap=PASS`；`offload=` 仍为信息项，同因；含 `rebind` 键号同步后复跑） | [`out/vm-kernel-7.2.8-arch1-2.log`](./out/vm-kernel-7.2.8-arch1-2.log)（`MATRIX-RESULT kernel=7.2.8-arch1-2 verify=PASS offload=FAIL cap=PASS`） |

两台内核都满足 `bpf_loop`（≥5.17）与 TCX（≥6.6）；VM 里 TCX 钩子同样是
`single/lan/wan → tcx/*`，进程退出后自动摘除（`fault/kill` 用例验证）。
K2 时代的旧结果（8 用例、C 数据面）已被上表取代。

## 数据面对标批次（ADR-0065，2026-10-16）在矩阵里的新增项

| 用例 | 内容 | 门禁？ |
|---|---|---|
| `l3-attach` | L3 接口（ipip，arphrd=768）被自动判定并挂上 `sodama_lan_ingress_l3` | ✅ 入门禁 |
| `l3` | `test-l3`：经 ipip 隧道的 L3 端到端代理（小连接分流 + 512KB 逐字节回显） | ✅ 入门禁（删 ipip/无法建隧道时 SKIP） |
| `xdp` | `--xdp landae` 探针挂载 + 计数器随流量推进（恒 `XDP_PASS`） | ✅ 入门禁 |
| `offload=`（`test-relay-offload` + `test-offload-lifecycle`） | offload 路径 + 字节记账（`probe_calls`/`kernel_bytes`/`reclaimed_bytes`） | ❌ 信息项：QEMU 环境既有抖动（2026-10-16 重启后四组对照含基线 5092723 均 9/9 失败，环境主导；待查注册交接竞态） |

## 能力缺口批次 #1–#4（ADR-0066）与 eBPF 余项批次（ADR-0067）在矩阵里的新增项

`vm-init.sh` 在 verify 与 offload 阶段之后增加 **cap 阶段**（9 对 `*-up`/`test-*`，各自独立会话，
汇总为 `MATRIX-RESULT … cap=PASS|FAIL`）：

| 用例 | 内容 | 门禁？ |
|---|---|---|
| `test-must` | `must_<组名>` 糖的 DNS 语义：`l4proto(udp) && dport(53) -> must_proxy` 下 DNS 不被劫持（`queries` 不增）+ 代理交付正常（夹具 `lab/must.dae`） | ✅ 入门禁（cap） |
| `test-sub-file` | 订阅 `http-file://`：拉取成功 + 落盘 `sub-cache/lab.bin` + 源掉线 SIGHUP 回退磁盘缓存后仍可拨号 | ✅ 入门禁（cap） |
| `test-hotplug` | 接口懒绑定/热插拔：`--lan 'hplug*'` 启动无匹配（懒绑定提示）→ 建接口自动补挂 + 分流 → 删接口清理 → 重加再挂 | ✅ 入门禁（cap） |
| `test-rules-cap` | `match_set` 容量：70 条填充规则 + 高位规则（71 个）经 verifier；index≥64 的规则命中 | ✅ 入门禁（cap） |
| `test-domain` | 域位图端到端回归（DNS 接管 → 位图 → domain 规则分流；domain 位下标编码的守门用例） | ✅ 入门禁（cap） |
| `test-gaps` | eBPF 余项：LAN hooks 含 `sodama_lan_egress@landae`；ICMP → `parse_unsupported_l4`；同 4 元组重连同代拒改（`syn_rebind_rejected`）/SIGHUP 后异代重路由（`rebind_rerouted`）；`routing_handoff` 非空 | ✅ 入门禁（cap） |
| `test-alive` | 出口连通性：组标死（杀后端）→ 新连接被数据面阻断（`connectivity_dead_groups`）+ 恢复后放行 | ✅ 入门禁（cap） |
| `test-fuse` | offload 背压 fuse：阈值 env 生效 + `failures=0` + `engages==lifts`（无残留）；数据流部分对 offload 环境抖动重试 + 可 SKIP | ✅ 入门禁（cap） |
| `test-pinning` | `conn_state_map` pinning：pin 文件保留 → 重启后 `conn_state pin: 迁移 N 条` + 新表非空 | ✅ 入门禁（cap） |

> 环境注记（本批踩到并已修）：QEMU 最小 initramfs 里根 ns `lo` 默认 down，凡依赖 `127.0.0.1`
> 的夹具（ss 后端、假上游 DNS）会得到误导性失败；`lab.sh up()` 现幂等拉起 `lo`，假上游加存活检查
> （`lab/lab.sh:528/:855`，详见 `docs/phase2-devlog.md` §20）。

> 注：宿主矩阵以 root 运行会在 `out/` 留下 root 属主目录；复跑 VM 前需先把 `out/`
> 改回调用者属主（`chown`），否则 initramfs 写入报 Permission denied。

## 未执行项（诚实标注）

`5.17 / 6.1 / 6.6 / 6.14+` 四个版本线在本环境无法获得内核镜像（网络受限，且本机
`/boot` 与模块树里只有 6.18.54-lts 与 7.2.8）。`lab/matrix.sh` 不限定内核版本：
把 `vmlinuz` + 对应模块树放到一台机器上即可用 `run`（原生）或 `vm`（QEMU）跑同一套
用例，脚本会按内核版本打印能力门槛（bpf_loop / TCX / redirect_peer CVE）。

- 预期差异：<6.6 时 aya 会退回 netlink 附加（TCX 不可用），摘钩语义不同
  （见决策档案 4.6 节的故障语义表）；<5.17 时 `bpf_loop` 不可用，加载应失败。
  这两条路径未在真机验证，属于 K3 之前的主要未覆盖风险。
- `bpf_redirect_peer`（含 CVE-2025-37959 修复）sodama 未使用，仅记录，不影响结果。

## 复现命令

```bash
# 当前内核（需要 root；本机用 privileged 容器 + chroot 执行）
lab/matrix.sh check
lab/matrix.sh run

# 第二内核（宿主普通用户即可；自动构建 initramfs 并引导 QEMU）
lab/matrix.sh vm
```

## QEMU 细节（便于将来换内核）

- `lab/matrix.sh initramfs` 会把发行版 initramfs 解包，补入 9p 依赖闭包
  （`netfs → 9pnet → 9pnet_virtio → 9p`，从 `/usr/lib/modules/<kver>` 取），
  并替换 `/init`：insmod 后把宿主根以 9p 挂到 `/newroot`，chroot 进 `lab/vm-init.sh`。
- 发行版 busybox 没编 `mount`/`insmod` applet，`/init` 用的是镜像自带的
  util-linux `mount` 与 kmod `insmod`；任何失败都会强制关机，不会停在 shell。
- `vm-init.sh` 在 VM 内跑 `matrix.sh check && lab.sh up && lab.sh verify && lab.sh down`，
  随后是 offload 信息项阶段（`offload-up` 重试三轮 + `test-relay-offload`/`test-offload-lifecycle`）
  与 cap 阶段（9 对 `must-up/test-must` … `pin-up/test-pinning`，汇总 `cap=`），
  结果写到 `out/vm-kernel-<ver>.log`（经 9p 以宿主用户身份落盘）。

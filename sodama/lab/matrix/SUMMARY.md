# K2 内核矩阵：执行汇总（最近复跑 2026-10-04，P9+）

同一份 sodama（**唯一 Rust/aya-ebpf 数据面对象 + Rust 加载器**，C 对象已移除，见 ADR-0025）
在不同内核上跑同一套 `lab.sh verify`（**9 个用例**：proxy / direct / block / host / reload /
rebind / status / fault-reload / fault-kill）。

| 内核 | 获取方式 | 结果 | 证据 |
|---|---|---|---|
| 6.18.54-2-lts（宿主） | `lab/matrix.sh run`（privileged 容器 + chroot） | **9/9 PASS** | [`out/host-kernel-6.18.54-2-lts.log`](./out/host-kernel-6.18.54-2-lts.log) |
| 7.2.8-arch1-2 | `lab/matrix.sh vm`（QEMU + virtio-9p root + 自制 initramfs） | **9/9 PASS** | [`out/vm-kernel-7.2.8-arch1-2.log`](./out/vm-kernel-7.2.8-arch1-2.log) |
| 7.2.8-arch1-2（数据面对标批次，2026-10-16） | 同上 | **11/11 PASS**（原 9 项 + `l3-attach` + `xdp`）；`offload=`/`l3_e2e=` 为信息项（QEMU 环境既有抖动 / lab 拓扑未补完，见 `docs/phase2-devlog.md` §19） | [`out/vm-kernel-7.2.8-arch1-2.log`](./out/vm-kernel-7.2.8-arch1-2.log)（`MATRIX-RESULT … verify=PASS`） |

两台内核都满足 `bpf_loop`（≥5.17）与 TCX（≥6.6）；VM 里 TCX 钩子同样是
`single/lan/wan → tcx/*`，进程退出后自动摘除（`fault/kill` 用例验证）。
K2 时代的旧结果（8 用例、C 数据面）已被上表取代。

## 数据面对标批次（ADR-0065，2026-10-16）在矩阵里的新增项

| 用例 | 内容 | 门禁？ |
|---|---|---|
| `l3-attach` | L3 接口（ipip，arphrd=768）被自动判定并挂上 `sodama_lan_ingress_l3` | ✅ 入门禁 |
| `xdp` | `--xdp landae` 探针挂载 + 计数器随流量推进（恒 `XDP_PASS`） | ✅ 入门禁 |
| `test-l3`（`l3_e2e=`） | 经 ipip 隧道的 L3 端到端代理（补头/剥头闭环） | ❌ 信息项：lab 回程腿未通（对照实验同样失败） |
| `offload=`（`test-relay-offload` + `test-offload-lifecycle`） | offload 路径 + 字节记账（`probe_calls`/`kernel_bytes`/`reclaimed_bytes`） | ❌ 信息项：QEMU 首连抖动（基线复现） |

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
- `vm-init.sh` 在 VM 内跑 `matrix.sh check && lab.sh up && lab.sh verify &&
  lab.sh down`，结果写到 `out/vm-kernel-<ver>.log`（经 9p 以宿主用户身份落盘）。

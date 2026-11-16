# 2026-11-05 · 非正常断电 + DNS 回归复盘

**平台**：OpenWrt x86_64（Kwrt），Celeron 3867U / 4 GB，内核 `6.12.92`，`PREEMPT_DYNAMIC`
**引擎**：`1.0.0-g76f6d25a677b`（v1.0.0 生产包），`--dial-mode domain`
**结论**：两件事，互不为因果——① 19:56 整机非正常断电/复位，2 周轮在 **209.7 h** 处中断；② 断电后排查「国内变慢」，定位为 **DNS 私网 ECS + `:53` 双绑**，与数据面无关。

---

## 1. 断电：不是服务重启

### 1.1 时间线

| 时刻（CST） | 事件 | 证据 |
|---|---|---|
| 19:50:51 | 最后一次正常采样：RSS 67.4 MB、线程 21、FD 163、`stragglers=0`、`conns_total=929359` | `sodama-health.tsv` 第 17223 行 |
| 19:52:33 | 该到的 5 分钟 map 采样点缺失 | `sodama-map.tsv` 最后一条为 19:47:33 |
| 19:50:51–19:52:33 | 机器死亡窗口 | 上两条夹逼 |
| 19:56:47 | 内核启动 | `btime 1793879807`；`rtc_cmos: setting system clock to 2026-11-05T11:56:52 UTC` |
| 19:58:45 | tracker 恢复采样 | `rc.local` 的 `sleep 90` + 启动耗时 |

**停机约 4–6 分钟。**

### 1.2 排除项

| 假设 | 判定 | 依据 |
|---|---|---|
| 服务崩溃 / procd respawn | 排除 | 机器 `uptime` 归零；`/var/log` 全部在 19:56 重建 |
| 内核 panic 自动重启 | 排除 | `kernel.panic=3` + `panic_on_oops=1`，panic 后 3 s 必然重启；实际间隔 4–6 min。且 `19:52:33` 采样已缺失 |
| 硬件看门狗 | 排除 | 无 `/dev/watchdog*`，dmesg 无 wdt/itco 驱动 |
| 过热 | 无证据 | 当前 27.8–32.0 °C；断电前温度无记录（弱证据） |
| OOM | 排除 | 死前 RSS 67.4 MB / 4 GB 可用；OOM 只会杀进程，不会重启整机 |
| 引擎内存/FD 失控 | 排除 | 死前 20 min RSS 67.2–67.6 MB 平台段、线程 21、FD 163–207 |
| 正常关机 | 排除 | `FAT-fs (sda1): Volume was not properly unmounted` |

**判定**：整机非正常断电/复位，主因指向供电（市电瞬断、12V 适配器/DC 头、插排接触）。10-28 曾出现三次同签名事件（采样断口 7.8 / 3.4 / 3.6 min），频率约每 6 天 1–2 次。

### 1.3 连续窗口统计

- 有效窗口：**2026-10-28 02:09:15 → 2026-11-05 19:50:51 = 209.70 h（8 d 17 h 42 m）**
- `sodama-health.tsv` 该区间 **12 538 个采样，`conns_total` 递减次数 = 0**（无隐藏重启）
- 逐小时样本数均为 59–60，无 >90 s 缺口
- 2 周轮（目标 11-11 02:07）**未达成**，需重跑；209.7 h 可作为连续窗口存档

### 1.4 为什么没有日志

- `/var` 是 tmpfs，重启即清空；重启前 `/var/log/sodama.log`（11-05 00:00 → 19:50，约 20 h）全丢
- `/root/logs` 归档脚本阈值 8 MiB、`KEEP=6`，该段未达阈值 → 无归档
- 无 pstore/ramoops（`/sys/fs/pstore` 不存在），无 netconsole 模块 → panic 也留不下栈

---

## 2. DNS 回归：国内访问变慢

### 2.1 现场症状

| 测量 | 结果 |
|---|---|
| 路由器 → 223.5.5.5 | 6.2 ms，0% 丢包 |
| 路由器 → 国内镜像（nju / ustc） | 65 / 74 MB/s |
| eth0 / eth1 / eth2 协商 | 1000 Mb/s 全双工 |
| LAN 客户端 10 次 DNS 查询 | 1175 / 1888 / 427 / 14 / 1771 / 12 / 11 / 13 / 13 / 13 ms |
| 路由器本机 `nslookup <name> 10.0.0.1` | **5 s 超时**（两次复现） |
| `www.taobao.com` 某次解析 | `155.102.4.43`：RTT **384–435 ms**、丢包 **25%** |

带宽与链路正常，问题集中在解析。

### 2.2 根因 1：`ecs=auto` 上送私网前缀

配置（`/etc/sodama/config.dae`）：

```
qname(geosite:cn) -> alidns_ecs
alidns_ecs: 'https://223.5.5.5/dns-query?sni=dns.alidns.com&ecs=auto'
```

`ecs=auto` 按「查询发起方地址」归整。LAN 客户端是 `10.0.0.x`，IPv6 是 ULA `fd9c:6848:52e6::/64`，因此上送的 ECS 是**私网前缀**。AliDNS 无法据此定位，返回了偏远 PoP。

对照组（同一时刻、同一域名、直连 AliDNS DoH）：

| 域名 | 无 ECS | 公网 ECS `203.0.113.0/24` | 私网 ECS `10.0.0.0/24` |
|---|---|---|---|
| www.taobao.com | 123.129.195.19 / .20 | 同左 | **59.47.236.104 / .103** |
| www.jd.com | 125.36.9.73 | 同左 | **111.225.218.3** |
| www.163.com | 42.56.65.201 | 同左 | **123.244.93.225** |

RTT 对比：

| 域名 | 无 ECS | 私网 ECS |
|---|---|---|
| taobao | 16.9–18.7 ms | **58.2–66.8 ms** |
| jd | 6.4–9.2 ms | **38.0–39.7 ms** |
| 163 | 27.1–28.2 ms | **32.1–38.2 ms** |

公网 ECS 与无 ECS 结果**完全一致**，只有私网 ECS 跑偏。

### 2.3 根因 2：`10.0.0.1:53` 双绑

```
udp 1920 0 10.0.0.1:53 5856/sodama
udp    0 0 10.0.0.1:53 8438/dnsmasq
```

两个进程同时监听同一地址端口，查询落到谁手里是随机的。落错路径时表现为 0.4–1.9 s 抖动或 5 s 超时。

### 2.4 放大因素：粘滞 IP

reload 时日志显示 `sticky: reload 重置 65 条粘滞 IP`。即使 DNS 已返回新答案，引擎仍按旧粘滞 IP 建连——`155.102.4.43` 这类坏 IP 因此长期不退场。

### 2.5 其它现场项

| 项 | 结果 | 处置 |
|---|---|---|
| `router: udp://192.168.5.1:53` | 不在 LAN 网段，`ping` 100% 不可达 | 已注释 |
| eth0 RX `dropped` | 30 s +15（≈0.34%），但 `rx_no_buffer/rx_missed/queue_drops` 全 0 | tc/eBPF 层；疑似主动 block，持续观察 |
| eth0 RX ring | 256 / 上限 4096 | 待调（`ethtool -G eth0 rx 4096`） |

---

## 3. 处置

| # | 改动 | 位置 |
|---:|---|---|
| 1 | `qname(geosite:cn) -> alidns`（去掉 ECS） | `/etc/sodama/config.dae` |
| 2 | 注释 `router: 'udp://192.168.5.1:53'` | 同上 |
| 3 | `dhcp.@dnsmasq[0].port=0`（dnsmasq 只做 DHCP） | UCI `dhcp` |
| 4 | `dhcp.@dnsmasq[0].dns_redirect=0`（移除 53 端口重定向） | UCI `dhcp` |
| 5 | `dhcp.lan.dhcp_option='6,10.0.0.1'`（显式下发） | UCI `dhcp` |
| 6 | `/etc/resolv.conf` 改为常规文件：`223.5.5.5`、`192.168.1.1` | 文件系统 |

第 6 项必需：dnsmasq 关闭 DNS 后 `127.0.0.1:53` 无人监听，路由器自身解析会 `Connection refused`。

**回滚**：`/root/config.dae.bak-20261105-2235`、`/root/dhcp.bak-20261105-2255`、`/root/resolv.conf.bak-20261105-2255`。

### 3.1 修复后验收

| 项 | 结果 |
|---|---|
| `:53` 监听 | 仅 sodama（v4 `10.0.0.1`、v6 ULA `fd9c:6848:52e6::1`、各劫持 IP） |
| LAN IPv4 DNS ×10 | 12 / 13 / 12 / 12 / 12 / 12 / 11 / 12 / 18 / 9 ms |
| LAN IPv6 DNS（ULA） | 12 ms |
| `curl https://www.taobao.com` | `dns=9–10 ms`、`conn=26–29 ms`、`ttfb=62–91 ms`、**total 0.11–0.13 s** |
| 修复前同项 | total 0.54 / 1.41 / 0.54 s；ttfb 275 / 754 / 267 ms |
| 路由器自身解析 | 10 ms（经 `223.5.5.5`） |
| 引擎 | `routing_deferred=0`、`routing_supported=16`、`match_sets=22`、reload `ok=true` |
| ECS | `alidns_ecs` 计数器冻结（25 s +0），`ecs.echo` 停止增长 |
| DHCP | `dhcp-option=lan,6,10.0.0.1` 已生成；租约正常 |

### 3.2 已知取舍

dnsmasq 的 DNS 关闭后，`.lan` / `home.arpa` 等本地主机名解析失效；引擎 schema 无本地 hosts/address 能力（仅 `enable_local_tcp_fast_redirect`），无法用引擎补回。若确有依赖，需改为「dnsmasq 仅监听回环」的变体并重新评估 `:53` 竞争。

---

## 4. 设计教训（已并入架构文档 §12 第 24–27 条）

1. **ECS 不允许私网前缀**。`auto` 模式必须识别 RFC1918 / 环回 / 链路本地 / ULA，改为省略 ECS 或使用公网出口前缀。
2. **`:53` 每地址族只能有一个 owner**。引擎接管 DNS 时要显式关闭系统解析器，并在启动期做端口占用检查。
3. **解析结果变化要能失效粘滞项**；候选 IP 可按 RTT/失败率排序。
4. **配套开关要成对校验**：`port=0 ⇒ dns_redirect=0`；变更后必须验证「网关自身 + LAN 客户端 + IPv6」三条解析路径。

---

## 5. 数据源

- 引擎状态：`/usr/bin/sodama status --socket /var/run/sodama.sock --json`
- 采样：路由器 `/root/sodama-health.tsv`、`sodama-mem-track.tsv`、`sodama-map.tsv`
- 归档：`/root/logs/archive.log`（11-05 00:00 之后无新归档）
- 现场备份：`/root/config.dae.bak-20261105-2235`、`/root/dhcp.bak-20261105-2255`、`/root/resolv.conf.bak-20261105-2255`

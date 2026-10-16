//! 全部 BTF maps（名字/类型/容量与 C 数据面一致，loader 按名字使用）。

use aya_ebpf::{
    btf_maps::{
        Array, ArrayOfMaps, HashMap, LpmTrie, LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf,
        SockHash, SockMap,
    },
    macros::btf_map,
};
use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;

use crate::common::*;

#[btf_map]
pub static config_map: Array<SodaConfig, 1> = Array::new();

/// A2 #3：trace 过滤器（单元素；loader 写，热路径 `trace_verdict` 读）。
#[btf_map]
pub static trace_filter_map: Array<SodaTraceFilter, 1> = Array::new();

#[btf_map]
pub static lpm_array_map: ArrayOfMaps<
    LpmTrie<[u8; 16], u32, 2_048_000>,
    { (SODAMA_EPOCH_SLOT_NUM * SODAMA_MAX_MATCH_SET_LEN + 8) as usize },
> = ArrayOfMaps::new();

#[btf_map]
pub static routing_map: Array<
    SodaMatchSet,
    { (SODAMA_EPOCH_SLOT_NUM * SODAMA_MAX_MATCH_SET_LEN) as usize },
> = Array::new();

#[btf_map]
pub static routing_meta_map: Array<u32, 2> = Array::new();

#[btf_map]
pub static active_routing_epoch_map: Array<u32, 1> = Array::new();

#[btf_map]
pub static route_ctx_scratch_map: PerCpuArray<SodaRouteCtx, 1> = PerCpuArray::new();

#[btf_map]
pub static conn_state_map: HashMap<SodaTuple, SodaConnState, 262144> = HashMap::new();

#[btf_map]
pub static redirect_track: HashMap<SodaTuple, SodaRedirectEntry, 65536> = HashMap::new();

#[btf_map]
pub static domain_routing_map: HashMap<
    SodaRoutingEpochIp,
    SodaDomainRouting,
    131072,
    { BPF_F_NO_PREALLOC as usize },
> = HashMap::new();

/// P17b：socket cookie → {pname, pid, last_seen}（cgroup 钩子写入，TC 反查）。
/// 对照 dae `cookie_pid_map`（HASH，BPF_F_NO_PREALLOC，65536，tproxy.c:87）。
#[btf_map]
pub static cookie_pid_map: HashMap<u64, SodaPidPname, 65536, { BPF_F_NO_PREALLOC as usize }> =
    HashMap::new();

/// P18c+：DNS 发送方（client addr+port）→ 进程名；WAN egress 新 UDP DNS 流写入，
/// 控制面按 (client, sport) 反查供 `dns.routing` 的 `pname()` 匹配。
#[btf_map]
pub static dns_sender_pname_map: HashMap<
    SodaDnsSenderKey,
    SodaDnsSenderPname,
    4096,
    { BPF_F_NO_PREALLOC as usize },
> = HashMap::new();

#[btf_map]
pub static sodama_stats_map: PerCpuArray<u64, { SODAMA_STAT_MAP_SIZE as usize }> = PerCpuArray::new();

#[btf_map]
pub static control_flags_map: Array<u32, 1> = Array::new();

#[btf_map]
pub static listen_socket_map: SockMap<4> = SockMap::new();

#[btf_map]
pub static fast_sock: SockHash<SodaTuple, 4096> = SockHash::new();

/// P8：Rust offload verdict 的预检镜像（aya-ebpf 未暴露 SockHash lookup）。
#[btf_map]
pub static offload_guard: HashMap<SodaTuple, u8, 4096> = HashMap::new();

/// C3：事件通道（对照 dae `event_ringbuf`，256 KiB；事件结构见 `SodaEvent`）。
#[btf_map]
pub static event_ringbuf: RingBuf<SodaEvent, { 256 * 1024 }> = RingBuf::new();

/// C3：事件限速窗口（键 0..=261：0..=255 = per-outbound（BLOCKED_ALIVE），256/257/258 =
/// blocked/rebind/overflow，259/260/261 = syn_rebind/stateless_tcp/frag_tail；
/// 值 = 上次发出的 ns）。**per-CPU**：限速基准是「每 CPU 1条/秒」
/// （对照 dae 的全局 ARRAY + CAS 严格 1条/秒——aya-ebpf 下 bpf 目标无 `target_has_atomic`，
/// 无法用 AtomicU64 做 CAS，故降级为 per-CPU；全局上界 = CPU 数/秒，见 ADR-0065）。
#[btf_map]
pub static event_rate_map: PerCpuArray<u64, { SODAMA_EVENT_RATE_MAP_SIZE as usize }> =
    PerCpuArray::new();

/// 对标批：offload 重定向字节按「注册键」记账（fentry/kprobe 写入；用户态在键摘除时
/// 回收求和。对照 dae `tcp_offload_sent`——其 per-key 背压 fuse 未实现）。
#[btf_map]
pub static offload_sent: PerCpuHashMap<SodaTuple, u64, 8192> = PerCpuHashMap::new();

/// 对标批：L3 接口登记表（key = ifindex，value = 1）。loader 在挂载 L3 变体时写入；
/// reply 路径（`sodama0_ingress`）据此判定「要不要剥掉回程包的 14B 链路头」。
/// dae 无此表：它对 L3 流的回程直接 redirect（包上留着 veth 的以太头），
/// sodama 显式修掉该形态（见 ADR-0065「偏离清单」）。
#[btf_map]
pub static l3_ifindex_map: HashMap<u32, u8, 64> = HashMap::new();

/// 对标批：`struct sk_buff` 字段偏移（loader 从 vmlinux BTF 解出后写入）。
#[btf_map]
pub static trace_param_map: Array<SodaTraceParam, 1> = Array::new();

/// C4：XDP 计量（key：0=包数 1=字节 2=IPv4 3=IPv6 4=其它；per-CPU）。
#[btf_map]
pub static xdp_stats_map: PerCpuArray<u64, { SODAMA_XDP_MAP_SIZE as usize }> = PerCpuArray::new();

/// 出口连通性投影（Array<u32>，1=alive / 0=not alive；键 = outbound*6+domain*2+ipver）。
/// 控制面健康检查把组存活集写入；数据面 `outbound_is_alive` 读取，不存活则阻断
/// （对照 dae `outbound_connectivity_map` + `wan_outbound_is_alive`，tproxy.c:116/3418）。
#[btf_map]
pub static outbound_connectivity_map: Array<u32, { SODAMA_CONNECTIVITY_MAP_SIZE as usize }> =
    Array::new();

/// offload 背压 fuse（LRU_HASH）：键在 = `sodama_tcp_offload` verdict 改回 SK_PASS，
/// 数据交用户态泵，等待内核把 retry 队列排空（对照 dae `tcp_offload_pause`，
/// tproxy.c:262-274；键即 fast_sock 键空间）。
#[btf_map]
pub static tcp_offload_pause: LruHashMap<SodaTuple, u8, { SODAMA_OFFLOAD_PAUSE_MAP_SIZE as usize }> =
    LruHashMap::new();

/// 首包路由结果交接（兜底）：控制面交付首包时 conn_state 可能尚未可见
/// （写序竞态），从这里补读（对照 dae `routing_handoff_map`，tproxy.c:292-295；
/// 读取优先序 conn_state → handoff，见 `control/utils.go:64-80`）。
#[btf_map]
pub static routing_handoff_map: HashMap<
    SodaTuple,
    SodaRoutingHandoffEntry,
    { SODAMA_ROUTING_HANDOFF_MAP_SIZE as usize },
    { BPF_F_NO_PREALLOC as usize },
> = HashMap::new();

/// handoff 写入的 per-CPU 暂存（不占热路径栈：entry 32B 若在栈上构造会把
/// `split_flow` 调用链的 combined stack 推过 512 限，verifier 实测 528 > 512）。
#[btf_map]
pub static handoff_scratch_map: PerCpuArray<SodaRoutingHandoffEntry, 1> = PerCpuArray::new();

/// 事件写入的 per-CPU 暂存（SodaEvent 72B 从栈移出：verifier 的 combined stack
/// 限制（实测链累 576 > 512）下，热路径帧必须尽量小）。TC 上下文禁抢占，
/// 同 CPU 一致性成立（与 `route_ctx_scratch_map` 同模式）。
#[btf_map]
pub static event_scratch_map: PerCpuArray<SodaEvent, 1> = PerCpuArray::new();

/// conn_state 写入的 per-CPU 暂存（SodaConnState 24B 从 `conn_save` /
/// `refresh_reverse_state` 帧移出；理由同上）。
#[btf_map]
pub static conn_scratch_map: PerCpuArray<SodaConnState, 1> = PerCpuArray::new();

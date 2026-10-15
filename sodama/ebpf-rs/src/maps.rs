//! 全部 BTF maps（名字/类型/容量与 C 数据面一致，loader 按名字使用）。

use aya_ebpf::{
    btf_maps::{
        Array, ArrayOfMaps, HashMap, LpmTrie, PerCpuArray, PerCpuHashMap, RingBuf, SockHash,
        SockMap,
    },
    macros::btf_map,
};
use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;

use crate::common::*;

#[btf_map]
pub static config_map: Array<SodaConfig, 1> = Array::new();

#[btf_map]
pub static lpm_array_map: ArrayOfMaps<LpmTrie<[u8; 16], u32, 2_048_000>, 128> = ArrayOfMaps::new();

#[btf_map]
pub static routing_map: Array<SodaMatchSet, 128> = Array::new();

#[btf_map]
pub static routing_meta_map: Array<u32, 2> = Array::new();

#[btf_map]
pub static active_routing_epoch_map: Array<u32, 1> = Array::new();

#[btf_map]
pub static route_ctx_scratch_map: PerCpuArray<SodaRouteCtx, 1> = PerCpuArray::new();

#[btf_map]
pub static conn_state_map: HashMap<SodaTuple, SodaConnState, 65536> = HashMap::new();

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

/// C3：事件限速窗口（key 0..=258：0..=255 预留 per-outbound，256/257/258 = blocked/
/// rebind/overflow；值 = 上次发出的 ns）。**per-CPU**：限速基准是「每 CPU 1条/秒」
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

//! 全部 BTF maps（名字/类型/容量与 C 数据面一致，loader 按名字使用）。

use aya_ebpf::{
    btf_maps::{Array, ArrayOfMaps, HashMap, LpmTrie, PerCpuArray, SockHash, SockMap},
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
pub static sodama_stats_map: PerCpuArray<u64, 5> = PerCpuArray::new();

#[btf_map]
pub static control_flags_map: Array<u32, 1> = Array::new();

#[btf_map]
pub static listen_socket_map: SockMap<4> = SockMap::new();

#[btf_map]
pub static fast_sock: SockHash<SodaTuple, 4096> = SockHash::new();

/// P8：Rust offload verdict 的预检镜像（aya-ebpf 未暴露 SockHash lookup）。
#[btf_map]
pub static offload_guard: HashMap<SodaTuple, u8, 4096> = HashMap::new();

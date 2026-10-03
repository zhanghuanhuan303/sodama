//! 全部 BTF maps（名字/类型/容量与 C 数据面一致，loader 按名字使用）。

use aya_ebpf::{
    btf_maps::{Array, ArrayOfMaps, HashMap, LpmTrie, PerCpuArray, SockHash, SockMap},
    macros::btf_map,
};
use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;

use crate::common::*;

#[btf_map]
pub static config_map: Array<MiniConfig, 1> = Array::new();

#[btf_map]
pub static lpm_array_map: ArrayOfMaps<LpmTrie<[u8; 16], u32, 2_048_000>, 128> = ArrayOfMaps::new();

#[btf_map]
pub static routing_map: Array<MiniMatchSet, 128> = Array::new();

#[btf_map]
pub static routing_meta_map: Array<u32, 2> = Array::new();

#[btf_map]
pub static active_routing_epoch_map: Array<u32, 1> = Array::new();

#[btf_map]
pub static route_ctx_scratch_map: PerCpuArray<MiniRouteCtx, 1> = PerCpuArray::new();

#[btf_map]
pub static conn_state_map: HashMap<MiniTuple, MiniConnState, 65536> = HashMap::new();

#[btf_map]
pub static redirect_track: HashMap<MiniTuple, MiniRedirectEntry, 65536> = HashMap::new();

#[btf_map]
pub static domain_routing_map: HashMap<
    MiniRoutingEpochIp,
    MiniDomainRouting,
    131072,
    { BPF_F_NO_PREALLOC as usize },
> = HashMap::new();

/// P17b：socket cookie → {pname, pid, last_seen}（cgroup 钩子写入，TC 反查）。
/// 对照 dae `cookie_pid_map`（HASH，BPF_F_NO_PREALLOC，65536，tproxy.c:87）。
#[btf_map]
pub static cookie_pid_map: HashMap<u64, MiniPidPname, 65536, { BPF_F_NO_PREALLOC as usize }> =
    HashMap::new();

#[btf_map]
pub static mini_stats_map: PerCpuArray<u64, 5> = PerCpuArray::new();

#[btf_map]
pub static control_flags_map: Array<u32, 1> = Array::new();

#[btf_map]
pub static listen_socket_map: SockMap<3> = SockMap::new();

#[btf_map]
pub static fast_sock: SockHash<MiniTuple, 4096> = SockHash::new();

/// P8：Rust offload verdict 的预检镜像（aya-ebpf 未暴露 SockHash lookup）。
#[btf_map]
pub static offload_guard: HashMap<MiniTuple, u8, 4096> = HashMap::new();

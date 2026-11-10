// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! C4：XDP 计量探针（可选路径）。
//!
//! 定位：**只计量、不干预**——恒返回 `XDP_PASS`，不做 redirect/drop/改写。
//! 依据 `docs/research/af-xdp-feasibility.md`（AF_XDP 预研否决）与 `docs/backlog.md` C4：
//! dae 无 XDP 数据面，sodama 也不做 XDP 分流；XDP 的唯一价值是「最早观察点」的
//! 计量与兼容性实测（driver 模式在软路由各种网卡/虚拟设备上的可用性）。
//!
//! 计数（per-CPU，`xdp_stats_map`）：包数 / 字节数 / IPv4 / IPv6 / 其它。
//! 因为零干预，即使探针逻辑出错也不会改变转发行为（最坏情况是计数不准）。

use aya_ebpf::{macros::xdp, programs::XdpContext};
use aya_ebpf_bindings::bindings::xdp_action::XDP_PASS;

use crate::common::*;
use crate::maps::xdp_stats_map;

#[inline(always)]
fn bump(key: u32, by: u64) {
    if let Some(v) = xdp_stats_map.get_ptr_mut(key) {
        unsafe { *v += by };
    }
}

#[xdp]
pub fn sodama_xdp_observe(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data_end <= data {
        return XDP_PASS;
    }
    bump(SODAMA_XDP_PACKETS, 1);
    bump(SODAMA_XDP_BYTES, (data_end - data) as u64);

    /* 以太头：需要 14B。不足视为畸形帧，计入其它。 */
    let eth_len = ETH_HLEN as usize;
    if data + eth_len > data_end {
        bump(SODAMA_XDP_OTHER, 1);
        return XDP_PASS;
    }

    /* 直接包访问：读以太类型（12..14）。与 TC 侧 parse 同口径（ETH_P_IP.to_be()）。 */
    let proto = unsafe {
        core::ptr::read_unaligned((data as *const u8).add(12) as *const u16)
    };
    if proto == ETH_P_IP.to_be() {
        bump(SODAMA_XDP_IPV4, 1);
    } else if proto == ETH_P_IPV6.to_be() {
        bump(SODAMA_XDP_IPV6, 1);
    } else {
        bump(SODAMA_XDP_OTHER, 1);
    }

    /* 恒放行：探针不改变数据面行为（C4 的硬约束）。 */
    XDP_PASS
}

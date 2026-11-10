// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! TCP relay offload verdict（sk_skb/stream_verdict），与 C `sodama_tcp_offload` 等价。

use aya_ebpf::{bindings::sk_action::SK_PASS, macros::stream_verdict, programs::SkBuffContext};

use crate::common::*;
use crate::maps::{fast_sock, offload_guard, sodama_stats_map, tcp_offload_pause};

#[stream_verdict]
pub fn sodama_tcp_offload(skb: SkBuffContext) -> u32 {
    if let Some(v) = sodama_stats_map.get_ptr_mut(SODAMA_STAT_OFFLOAD_VERDICTS) {
        unsafe { *v += 1 };
    }

    if skb.skb.family() != AF_INET {
        return SK_PASS;
    }

    let rport_raw = skb.skb.remote_port();
    #[cfg(target_endian = "little")]
    let sport = (rport_raw >> 16) as u16;
    #[cfg(target_endian = "big")]
    let sport = rport_raw as u16;

    let mut peer = SodaTuple {
        sip: v4_mapped_bytes(skb.skb.remote_ipv4()),
        dip: v4_mapped_bytes(skb.skb.local_ipv4()),
        sport,
        dport: (skb.skb.local_port() as u16).to_be(),
        l4proto: IPPROTO_TCP,
        is_v6: 0,
        pad: [0; 2],
    };

    /* 预检镜像：未命中必须 SK_PASS（redirect 未命中会丢包） */
    if unsafe { offload_guard.get(&peer) }.is_none() {
        return SK_PASS;
    }

    /* 背压 fuse（对照 dae tproxy.c:4290-4294）：键在 = 暂停内核拼接，数据 SK_PASS
     * 交用户态泵转发；fast_sock 条目保留，内核继续排空 retry 队列。 */
    if unsafe { tcp_offload_pause.get(&peer) }.is_some() {
        if let Some(c) = sodama_stats_map.get_ptr_mut(SODAMA_STAT_OFFLOAD_PAUSE_PASSES) {
            unsafe { *c += 1 };
        }
        return SK_PASS;
    }

    if let Some(c) = sodama_stats_map.get_ptr_mut(SODAMA_STAT_OFFLOAD_REDIRECTS) {
        unsafe { *c += 1 };
    }
    let _ = fast_sock.redirect_skb(&skb, &mut peer, 0);
    SK_PASS
}

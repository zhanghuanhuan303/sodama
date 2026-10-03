//! TCP relay offload verdict（sk_skb/stream_verdict），与 C `mini_tcp_offload` 等价。

use aya_ebpf::{bindings::sk_action::SK_PASS, macros::stream_verdict, programs::SkBuffContext};

use crate::common::*;
use crate::maps::{fast_sock, mini_stats_map, offload_guard};

#[stream_verdict]
pub fn mini_tcp_offload(skb: SkBuffContext) -> u32 {
    if let Some(v) = mini_stats_map.get_ptr_mut(MINI_STAT_OFFLOAD_VERDICTS) {
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

    let mut peer = MiniTuple {
        sip: skb.skb.remote_ipv4(),
        dip: skb.skb.local_ipv4(),
        sport,
        dport: (skb.skb.local_port() as u16).to_be(),
        l4proto: IPPROTO_TCP,
        pad: [0; 3],
    };

    /* 预检镜像：未命中必须 SK_PASS（redirect 未命中会丢包） */
    if unsafe { offload_guard.get(&peer) }.is_none() {
        return SK_PASS;
    }

    if let Some(c) = mini_stats_map.get_ptr_mut(MINI_STAT_OFFLOAD_REDIRECTS) {
        unsafe { *c += 1 };
    }
    let _ = fast_sock.redirect_skb(&skb, &mut peer, 0);
    SK_PASS
}

//! 7 个 TC classifier 程序（与 C 同名同 section，loader 按名字挂载）。

use core::ffi::c_void;

use aya_ebpf::{bpf_printk, macros::classifier, programs::TcContext};
use aya_ebpf_bindings::{
    bindings::BPF_F_INGRESS,
    helpers::{bpf_sk_assign, bpf_sk_release},
};

use crate::common::*;
use crate::flow::*;
use crate::maps::*;
use crate::parse::parse_ip;

/// 控制面自己的 socket：直接放行（防自环）。
#[inline(always)]
fn dae_socket(ctx: &TcContext) -> bool {
    unsafe { (*ctx.skb.skb).mark == SODAMA_DAE_SOCKET_MARK }
}

#[classifier]
pub fn sodama_lan_ingress(mut ctx: TcContext) -> i32 {
    if dae_socket(&ctx) {
        return tc_ok();
    }
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_ip(&ctx) else {
        return tc_ok();
    };
    unsafe { split_flow(&mut ctx, &p, 0) }
}

#[classifier]
pub fn sodama_wan_egress(mut ctx: TcContext) -> i32 {
    if dae_socket(&ctx) {
        return tc_ok();
    }
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_ip(&ctx) else {
        return tc_ok();
    };
    unsafe { split_flow(&mut ctx, &p, 1) }
}

#[classifier]
pub fn sodama_wan_ingress(ctx: TcContext) -> i32 {
    let Some(p) = parse_ip(&ctx) else {
        return tc_ok();
    };
    unsafe { refresh_reverse_state(&p) };
    tc_ok()
}

#[classifier]
pub fn sodama_wan_lan_ingress(mut ctx: TcContext) -> i32 {
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_ip(&ctx) else {
        return tc_ok();
    };
    unsafe { refresh_reverse_state(&p) };
    unsafe { split_flow(&mut ctx, &p, 0) }
}

#[classifier]
pub fn sodama_lan_wan_egress(mut ctx: TcContext) -> i32 {
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_ip(&ctx) else {
        return tc_ok();
    };
    unsafe { refresh_reverse_state(&p) };
    unsafe { split_flow(&mut ctx, &p, 1) }
}

#[classifier]
pub fn sodama0peer_ingress(ctx: TcContext) -> i32 {
    let (cb0, cb1, cb2, cb3) = {
        let cb = ctx.cb();
        (cb[0], cb[1], cb[2], cb[3])
    };
    unsafe {
        if crate::flow::debug_log() {
            bpf_printk!(
                c"sodama: dae0peer_ingress cb0=%u cb1=%u cb2=%u cb3=%u\n",
                cb0,
                cb1,
                cb2,
                cb3
            );
        }
    }

    if cb0 != TPROXY_MARK {
        return tc_shot();
    }

    ctx.set_mark(TPROXY_MARK);
    let _ = unsafe { skb_change_type(&ctx, SODAMA_PACKET_HOST) };

    /* 已建立的 TCP 不需要 assign：靠 fwmark -> local 路由送到已分配的 socket。 */
    if cb2 == 0 {
        return tc_ok();
    }

    // sockmap key：0/1 = TCP/UDP IPv4，2/3 = TCP/UDP IPv6（cb3=1 表示 v6）
    let key: u32 = (if cb1 == IPPROTO_UDP as u32 { 1 } else { 0 }) + (if cb3 != 0 { 2 } else { 0 });
    let sk = unsafe {
        map_lookup_raw(
            &listen_socket_map as *const _ as *const c_void,
            &key as *const u32 as *const c_void,
        )
    };
    if sk.is_null() {
        return tc_ok();
    }

    let ret = unsafe { bpf_sk_assign(ctx.skb.skb as *mut c_void, sk, 0) };
    if crate::flow::debug_log() {
        unsafe {
            bpf_printk!(c"sodama: sk_assign key=%u ret=%d\n", key, ret as i32);
        }
    }
    unsafe {
        bpf_sk_release(sk);
    }
    tc_ok()
}

#[classifier]
pub fn sodama0_ingress(ctx: TcContext) -> i32 {
    let Some(p) = parse_ip(&ctx) else {
        return tc_ok();
    };

    let rev = SodaTuple {
        sip: p.tuples.dip,
        dip: p.tuples.sip,
        sport: p.tuples.dport,
        dport: p.tuples.sport,
        l4proto: p.tuples.l4proto,
        is_v6: p.tuples.is_v6,
        pad: [0; 2],
    };
    let Some(entry) = redirect_track.get_ptr_mut(&rev) else {
        return tc_ok();
    };

    /* 只有绑定的发布者能续租（防止被拒竞争者的回包替赢家续租）。 */
    let eth: Option<EthHdr> = ctx.load(0).ok();
    if let Some(eth) = eth {
        let (smac, dmac) = unsafe { ((*entry).smac, (*entry).dmac) };
        if smac == eth.h_source && dmac == eth.h_dest {
            unsafe {
                (*entry).last_seen_ns = aya_ebpf_bindings::helpers::bpf_ktime_get_ns();
            }
        }
    }

    let (entry_dmac, entry_smac, from_wan, ifindex) = unsafe {
        (
            (*entry).dmac,
            (*entry).smac,
            (*entry).from_wan,
            (*entry).ifindex,
        )
    };

    if ctx.store(6usize, &entry_dmac, 0).is_err() {
        return tc_shot();
    }
    if ctx.store(0usize, &entry_smac, 0).is_err() {
        return tc_shot();
    }

    let ty = if from_wan != 0 {
        SODAMA_PACKET_HOST
    } else {
        SODAMA_PACKET_OTHERHOST
    };
    let _ = unsafe { skb_change_type(&ctx, ty) };

    let flags: u64 = if from_wan != 0 {
        BPF_F_INGRESS as u64
    } else {
        0
    };
    if crate::flow::debug_log() {
        unsafe {
            bpf_printk!(
                c"sodama: dae0_ingress reply -> ifindex=%u ingress=%u\n",
                ifindex,
                (flags != 0) as u32
            );
        }
    }
    unsafe { aya_ebpf_bindings::helpers::bpf_redirect(ifindex, flags) as i32 }
}

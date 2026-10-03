//! 连接状态、redirect_track 单写者、判决落地与分流主流程（对照 C mini_conn_*/mini_split_flow）。

use core::ffi::c_void;

use aya_ebpf::{bpf_printk, programs::TcContext};
use aya_ebpf_bindings::{
    bindings::{BPF_ANY, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_ktime_get_ns, bpf_redirect},
};

use crate::common::*;
use crate::maps::*;
use crate::route::mini_route;

pub fn suspended() -> bool {
    match control_flags_map.get(0) {
        Some(v) => *v & MINI_FLAG_SUSPEND != 0,
        None => false,
    }
}

unsafe fn conn_lookup(key: &MiniTuple, l4proto: u8) -> Option<*mut MiniConnState> {
    let st = conn_state_map.get_ptr_mut(key)?;
    let now = bpf_ktime_get_ns();
    let timeout = if l4proto == IPPROTO_TCP {
        MINI_TCP_CONN_TIMEOUT_NS
    } else {
        MINI_UDP_CONN_TIMEOUT_NS
    };
    let last = (*st).last_seen_ns;
    if last <= now && now - last > timeout {
        let _ = conn_state_map.remove(key);
        return None;
    }
    (*st).last_seen_ns = now;
    Some(st)
}

unsafe fn conn_save(key: &MiniTuple, outbound: u8, mark: u32, must: u8, l4proto: u8) {
    let st = MiniConnState {
        last_seen_ns: bpf_ktime_get_ns(),
        mark,
        outbound,
        must,
        has_routing: 1,
        l4proto,
        is_wan_ingress_direction: 0,
        pad: [0; 3],
    };
    let _ = conn_state_map.insert(key, &st, BPF_ANY as u64);
}

unsafe fn conn_delete(key: &MiniTuple) {
    let _ = conn_state_map.remove(key);
}

unsafe fn stat_inc(key: u32) {
    if let Some(v) = mini_stats_map.get_ptr_mut(key) {
        *v += 1;
    }
}

/// P17b：按 socket cookie 反查进程名（仅 WAN egress 新连接调用；全 0 = 不可得）。
/// 对照 dae tproxy.c:3476-3488：TCP 仅 SYN、UDP 首包查一次；已建立连接走 conn_state。
#[inline(always)]
unsafe fn lookup_pname(ctx: &TcContext) -> [u8; 16] {
    let cookie = aya_ebpf_bindings::helpers::bpf_get_socket_cookie(ctx.skb.skb as *mut c_void);
    if cookie == 0 {
        return [0u8; 16];
    }
    match cookie_pid_map.get(&cookie) {
        Some(v) => v.pname,
        None => [0u8; 16],
    }
}

fn mac_equal(a: &[u8; 6], b: &[u8; 6]) -> bool {
    a == b
}

/// 对照 C `mini_publish_redirect_track`：单写者语义（同发布者续租 / 新鲜期拒绝改绑 / 陈旧允许）。
unsafe fn publish_redirect_track(ctx: &TcContext, pkt: &MiniParseResult, from_wan: u8) -> i32 {
    let entry = MiniRedirectEntry {
        ifindex: (*ctx.skb.skb).ifindex,
        smac: pkt.smac,
        dmac: pkt.dmac,
        from_wan,
        pad: [0; 3],
        last_seen_ns: bpf_ktime_get_ns(),
    };

    if let Some(existing) = redirect_track.get_ptr_mut(&pkt.tuples) {
        let same_publisher = (*existing).ifindex == entry.ifindex
            && (*existing).from_wan == entry.from_wan
            && mac_equal(&(*existing).smac, &entry.smac);
        if same_publisher {
            (*existing).last_seen_ns = entry.last_seen_ns;
            return 0;
        }
        if (*existing).last_seen_ns <= entry.last_seen_ns
            && entry.last_seen_ns - (*existing).last_seen_ns < MINI_REDIRECT_REBIND_STALE_NS
        {
            stat_inc(MINI_STAT_REBIND_REJECTED);
            bpf_printk!(c"mini-dae: redirect rebind rejected\n");
            return 0;
        }
    }

    match redirect_track.insert(&pkt.tuples, &entry, BPF_ANY as u64) {
        Ok(()) => 0,
        Err(ret) => {
            stat_inc(MINI_STAT_REDIRECT_UPDATE_FAILED);
            bpf_printk!(c"mini-dae: redirect update failed ret=%d\n", ret);
            ret
        }
    }
}

unsafe fn redirect_to_control_plane(
    ctx: &mut TcContext,
    pkt: &MiniParseResult,
    cfg: &MiniConfig,
    from_wan: u8,
) -> i32 {
    if ctx.store(0usize, &cfg.dae0peer_mac, 0).is_err() {
        return TC_ACT_SHOT as i32;
    }
    if publish_redirect_track(ctx, pkt, from_wan) != 0 {
        return TC_ACT_SHOT as i32;
    }
    {
        let cb = ctx.cb_mut();
        cb[0] = TPROXY_MARK;
        cb[1] = pkt.l4proto as u32;
        cb[2] = pkt.new_flow as u32;
        cb[3] = if pkt.is_v4 != 0 { 0 } else { 1 };
    }
    bpf_redirect(cfg.dae0_ifindex, 0) as i32
}

/// 分流主流程（LAN ingress / WAN egress / 单臂共用），对照 C `mini_split_flow`。
pub unsafe fn split_flow(ctx: &mut TcContext, pkt: &MiniParseResult, is_wan: u8) -> i32 {
    let Some(cfg) = config_map.get(0) else {
        return TC_ACT_SHOT as i32;
    };
    let cfg = *cfg;

    let st = conn_lookup(&pkt.tuples, pkt.l4proto);
    let cached = match st {
        Some(s) if (*s).has_routing != 0 => Some(s),
        _ => None,
    };

    let outbound;
    let mark;
    if let Some(s) = cached {
        outbound = (*s).outbound;
        mark = (*s).mark;
        let _ = (*s).must; /* C 同位置也读了 must 但缓存路径不消费 */
        bpf_printk!(
            c"mini-dae: cached outbound=0x%x dport=%u\n",
            outbound as u32,
            pkt.h_dport as u32
        );
    } else {
        if pkt.l4proto == IPPROTO_TCP && pkt.new_flow == 0 {
            /* 无状态的非 SYN TCP：放行（对照 dae tproxy.c:2935）。 */
            bpf_printk!(
                c"mini-dae: stateless tcp passthrough dport=%u\n",
                pkt.h_dport as u32
            );
            return TC_ACT_OK as i32;
        }
        if pkt.l4proto == IPPROTO_TCP && pkt.new_flow == 0 {
            if let Some(s) = st {
                if (*s).has_routing == 0 {
                    conn_delete(&pkt.tuples);
                }
            }
        }

        let result = mini_route(pkt, is_wan, &lookup_pname(ctx));
        if result < 0 {
            bpf_printk!(c"mini-dae: shot routing %d\n", result as i32);
            return TC_ACT_SHOT as i32;
        }
        outbound = (result & 0xff) as u8;
        mark = ((result as u64 >> MINI_RESULT_MARK_SHIFT) & 0xffff_ffff) as u32;
        let must = ((result as u64 >> MINI_RESULT_MUST_SHIFT) & 1) as u8;
        bpf_printk!(
            c"mini-dae: route outbound=0x%x mark=0x%x must=%u dport=%u\n",
            outbound as u32,
            mark,
            must as u32,
            pkt.h_dport as u32
        );

        if !(pkt.l4proto == IPPROTO_UDP && pkt.h_dport == 53) {
            conn_save(&pkt.tuples, outbound, mark, must, pkt.l4proto);
        }
    }

    if outbound == MINI_OUTBOUND_BLOCK {
        return TC_ACT_SHOT as i32;
    }
    if outbound == MINI_OUTBOUND_DIRECT {
        ctx.set_mark(mark);
        return TC_ACT_OK as i32;
    }
    redirect_to_control_plane(ctx, pkt, &cfg, is_wan)
}

/// 反方向 conntrack 刷新（对照 C `mini_refresh_reverse_state`）。
pub unsafe fn refresh_reverse_state(pkt: &MiniParseResult) {
    let rev = MiniTuple {
        sip: pkt.tuples.dip,
        dip: pkt.tuples.sip,
        sport: pkt.tuples.dport,
        dport: pkt.tuples.sport,
        l4proto: pkt.tuples.l4proto,
        is_v6: pkt.tuples.is_v6,
        pad: [0; 2],
    };
    if let Some(st) = conn_state_map.get_ptr_mut(&rev) {
        (*st).last_seen_ns = bpf_ktime_get_ns();
        (*st).is_wan_ingress_direction = 1;
    }
}

#[inline(always)]
pub fn tc_ok() -> i32 {
    TC_ACT_OK as i32
}

#[inline(always)]
pub fn tc_shot() -> i32 {
    TC_ACT_SHOT as i32
}

#[inline(always)]
pub unsafe fn skb_change_type(ctx: &TcContext, ty: u32) -> i32 {
    aya_ebpf_bindings::helpers::bpf_skb_change_type(ctx.skb.skb, ty) as i32
}

#[inline(always)]
pub unsafe fn map_lookup_raw(map: *const c_void, key: *const c_void) -> *mut c_void {
    aya_ebpf_bindings::helpers::bpf_map_lookup_elem(map as *mut c_void, key)
}

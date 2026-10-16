//! 连接状态、redirect_track 单写者、判决落地与分流主流程（对照 C sodama_conn_*/sodama_split_flow）。

use core::ffi::c_void;

use aya_ebpf::{bpf_printk, programs::TcContext};
use aya_ebpf_bindings::{
    bindings::{BPF_ANY, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_ktime_get_ns, bpf_redirect, bpf_skb_change_head, bpf_skb_store_bytes},
};

use crate::common::*;
use crate::event::{bump_stat, send_event_limited};
use crate::maps::*;
use crate::route::sodama_route;

pub fn suspended() -> bool {
    match control_flags_map.get(0) {
        Some(v) => *v & SODAMA_FLAG_SUSPEND != 0,
        None => false,
    }
}

/// M1：热路径调试打印开关（默认关；避免 per-packet bpf_printk 的 trace 开销）。
pub fn debug_log() -> bool {
    match control_flags_map.get(0) {
        Some(v) => *v & SODAMA_FLAG_DEBUG != 0,
        None => false,
    }
}

unsafe fn conn_lookup(key: &SodaTuple, l4proto: u8) -> Option<*mut SodaConnState> {
    let st = conn_state_map.get_ptr_mut(key)?;
    let now = bpf_ktime_get_ns();
    let timeout = if l4proto == IPPROTO_TCP {
        SODAMA_TCP_CONN_TIMEOUT_NS
    } else {
        SODAMA_UDP_CONN_TIMEOUT_NS
    };
    let last = (*st).last_seen_ns;
    if last <= now && now - last > timeout {
        let _ = conn_state_map.remove(key);
        return None;
    }
    (*st).last_seen_ns = now;
    Some(st)
}

unsafe fn conn_save(key: &SodaTuple, outbound: u8, mark: u32, must: u8, l4proto: u8) {
    let st = SodaConnState {
        last_seen_ns: bpf_ktime_get_ns(),
        mark,
        outbound,
        must,
        has_routing: 1,
        l4proto,
        is_wan_ingress_direction: 0,
        pad: [0; 3],
    };
    if let Err(_ret) = conn_state_map.insert(key, &st, BPF_ANY as u64) {
        /* 表满/更新失败：旧实现静默丢——连接会拿不到缓存路由（下一包重新查规则）。
         * 对照 dae tproxy.c:2440-2450/2700-2710：计数 + 限速事件。 */
        bump_stat(SODAMA_STAT_CONN_OVERFLOW);
        let ty = if l4proto == IPPROTO_TCP {
            SODAMA_EVENT_TCP_CONN_OVERFLOW
        } else {
            SODAMA_EVENT_UDP_CONN_OVERFLOW
        };
        send_event_limited(SODAMA_EVENT_RATE_OVERFLOW, ty, outbound, l4proto, Some(key));
    }
}

unsafe fn conn_delete(key: &SodaTuple) {
    let _ = conn_state_map.remove(key);
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

/// 对照 C `sodama_publish_redirect_track`：单写者语义（同发布者续租 / 新鲜期拒绝改绑 / 陈旧允许）。
///
/// L3（`link_h_len == 0`）流没有 L2 绑定，MAC 置 0（对照 dae
/// `fill_redirect_entry_from_forward_packet`，tproxy.c:2151-2164）。
unsafe fn publish_redirect_track(
    ctx: &TcContext,
    pkt: &SodaParseResult,
    from_wan: u8,
    link_h_len: u32,
) -> i32 {
    let has_l2 = link_h_len == ETH_HLEN;
    let entry = SodaRedirectEntry {
        ifindex: (*ctx.skb.skb).ifindex,
        smac: if has_l2 { pkt.smac } else { [0u8; 6] },
        dmac: if has_l2 { pkt.dmac } else { [0u8; 6] },
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
            && entry.last_seen_ns - (*existing).last_seen_ns < SODAMA_REDIRECT_REBIND_STALE_NS
        {
            bump_stat(SODAMA_STAT_REBIND_REJECTED);
            send_event_limited(
                SODAMA_EVENT_RATE_REDIRECT_REBIND,
                SODAMA_EVENT_REDIRECT_REBIND_REJECTED,
                0,
                pkt.l4proto,
                Some(&pkt.tuples),
            );
            return 0;
        }
    }

    match redirect_track.insert(&pkt.tuples, &entry, BPF_ANY as u64) {
        Ok(()) => 0,
        Err(ret) => {
            bump_stat(SODAMA_STAT_REDIRECT_UPDATE_FAILED);
            send_event_limited(
                SODAMA_EVENT_RATE_OVERFLOW,
                SODAMA_EVENT_REDIRECT_UPDATE_FAILED,
                0,
                pkt.l4proto,
                Some(&pkt.tuples),
            );
            ret
        }
    }
}

/// 送控制面的报文改写（对照 dae `rewrite_packet_for_control_plane`，tproxy.c:2253-2279）：
///  - L2：直接改以太头目的 MAC（直接包访问）；
///  - L3：包上没有链路头，而 dae0peer 是 veth（以太设备），所以先 `bpf_skb_change_head`
///    补上 14B 以太头（h_proto = skb->protocol、源 MAC 置 0、目的 = dae0peer MAC）。
unsafe fn rewrite_packet_for_control_plane(
    ctx: &TcContext,
    cfg: &SodaConfig,
    link_h_len: u32,
) -> i32 {
    if link_h_len == ETH_HLEN {
        if ctx.store(0usize, &cfg.dae0peer_mac, 0).is_err() {
            return TC_ACT_SHOT as i32;
        }
        return 0;
    }
    let skb = ctx.skb.skb;
    let zero_mac = [0u8; 6];
    let l3proto = (*skb).protocol as u16;
    let ch = bpf_skb_change_head(skb, ETH_HLEN, 0);
    if debug_log() {
        bpf_printk!(c"sodama: L3 push eth change_head=%d proto=0x%x\n", ch as i32, l3proto as u32);
    }
    if ch != 0 {
        return TC_ACT_SHOT as i32;
    }
    let ret = bpf_skb_store_bytes(
        skb,
        12,
        &l3proto as *const u16 as *const c_void,
        2,
        0,
    );
    if ret != 0 {
        return ret as i32;
    }
    let ret = bpf_skb_store_bytes(
        skb,
        6,
        zero_mac.as_ptr() as *const c_void,
        6,
        0,
    );
    if ret != 0 {
        return ret as i32;
    }
    bpf_skb_store_bytes(
        skb,
        0,
        cfg.dae0peer_mac.as_ptr() as *const c_void,
        6,
        0,
    ) as i32
}

unsafe fn redirect_to_control_plane(
    ctx: &mut TcContext,
    pkt: &SodaParseResult,
    cfg: &SodaConfig,
    from_wan: u8,
    link_h_len: u32,
) -> i32 {
    let ret = rewrite_packet_for_control_plane(ctx, cfg, link_h_len);
    if ret != 0 {
        return ret;
    }
    if publish_redirect_track(ctx, pkt, from_wan, link_h_len) != 0 {
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

/// 分流主流程（LAN ingress / WAN egress / 单臂共用），对照 C `sodama_split_flow`。
/// `link_h_len`：以太 14 / L3 0——影响「补链路头」与「redirect_track 是否记 MAC」。
pub unsafe fn split_flow(
    ctx: &mut TcContext,
    pkt: &SodaParseResult,
    is_wan: u8,
    link_h_len: u32,
) -> i32 {
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
        if debug_log() {
            bpf_printk!(
                c"sodama: cached outbound=0x%x dport=%u\n",
                outbound as u32,
                pkt.h_dport as u32
            );
        }
    } else {
        if pkt.l4proto == IPPROTO_TCP && pkt.new_flow == 0 {
            /* 无状态的非 SYN TCP：放行（对照 dae tproxy.c:2935）。 */
            if debug_log() {
                bpf_printk!(
                    c"sodama: stateless tcp passthrough dport=%u\n",
                    pkt.h_dport as u32
                );
            }
            return TC_ACT_OK as i32;
        }
        if pkt.l4proto == IPPROTO_TCP && pkt.new_flow == 0 {
            if let Some(s) = st {
                if (*s).has_routing == 0 {
                    conn_delete(&pkt.tuples);
                }
            }
        }

        let pname = lookup_pname(ctx);
        let result = sodama_route(pkt, is_wan, &pname);
        if result < 0 {
            bpf_printk!(c"sodama: shot routing %d\n", result as i32);
            return TC_ACT_SHOT as i32;
        }
        outbound = (result & 0xff) as u8;
        mark = ((result as u64 >> SODAMA_RESULT_MARK_SHIFT) & 0xffff_ffff) as u32;
        let must = ((result as u64 >> SODAMA_RESULT_MUST_SHIFT) & 1) as u8;
        if debug_log() {
            bpf_printk!(
                c"sodama: route outbound=0x%x mark=0x%x must=%u dport=%u\n",
                outbound as u32,
                mark,
                must as u32,
                pkt.h_dport as u32
            );
        }

        // P18c+：WAN egress 新 DNS 流（UDP 首包 / TCP SYN）：把发送方进程名记入
        // dns_sender_pname_map，控制面（透明 DNS）按 (client, sport) 反查，供
        // dns.routing 的 pname() 匹配。注意：tuples 端口是网络序原始值，map 键
        // 统一用主机序（pkt.h_sport），否则控制面反查键不匹配。
        if is_wan != 0
            && pkt.h_dport == 53
            && (pkt.l4proto == IPPROTO_UDP || (pkt.l4proto == IPPROTO_TCP && pkt.new_flow != 0))
        {
            let key = SodaDnsSenderKey {
                addr: pkt.tuples.sip,
                port: pkt.h_sport,
                pad: 0,
            };
            let val = SodaDnsSenderPname {
                pname,
                pad: 0,
                _pad2: [0; 6],
                ts_ns: bpf_ktime_get_ns(),
            };
            let _ = dns_sender_pname_map.insert(&key, &val, BPF_ANY as u64);
        }

        if !(pkt.l4proto == IPPROTO_UDP && pkt.h_dport == 53) {
            conn_save(&pkt.tuples, outbound, mark, must, pkt.l4proto);
        }
    }

    if outbound == SODAMA_OUTBOUND_BLOCK {
        /* 对照 dae `send_blocked_event`（tproxy.c:836-849）：被阻断的流量不计数，
         * 只发限速事件——洪泛时每 CPU 每秒最多一条，否则 ringbuf 会被刷满。 */
        send_event_limited(
            SODAMA_EVENT_RATE_BLOCKED,
            SODAMA_EVENT_BLOCKED,
            outbound,
            pkt.l4proto,
            Some(&pkt.tuples),
        );
        return TC_ACT_SHOT as i32;
    }
    if outbound == SODAMA_OUTBOUND_DIRECT {
        ctx.set_mark(mark);
        return TC_ACT_OK as i32;
    }
    redirect_to_control_plane(ctx, pkt, &cfg, is_wan, link_h_len)
}

/// 反方向 conntrack 刷新（对照 C `sodama_refresh_reverse_state`）。
pub unsafe fn refresh_reverse_state(pkt: &SodaParseResult) {
    let rev = SodaTuple {
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

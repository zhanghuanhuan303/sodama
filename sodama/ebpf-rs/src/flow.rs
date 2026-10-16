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

/// 当前 epoch 槽编码（slot+1；0 = 不可用）——= route 结果高位的 slot_enc 同值。
#[inline(always)]
unsafe fn active_slot_enc() -> u8 {
    match active_routing_epoch_map.get(0) {
        Some(v) if *v < SODAMA_EPOCH_SLOT_NUM => (*v as u8) + 1,
        _ => 0,
    }
}

/// 写 conn_state（含写时 epoch 槽/代次，供纯 SYN 重绑判定）。返回是否写入成功
/// （TCP 调用方据此 fail-closed，对照 dae `tproxy.c:3115-3133`）。
/// `inline(never)`：独立子程序帧（SodaConnState 24B 不进 `split_flow` 主帧，
/// verifier 的 combined stack 限制：实测主帧过大报 `528 > 512`）。
#[inline(never)]
unsafe fn conn_save(
    key: &SodaTuple,
    outbound: u8,
    mark: u32,
    must: u8,
    l4proto: u8,
    slot_enc: u8,
    generation: u16,
) -> bool {
    let Some(st) = conn_scratch_map.get_ptr_mut(0) else {
        return false;
    };
    (*st).last_seen_ns = bpf_ktime_get_ns();
    (*st).mark = mark;
    (*st).outbound = outbound;
    (*st).must = must;
    (*st).has_routing = 1;
    (*st).l4proto = l4proto;
    (*st).is_wan_ingress_direction = 0;
    (*st).routing_epoch_slot = slot_enc;
    (*st).pad = [0; 2];
    (*st).datapath_generation = generation;
    if conn_state_map.insert(key, &*st, BPF_ANY as u64).is_err() {
        /* 表满/更新失败：旧实现静默丢——连接会拿不到缓存路由（下一包重新查规则）。
         * 对照 dae tproxy.c:2440-2450/2700-2710：计数（按 L4 拆键）+ 限速事件。 */
        let ty = if l4proto == IPPROTO_TCP {
            bump_stat(SODAMA_STAT_TCP_CONN_OVERFLOW);
            SODAMA_EVENT_TCP_CONN_OVERFLOW
        } else {
            bump_stat(SODAMA_STAT_UDP_CONN_OVERFLOW);
            SODAMA_EVENT_UDP_CONN_OVERFLOW
        };
        send_event_limited(SODAMA_EVENT_RATE_OVERFLOW, ty, outbound, l4proto, Some(key));
        return false;
    }
    true
}

/// 出口存活判定（对照 dae `wan_outbound_is_alive`，tproxy.c:3418-3450）：
/// 保留 outbound（must_rules/控制面/逻辑标记）与 DNS（dport 53）一律放行；
/// 其余按 `outbound*6 + domain*2 + ipver` 读连通性投影，值 0 = 不存活。
/// 控制面在健康检查后写入投影（dial_mode=ip 且策略非 random/fixed 时生效）。
#[inline(always)]
unsafe fn outbound_is_alive(outbound: u8, l4proto: u8, h_dport: u16, is_v4: u8) -> bool {
    if outbound >= SODAMA_OUTBOUND_MUST_RULES {
        return true;
    }
    if h_dport == 53 {
        return true;
    }
    let domain = if l4proto == IPPROTO_UDP {
        SODAMA_CONNECTIVITY_DOMAIN_DATA_UDP
    } else {
        SODAMA_CONNECTIVITY_DOMAIN_TCP
    };
    let ipv = if is_v4 != 0 { 0 } else { 1 };
    let key = (outbound as u32) * SODAMA_CONNECTIVITY_PER_OUTBOUND + domain * 2 + ipv;
    match outbound_connectivity_map.get(key) {
        Some(v) => *v != 0,
        None => true,
    }
}

/// 首包路由结果交接（对照 dae `publish_routing_handoff`，tproxy.c:2120-2134）：
/// 控制面交付首包时从 conn_state 可能读不到（写序竞态），这里补一条兑底读数。
/// entry 写进 `handoff_scratch_map` 而不是栈；`inline(never)` 独立子程序帧
/// （verifier combined stack：实测主帧过大报 `528 > 512`）。
#[inline(never)]
unsafe fn publish_routing_handoff(pkt: &SodaParseResult, result: i64, generation: u16) {
    if result < 0 {
        return;
    }
    let Some(scratch) = handoff_scratch_map.get_ptr_mut(0) else {
        return;
    };
    (*scratch).last_seen_ns = bpf_ktime_get_ns();
    (*scratch).result = result as u64;
    (*scratch).datapath_generation = generation;
    (*scratch).dscp = pkt.dscp;
    (*scratch).pad = 0;
    (*scratch).mac = pkt.smac;
    let _ = routing_handoff_map.insert(&pkt.tuples, &*scratch, BPF_ANY as u64);
}

/// 限速发「出口不存活」事件（键 = outbound 本身：0..255 键域，对照 dae
/// `send_blocked_alive_event` 的 `blocked_event_rate_limited(outbound)`，tproxy.c:820-834）。
/// `inline(never)`：事件结构（72B）不进 `split_flow` 主帧。
#[inline(never)]
unsafe fn send_blocked_alive_event(outbound: u8, l4proto: u8, key: &SodaTuple) {
    send_event_limited(
        outbound as u32,
        SODAMA_EVENT_BLOCKED_ALIVE,
        outbound,
        l4proto,
        Some(key),
    );
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
            bump_stat(SODAMA_STAT_REDIRECT_REBIND_REJECTED);
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

    let mut st = conn_lookup(&pkt.tuples, pkt.l4proto);

    // 纯 SYN 重绑（对照 dae `__mark_tcp_seen`，tproxy.c:2591-2621）：
    //  - 同代（epoch 槽与 datapath_generation 均匹配）→ 拒改：保留条目、计数 + 限速事件；
    //  - 异代（跨重载/重启的旧缓存）→ 删条目、本轮重路由：计数 + 限速事件。
    if pkt.l4proto == IPPROTO_TCP && pkt.new_flow != 0 {
        if let Some(s) = st {
            if (*s).has_routing != 0 {
                let cur_slot = active_slot_enc();
                let same_slot = (*s).routing_epoch_slot != 0 && (*s).routing_epoch_slot == cur_slot;
                let same_gen = (*s).datapath_generation == cfg.datapath_generation;
                if same_slot && same_gen {
                    bump_stat(SODAMA_STAT_SYN_REBIND_REJECTED);
                    send_event_limited(
                        SODAMA_EVENT_RATE_SYN_REBIND,
                        SODAMA_EVENT_SYN_REBIND_REJECTED,
                        (*s).outbound,
                        pkt.l4proto,
                        Some(&pkt.tuples),
                    );
                } else {
                    conn_delete(&pkt.tuples);
                    st = None;
                    bump_stat(SODAMA_STAT_REBIND_REROUTED);
                    send_event_limited(
                        SODAMA_EVENT_RATE_SYN_REBIND,
                        SODAMA_EVENT_SYN_REBIND_REROUTED,
                        0,
                        pkt.l4proto,
                        Some(&pkt.tuples),
                    );
                }
            }
        }
    }

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
            /* 无缓存路由的已建立 TCP：
             *  - WAN egress（宿主自身存量流）：放行 + 计数（对照 dae tproxy.c:2935）；
             *  - LAN ingress：有 state 无路由时删旧后本轮重路由（下表）；无 state 的
             *    情形在 route 后 fail-closed（对照 dae tproxy.c:3115-3133）。 */
            if is_wan != 0 {
                bump_stat(SODAMA_STAT_STATELESS_TCP_PASSTHROUGH);
                if debug_log() {
                    bpf_printk!(
                        c"sodama: stateless tcp passthrough dport=%u\n",
                        pkt.h_dport as u32
                    );
                }
                return TC_ACT_OK as i32;
            }
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

        // 能力缺口 #1：must 的 UDP-53 流要存 conn_state——交付侧（控制面）据此区分
        // 「劫持到本地 DNS」与「按普通代理流转发」（must 语义，dae routing.md）。
        // 普通 DNS 不存（保持原热路径开销；端口 53 由交付侧按端口短路）。
        let mut save_failed = false;
        if !(pkt.l4proto == IPPROTO_UDP && pkt.h_dport == 53) || must != 0 {
            save_failed = !conn_save(
                &pkt.tuples,
                outbound,
                mark,
                must,
                pkt.l4proto,
                active_slot_enc(),
                cfg.datapath_generation,
            );
        }

        // LAN ingress fail-closed（对照 dae tproxy.c:3115-3133）：TCP 且 conn_state
        // 创建失败（表满）时，仅「direct 且 mark=0」允许直通，否则阻断——防路由泄漏。
        if is_wan == 0
            && pkt.l4proto == IPPROTO_TCP
            && save_failed
            && !(outbound == SODAMA_OUTBOUND_DIRECT && mark == 0)
        {
            if debug_log() {
                bpf_printk!(c"sodama: LAN tcp shot (conn_state map full)\n");
            }
            return TC_ACT_SHOT as i32;
        }

        // 首包路由结果交接（对照 dae：LAN handoff_required / WAN egress tcp_state_syn /
        // UDP 非 EXISTING；tproxy.c:2120-2134/3165-3180/3612-3618/3766-3773）。
        let handoff_required = if pkt.l4proto == IPPROTO_TCP {
            pkt.new_flow != 0
        } else {
            st.is_none()
        };
        if handoff_required {
            publish_routing_handoff(pkt, result, cfg.datapath_generation);
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
    // 出口存活判定（对照 dae `wan_outbound_is_alive` 的三处调用）：只在「本轮新出
    // 路由」时查（cached 路径不查，dae 同）；不存活 → 阻断 + 限速事件（BLOCKED_ALIVE，
    // 限速键 = outbound 本身）。
    if cached.is_none() && !outbound_is_alive(outbound, pkt.l4proto, pkt.h_dport, pkt.is_v4) {
        send_blocked_alive_event(outbound, pkt.l4proto, &pkt.tuples);
        return TC_ACT_SHOT as i32;
    }
    redirect_to_control_plane(ctx, pkt, &cfg, is_wan, link_h_len)
}

/// 反方向 conntrack 刷新（对照 C `sodama_refresh_reverse_state`；LAN egress /
/// WAN ingress 角色共用）。
///
/// 无主 WAN-ingress UDP（对照 dae `BPF_STATS_UNSOLICITED_UDP_SEEN`）：计数并创建
/// 「仅方向标记」的状态——host-terminated UDP 回包靠该标记走直通路径（tproxy.c:3820-3850）。
/// `inline(never)`：SodaConnState（24B）不进角色入口主帧。
#[inline(never)]
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
        return;
    }
    if pkt.tuples.l4proto == IPPROTO_UDP {
        bump_stat(SODAMA_STAT_UNSOLICITED_UDP_SEEN);
        let Some(st) = conn_scratch_map.get_ptr_mut(0) else {
            return;
        };
        (*st).last_seen_ns = bpf_ktime_get_ns();
        (*st).mark = 0;
        (*st).outbound = 0;
        (*st).must = 0;
        (*st).has_routing = 0;
        (*st).l4proto = IPPROTO_UDP;
        (*st).is_wan_ingress_direction = 1;
        (*st).routing_epoch_slot = 0;
        (*st).pad = [0; 2];
        (*st).datapath_generation = 0;
        let _ = conn_state_map.insert(&rev, &*st, BPF_ANY as u64);
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

//! 规则 VM（有界循环扫描 + LPM array-of-maps + 双 epoch 槽），与 C `mini_route*` 等价。
//!
//! 用有界循环（`rules_len <= 64` 已先验证明）而非 `bpf_loop`：aya-obj 对回调函数
//! 指针的 relocation 不产生内核要求的 `BPF_PSEUDO_FUNC` 形式（实测 verifier 报
//! `callback function not static`），内核 >= 5.3 对特权程序支持 bounded loop，语义相同。

use aya_ebpf::btf_maps::lpm_trie::Key;

use crate::common::*;
use crate::maps::*;

#[inline(never)]
unsafe fn route_loop_cb(ctx: *mut MiniRouteCtx, index: u32) -> i32 {
    if index >= MINI_MAX_MATCH_SET_LEN {
        (*ctx).result = EFAULT;
        return 1;
    }
    let k = ((*ctx).routing_epoch_slot as u32) * MINI_MAX_MATCH_SET_LEN + index;
    let Some(ms) = routing_map.get(k) else {
        (*ctx).result = EFAULT;
        return 1;
    };
    if ((*ctx).state & (MINI_STATE_BAD_RULE | MINI_STATE_GOOD_SUBRULE)) == 0
        && route_eval_match(ctx, ms, index) != 0
    {
        return 1;
    }
    route_finalize_match(ctx, ms)
}

unsafe fn route_match_lpm(ctx: *mut MiniRouteCtx, ms: &MiniMatchSet, key: &MiniLpmKey) -> i32 {
    let index = ms.u.index;
    if index >= MINI_MAX_MATCH_SET_LEN {
        (*ctx).result = EFAULT;
        return 1;
    }
    let idx = ((*ctx).routing_epoch_slot as u32) * MINI_MAX_MATCH_SET_LEN + index;
    let lpm_key = Key::new(MINI_IPV6_BYTE_LENGTH as u32 * 8, key.data);
    if lpm_array_map.get_value_ptr_mut(idx, &lpm_key).is_some() {
        (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
    }
    0
}

unsafe fn route_match_domain_set(ctx: *mut MiniRouteCtx, index: u32) -> i32 {
    if index >= MINI_MAX_MATCH_SET_LEN {
        (*ctx).result = EFAULT;
        return 1;
    }
    let word_idx = index >> 5;
    if (*ctx).domain_word_cached == 0 || (*ctx).domain_word_idx != word_idx {
        let d = (*ctx).lpm_daddr.data;
        let daddr = MiniRoutingEpochIp {
            slot: (*ctx).routing_epoch_slot as u32,
            addr: [
                u32::from_ne_bytes([d[0], d[1], d[2], d[3]]),
                u32::from_ne_bytes([d[4], d[5], d[6], d[7]]),
                u32::from_ne_bytes([d[8], d[9], d[10], d[11]]),
                u32::from_ne_bytes([d[12], d[13], d[14], d[15]]),
            ],
        };
        let bits = match domain_routing_map.get_ptr(&daddr) {
            Some(dr) => (*dr).bitmap[word_idx as usize],
            None => 0,
        };
        (*ctx).domain_word_idx = word_idx;
        (*ctx).domain_word_bits = bits;
        (*ctx).domain_word_cached = 1;
    }
    if ((*ctx).domain_word_bits >> (index % 32)) & 1 != 0 {
        (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
    }
    0
}

unsafe fn route_eval_match(ctx: *mut MiniRouteCtx, ms: &MiniMatchSet, index: u32) -> i32 {
    match ms.type_ {
        MINI_MATCH_DOMAIN_SET => route_match_domain_set(ctx, index),
        MINI_MATCH_IP_SET => route_match_lpm(ctx, ms, &(*ctx).lpm_daddr),
        MINI_MATCH_SOURCE_IP_SET => route_match_lpm(ctx, ms, &(*ctx).lpm_saddr),
        MINI_MATCH_MAC => route_match_lpm(ctx, ms, &(*ctx).lpm_mac),
        MINI_MATCH_PORT => {
            let port = ms.u.port;
            if (*ctx).h_dport >= port.start && (*ctx).h_dport <= port.end {
                (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
            }
            0
        }
        MINI_MATCH_SOURCE_PORT => {
            let port = ms.u.port;
            if (*ctx).h_sport >= port.start && (*ctx).h_sport <= port.end {
                (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
            }
            0
        }
        MINI_MATCH_L4_PROTO => {
            if (*ctx).l4proto_mask & ms.u.l4proto_mask != 0 {
                (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
            }
            0
        }
        MINI_MATCH_IP_VERSION => {
            if (*ctx).ipversion_mask & ms.u.ipversion_mask != 0 {
                (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
            }
            0
        }
        MINI_MATCH_DSCP => {
            if (*ctx).dscp == ms.u.dscp {
                (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
            }
            0
        }
        MINI_MATCH_FALLBACK => {
            (*ctx).state |= MINI_STATE_GOOD_SUBRULE;
            0
        }
        _ => {
            (*ctx).result = EINVAL;
            1
        }
    }
}

unsafe fn route_finalize_match(ctx: *mut MiniRouteCtx, ms: &MiniMatchSet) -> i32 {
    let match_outbound = ms.outbound;
    let match_not = ms.not != 0;

    if match_outbound != MINI_OUTBOUND_LOGICAL_OR {
        let good = (*ctx).state & MINI_STATE_GOOD_SUBRULE != 0;
        if good == match_not {
            (*ctx).state |= MINI_STATE_BAD_RULE;
        }
        (*ctx).state &= !MINI_STATE_GOOD_SUBRULE;
    }
    if match_outbound & MINI_OUTBOUND_LOGICAL_MASK != MINI_OUTBOUND_LOGICAL_MASK {
        if (*ctx).state & MINI_STATE_BAD_RULE == 0 {
            if match_outbound == MINI_OUTBOUND_MUST_RULES {
                (*ctx).state |= MINI_STATE_MUST;
            } else {
                let must = ((*ctx).state & MINI_STATE_MUST != 0) || ms.must != 0;
                let mut slot_enc = 0u8;
                if ((*ctx).routing_epoch_slot as u32) < MINI_EPOCH_SLOT_NUM {
                    slot_enc = (*ctx).routing_epoch_slot + 1;
                }
                if !must && (*ctx).state & MINI_STATE_DNS_QUERY != 0 {
                    (*ctx).result = (MINI_OUTBOUND_CONTROL_PLANE as i64)
                        | ((ms.mark as i64) << MINI_RESULT_MARK_SHIFT)
                        | ((slot_enc as i64) << MINI_EPOCH_SLOT_RESULT_SHIFT);
                    return 1;
                }
                (*ctx).result = (match_outbound as i64)
                    | ((ms.mark as i64) << MINI_RESULT_MARK_SHIFT)
                    | ((must as i64) << MINI_RESULT_MUST_SHIFT)
                    | ((slot_enc as i64) << MINI_EPOCH_SLOT_RESULT_SHIFT);
                return 1;
            }
        }
        (*ctx).state &= !MINI_STATE_BAD_RULE;
    }
    0
}

fn fill_lpm_addr(key: &mut MiniLpmKey, addr: &[u8; 16]) {
    *key = MiniLpmKey {
        prefixlen: MINI_IPV6_BYTE_LENGTH as u32 * 8,
        data: *addr,
    };
}

fn fill_lpm_mac(key: &mut MiniLpmKey, mac: &[u8; 6]) {
    *key = MiniLpmKey {
        prefixlen: MINI_IPV6_BYTE_LENGTH as u32 * 8,
        data: [0; 16],
    };
    key.data[10..16].copy_from_slice(mac);
}

/// 规则 VM 入口（对照 C `mini_route`）：返回 >=0 = outbound 编码，<0 = errno。
pub unsafe fn mini_route(pkt: &MiniParseResult, is_wan: u8) -> i64 {
    let Some(ctx) = route_ctx_scratch_map.get_ptr_mut(0) else {
        return EFAULT;
    };
    core::ptr::write_bytes(ctx, 0, 1);

    let mut slot = 0u32;
    if let Some(vp) = active_routing_epoch_map.get(0) {
        slot = *vp;
        if slot >= MINI_EPOCH_SLOT_NUM {
            return EFAULT;
        }
    }
    (*ctx).routing_epoch_slot = slot as u8;
    (*ctx).l4proto_mask = if pkt.l4proto == IPPROTO_TCP {
        MINI_L4_TCP
    } else {
        MINI_L4_UDP
    };
    (*ctx).ipversion_mask = if pkt.is_v4 != 0 { MINI_IPV4 } else { MINI_IPV6 };
    (*ctx).h_sport = pkt.h_sport;
    (*ctx).h_dport = pkt.h_dport;
    (*ctx).dscp = pkt.dscp;
    (*ctx).is_wan = is_wan;
    (*ctx).result = ENOEXEC;
    fill_lpm_addr(&mut (*ctx).lpm_saddr, &pkt.tuples.sip);
    fill_lpm_addr(&mut (*ctx).lpm_daddr, &pkt.tuples.dip);
    fill_lpm_mac(&mut (*ctx).lpm_mac, &pkt.smac);

    if pkt.h_dport == 53 && (pkt.l4proto == IPPROTO_TCP || pkt.l4proto == IPPROTO_UDP) {
        (*ctx).state |= MINI_STATE_DNS_QUERY;
    }

    let Some(vp) = routing_meta_map.get(slot) else {
        return EFAULT;
    };
    if *vp > MINI_MAX_MATCH_SET_LEN {
        return EFAULT;
    }
    let rules_len = *vp;
    if rules_len == 0 {
        return EPERM;
    }

    let mut i = 0u32;
    while i < rules_len {
        if route_loop_cb(ctx, i) != 0 {
            break;
        }
        i += 1;
    }
    if (*ctx).result >= 0 {
        return (*ctx).result;
    }
    EPERM
}

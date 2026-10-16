//! 规则 VM（`bpf_loop` 扫描 + LPM array-of-maps + 双 epoch 槽），与 C `sodama_route*` 等价。
//!
//! 扫描用内核 `bpf_loop` helper（>= 5.17，矩阵门槛同款）：verifier 成本与迭代数无关，
//! 因此 match_set 上界可与 dae 默认值对齐（1024）。回调经 aya-obj 的 `BPF_PSEUDO_FUNC`
//! relocation（aya-obj 0.3.0 已支持：`relocation.rs` 对非调用的文本引用设置
//! `BPF_PSEUDO_FUNC`）——早期（P8）曾报 `callback function not static`，那是旧版 aya-obj
//! 把函数指针发射成 `BPF_PSEUDO_CALL` 的缺口；现在不再需要「有界循环替代」。

use aya_ebpf::btf_maps::lpm_trie::Key;
use aya_ebpf_bindings::helpers::bpf_loop;

use crate::common::*;
use crate::maps::*;

#[inline(never)]
unsafe fn route_loop_cb(ctx: *mut SodaRouteCtx, index: u32) -> i32 {
    if index >= SODAMA_MAX_MATCH_SET_LEN {
        (*ctx).result = EFAULT;
        return 1;
    }
    let k = ((*ctx).routing_epoch_slot as u32) * SODAMA_MAX_MATCH_SET_LEN + index;
    let Some(ms) = routing_map.get(k) else {
        (*ctx).result = EFAULT;
        return 1;
    };
    if ((*ctx).state & (SODAMA_STATE_BAD_RULE | SODAMA_STATE_GOOD_SUBRULE)) == 0
        && route_eval_match(ctx, ms) != 0
    {
        return 1;
    }
    route_finalize_match(ctx, ms)
}

unsafe fn route_match_lpm(ctx: *mut SodaRouteCtx, ms: &SodaMatchSet, key: &SodaLpmKey) -> i32 {
    let index = ms.u.index;
    if index >= SODAMA_MAX_MATCH_SET_LEN {
        (*ctx).result = EFAULT;
        return 1;
    }
    let idx = ((*ctx).routing_epoch_slot as u32) * SODAMA_MAX_MATCH_SET_LEN + index;
    let lpm_key = Key::new(SODAMA_IPV6_BYTE_LENGTH as u32 * 8, key.data);
    if lpm_array_map.get_value_ptr_mut(idx, &lpm_key).is_some() {
        (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
    }
    0
}

unsafe fn route_match_domain_set(ctx: *mut SodaRouteCtx, ms: &SodaMatchSet) -> i32 {
    // word_idx/bit 由 loader 预计算写进 `value[0..2]`（对照 dae addDomain 的位下标）。
    // 不从循环下标推导：`bpf_loop` 回调的 u32 参数会被 LLVM 二次物化（校验得到的
    // 上界不随下游使用），verifier 会把 `bitmap[(index>>5)]` 报为越界可能（实测）。
    // 从 map 读出的 u8 经下面的检查即可获得 verifier 可证的上界（与 LPM 分支同款）。
    let word_idx = ms.u.value[0] as u32;
    let bit = (ms.u.value[1] as u32) & 31;
    // 注意：不要写「word_idx >= 32 || bit >= 32」两个同形检查——LLVM 会合并成一个
    // (word_idx|bit) >= 32，verifier 无法从合并条件回推 word_idx ≤ 31（实测：
    // bitmap 越界报错）。bit 用 & 31（loader 恒写 <32，掩码在可达路径上是恒等）。
    if word_idx >= SODAMA_MAX_MATCH_SET_LEN / 32 {
        (*ctx).result = EFAULT;
        return 1;
    }
    if (*ctx).domain_word_cached == 0 || (*ctx).domain_word_idx != word_idx {
        let d = (*ctx).lpm_daddr.data;
        let daddr = SodaRoutingEpochIp {
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
    if ((*ctx).domain_word_bits >> bit) & 1 != 0 {
        (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
    }
    0
}

unsafe fn route_eval_match(ctx: *mut SodaRouteCtx, ms: &SodaMatchSet) -> i32 {
    match ms.type_ {
        SODAMA_MATCH_DOMAIN_SET => route_match_domain_set(ctx, ms),
        SODAMA_MATCH_IP_SET => route_match_lpm(ctx, ms, &(*ctx).lpm_daddr),
        SODAMA_MATCH_SOURCE_IP_SET => route_match_lpm(ctx, ms, &(*ctx).lpm_saddr),
        SODAMA_MATCH_MAC => route_match_lpm(ctx, ms, &(*ctx).lpm_mac),
        SODAMA_MATCH_PORT => {
            let port = ms.u.port;
            if (*ctx).h_dport >= port.start && (*ctx).h_dport <= port.end {
                (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
            }
            0
        }
        SODAMA_MATCH_SOURCE_PORT => {
            let port = ms.u.port;
            if (*ctx).h_sport >= port.start && (*ctx).h_sport <= port.end {
                (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
            }
            0
        }
        SODAMA_MATCH_L4_PROTO => {
            if (*ctx).l4proto_mask & ms.u.l4proto_mask != 0 {
                (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
            }
            0
        }
        SODAMA_MATCH_IP_VERSION => {
            if (*ctx).ipversion_mask & ms.u.ipversion_mask != 0 {
                (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
            }
            0
        }
        SODAMA_MATCH_DSCP => {
            if (*ctx).dscp == ms.u.dscp {
                (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
            }
            0
        }
        SODAMA_MATCH_PNAME => {
            // P17b，对照 dae tproxy.c:1784-1792：仅 WAN egress 参与，16 字节精确
            // 比较（短名已在控制面按 NUL 补全）；pname 为空（LAN/降级）时不命中。
            if (*ctx).is_wan != 0 && (*ctx).pname == ms.u.value {
                (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
                if let Some(v) = sodama_stats_map.get_ptr_mut(SODAMA_STAT_PNAME_HITS) {
                    *v += 1;
                }
            }
            0
        }
        SODAMA_MATCH_FALLBACK => {
            (*ctx).state |= SODAMA_STATE_GOOD_SUBRULE;
            0
        }
        _ => {
            (*ctx).result = EINVAL;
            1
        }
    }
}

unsafe fn route_finalize_match(ctx: *mut SodaRouteCtx, ms: &SodaMatchSet) -> i32 {
    let match_outbound = ms.outbound;
    let match_not = ms.not != 0;

    if match_outbound != SODAMA_OUTBOUND_LOGICAL_OR {
        let good = (*ctx).state & SODAMA_STATE_GOOD_SUBRULE != 0;
        if good == match_not {
            (*ctx).state |= SODAMA_STATE_BAD_RULE;
        }
        (*ctx).state &= !SODAMA_STATE_GOOD_SUBRULE;
    }
    if match_outbound & SODAMA_OUTBOUND_LOGICAL_MASK != SODAMA_OUTBOUND_LOGICAL_MASK {
        if (*ctx).state & SODAMA_STATE_BAD_RULE == 0 {
            if match_outbound == SODAMA_OUTBOUND_MUST_RULES {
                (*ctx).state |= SODAMA_STATE_MUST;
            } else {
                let must = ((*ctx).state & SODAMA_STATE_MUST != 0) || ms.must != 0;
                let mut slot_enc = 0u8;
                if ((*ctx).routing_epoch_slot as u32) < SODAMA_EPOCH_SLOT_NUM {
                    slot_enc = (*ctx).routing_epoch_slot + 1;
                }
                if !must && (*ctx).state & SODAMA_STATE_DNS_QUERY != 0 {
                    (*ctx).result = (SODAMA_OUTBOUND_CONTROL_PLANE as i64)
                        | ((ms.mark as i64) << SODAMA_RESULT_MARK_SHIFT)
                        | ((slot_enc as i64) << SODAMA_EPOCH_SLOT_RESULT_SHIFT);
                    return 1;
                }
                (*ctx).result = (match_outbound as i64)
                    | ((ms.mark as i64) << SODAMA_RESULT_MARK_SHIFT)
                    | ((must as i64) << SODAMA_RESULT_MUST_SHIFT)
                    | ((slot_enc as i64) << SODAMA_EPOCH_SLOT_RESULT_SHIFT);
                return 1;
            }
        }
        (*ctx).state &= !SODAMA_STATE_BAD_RULE;
    }
    0
}

fn fill_lpm_addr(key: &mut SodaLpmKey, addr: &[u8; 16]) {
    *key = SodaLpmKey {
        prefixlen: SODAMA_IPV6_BYTE_LENGTH as u32 * 8,
        data: *addr,
    };
}

fn fill_lpm_mac(key: &mut SodaLpmKey, mac: &[u8; 6]) {
    *key = SodaLpmKey {
        prefixlen: SODAMA_IPV6_BYTE_LENGTH as u32 * 8,
        data: [0; 16],
    };
    key.data[10..16].copy_from_slice(mac);
}

/// 规则 VM 入口（对照 C `sodama_route`）：返回 >=0 = outbound 编码，<0 = errno。
/// P17b：`pname` 为本报文所属进程名（仅 WAN egress 新连接非零；见 flow.rs）。
pub unsafe fn sodama_route(pkt: &SodaParseResult, is_wan: u8, pname: &[u8; 16]) -> i64 {
    let Some(ctx) = route_ctx_scratch_map.get_ptr_mut(0) else {
        return EFAULT;
    };
    core::ptr::write_bytes(ctx, 0, 1);

    let mut slot = 0u32;
    if let Some(vp) = active_routing_epoch_map.get(0) {
        slot = *vp;
        if slot >= SODAMA_EPOCH_SLOT_NUM {
            return EFAULT;
        }
    }
    (*ctx).routing_epoch_slot = slot as u8;
    (*ctx).l4proto_mask = if pkt.l4proto == IPPROTO_TCP {
        SODAMA_L4_TCP
    } else {
        SODAMA_L4_UDP
    };
    (*ctx).ipversion_mask = if pkt.is_v4 != 0 { SODAMA_IPV4 } else { SODAMA_IPV6 };
    (*ctx).h_sport = pkt.h_sport;
    (*ctx).h_dport = pkt.h_dport;
    (*ctx).dscp = pkt.dscp;
    (*ctx).is_wan = is_wan;
    (*ctx).pname = *pname;
    (*ctx).result = ENOEXEC;
    fill_lpm_addr(&mut (*ctx).lpm_saddr, &pkt.tuples.sip);
    fill_lpm_addr(&mut (*ctx).lpm_daddr, &pkt.tuples.dip);
    fill_lpm_mac(&mut (*ctx).lpm_mac, &pkt.smac);

    if pkt.h_dport == 53 && (pkt.l4proto == IPPROTO_TCP || pkt.l4proto == IPPROTO_UDP) {
        (*ctx).state |= SODAMA_STATE_DNS_QUERY;
    }

    let Some(vp) = routing_meta_map.get(slot) else {
        return EFAULT;
    };
    if *vp > SODAMA_MAX_MATCH_SET_LEN {
        return EFAULT;
    }
    let rules_len = *vp;
    if rules_len == 0 {
        return EPERM;
    }

    // bpf_loop（helper 181；内核 >= 5.17）：verifier 成本与迭代数无关——旧的有界循环
    // 在 64 → 512/1024 时撞 1M processed insn 墙（实测 ≈4600 insn/迭代 ⇒ 上限 ≈217）。
    // 回调返回 0 = 继续、1 = 停止（命中规则）——与 dae bpf_loop 用法一致。
    // ctx 必须传栈指针或 NULL（内核 ARG_PTR_TO_STACK_OR_NULL）——传 NULL，回调自行
    // 从 `route_ctx_scratch_map`（per-CPU，TC 上下文禁抢占，同 CPU 一致性成立）取回。
    let rc = unsafe {
        bpf_loop(
            rules_len,
            route_bpf_loop_cb as *const () as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc < 0 {
        return EFAULT;
    }
    if (*ctx).result >= 0 {
        return (*ctx).result;
    }
    EPERM
}

/// `bpf_loop` 回调适配层（内核 ABI：`extern "C" fn(u32 index, *mut c_void ctx) -> i64`；
/// 返回 0 = 继续、1 = 停止）。经 aya-obj 的 `BPF_PSEUDO_FUNC` relocation 链接。
/// ctx 参数传 NULL（内核只允许栈指针/NULL）：上下文从 per-CPU scratch map 取回。
/// index 的边界检查在 `route_loop_cb` 内（那里不依赖回调参数做数组下标——domain 位图
/// 的 word/bit 已由 loader 预计算进 match_set，见 `route_match_domain_set`）。
extern "C" fn route_bpf_loop_cb(index: u32, _ctx: *mut core::ffi::c_void) -> i64 {
    let Some(ctx) = route_ctx_scratch_map.get_ptr_mut(0) else {
        return 1;
    };
    unsafe { route_loop_cb(ctx, index) as i64 }
}

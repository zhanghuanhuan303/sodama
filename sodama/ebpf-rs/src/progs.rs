// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! TC classifier 程序族（与 C 同名 + `_l3` 后缀，loader 按名字挂载）。
//!
//! 每个分流角色两套程序：无后缀 = 以太（链路头 14B，既有语义）；`_l3` = 无链路头
//! （tun/ppp/ipip/none，链路头 0B）。对照 dae 的 `tproxy_*_l2/_l3` 成对程序
//! （`dae/control/kern/tproxy.c` 的 `SEC("tc/lan_ingress_l2")` / `_l3`），
//! 选择逻辑在 dae 控制面 `control_plane_core_bind.go:256-273`（按 netlink EncapType）。

use core::ffi::c_void;

use aya_ebpf::{
    bpf_printk,
    macros::classifier,
    programs::TcContext,
};
use aya_ebpf_bindings::{
    bindings::BPF_F_INGRESS,
    helpers::{bpf_sk_assign, bpf_sk_release},
};

use crate::common::*;
use crate::event::bump_stat;
use crate::flow::*;
use crate::maps::*;
use crate::parse::{parse_ip, parse_ip_at_reason, ParseSkip};

/// 控制面自己的 socket：直接放行（防自环）。mark 值来自 config（`so_mark_from_dae`，
/// A2 #6；缺 config 时回落编译期默认）。
#[inline(always)]
fn dae_socket(ctx: &TcContext) -> bool {
    let mark = match config_map.get(0) {
        Some(c) => c.so_mark,
        None => SODAMA_DAE_SOCKET_MARK,
    };
    unsafe { (*ctx.skb.skb).mark == mark }
}

/// 带原因计数的解析：分片尾/L4 不支持分别计数后直通（对照 dae 的
/// `report_parse_passthrough`：BPF_STATS_FRAG_TAIL_PASSED /
/// BPF_STATS_PARSE_UNSUPPORTED_L4，tproxy.c:540-580/1131/1214）。
#[inline(always)]
fn parse_or_count(ctx: &TcContext, link_h_len: u32) -> Option<SodaParseResult> {
    match parse_ip_at_reason(ctx, link_h_len) {
        Ok(p) => Some(p),
        Err(ParseSkip::FragTail) => {
            unsafe { bump_stat(SODAMA_STAT_FRAG_TAIL_PASSED) };
            None
        }
        Err(ParseSkip::UnsupportedL4) => {
            unsafe { bump_stat(SODAMA_STAT_PARSE_UNSUPPORTED_L4) };
            None
        }
        Err(ParseSkip::Other) => None,
    }
}

/* ---------------- LAN ingress：分流（split_flow is_wan=0） ---------------- */

#[inline(always)]
fn lan_ingress_body(ctx: &mut TcContext, link_h_len: u32) -> i32 {
    if dae_socket(ctx) {
        return tc_ok();
    }
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_or_count(ctx, link_h_len) else {
        return tc_ok();
    };
    unsafe { split_flow(ctx, &p, 0, link_h_len) }
}

#[classifier]
pub fn sodama_lan_ingress(mut ctx: TcContext) -> i32 {
    lan_ingress_body(&mut ctx, ETH_HLEN)
}

#[classifier]
pub fn sodama_lan_ingress_l3(mut ctx: TcContext) -> i32 {
    lan_ingress_body(&mut ctx, 0)
}

/* ---------------- LAN egress：反向 conntrack 刷新（容器/独立 netns 出口） ---------------- */

/// LAN egress 角色（对照 dae `tproxy_lan_egress_l2/_l3`，tproxy.c:2771-2855）：
/// LAN 接口**出方向**的反向 conntrack 刷新——独立 netns/容器场景下，容器内流量
/// 经 veth 出口时，回程状态靠这里保活（dae 在每个 LAN 接口上同时挂 ingress+egress）。
#[inline(always)]
fn lan_egress_body(ctx: &TcContext, link_h_len: u32) -> i32 {
    let Some(p) = parse_or_count(ctx, link_h_len) else {
        return tc_ok();
    };
    unsafe { refresh_reverse_state(&p) };
    tc_ok()
}

#[classifier]
pub fn sodama_lan_egress(ctx: TcContext) -> i32 {
    lan_egress_body(&ctx, ETH_HLEN)
}

#[classifier]
pub fn sodama_lan_egress_l3(ctx: TcContext) -> i32 {
    lan_egress_body(&ctx, 0)
}

/* ---------------- WAN egress：分流（is_wan=1） ---------------- */

#[inline(always)]
fn wan_egress_body(ctx: &mut TcContext, link_h_len: u32) -> i32 {
    if dae_socket(ctx) {
        return tc_ok();
    }
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_or_count(ctx, link_h_len) else {
        return tc_ok();
    };
    unsafe { split_flow(ctx, &p, 1, link_h_len) }
}

#[classifier]
pub fn sodama_wan_egress(mut ctx: TcContext) -> i32 {
    wan_egress_body(&mut ctx, ETH_HLEN)
}

#[classifier]
pub fn sodama_wan_egress_l3(mut ctx: TcContext) -> i32 {
    wan_egress_body(&mut ctx, 0)
}

/* ---------------- WAN ingress：反向 conntrack 刷新 ---------------- */

#[inline(always)]
fn wan_ingress_body(ctx: &TcContext, link_h_len: u32) -> i32 {
    let Some(p) = parse_or_count(ctx, link_h_len) else {
        return tc_ok();
    };
    unsafe { refresh_reverse_state(&p) };
    tc_ok()
}

#[classifier]
pub fn sodama_wan_ingress(ctx: TcContext) -> i32 {
    wan_ingress_body(&ctx, ETH_HLEN)
}

#[classifier]
pub fn sodama_wan_ingress_l3(ctx: TcContext) -> i32 {
    wan_ingress_body(&ctx, 0)
}

/* ---------------- 单臂：ingress 双向（WAN ingress 刷新 + LAN 分流） ---------------- */

#[inline(always)]
fn wan_lan_ingress_body(ctx: &mut TcContext, link_h_len: u32) -> i32 {
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_or_count(ctx, link_h_len) else {
        return tc_ok();
    };
    unsafe { refresh_reverse_state(&p) };
    unsafe { split_flow(ctx, &p, 0, link_h_len) }
}

#[classifier]
pub fn sodama_wan_lan_ingress(mut ctx: TcContext) -> i32 {
    wan_lan_ingress_body(&mut ctx, ETH_HLEN)
}

#[classifier]
pub fn sodama_wan_lan_ingress_l3(mut ctx: TcContext) -> i32 {
    wan_lan_ingress_body(&mut ctx, 0)
}

/* ---------------- 单臂：egress 双向（WAN ingress 刷新 + WAN 分流） ---------------- */

#[inline(always)]
fn lan_wan_egress_body(ctx: &mut TcContext, link_h_len: u32) -> i32 {
    if suspended() {
        return tc_ok();
    }
    let Some(p) = parse_or_count(ctx, link_h_len) else {
        return tc_ok();
    };
    unsafe { refresh_reverse_state(&p) };
    unsafe { split_flow(ctx, &p, 1, link_h_len) }
}

#[classifier]
pub fn sodama_lan_wan_egress(mut ctx: TcContext) -> i32 {
    lan_wan_egress_body(&mut ctx, ETH_HLEN)
}

#[classifier]
pub fn sodama_lan_wan_egress_l3(mut ctx: TcContext) -> i32 {
    lan_wan_egress_body(&mut ctx, 0)
}

/* ---------------- dae0peer：控制面交付（L2/L3 共用） ---------------- */

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

/* ---------------- dae0 ingress：回程交付（L2/L3 按 ifindex 判定） ---------------- */

/// L3 回程：把回程包 redirect 回原接口；**不手工剥链路头**。
///
/// 实测结论（VM/7.2.8，抓包 + 十六进制取证）：从 TC ingress 把包 redirect 到
/// **L3 设备**（ipip/tun）时，内核自己会在送出前去掉 L2 头——若我们再用
/// `bpf_skb_adjust_room(-14, BPF_ADJ_ROOM_MAC)` 手工剥一次，会多剥 14 字节，
/// 外层载荷变成「内层 IP 头第 14 字节起」（实测外层 IP total_length=66，
/// 载荷 `01 01 0a 14 00 02 1f 90 b0 a8 …`），对端解封后 IP 版本字节不对 → 静默丢包。
///
/// 这还是对 dae 的一处**有意偏离**（见 ADR-0065「偏离清单」）：dae 的
/// `tproxy_dae0_ingress` 对任何回程都按以太处理（写 MAC + redirect），L3 目标接口
/// 会把以太头带进隧道。sodama 靠 loader 写入的 `l3_ifindex_map` 识别 L3 目标：
/// 跳过 MAC 改写（没有 L2 绑定可写），直接 redirect——L2 头的去除由 redirect 完成。
#[inline(always)]
unsafe fn dae0_ingress_l3_reply(ifindex: u32, from_wan: u8) -> i32 {
    let flags: u64 = if from_wan != 0 {
        BPF_F_INGRESS as u64
    } else {
        0
    };
    if crate::flow::debug_log() {
        bpf_printk!(
            c"sodama: L3 reply redirect ifindex=%u ingress=%u\n",
            ifindex,
            (flags != 0) as u32
        );
    }
    aya_ebpf_bindings::helpers::bpf_redirect(ifindex, flags) as i32
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

    let (entry_dmac, entry_smac, from_wan, ifindex) = unsafe {
        (
            (*entry).dmac,
            (*entry).smac,
            (*entry).from_wan,
            (*entry).ifindex,
        )
    };

    /* 是否 L3 目标接口：loader 在挂 L3 变体时登记。 */
    let l3_target = unsafe { l3_ifindex_map.get(&ifindex) }.is_some();

    /* 只有绑定的发布者能续租（防止被拒竞争者的回包替赢家续租）。
     *
     * L3 流没有 L2 绑定（entry MAC 全 0，回程包的以太头是控制面侧 veth 的），无法做
     * MAC 比对：此时按「有回程 = 流仍活跃」续租（dae 在此形态下比对恒失败 → 不续租，
     * 反向活跃的正向静默流会被 janitor 过期，属缺陷；偏离见 ADR-0065）。 */
    let eth: Option<EthHdr> = ctx.load(0).ok();
    if let Some(eth) = eth {
        if l3_target || (entry_smac == eth.h_source && entry_dmac == eth.h_dest) {
            unsafe {
                (*entry).last_seen_ns = aya_ebpf_bindings::helpers::bpf_ktime_get_ns();
            }
        }
    }

    /* 报文类型：L2/L3 两条路径都要设（回程进入原接口时决定 PACKET_HOST 语义）。 */
    let ty = if from_wan != 0 {
        SODAMA_PACKET_HOST
    } else {
        SODAMA_PACKET_OTHERHOST
    };
    let _ = unsafe { skb_change_type(&ctx, ty) };

    if l3_target {
        return unsafe { dae0_ingress_l3_reply(ifindex, from_wan) };
    }

    if ctx.store(6usize, &entry_dmac, 0).is_err() {
        return tc_shot();
    }
    if ctx.store(0usize, &entry_smac, 0).is_err() {
        return tc_shot();
    }

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

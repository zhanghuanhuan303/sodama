// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! 报文解析（与 C `parse_v4`/`load_l4` 等价，全部走 `bpf_skb_load_bytes`）。
//!
//! 链路头长度（`link_h_len`）对标 dae：以太 14B / 无链路头（tun/ppp/ipip/none）0B
//! （dae `linkHdrLen()`：`control/control_plane_core_bind.go:61-77`）。L2/L3 用同一套
//! 逻辑解析，只是起始偏移不同（dae `parse_transport_fast`，`kern/tproxy.c:1056-1105`）。

use aya_ebpf::programs::TcContext;

use crate::common::*;

/// 解析未产出可路由报文的原因（对照 dae `parse_transport` 的「正返回 = 直通并计数」
/// 与「负返回 = 错误」两分法；sodama 把可计数的直通类原因显式区分出来）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParseSkip {
    /// 非首分片（v4 或 v6）：无完整 L4 头，交内核原路径（计 `FRAG_TAIL_PASSED`）。
    FragTail,
    /// L4 非 TCP/UDP：交内核原路径（计 `PARSE_UNSUPPORTED_L4`）。
    UnsupportedL4,
    /// 其它（非 IP、截断、扩展头超限——按现状放行不计数）。
    Other,
}

/// 统一的 v4/v6 解析入口（TC classifier 用，链路头 14B）。
#[inline(always)]
pub fn parse_ip(ctx: &TcContext) -> Option<SodaParseResult> {
    parse_ip_at(ctx, ETH_HLEN)
}

/// 按链路头长度解析：`link_h_len == ETH_HLEN` 取以太类型字段判定 v4/v6；
/// `link_h_len == 0`（L3 设备）取 `skb->protocol`，地址/端口布局不变，MAC 置 0。
#[inline(always)]
pub fn parse_ip_at(ctx: &TcContext, link_h_len: u32) -> Option<SodaParseResult> {
    parse_ip_at_reason(ctx, link_h_len).ok()
}

/// 带原因的解析（新调用点用它把分片尾/L4 不支持计数）。
#[inline(always)]
pub fn parse_ip_at_reason(ctx: &TcContext, link_h_len: u32) -> Result<SodaParseResult, ParseSkip> {
    let mut smac = [0u8; 6];
    let mut dmac = [0u8; 6];
    /* proto 的取值口径与 dae 一致：L2 直接读以太类型字段；L3 读 skb->protocol
     * （内核把该字段按网络序映射成与以太类型字段**同一字节形态**的 u16，故两者
     * 可直接比较、也可原样写入补出的以太头，见 kern/tproxy.c:1103/2261）。 */
    let proto = if link_h_len == ETH_HLEN {
        let eth: EthHdr = ctx.load(0).map_err(|_| ParseSkip::Other)?;
        smac = eth.h_source;
        dmac = eth.h_dest;
        eth.h_proto
    } else {
        unsafe { (*ctx.skb.skb).protocol as u16 }
    };

    let mut out = if proto == ETH_P_IP.to_be() {
        parse_v4_at(ctx, link_h_len)?
    } else if proto == ETH_P_IPV6.to_be() {
        parse_v6_at(ctx, link_h_len)?
    } else {
        return Err(ParseSkip::Other);
    };
    out.smac = smac;
    out.dmac = dmac;
    Ok(out)
}

/// IPv4 解析：`off` = 链路头长度（以太 14 / L3 0）。
#[inline(always)]
pub fn parse_v4_at(ctx: &TcContext, link_h_len: u32) -> Result<SodaParseResult, ParseSkip> {
    let iph: IpHdr = ctx.load(link_h_len as usize).map_err(|_| ParseSkip::Other)?;
    // P38：头合法性判定抽到 `ebpf-logic`（host 可单测；`#[inline(always)]` 内联等价）。
    if !ebpf_logic::v4_ihl_valid(iph.vihl) {
        return Err(ParseSkip::Other);
    }
    let ihl = ((iph.vihl & 0x0f) as u32) * 4;
    // 分片：非首片（offset != 0）没有完整 L4 头，交内核原路径（对照 dae tproxy.c:1131）。
    if ebpf_logic::v4_frag_tail(iph.frag_off) {
        return Err(ParseSkip::FragTail);
    }

    let mut out = SodaParseResult::default();
    out.tuples.sip = v4_mapped_bytes(iph.saddr);
    out.tuples.dip = v4_mapped_bytes(iph.daddr);
    out.tuples.l4proto = iph.protocol;
    out.l4proto = iph.protocol;
    out.is_v4 = 1;
    out.dscp = (iph.tos >> 2) & 0x3f;

    load_l4(ctx, link_h_len + ihl, iph.protocol, &mut out)?;
    Ok(out)
}

/// IPv6 解析：固定头 + 跳过 hop-by-hop/routing/dest-opts 扩展头（最多 4 个）；
/// 分片（44）与其余扩展头不处理（返回 `FragTail`，交内核原路径）。
#[inline(always)]
pub fn parse_v6_at(ctx: &TcContext, link_h_len: u32) -> Result<SodaParseResult, ParseSkip> {
    let iph: Ipv6Hdr = ctx.load(link_h_len as usize).map_err(|_| ParseSkip::Other)?;
    let word = u32::from_be(iph.vtc_flow);
    if (word >> 28) != 6 {
        return Err(ParseSkip::Other);
    }
    let mut next = iph.next_header;
    let mut off = link_h_len + 40;
    let mut hops = 0u8;
    while next == 0x00 || next == 0x2b || next == 0x3c {
        if hops >= 4 {
            return Err(ParseSkip::Other);
        }
        let ext_next: u8 = ctx.load(off as usize).map_err(|_| ParseSkip::Other)?;
        let ext_len: u8 = ctx.load(off as usize + 1).map_err(|_| ParseSkip::Other)?;
        let hdr_len = (ext_len as u32 + 1) * 8;
        off += hdr_len;
        next = ext_next;
        hops += 1;
    }
    // 分片头（44）：非首片交内核；首片跳过 8B 继续解 L4（对照 dae tproxy.c:1214）。
    if next == 0x2c {
        let frag_next: u8 = ctx.load(off as usize).map_err(|_| ParseSkip::Other)?;
        let frag_word: u16 = ctx.load(off as usize + 2).map_err(|_| ParseSkip::Other)?;
        if (u16::from_be(frag_word) & 0xfff8) != 0 {
            return Err(ParseSkip::FragTail);
        }
        off += 8;
        next = frag_next;
    }

    let mut out = SodaParseResult::default();
    out.tuples.sip = iph.saddr;
    out.tuples.dip = iph.daddr;
    out.tuples.l4proto = next;
    out.l4proto = next;
    out.is_v4 = 0;
    out.dscp = ((word >> 22) & 0x3f) as u8;

    load_l4(ctx, off, next, &mut out)?;
    Ok(out)
}

#[inline(always)]
fn load_l4(ctx: &TcContext, off: u32, proto: u8, out: &mut SodaParseResult) -> Result<(), ParseSkip> {
    match proto {
        IPPROTO_TCP => {
            let th: TcpHdr = ctx.load(off as usize).map_err(|_| ParseSkip::Other)?;
            out.tuples.sport = th.source;
            out.tuples.dport = th.dest;
            out.h_sport = u16::from_be(th.source);
            out.h_dport = u16::from_be(th.dest);
            /* 位段按 LE u16：首字节高半字节是 doff，flags 在高字节：fin=bit8, syn=bit9,
             * rst=bit10, psh=bit11, ack=bit12（C 的位段等价写法）。 */
            let flags = (th.doff_flags >> 8) as u8;
            out.new_flow = ebpf_logic::tcp_flags_new_flow(flags) as u8;
            Ok(())
        }
        IPPROTO_UDP => {
            let uh: UdpHdr = ctx.load(off as usize).map_err(|_| ParseSkip::Other)?;
            out.tuples.sport = uh.source;
            out.tuples.dport = uh.dest;
            out.h_sport = u16::from_be(uh.source);
            out.h_dport = u16::from_be(uh.dest);
            out.new_flow = 1;
            Ok(())
        }
        _ => Err(ParseSkip::UnsupportedL4),
    }
}

//! 报文解析（与 C `parse_v4`/`load_l4` 等价，全部走 `bpf_skb_load_bytes`）。

use aya_ebpf::programs::TcContext;

use crate::common::*;

#[inline(always)]
pub fn parse_v4(ctx: &TcContext) -> Option<MiniParseResult> {
    let eth: EthHdr = ctx.load(0).ok()?;
    if eth.h_proto != ETH_P_IP.to_be() {
        return None;
    }
    let iph: IpHdr = ctx.load(ETH_HLEN as usize).ok()?;
    if (iph.vihl >> 4) != 4 {
        return None;
    }
    let ihl = ((iph.vihl & 0x0f) as u32) * 4;
    if ihl < 20 {
        return None;
    }

    let mut out = MiniParseResult::default();
    out.tuples.sip = v4_mapped_bytes(iph.saddr);
    out.tuples.dip = v4_mapped_bytes(iph.daddr);
    out.tuples.l4proto = iph.protocol;
    out.l4proto = iph.protocol;
    out.is_v4 = 1;
    out.dscp = (iph.tos >> 2) & 0x3f;
    out.smac = eth.h_source;
    out.dmac = eth.h_dest;

    load_l4(ctx, ETH_HLEN + ihl, iph.protocol, &mut out)?;
    Some(out)
}

/// IPv6 解析：固定头 + 跳过 hop-by-hop/routing/dest-opts 扩展头（最多 4 个）；
/// 分片（44）与其余扩展头不处理（返回 None，交内核原路径）。
#[inline(always)]
pub fn parse_v6(ctx: &TcContext) -> Option<MiniParseResult> {
    let eth: EthHdr = ctx.load(0).ok()?;
    if eth.h_proto != ETH_P_IPV6.to_be() {
        return None;
    }
    let iph: Ipv6Hdr = ctx.load(ETH_HLEN as usize).ok()?;
    let word = u32::from_be(iph.vtc_flow);
    if (word >> 28) != 6 {
        return None;
    }
    let mut next = iph.next_header;
    let mut off = ETH_HLEN + 40;
    let mut hops = 0u8;
    while next == 0x00 || next == 0x2b || next == 0x3c {
        if hops >= 4 {
            return None;
        }
        let ext_next: u8 = ctx.load(off as usize).ok()?;
        let ext_len: u8 = ctx.load(off as usize + 1).ok()?;
        let hdr_len = (ext_len as u32 + 1) * 8;
        off += hdr_len;
        next = ext_next;
        hops += 1;
    }

    let mut out = MiniParseResult::default();
    out.tuples.sip = iph.saddr;
    out.tuples.dip = iph.daddr;
    out.tuples.l4proto = next;
    out.l4proto = next;
    out.is_v4 = 0;
    out.dscp = ((word >> 22) & 0x3f) as u8;
    out.smac = eth.h_source;
    out.dmac = eth.h_dest;

    load_l4(ctx, off, next, &mut out)?;
    Some(out)
}

/// 统一的 v4/v6 解析入口（TC classifier 用）。
#[inline(always)]
pub fn parse_ip(ctx: &TcContext) -> Option<MiniParseResult> {
    let eth: EthHdr = ctx.load(0).ok()?;
    if eth.h_proto == ETH_P_IP.to_be() {
        parse_v4(ctx)
    } else if eth.h_proto == ETH_P_IPV6.to_be() {
        parse_v6(ctx)
    } else {
        None
    }
}

#[inline(always)]
fn load_l4(ctx: &TcContext, off: u32, proto: u8, out: &mut MiniParseResult) -> Option<()> {
    match proto {
        IPPROTO_TCP => {
            let th: TcpHdr = ctx.load(off as usize).ok()?;
            out.tuples.sport = th.source;
            out.tuples.dport = th.dest;
            out.h_sport = u16::from_be(th.source);
            out.h_dport = u16::from_be(th.dest);
            /* 位段按 LE u16：首字节高半字节是 doff，flags 在高字节：fin=bit8, syn=bit9,
             * rst=bit10, psh=bit11, ack=bit12（C 的位段等价写法）。 */
            let flags = (th.doff_flags >> 8) as u8;
            out.new_flow = ((flags & 0x02) != 0 && (flags & 0x10) == 0) as u8;
            Some(())
        }
        IPPROTO_UDP => {
            let uh: UdpHdr = ctx.load(off as usize).ok()?;
            out.tuples.sport = uh.source;
            out.tuples.dport = uh.dest;
            out.h_sport = u16::from_be(uh.source);
            out.h_dport = u16::from_be(uh.dest);
            out.new_flow = 1;
            Some(())
        }
        _ => None,
    }
}

//! 报文解析（与 C `parse_v4`/`load_l4` 等价，全部走 `bpf_skb_load_bytes`）。

use aya_ebpf::programs::TcContext;

use crate::common::*;

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
    out.tuples.sip = iph.saddr;
    out.tuples.dip = iph.daddr;
    out.tuples.l4proto = iph.protocol;
    out.l4proto = iph.protocol;
    out.is_v4 = 1;
    out.dscp = (iph.tos >> 2) & 0x3f;
    out.smac = eth.h_source;
    out.dmac = eth.h_dest;

    load_l4(ctx, ETH_HLEN + ihl, iph.protocol, &mut out)?;
    Some(out)
}

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

//! 对标批：`skb_send_sock` 记账（fentry + kprobe 双形态），对照 dae
//! `tcp_offload_sent_account(_kprobe)` + `include/tcp_offload.h:tcp_offload_skb_key`
//! （`dae/control/kern/tproxy.c:4360-4393`）。
//!
//! 语义：sockmap verdict 重定向后，`sk_psock_verdict_apply -> sk_psock_skb_redirect ->
//! sk_psock_handle_skb -> skb_send_sock` 把 skb 的载荷推进对端 relay socket 的发送路径；
//! 本探针按 skb 上**原始**（重定向前）的四元组记账字节数——该键与 fast_sock 的注册键
//! 同布局，用户态据此在键摘除时回收（dae 用同一布局做 backpressure fuse 的读数）。
//!
//! 与 dae 的三点差异（见 ADR-0065）：
//!   1. dae 用 clang CO-RE（`BPF_CORE_READ_INTO`）读 `struct sk_buff` 字段；aya-ebpf 无
//!      CO-RE field access，改为 loader 从 vmlinux BTF 解出偏移写入 `trace_param_map`；
//!   2. dae 对任何 `skb_send_sock` 调用都建键/累加（map 会被无关流量撑满）；sodama 先查
//!      `offload_guard`（只含本进程注册的 offload 键）过滤，未注册的流量不计；
//!   3. dae 的 per-key 读数服务于背压 fuse（未实现）：sodama 只在键摘除时汇总回收。
//!
//! 记账口径注意（继承 dae）：fentry 在函数入口触发，`EAGAIN` 重试路径
//! （`!sock_writeable` 经 `sk_psock_handle_skb` 重入）会重复计数——拥塞时高估「已发送」，
//! 方向保守（相对死计数），接受。

use core::ffi::c_void;

use aya_ebpf::{
    bpf_printk,
    macros::{fentry, kprobe},
    programs::{FEntryContext, ProbeContext},
};
use aya_ebpf_bindings::{
    bindings::BPF_ANY,
    helpers::bpf_probe_read_kernel,
};

use crate::common::*;
use crate::event::bump_stat;
use crate::maps::*;

/// 读内核内存（失败返回 None）。
#[inline(always)]
unsafe fn kread<T: Copy>(addr: *const c_void, out: &mut T) -> Option<()> {
    let ret = bpf_probe_read_kernel(
        out as *mut T as *mut c_void,
        core::mem::size_of::<T>() as u32,
        addr,
    );
    if ret == 0 {
        Some(())
    } else {
        None
    }
}

/// 从 `struct sk_buff *` 取记账键（对照 dae `tcp_offload_skb_key`）。
///
/// 偏移由 loader 从 vmlinux BTF 提供（`trace_param_map`）；
/// 未提供时（loader 未解析 BTF / 对象由旧 loader 加载）直接放弃记账。
#[inline(always)]
unsafe fn skb_key(skb: *const c_void, key: &mut SodaTuple) -> bool {
    let Some(p) = trace_param_map.get(0) else {
        return false;
    };
    let base = skb as *const u8;

    let mut nh = 0u16;
    let mut th = 0u16;
    let mut tail = 0u32;
    let mut head = 0u64;
    if kread(base.add(p.network_header as usize) as *const c_void, &mut nh).is_none()
        || kread(base.add(p.transport_header as usize) as *const c_void, &mut th).is_none()
        || kread(base.add(p.tail as usize) as *const c_void, &mut tail).is_none()
        || kread(base.add(p.head as usize) as *const c_void, &mut head).is_none()
    {
        return false;
    }

    /* 与 dae 相同的边界与合法性判定：transport_header 未设置（0xffff）、
     * 位于 network_header 之前（v6 已走过扩展头才设置）、或超出 tail 时放弃。 */
    if head == 0 || th == 0xffffu16 || th < nh || (th as u32 + core::mem::size_of::<TcpHdr>() as u32) > tail
    {
        return false;
    }

    let mut version = 0u8;
    if kread(head as *const u8 as *const c_void, &mut version).is_none() {
        return false;
    }

    let mut ip4 = IpHdr::default();
    let mut ip6 = Ipv6Hdr::default();
    if (version & 0xf0) == 0x40 {
        let ihl = ((version & 0x0f) as u32) * 4;
        if ihl < 20 || (th as u32) - (nh as u32) != ihl {
            return false;
        }
        if kread(
            (head as *const u8).add(nh as usize) as *const c_void,
            &mut ip4,
        )
        .is_none()
        {
            return false;
        }
        if ip4.protocol != IPPROTO_TCP {
            return false;
        }
        key.sip = v4_mapped_bytes(ip4.saddr);
        key.dip = v4_mapped_bytes(ip4.daddr);
        key.is_v6 = 0;
    } else if (version & 0xf0) == 0x60 {
        if (th as u32) - (nh as u32) < 40 {
            return false;
        }
        if kread(
            (head as *const u8).add(nh as usize) as *const c_void,
            &mut ip6,
        )
        .is_none()
        {
            return false;
        }
        key.sip = ip6.saddr;
        key.dip = ip6.daddr;
        key.is_v6 = 1;
    } else {
        return false;
    }

    let mut tcp = TcpHdr::default();
    if kread(
        (head as *const u8).add(th as usize) as *const c_void,
        &mut tcp,
    )
    .is_none()
    {
        return false;
    }
    key.l4proto = IPPROTO_TCP;
    key.sport = tcp.source;
    key.dport = tcp.dest;
    true
}

/// 记账主体（fentry 与 kprobe 两个入口共用）。
#[inline(always)]
unsafe fn account(skb: *const c_void, len: i32) {
    let mut key = SodaTuple {
        sip: [0u8; 16],
        dip: [0u8; 16],
        sport: 0,
        dport: 0,
        l4proto: IPPROTO_TCP,
        is_v6: 0,
        pad: [0; 2],
    };
    if !skb_key(skb, &mut key) {
        return;
    }
    /* 只记本进程注册的 offload 键（offload_guard 与 fast_sock 同键集、先写后删）。 */
    if offload_guard.get(&key).is_none() {
        return;
    }

    let bytes = if len > 0 { len as u64 } else { 0 };
    match offload_sent.get_ptr_mut(&key) {
        Some(v) => *v += bytes,
        None => {
            if offload_sent.insert(&key, &bytes, BPF_ANY as u64).is_err() {
                /* 表满：这次记账丢失——必须可数（用户态可见）。 */
                bump_stat(SODAMA_STAT_ACCOUNT_DROPS);
                return;
            }
        }
    }
    /* 内核侧全局口径：探针观测到的推送字节总数（per-session 归因由用户态在
     * 键摘除时汇总 `offload_sent` 得到）。 */
    if let Some(v) = sodama_stats_map.get_ptr_mut(SODAMA_STAT_OFFLOAD_SENT_BYTES) {
        *v += bytes;
    }
}

#[fentry(function = "skb_send_sock")]
pub fn skb_send_sock_account(ctx: FEntryContext) -> i32 {
    let skb: *const c_void = ctx.arg(1);
    let len: i32 = ctx.arg(3);
    unsafe {
        if crate::flow::debug_log() {
            bpf_printk!(c"sodama: fentry skb_send_sock len=%d\n", len);
        }
        account(skb, len);
    }
    0
}

/// kprobe 形态：内核无 `CONFIG_DYNAMIC_FTRACE`（精简路由固件）或 fentry 目标已被
/// 直接调用/其它 trampoline 占用（EBUSY）时由 loader 回退使用（对照 dae
/// `tcp_offload_sent_account_kprobe` 与 `tcp_offload_hook.go` 的选用逻辑）。
#[kprobe(function = "skb_send_sock")]
pub fn skb_send_sock_account_kprobe(ctx: ProbeContext) -> u32 {
    let Some(skb) = ctx.arg::<*const c_void>(1) else {
        return 0;
    };
    let len: i32 = ctx.arg(3).unwrap_or(0);
    unsafe {
        account(skb, len);
    }
    0
}

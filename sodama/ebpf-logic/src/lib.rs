// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! sodama eBPF 数据面的**纯逻辑**（无 BPF 依赖、no_std 可编、host 可单测）。
//!
//! 为什么单独一个 crate：`ebpf-rs` 只能编译到 `bpfel-unknown-none`（无法在 host 跑
//! `cargo test`），而数据面里最易错的部分恰恰是与指针/映射无关的**判定逻辑**。把这类
//! 逻辑抽到这里，`ebpf-rs` 以 `#[inline(always)]` 内联调用（对 verifier 逐字节等价），
//! host 侧则用常规单测逐条锁定（对照 dae 的 C 宏/Go 侧镜像测试）。
//!
//! 已覆盖的判定（与 `ebpf-rs/src/*` 对应）：
//! - TCP 首包/纯 SYN 位判定（`parse.rs` / `flow.rs` 重绑路径）
//! - IPv4 头合法性（版本/IHL）与分片尾判定（`parse.rs`）
//! - 事件限速窗口（`event.rs`）
#![cfg_attr(not(test), no_std)]

/// TCP flags 里「新流/纯 SYN」判定：SYN=1 且 ACK=0（对照 `parse.rs` 的位段提取）。
///
/// 位含义（`th.doff_flags` 高字节）：fin=0x01 syn=0x02 rst=0x04 psh=0x08 ack=0x10。
#[inline(always)]
pub const fn tcp_flags_new_flow(flags: u8) -> bool {
    (flags & 0x02) != 0 && (flags & 0x10) == 0
}

/// IPv4 头合法性：版本 == 4 且 IHL ≥ 5（20 字节）——`vihl` 高 4 位为版本、低 4 位为 IHL/4。
#[inline(always)]
pub const fn v4_ihl_valid(vihl: u8) -> bool {
    (vihl >> 4) == 4 && (vihl & 0x0f) >= 5
}

/// IPv4 分片尾判定：非首分片（offset != 0）没有完整 L4 头，交内核原路径。
/// 入参为 `frag_off` 的**大端原值**（网络序 u16 直接读入）。
#[inline(always)]
pub const fn v4_frag_tail(frag_off_be: u16) -> bool {
    (u16::from_be(frag_off_be) & 0x1fff) != 0
}

/// 事件限速窗口：距上次上报不足 `window_ns` → 被限速（`now - last < window`，
/// 用 wrapping 算术防单调钟回绕/首值 0）。
#[inline(always)]
pub const fn rate_window_closed(now_ns: u64, last_ns: u64, window_ns: u64) -> bool {
    now_ns.wrapping_sub(last_ns) < window_ns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_new_flow_syn_without_ack() {
        // 纯 SYN（首包）
        assert!(tcp_flags_new_flow(0x02));
        // SYN+ACK（回包，不是新流）
        assert!(!tcp_flags_new_flow(0x12));
        // 纯 ACK / FIN / RST / PSH
        for f in [0x00u8, 0x10, 0x01, 0x04, 0x08] {
            assert!(!tcp_flags_new_flow(f), "{f:#x}");
        }
        // SYN+FIN（畸形）视作新流（与位段原语义一致）
        assert!(tcp_flags_new_flow(0x03));
    }

    #[test]
    fn v4_header_and_fragment_tail() {
        assert!(v4_ihl_valid(0x45)); // v4, IHL=5
        assert!(v4_ihl_valid(0x4f)); // v4, IHL=15
        assert!(!v4_ihl_valid(0x40)); // IHL=0 非法
        assert!(!v4_ihl_valid(0x44)); // IHL=4（<20 字节）非法
        assert!(!v4_ihl_valid(0x65)); // 版本 6
        assert!(!v4_ihl_valid(0x00));
        // 分片：大端原值。0x0000 = 首片/未分片；0x2000 = MF 置位仍为首片；低位!=0 = 尾片
        assert!(!v4_frag_tail(0x0000u16.to_be()));
        assert!(!v4_frag_tail(0x2000u16.to_be()));
        assert!(v4_frag_tail(0x0001u16.to_be()));
        assert!(v4_frag_tail(0x1fff_u16.to_be()));
        // 0xE000 是保留位（Evil/DF），低位为 0 → 不算尾片（与 dae 的 & 0x1fff 一致）
        assert!(!v4_frag_tail(0xE000u16.to_be()));
    }

    #[test]
    fn rate_window_semantics() {
        const W: u64 = 1_000_000_000;
        // 首值 last=0：现在远大于窗口 → 窗口开（可上报）
        assert!(!rate_window_closed(2 * W, 0, W));
        // 刚刚报过（差 1ns < 窗口）→ 限速
        assert!(rate_window_closed(100, 99, W));
        // 差 == 窗口 → 开（严格小于才对内）
        assert!(!rate_window_closed(W, 0, W));
        // wrapping：last 更“新”（时钟回绕/竞态）→ 视为刚报过
        assert!(rate_window_closed(0, u64::MAX - 10, W));
    }
}

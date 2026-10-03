//! mini-dae 数据面（Rust / aya-ebpf）——由 C 版移植而来，现为唯一数据面（ADR-0024/0025）。
//!
//! 程序与 map 的名字、类型、容量、section 与 C 版逐一对齐（原 C 对象已移除，ADR-0025）：
//!   - 7 个 TC classifier（lan/wan/dual/dae0peer/dae0）+ 1 个 sk_skb offload verdict；
//!   - 规则 VM：有界循环（bounded loop；bpf_loop 因 aya-obj relocation 缺口不可用）+ LPM array-of-maps + 双 epoch 槽；
//!   - conn_state / redirect_track 单写者 / 域位图 / 控制位（suspend）。
#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

mod cgroup;
mod common;
mod flow;
mod maps;
mod offload;
mod parse;
mod progs;
mod route;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

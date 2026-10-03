//! P17b：pname 采集程序（cgroup 钩子），对照 dae `tproxy.c` 的
//! `update_map_elem_by_cookie` + 6 个 cgroup 程序（sock_create/sock_release/
//! connect4/6/sendmsg4/6）。
//!
//! 链路：进程调 socket()/connect()/sendmsg() → 本程序按 socket cookie 写入
//! `cookie_pid_map`（pname 16B + pid + last_seen）→ TC 侧（WAN egress 新连接）
//! 用 `bpf_get_socket_cookie(skb)` 反查，交给规则 VM 的 `pname()` 匹配。
//!
//! 与 dae 的差异（如实）：pname 取 `bpf_get_current_comm`（≤15 字符，内核线程/短名
//! 一致）；dae 优先用 CO-RE 读 `task->mm->arg_start` 取 argv[0] basename（需要
//! `bpf_loop`，本项目因 aya-obj relocation 缺口不用），comm 在 setuid/容器场景
//! 可能与 argv 不同（见 ADR-0033）。所有钩子返回 1（放行），失败绝不阻断业务。

use core::ffi::c_void;

use aya_ebpf::{
    macros::{cgroup_sock, cgroup_sock_addr},
    programs::{SockAddrContext, SockContext},
    EbpfContext,
};
use aya_ebpf_bindings::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_socket_cookie, bpf_ktime_get_ns,
};

use crate::common::*;
use crate::maps::*;

/// 采集/刷新一条 cookie → pname 映射。返回 1 = 放行（cgroup 钩子语义）。
#[inline(always)]
unsafe fn record(ctx: *mut c_void) -> i32 {
    let cookie = bpf_get_socket_cookie(ctx);
    if cookie == 0 {
        // 转发流量无 skb->sk / 非 socket 上下文：与 dae 一致，拒绝零 cookie。
        return 1;
    }
    if let Some(e) = cookie_pid_map.get_ptr_mut(&cookie) {
        // 已存在（connect/sendmsg 会重复触发）：仅刷新时间戳（对照 dae）。
        (*e).last_seen_ns = bpf_ktime_get_ns();
        return 1;
    }
    let mut v = MiniPidPname {
        pname: [0u8; 16],
        pid: 0,
        pad: [0u8; 4],
        last_seen_ns: bpf_ktime_get_ns(),
    };
    // 取 comm（失败则只写 pid：正规则不命中，负规则照常 —— dae 的降级同义）。
    if bpf_get_current_comm(v.pname.as_mut_ptr() as *mut c_void, 16) < 0 {
        v.pname = [0u8; 16];
    }
    v.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = cookie_pid_map.insert(&cookie, &v, 0);
    1
}

#[cgroup_sock(sock_create)]
pub fn mini_cgroup_sock_create(ctx: SockContext) -> i32 {
    unsafe { record(ctx.as_ptr()) }
}

#[cgroup_sock(sock_release)]
pub fn mini_cgroup_sock_release(ctx: SockContext) -> i32 {
    unsafe {
        let cookie = bpf_get_socket_cookie(ctx.as_ptr());
        if cookie != 0 {
            let _ = cookie_pid_map.remove(&cookie);
        }
    }
    1
}

#[cgroup_sock_addr(connect4)]
pub fn mini_cgroup_connect4(ctx: SockAddrContext) -> i32 {
    unsafe { record(ctx.as_ptr()) }
}

#[cgroup_sock_addr(connect6)]
pub fn mini_cgroup_connect6(ctx: SockAddrContext) -> i32 {
    unsafe { record(ctx.as_ptr()) }
}

#[cgroup_sock_addr(sendmsg4)]
pub fn mini_cgroup_sendmsg4(ctx: SockAddrContext) -> i32 {
    unsafe { record(ctx.as_ptr()) }
}

#[cgroup_sock_addr(sendmsg6)]
pub fn mini_cgroup_sendmsg6(ctx: SockAddrContext) -> i32 {
    unsafe { record(ctx.as_ptr()) }
}

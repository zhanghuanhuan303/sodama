// SPDX-License-Identifier: GPL-2.0
//! O8：跨连接复用的小块缓冲池。
//!
//! 回收点：codec 会话每方向 `out`（生长到 128KB）、回退泵每方向 64KB、
//! UDP 会话槽 64KB。池按档位（64KB/128KB）各保留至多 `MAX_PER_CLASS` 个，
//! 内存有界；`PoolBuf` Drop 时自动按容量归还。

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, OnceLock};

pub const CLASS_SMALL: usize = 64 * 1024;
pub const CLASS_LARGE: usize = 128 * 1024;
/// 池内保留字节总量上限（两档共享；超出即直接释放，RSS 不会随 churn 虚高）。
const POOL_MAX_BYTES: usize = 8 << 20;

struct Pool {
    small: Vec<Vec<u8>>,
    large: Vec<Vec<u8>>,
    bytes: usize,
}

static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();

fn pool() -> &'static Mutex<Pool> {
    POOL.get_or_init(|| {
        Mutex::new(Pool {
            small: Vec::new(),
            large: Vec::new(),
            bytes: 0,
        })
    })
}

/// 池化字节缓冲（`Deref` 到 `Vec<u8>`）；Drop 时按容量归还有界池。
pub struct PoolBuf {
    v: Vec<u8>,
}

impl PoolBuf {
    /// 取得至少 `len` 字节、已初始化为 0 的缓冲（优先复用池中同档缓冲）。
    pub fn zeroed(len: usize) -> PoolBuf {
        let class = if len <= CLASS_SMALL {
            CLASS_SMALL
        } else {
            CLASS_LARGE
        };
        if let Ok(mut p) = pool().lock() {
            let stack = if class == CLASS_SMALL {
                &mut p.small
            } else {
                &mut p.large
            };
            if let Some(mut v) = stack.pop() {
                p.bytes = p.bytes.saturating_sub(v.capacity());
                v.clear();
                v.resize(len, 0);
                return PoolBuf { v };
            }
        }
        PoolBuf { v: vec![0u8; len] }
    }

    /// 空缓冲（容量 0，随使用生长；Drop 时按实际容量入池）。
    pub fn empty() -> PoolBuf {
        PoolBuf { v: Vec::new() }
    }

    /// 就绪可写切片（长度 = 当前 len；`recvmmsg_udp` 用 `set_len` 预张）。
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.v
    }
}

impl Deref for PoolBuf {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.v
    }
}

impl DerefMut for PoolBuf {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.v
    }
}

impl Drop for PoolBuf {
    fn drop(&mut self) {
        let v = std::mem::take(&mut self.v);
        let cap = v.capacity();
        let Ok(mut p) = pool().lock() else {
            return;
        };
        if p.bytes + cap > POOL_MAX_BYTES {
            return; // 池已满：直接释放，避免 RSS 虚高
        }
        let stack = if cap >= CLASS_LARGE {
            &mut p.large
        } else if cap >= CLASS_SMALL {
            &mut p.small
        } else {
            return; // 小缓冲不入池（避免碎片）
        };
        stack.push(v);
        p.bytes += cap;
    }
}

/// 测试/诊断：当前池内缓冲数（small, large）与保留字节数。
/// P38：当前无调用方（lab 用 perf/mem 采样 RSS）；保留为池内省 API。
#[allow(dead_code)]
pub fn pool_len() -> (usize, usize) {
    match pool().lock() {
        Ok(p) => (p.small.len(), p.large.len()),
        Err(_) => (0, 0),
    }
}

/// 测试/诊断：池内保留字节数。
#[allow(dead_code)]
pub fn pool_bytes() -> usize {
    match pool().lock() {
        Ok(p) => p.bytes,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_recycles_and_is_bounded() {
        // 串行化本模块测试，避免与并行用例争抢池内缓冲。
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let (s0, l0) = pool_len();
        {
            let b = PoolBuf::zeroed(CLASS_SMALL);
            assert!(b.capacity() >= CLASS_SMALL);
            drop(b);
        }
        assert_eq!(pool_len().0, s0 + 1, "归还后应入池");
        let b = PoolBuf::zeroed(CLASS_SMALL);
        assert_eq!(pool_len().0, s0, "取用后应从池中弹出");
        drop(b);

        // 有界：按字节封顶
        let mut hold = Vec::new();
        for _ in 0..(POOL_MAX_BYTES / CLASS_SMALL + 32) {
            hold.push(PoolBuf::zeroed(CLASS_SMALL));
        }
        drop(hold);
        assert!(pool_bytes() <= POOL_MAX_BYTES, "池必须按字节有界");

        // 生长到 128KB 的缓冲按大档回收
        {
            let mut big = PoolBuf::empty();
            big.resize(CLASS_LARGE, 0);
            drop(big);
        }
        assert!(pool_len().1 > l0 || pool_bytes() >= POOL_MAX_BYTES);
    }
}

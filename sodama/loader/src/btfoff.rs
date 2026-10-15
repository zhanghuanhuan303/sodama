// SPDX-License-Identifier: GPL-2.0
//! 运行内核 BTF 解析：`struct sk_buff` 字段偏移（CO-RE 的用户态替代品）。
//!
//! 为什么需要：aya/aya-ebpf 没有 clang CO-RE 的 `bpf_core_read` / `BPF_CORE_READ`
//! 字段访问能力，而数据面记账探针（`sodama/ebpf-rs/src/trace.rs` 的 `skb_key`，
//! fentry+kprobe 挂在 `skb_send_sock`）必须按**运行内核**的真实布局读 `struct sk_buff`
//! 的 4 个字段：`network_header`(u16)、`transport_header`(u16)、`tail`(u32)、`head`(指针)。
//! 这些偏移随内核版本/编译选项变化，所以由用户态（loader 以 root 运行）解析运行内核的
//! `/sys/kernel/btf/vmlinux`，把结果交给 loader 写入 eBPF map `trace_param_map`
//! （map 元素 `SodaTraceParam` 见 `sodama/ebpf-rs/src/common.rs:282` 与
//! `sodama/ebpf-rs/src/maps.rs:104`）。本模块只提供解析 API，不碰 map 本身。
//!
//! 对照 dae（Go）：dae 用 clang CO-RE 宏 `BPF_CORE_READ_INTO(&nh, skb, network_header)`
//! （`dae/control/kern/include/tcp_offload.h:26-29` 的 `tcp_offload_skb_key`，记账调用点
//! `dae/control/kern/tproxy.c:4376`）；本模块是它的用户态等价物。
//!
//! BTF 二进制格式（内核 `include/uapi/linux/btf.h`）：
//!   - 头部 `btf_header`（btf.h:21）字段全小端：magic(=0xEB9F)、version、flags、hdr_len、
//!     type_off、type_len、str_off、str_len；类型/字符串段起点 = `hdr_len + 对应 off`。
//!     hdr_len 是头部自身长度，真机 6.18 上是 32（24 字节固定字段 + 8 字节保留），
//!     不能写死 24。magic 按小端读成 0x9FEB 说明内核是大端（字节反序），只支持小端。
//!   - 类型段是一串 `struct btf_type{name_off, info, size_or_type}`（btf.h:47）：
//!     `kind = (info >> 24) & 0x7f`、`vlen = info & 0xffffff`（btf.h:51 注释）、
//!     `kind_flag = info >> 31`；每条记录后面的尾随数据长度由 kind 决定
//!     （见 `next_type_off`，kind 编号见 btf.h:74-94）。
//!   - STRUCT/UNION 成员是 `struct btf_member{name_off, type, offset}`（btf.h:137）：
//!     offset 单位是 bit；kind_flag 置位时高 8 位是位域宽度、低 24 位才是 bit 偏移。
//!   - `name_off == 0` 表示空名（匿名成员）；类型 id 从 1 开始（= 记录序号 + 1）。
//!
//! 查找算法：定位第一条 `kind == STRUCT && name == <目标>` 的记录（正常内核 BTF 里
//! 同名 struct 只有一份；多份时取第一条），先在其**直接成员**里按名匹配，未命中再递归
//! 进**匿名** struct/union 并累加父偏移——`sk_buff.headers.network_header` 就藏在两层
//! 匿名成员里。bit 偏移不是 8 的倍数（位域）视为不可按字节读，返回 Err。

/// 小端 BTF 魔数（`btf_header.magic`）。
const BTF_MAGIC: u16 = 0xEB9F;
/// 大端内核上同一字段按小端读出的值（magic 字节反序）。
const BTF_MAGIC_SWAPPED: u16 = 0x9FEB;
/// `btf_header` 固定字段占 24 字节，hdr_len 不允许更小。
const BTF_HEADER_MIN: usize = 24;
/// 匿名 struct/union 递归上限：畸形 BTF 里匿名成员可以自引用成环。
const MAX_ANON_DEPTH: u32 = 8;

// BTF kind 编号（include/uapi/linux/btf.h:74-94）。未知 kind（> 19）必须报错而不是瞎跳。
const KIND_UNKN: u8 = 0;
const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;

/// `struct sk_buff` 记账所需字段的字节偏移。
///
/// 字段布局与数据面 `SodaTraceParam`（`sodama/ebpf-rs/src/common.rs:282`）一一对应，
/// loader 解析后原样写进 `trace_param_map`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SkBuffOffsets {
    pub network_header: u32,
    pub transport_header: u32,
    pub tail: u32,
    pub head: u32,
}

/// 从运行内核 `/sys/kernel/btf/vmlinux` 解析 `struct sk_buff` 的字段偏移。
///
/// 需要 root（普通用户读该文件通常 EACCES）；文件不存在说明内核未开
/// CONFIG_DEBUG_INFO_BTF，调用方应降级为「不记账」而不是加载失败。
pub fn sk_buff_offsets() -> Result<SkBuffOffsets, String> {
    const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";
    let bytes = std::fs::read(VMLINUX_BTF).map_err(|e| format!("读取 {VMLINUX_BTF} 失败: {e}"))?;
    sk_buff_offsets_from(&bytes)
}

/// 从任意 BTF 字节流解析（便于测试与离线核对；`btf_bytes` 是完整 BTF 段内容）。
pub fn sk_buff_offsets_from(btf_bytes: &[u8]) -> Result<SkBuffOffsets, String> {
    let v = struct_member_byte_offsets(
        btf_bytes,
        "sk_buff",
        &["network_header", "transport_header", "tail", "head"],
    )?;
    match v.as_slice() {
        [network_header, transport_header, tail, head] => Ok(SkBuffOffsets {
            network_header: *network_header,
            transport_header: *transport_header,
            tail: *tail,
            head: *head,
        }),
        // 上面这个函数按请求顺序逐项返回，个数必然一致；走到这里说明它有 bug。
        _ => Err("struct_member_byte_offsets 返回个数与请求不符".to_string()),
    }
}

/// 通用：取 `struct <struct_name>` 中若干成员的字节偏移（成员可位于匿名 struct/union 内，
/// 需要递归累加父偏移）。返回顺序与传入 `members` 一致；找不到的成员返回 Err。
///
/// 同名 struct 正常只有一份（vmlinux BTF 会去重，拆分引用只出现在模块 BTF 里）；
/// 若出现多份，取**第一条**记录。
pub fn struct_member_byte_offsets(
    btf_bytes: &[u8],
    struct_name: &str,
    members: &[&str],
) -> Result<Vec<u32>, String> {
    let (types, strs) = sections(btf_bytes)?;
    let (record_off, header) = find_struct(types, strs, struct_name)?;
    let mut out = Vec::with_capacity(members.len());
    for member in members {
        match lookup_member_bits(types, strs, record_off, &header, member, 0, 0)? {
            Some(byte_off) => out.push(byte_off),
            None => {
                return Err(format!(
                    "`struct {struct_name}` 中找不到成员 `{member}`（含匿名 struct/union 嵌套）"
                ))
            }
        }
    }
    Ok(out)
}

/// 切出类型段与字符串段（都相对 `hdr_len` 之后定位），顺手做 magic/边界校验。
fn sections(btf_bytes: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if btf_bytes.len() < BTF_HEADER_MIN {
        return Err(format!(
            "BTF 段只有 {} 字节，不足 {BTF_HEADER_MIN} 字节头部",
            btf_bytes.len()
        ));
    }
    let magic = u16::from_le_bytes([btf_bytes[0], btf_bytes[1]]);
    if magic == BTF_MAGIC_SWAPPED {
        return Err(format!(
            "BTF magic 0x{magic:04X}：大端字节序内核，本解析器只支持小端"
        ));
    }
    if magic != BTF_MAGIC {
        return Err(format!(
            "BTF magic 错误：0x{magic:04X}（应为 0x{BTF_MAGIC:04X}）"
        ));
    }
    let hdr_len = read_u32(btf_bytes, 4)? as usize;
    if hdr_len < BTF_HEADER_MIN {
        return Err(format!(
            "BTF hdr_len={hdr_len} 小于固定头部 {BTF_HEADER_MIN} 字节"
        ));
    }
    let type_off = read_u32(btf_bytes, 8)? as usize;
    let type_len = read_u32(btf_bytes, 12)? as usize;
    let str_off = read_u32(btf_bytes, 16)? as usize;
    let str_len = read_u32(btf_bytes, 20)? as usize;

    let types = section(btf_bytes, hdr_len, type_off, type_len, "类型段")?;
    let strs = section(btf_bytes, hdr_len, str_off, str_len, "字符串段")?;
    Ok((types, strs))
}

/// 取 `hdr_len + off` 起 `len` 字节的子段，越界即 Err。
fn section<'a>(
    btf_bytes: &'a [u8],
    hdr_len: usize,
    off: usize,
    len: usize,
    what: &str,
) -> Result<&'a [u8], String> {
    let start = hdr_len
        .checked_add(off)
        .ok_or_else(|| format!("BTF {what}偏移溢出"))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| format!("BTF {what}长度溢出"))?;
    btf_bytes.get(start..end).ok_or_else(|| {
        format!(
            "BTF {what}越界：{start}..{end}，实际 {} 字节",
            btf_bytes.len()
        )
    })
}

/// 小端读 u32（越界 Err，不 panic）。
fn read_u32(buf: &[u8], off: usize) -> Result<u32, String> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| "BTF 偏移溢出".to_string())?;
    let s = buf
        .get(off..end)
        .ok_or_else(|| format!("BTF 在偏移 {off} 处截断（需 4 字节）"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// 取字符串段里 `name_off` 处的 NUL 结尾字符串；`name_off == 0` 是空名（匿名成员）。
fn str_at(strs: &[u8], name_off: u32) -> Result<&str, String> {
    if name_off == 0 {
        return Ok("");
    }
    let start = name_off as usize;
    let rest = strs
        .get(start..)
        .ok_or_else(|| format!("字符串偏移 {start} 越界（字符串段 {} 字节）", strs.len()))?;
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| format!("字符串偏移 {start} 处没有 NUL 终止符"))?;
    std::str::from_utf8(&rest[..end])
        .map_err(|_| format!("字符串偏移 {start} 处不是合法 UTF-8（BTF 名称应为 ASCII）"))
}

/// 一条 `struct btf_type` 的头部字段；尾随数据长度由 kind/vlen 决定，另行跳过。
#[derive(Clone, Copy)]
struct TypeHeader {
    kind: u8,
    kflag: bool,
    vlen: u32,
    name_off: u32,
    size_or_type: u32,
}

fn parse_type_header(types: &[u8], off: usize) -> Result<TypeHeader, String> {
    let name_off = read_u32(types, off)?;
    let info = read_u32(types, off + 4)?;
    let size_or_type = read_u32(types, off + 8)?;
    Ok(TypeHeader {
        kind: ((info >> 24) & 0x7f) as u8,
        kflag: info >> 31 != 0,
        vlen: info & 0x00ff_ffff,
        name_off,
        size_or_type,
    })
}

/// 返回下一条类型记录的起点：跳过 kind 对应的尾随数据（btf.h 各 kind 注释）。
/// kind > 19 不在 BTF 规范内——必须报错，不能猜长度（否则会读越界或错位）。
fn next_type_off(types: &[u8], off: usize, h: &TypeHeader) -> Result<usize, String> {
    let tail = match h.kind {
        // btf_int(4) / btf_var(4) / btf_decl_tag(4)
        KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
        // btf_array{type, index_type, nelems}(12)
        KIND_ARRAY => 12,
        // btf_member(12) / btf_var_secinfo(12) / btf_enum64(12)
        KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => (h.vlen as usize)
            .checked_mul(12)
            .ok_or_else(|| "BTF 尾随数据长度溢出".to_string())?,
        // btf_enum(8) / btf_param(8)
        KIND_ENUM | KIND_FUNC_PROTO => (h.vlen as usize)
            .checked_mul(8)
            .ok_or_else(|| "BTF 尾随数据长度溢出".to_string())?,
        // UNKN/PTR/FWD/TYPEDEF/VOLATILE/CONST/RESTRICT/FUNC/FLOAT/TYPE_TAG 无尾随数据
        KIND_UNKN | KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST
        | KIND_RESTRICT | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
        other => {
            return Err(format!(
                "未知 BTF kind {other}（规范只到 {KIND_ENUM64}），无法确定记录长度"
            ))
        }
    };
    let end = off
        .checked_add(12)
        .and_then(|x| x.checked_add(tail))
        .ok_or_else(|| "BTF 记录长度溢出".to_string())?;
    if end > types.len() {
        return Err(format!(
            "类型记录在偏移 {off} 处截断：kind={} vlen={} 需要 {tail} 字节尾随数据",
            h.kind, h.vlen
        ));
    }
    Ok(end)
}

/// 按类型 id（从 1 起）定位记录；0 是保留的 void，没有对应记录。
fn type_at(types: &[u8], id: u32) -> Result<(usize, TypeHeader), String> {
    if id == 0 {
        return Err("类型 id 0 保留给 void，没有对应记录".to_string());
    }
    let mut off = 0usize;
    let mut cur = 1u32;
    while off < types.len() {
        let h = parse_type_header(types, off)?;
        if cur == id {
            return Ok((off, h));
        }
        off = next_type_off(types, off, &h)?;
        cur += 1;
    }
    Err(format!("类型 id {id} 超出类型段（共 {} 条记录）", cur - 1))
}

/// 剥掉 TYPEDEF/CONST/VOLATILE/RESTRICT/TYPE_TAG 这类不改变布局的修饰，返回目标类型。
fn resolve_type(types: &[u8], mut id: u32) -> Result<(usize, TypeHeader), String> {
    for _ in 0..MAX_ANON_DEPTH {
        let (off, h) = type_at(types, id)?;
        match h.kind {
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                id = h.size_or_type;
            }
            _ => return Ok((off, h)),
        }
    }
    Err("类型修饰链过深（疑似类型 id 成环）".to_string())
}

/// 找第一条名为 `struct <name>` 的记录。
fn find_struct(types: &[u8], strs: &[u8], name: &str) -> Result<(usize, TypeHeader), String> {
    let mut off = 0usize;
    while off < types.len() {
        let h = parse_type_header(types, off)?;
        // 只解析 STRUCT 的名字：其它记录的名字与本查询无关，越界还能容忍（但本实现
        // 对越界仍会在成员查询路径上报错，见 str_at）。
        if h.kind == KIND_STRUCT && str_at(strs, h.name_off)? == name {
            return Ok((off, h));
        }
        off = next_type_off(types, off, &h)?;
    }
    Err(format!("BTF 中没有名为 `struct {name}` 的类型"))
}

/// 成员项里取 bit 偏移：kind_flag 置位时高 8 位是位域宽度，低 24 位才是 bit 偏移
/// （btf.h:140-145 的 `struct btf_member` 注释）。
fn member_bit_offset(kflag: bool, raw: u32) -> u32 {
    if kflag {
        raw & 0x00ff_ffff
    } else {
        raw
    }
}

fn member_u32(m: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([m[i], m[i + 1], m[i + 2], m[i + 3]])
}

/// 在 `record_off` 指向的 STRUCT/UNION 里找成员，返回字节偏移；`parent_bits` 是外层
/// 匿名成员已累计的 bit 偏移。查找分两遍：先直接成员（同名冲突时直接层优先），
/// 未命中再递归匿名 struct/union。
fn lookup_member_bits(
    types: &[u8],
    strs: &[u8],
    record_off: usize,
    header: &TypeHeader,
    member: &str,
    parent_bits: u32,
    depth: u32,
) -> Result<Option<u32>, String> {
    if header.kind != KIND_STRUCT && header.kind != KIND_UNION {
        return Err(format!(
            "成员查找只支持 STRUCT/UNION，拿到 kind={}",
            header.kind
        ));
    }
    let members_start = record_off + 12;
    let members_len = (header.vlen as usize)
        .checked_mul(12)
        .ok_or_else(|| "BTF 成员表长度溢出".to_string())?;
    let members = types
        .get(members_start..members_start.wrapping_add(members_len))
        .ok_or_else(|| {
            format!(
                "struct 成员表越界：记录偏移 {record_off} 声明 {} 个成员",
                header.vlen
            )
        })?;

    // 第一遍：具名直接成员。
    for m in members.chunks_exact(12) {
        let name_off = member_u32(m, 0);
        if name_off == 0 {
            continue;
        }
        if str_at(strs, name_off)? == member {
            let bits = parent_bits
                .checked_add(member_bit_offset(header.kflag, member_u32(m, 8)))
                .ok_or_else(|| "成员 bit 偏移累加溢出".to_string())?;
            if bits % 8 != 0 {
                return Err(format!(
                    "成员 `{member}` 位于 bit {bits}，不是字节对齐字段（位域无法按字节读）"
                ));
            }
            return Ok(Some(bits / 8));
        }
    }

    // 第二遍：匿名 struct/union（name_off == 0）里递归。
    if depth >= MAX_ANON_DEPTH {
        return Ok(None);
    }
    for m in members.chunks_exact(12) {
        if member_u32(m, 0) != 0 {
            continue;
        }
        let (child_off, child) = resolve_type(types, member_u32(m, 4))?;
        if child.kind != KIND_STRUCT && child.kind != KIND_UNION {
            continue;
        }
        let bits = parent_bits
            .checked_add(member_bit_offset(header.kflag, member_u32(m, 8)))
            .ok_or_else(|| "成员 bit 偏移累加溢出".to_string())?;
        if let Some(byte_off) =
            lookup_member_bits(types, strs, child_off, &child, member, bits, depth + 1)?
        {
            return Ok(Some(byte_off));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拼一个完整 BTF 段：头部 + 类型段 + 字符串段（type_off=0、str_off=type_len，两段相邻）。
    /// `hdr_len` 可调：真机 vmlinux BTF 是 32（24 字节固定字段 + 8 字节保留）。
    fn raw_blob(hdr_len: u32, types: &[u8], strs: &[u8]) -> Vec<u8> {
        assert!(hdr_len as usize >= BTF_HEADER_MIN);
        let mut v = Vec::new();
        v.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        v.push(1); // version
        v.push(0); // flags
        v.extend_from_slice(&hdr_len.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // type_off
        v.extend_from_slice(&(types.len() as u32).to_le_bytes()); // type_len
        v.extend_from_slice(&(types.len() as u32).to_le_bytes()); // str_off
        v.extend_from_slice(&(strs.len() as u32).to_le_bytes()); // str_len
        v.resize(hdr_len as usize, 0);
        v.extend_from_slice(types);
        v.extend_from_slice(strs);
        v
    }

    /// 最小 BTF 构造器：类型 id = 记录序号 + 1；字符串段 0 号字节留作空名（name_off=0）。
    struct BtfBuilder {
        types: Vec<u8>,
        strs: Vec<u8>,
        next_id: u32,
    }

    impl BtfBuilder {
        fn new() -> Self {
            Self {
                types: Vec::new(),
                strs: vec![0],
                next_id: 1,
            }
        }

        /// 加入字符串段，返回 name_off（永远 NUL 结尾）。
        fn intern(&mut self, s: &str) -> u32 {
            let off = self.strs.len() as u32;
            self.strs.extend_from_slice(s.as_bytes());
            self.strs.push(0);
            off
        }

        /// 下一条类型记录将获得的 id（用于构造自引用等畸形结构）。
        fn peek_id(&self) -> u32 {
            self.next_id
        }

        fn push_extra(&mut self, bytes: &[u8]) {
            self.types.extend_from_slice(bytes);
        }

        /// 追加 `struct btf_type` 头（12 字节），返回类型 id。kind/vlen 按位截断，
        /// 故意不校验——测试「未知 kind」时要把越界编号原样写进去。
        fn push_raw_type(
            &mut self,
            name_off: u32,
            kind: u32,
            kflag: bool,
            vlen: u32,
            size_or_type: u32,
        ) -> u32 {
            let info = ((kind & 0x7f) << 24) | ((kflag as u32) << 31) | (vlen & 0x00ff_ffff);
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size_or_type.to_le_bytes());
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        fn push_member_raw(&mut self, name_off: u32, type_id: u32, offset: u32) {
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&type_id.to_le_bytes());
            self.types.extend_from_slice(&offset.to_le_bytes());
        }

        fn add_int(&mut self, name: &str) -> u32 {
            let name_off = self.intern(name);
            let id = self.push_raw_type(name_off, KIND_INT as u32, false, 0, 4);
            self.push_extra(&32u32.to_le_bytes()); // btf_int_data：32 bit、无符号
            id
        }

        fn add_ptr(&mut self, target: u32) -> u32 {
            self.push_raw_type(0, KIND_PTR as u32, false, 0, target)
        }

        fn add_array(&mut self, elem: u32, index: u32, nelems: u32) -> u32 {
            let id = self.push_raw_type(0, KIND_ARRAY as u32, false, 0, 0);
            self.push_extra(&elem.to_le_bytes());
            self.push_extra(&index.to_le_bytes());
            self.push_extra(&nelems.to_le_bytes());
            id
        }

        /// 追加 STRUCT/UNION；`members` 是 (成员名, 类型 id, 原始 offset 字段)，
        /// 成员名为空串表示匿名成员（name_off=0）。
        fn add_aggregate(
            &mut self,
            name: &str,
            kind: u8,
            kflag: bool,
            members: &[(&str, u32, u32)],
        ) -> u32 {
            let name_off = if name.is_empty() {
                0
            } else {
                self.intern(name)
            };
            self.add_aggregate_raw(name_off, kind, kflag, members)
        }

        /// 同 `add_aggregate`，但名字偏移原样给（用于构造越界名字）。
        fn add_aggregate_raw(
            &mut self,
            name_off: u32,
            kind: u8,
            kflag: bool,
            members: &[(&str, u32, u32)],
        ) -> u32 {
            let id = self.push_raw_type(name_off, kind as u32, kflag, members.len() as u32, 0);
            for &(member, type_id, offset) in members {
                let member_off = if member.is_empty() {
                    0
                } else {
                    self.intern(member)
                };
                self.push_member_raw(member_off, type_id, offset);
            }
            id
        }

        fn finish(&self, hdr_len: u32) -> Vec<u8> {
            raw_blob(hdr_len, &self.types, &self.strs)
        }
    }

    /// 模拟 `struct sk_buff` 的关键布局（字节偏移对齐真机 pahole 输出）：
    /// - `network_header`/`transport_header` 在匿名 union 的匿名 struct 里（两层匿名，
    ///   真机路径 `sk_buff -> union{...} -> struct{...} headers`，偏移需跨层累加）；
    /// - `tail`/`head` 是直接成员；
    /// - kflag 置位并带一个位域成员，走真机同款「高 8 位是位宽」解码路径。
    fn add_skb_shape(b: &mut BtfBuilder, name: &str) -> u32 {
        let u16ty = b.add_int("__u16");
        let u32ty = b.add_int("__u32");
        let uchar = b.add_int("unsigned char");
        let ptr = b.add_ptr(uchar);

        // 内层匿名 struct：真机 `sk_buff.headers` 从 128 字节起
        let headers = b.add_aggregate(
            "",
            KIND_STRUCT,
            false,
            &[
                ("protocol", u16ty, (180 - 128) * 8),
                ("transport_header", u16ty, (182 - 128) * 8),
                ("network_header", u16ty, (184 - 128) * 8),
            ],
        );
        // 顶层匿名 union：真机 `sk_buff` 的 `union { ... }` 从 128 字节起
        let top_union = b.add_aggregate("", KIND_UNION, false, &[("", headers, 0)]);
        b.add_aggregate(
            name,
            KIND_STRUCT,
            true,
            &[
                ("dev", ptr, 24 * 8),
                ("", top_union, 128 * 8),
                ("cloned", u16ty, (1u32 << 24) | (126 * 8 + 6)), // 位域：宽 1 bit
                ("tail", u32ty, 188 * 8),
                ("head", ptr, 200 * 8),
            ],
        )
    }

    fn synthetic_skb_blob(hdr_len: u32) -> Vec<u8> {
        let mut b = BtfBuilder::new();
        add_skb_shape(&mut b, "sk_buff");
        b.finish(hdr_len)
    }

    #[test]
    fn sk_buff_offsets_from_synthetic_blob() {
        let blob = synthetic_skb_blob(24);
        let offs = sk_buff_offsets_from(&blob).expect("合成 BTF 应可解析");
        assert_eq!(
            offs,
            SkBuffOffsets {
                network_header: 184,
                transport_header: 182,
                tail: 188,
                head: 200,
            }
        );
        // Default 表示「数据面还没拿到偏移」（trace.rs 只在 map 有值时读）
        assert_ne!(offs, SkBuffOffsets::default());
    }

    #[test]
    fn member_offsets_preserve_request_order() {
        let blob = synthetic_skb_blob(24);
        let v = struct_member_byte_offsets(
            &blob,
            "sk_buff",
            &["head", "network_header", "dev", "transport_header", "tail"],
        )
        .unwrap();
        assert_eq!(v, vec![200, 184, 24, 182, 188]);
        assert_eq!(
            struct_member_byte_offsets(&blob, "sk_buff", &["tail"]).unwrap(),
            vec![188]
        );
        // 重复请求同样按顺序返回
        assert_eq!(
            struct_member_byte_offsets(&blob, "sk_buff", &["tail", "tail"]).unwrap(),
            vec![188, 188]
        );
    }

    #[test]
    fn hdr_len_32_like_real_vmlinux() {
        // 真机 /sys/kernel/btf/vmlinux 的 hdr_len 是 32（多 8 字节保留区），
        // 段起点必须用头部里的 hdr_len，而不是固定 24。
        let blob = synthetic_skb_blob(32);
        assert_eq!(sk_buff_offsets_from(&blob).unwrap().network_header, 184);
    }

    /// 0-19 所有 kind 各来一条、目标 struct 放最后：任何一条记录的尾随数据长度算错
    /// 都会让后续记录错位，最终找不到 `sk_buff` 或直接报错。
    #[test]
    fn all_kind_trailing_data_lengths() {
        let mut b = BtfBuilder::new();
        let int = b.add_int("int");

        b.push_raw_type(0, KIND_UNKN as u32, false, 0, 0);
        let ptr = b.add_ptr(int);
        let arr = b.add_array(int, int, 8);
        assert_eq!(arr, 4); // 记录序号：UNKN, INT, PTR, ARRAY → id 4
        b.push_raw_type(0, KIND_FWD as u32, false, 0, 0);
        let my_int = b.intern("my_int");
        let typedef = b.push_raw_type(my_int, KIND_TYPEDEF as u32, false, 0, int);
        b.push_raw_type(0, KIND_VOLATILE as u32, false, 0, typedef);
        b.push_raw_type(0, KIND_CONST as u32, false, 0, typedef);
        b.push_raw_type(0, KIND_RESTRICT as u32, false, 0, ptr);
        let my_func = b.intern("my_func");
        b.push_raw_type(my_func, KIND_FUNC as u32, false, 0, int);
        // FUNC_PROTO：vlen 个 btf_param{name_off, type}(8B)
        b.push_raw_type(0, KIND_FUNC_PROTO as u32, false, 2, int);
        b.push_extra(&[0u8; 16]);
        // VAR：btf_var{linkage}(4B)
        let my_var = b.intern("my_var");
        b.push_raw_type(my_var, KIND_VAR as u32, false, 0, int);
        b.push_extra(&[0u8; 4]);
        // DATASEC：vlen 个 btf_var_secinfo{type, offset, size}(12B)
        b.push_raw_type(0, KIND_DATASEC as u32, false, 1, 4);
        b.push_extra(&[0u8; 12]);
        b.push_raw_type(0, KIND_FLOAT as u32, false, 0, 4);
        // DECL_TAG：btf_decl_tag{component_idx}(4B)
        b.push_raw_type(0, KIND_DECL_TAG as u32, false, 0, int);
        b.push_extra(&0xffff_ffffu32.to_le_bytes());
        b.push_raw_type(0, KIND_TYPE_TAG as u32, false, 0, int);
        // ENUM：vlen 个 btf_enum{name_off, val}(8B)
        b.push_raw_type(0, KIND_ENUM as u32, false, 2, 4);
        b.push_extra(&[0u8; 16]);
        // ENUM64：vlen 个 btf_enum64{name_off, val_lo32, val_hi32}(12B)
        b.push_raw_type(0, KIND_ENUM64 as u32, false, 2, 8);
        b.push_extra(&[0u8; 24]);

        // 目标在最后：前面 19 种 kind 的跳转全对才可能找到它。
        add_skb_shape(&mut b, "sk_buff");

        let blob = b.finish(24);
        let offs = sk_buff_offsets_from(&blob).expect("全部 kind 的尾随数据都要跳过正确");
        assert_eq!(
            offs,
            SkBuffOffsets {
                network_header: 184,
                transport_header: 182,
                tail: 188,
                head: 200,
            }
        );
    }

    #[test]
    fn direct_member_wins_over_anonymous_nested() {
        let mut b = BtfBuilder::new();
        let u32ty = b.add_int("__u32");
        let u = b.add_aggregate(
            "",
            KIND_UNION,
            false,
            &[("x", u32ty, 8 * 8), ("y", u32ty, 4 * 8)],
        );
        b.add_aggregate(
            "outer",
            KIND_STRUCT,
            false,
            &[("", u, 0), ("x", u32ty, 32 * 8)],
        );
        let blob = b.finish(24);
        // 直接层与匿名内层同名时取直接层
        assert_eq!(
            struct_member_byte_offsets(&blob, "outer", &["x"]).unwrap(),
            vec![32]
        );
        // 只有匿名内层有的成员正常递归找到
        assert_eq!(
            struct_member_byte_offsets(&blob, "outer", &["y"]).unwrap(),
            vec![4]
        );
    }

    #[test]
    fn named_nested_struct_is_not_searched() {
        let mut b = BtfBuilder::new();
        let u32ty = b.add_int("__u32");
        let inner = b.add_aggregate("inner", KIND_STRUCT, false, &[("x", u32ty, 8)]);
        b.add_aggregate("outer", KIND_STRUCT, false, &[("field", inner, 0)]);
        let blob = b.finish(24);
        // 具名成员的内部不再递归（匿名才是布局透明的）
        assert!(struct_member_byte_offsets(&blob, "outer", &["x"]).is_err());
        assert_eq!(
            struct_member_byte_offsets(&blob, "outer", &["field"]).unwrap(),
            vec![0]
        );
    }

    #[test]
    fn missing_members_and_struct_are_errors() {
        let blob = synthetic_skb_blob(24);
        let err = struct_member_byte_offsets(&blob, "sk_buff", &["mark"]).unwrap_err();
        assert!(err.contains("mark"), "{err}");
        let err = struct_member_byte_offsets(&blob, "sk_buff", &["tail", "nope"]).unwrap_err();
        assert!(err.contains("nope"), "{err}");
        let err = struct_member_byte_offsets(&blob, "no_such_struct", &["tail"]).unwrap_err();
        assert!(err.contains("no_such_struct"), "{err}");
    }

    #[test]
    fn kind_flag_bitfield_offsets_are_masked() {
        let mut b = BtfBuilder::new();
        let u16ty = b.add_int("__u16");
        b.add_aggregate(
            "bf",
            KIND_STRUCT,
            true,
            &[
                // 位域：宽 3 bit、bit 偏移 64 → 字节偏移 8（高 8 位位宽不参与计算）
                ("first", u16ty, (3u32 << 24) | (8 * 8)),
                // 非字节对齐：bit 偏移 131
                ("bad", u16ty, (1u32 << 24) | (16 * 8 + 3)),
            ],
        );
        let blob = b.finish(24);
        assert_eq!(
            struct_member_byte_offsets(&blob, "bf", &["first"]).unwrap(),
            vec![8]
        );
        // 位域不能按字节读：报 Err 而不是猜一个对齐地址
        assert!(struct_member_byte_offsets(&blob, "bf", &["bad"]).is_err());
    }

    #[test]
    fn unknown_kind_is_error_not_panic() {
        // 32 & 0x1f == 0：若 kind 掩码写错（0x1f），它会被当成 UNKN 静默跳过，
        // 所以这里必须用按规范掩码（0x7f）仍 >19 的值来钉住错误路径。
        for kind in [20u32, 32, 0x7f] {
            let mut b = BtfBuilder::new();
            b.push_raw_type(0, kind, false, 0, 0);
            let blob = b.finish(24);
            let err = struct_member_byte_offsets(&blob, "sk_buff", &["tail"]).unwrap_err();
            assert!(err.contains("kind"), "kind={kind}: {err}");
            assert!(sk_buff_offsets_from(&blob).is_err());
        }
    }

    #[test]
    fn anonymous_self_reference_terminates() {
        let mut b = BtfBuilder::new();
        let self_id = b.peek_id();
        // 畸形 BTF：匿名成员指向自己（真内核不可能出现，但解析器不能死循环/爆栈）
        b.add_aggregate("a", KIND_STRUCT, false, &[("", self_id, 0)]);
        let blob = b.finish(24);
        let err = struct_member_byte_offsets(&blob, "a", &["x"]).unwrap_err();
        assert!(err.contains("x"), "{err}");
    }

    #[test]
    fn truncated_blob_is_error() {
        let blob = synthetic_skb_blob(24);
        // 连头部都不完整
        for cut in [0usize, 4, 23] {
            assert!(sk_buff_offsets_from(&blob[..cut]).is_err(), "cut={cut}");
        }
        // 声明长度超出实际内容（文件级截断）
        for cut in [blob.len() - 1, blob.len() / 2] {
            assert!(sk_buff_offsets_from(&blob[..cut]).is_err(), "cut={cut}");
        }
        // 段内部截断：type_len 自洽，但 STRUCT 声明的成员表不完整
        let mut b = BtfBuilder::new();
        b.push_raw_type(0, KIND_PTR as u32, false, 0, 1);
        let name = b.intern("sk_buff");
        b.push_raw_type(name, KIND_STRUCT as u32, false, 4, 0); // 声称 4 个成员，成员数据没写
        let short = b.finish(24);
        assert!(sk_buff_offsets_from(&short).is_err());
    }

    #[test]
    fn bad_magic_and_big_endian_are_errors() {
        let mut blob = synthetic_skb_blob(24);
        blob[0] = 0x34;
        blob[1] = 0x12;
        assert!(sk_buff_offsets_from(&blob).is_err());

        // 大端内核：magic 字节反序（按小端读出 0x9FEB），明确拒绝而不是当损坏数据
        let mut blob = synthetic_skb_blob(24);
        blob[0] = 0xeb;
        blob[1] = 0x9f;
        let err = sk_buff_offsets_from(&blob).unwrap_err();
        assert!(err.contains("大端"), "{err}");
    }

    #[test]
    fn string_out_of_bounds_and_unterminated_are_errors() {
        // struct 名偏移越界
        let mut b = BtfBuilder::new();
        let u32ty = b.add_int("__u32");
        b.add_aggregate_raw(0xffff_fff0, KIND_STRUCT, false, &[("tail", u32ty, 8 * 8)]);
        let blob = b.finish(24);
        let err = struct_member_byte_offsets(&blob, "sk_buff", &["tail"]).unwrap_err();
        assert!(err.contains("越界"), "{err}");

        // 成员名偏移越界
        let mut b = BtfBuilder::new();
        let u32ty = b.add_int("__u32");
        let name = b.intern("sk_buff");
        b.push_raw_type(name, KIND_STRUCT as u32, false, 1, 0);
        b.push_member_raw(0xffff_fff0, u32ty, 0);
        let blob = b.finish(24);
        let err = struct_member_byte_offsets(&blob, "sk_buff", &["tail"]).unwrap_err();
        assert!(err.contains("越界"), "{err}");

        // 字符串没有 NUL 终止符
        let mut types = Vec::new();
        types.extend_from_slice(&1u32.to_le_bytes()); // name_off = 1
        types.extend_from_slice(&((KIND_STRUCT as u32) << 24).to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());
        let blob = raw_blob(24, &types, b"sk_buff"); // 末尾没有 NUL
        let err = struct_member_byte_offsets(&blob, "sk_buff", &[]).unwrap_err();
        assert!(err.contains("NUL"), "{err}");
    }

    /// 真机核对：本机（6.18.54-2-lts）`pahole -C sk_buff /sys/kernel/btf/vmlinux` 给出
    /// network_header=184、transport_header=182、tail=188、head=200。测试只断言跨内核
    /// 稳定的不变量（解析成功、两两不同、落在 sk_buff 大小范围内），不写死具体数值——
    /// 换内核（字段增删/重排）时本测试仍应通过，具体值由人工对照 pahole 核对。
    #[test]
    fn real_kernel_btf_if_available() {
        const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";
        let bytes = match std::fs::read(VMLINUX_BTF) {
            Ok(b) => b,
            Err(e) => {
                // 非 Linux / 内核未开 CONFIG_DEBUG_INFO_BTF / 非 root：跳过，不算失败
                eprintln!("跳过真机 BTF 核对：读取 {VMLINUX_BTF} 失败: {e}");
                return;
            }
        };
        let offs = sk_buff_offsets().expect("真机 BTF 必须能解出 sk_buff 字段偏移");
        assert_eq!(
            offs,
            sk_buff_offsets_from(&bytes).unwrap(),
            "同一 BTF 两次解析"
        );

        let all = [
            offs.network_header,
            offs.transport_header,
            offs.tail,
            offs.head,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(*a < 4096, "偏移异常: {offs:?}");
            for b in &all[i + 1..] {
                assert_ne!(a, b, "偏移重复: {offs:?}");
            }
        }
        // 通用接口与专用接口一致（顺序按请求）
        let v = struct_member_byte_offsets(
            &bytes,
            "sk_buff",
            &["network_header", "transport_header", "tail", "head"],
        )
        .unwrap();
        assert_eq!(
            v,
            vec![
                offs.network_header,
                offs.transport_header,
                offs.tail,
                offs.head
            ]
        );
        eprintln!("真机 sk_buff 偏移: {offs:?}（本机 6.18 对照 pahole：184/182/188/200）");
    }
}

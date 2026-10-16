// SPDX-License-Identifier: AGPL-3.0-only
//! A2 #2/#4：归档原语（tar + gzip_stored 自实现）。
//!
//! 为什么不用 `flate2`/`tar` crate：本仓库的依赖纪律是「标准库 + 已在锁文件里的依赖」
//! （离线可构建、供应链面小）。这里只需要**写**能力，且 gzip 用 **stored 块**
//! （BTYPE=00，不压缩）——产物是合法 gzip（`gzip -d`/`tar xzf` 可解），代价是体积为
//! 原始大小。对 sysdump（几十 KB 级）与日志轮转（MB 级）都可接受；
//! 解压侧由系统工具负责（归档不是热路径）。
//!
//! 格式参考：RFC 1952（gzip）、POSIX ustar（tar）。
//! 单测同时充当**格式自证**：自带 stored-deflate 解压器做往返验证。

/// gzip（stored 块，RFC 1952 + RFC 1951 §3.2.4）。
pub fn gzip_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 32);
    // ID1 ID2 CM FLG MTIME(4) XFL OS
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff]);
    if data.is_empty() {
        // 空输入也要有一个 final stored 块（否则 ISIZE=0 被某些解压器视为截断）。
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    } else {
        let mut i = 0;
        while i < data.len() {
            let n = (data.len() - i).min(65535);
            let last = i + n == data.len();
            out.push(if last { 0x01 } else { 0x00 }); // BFINAL + BTYPE=00
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(&(!(n as u16)).to_le_bytes());
            out.extend_from_slice(&data[i..i + n]);
            i += n;
        }
    }
    out.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// ustar 归档写入器（只写普通文件；uid/gid=0、mode 0644、mtime 由调用方给）。
pub struct TarWriter {
    buf: Vec<u8>,
}

impl Default for TarWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl TarWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// 加一个普通文件。名字超 100 字节时按 ustar 规则拆进 prefix 字段。
    pub fn add(&mut self, name: &str, data: &[u8], mtime_sec: u64) {
        let (prefix, name) = split_ustar_name(name);
        let mut hdr = [0u8; 512];
        hdr[..name.len()].copy_from_slice(name.as_bytes());
        write_octal(&mut hdr[100..108], 0o644); // mode
        write_octal(&mut hdr[108..116], 0); // uid
        write_octal(&mut hdr[116..124], 0); // gid
        write_octal12(&mut hdr[124..136], data.len() as u64); // size
        write_octal12(&mut hdr[136..148], mtime_sec); // mtime
        hdr[156] = b'0'; // typeflag: regular file
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        hdr[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        // 校验和：chksum 字段先置空格再求和。
        for b in &mut hdr[148..156] {
            *b = b' ';
        }
        let sum: u32 = hdr.iter().map(|b| *b as u32).sum();
        write_checksum(&mut hdr[148..156], sum);
        self.buf.extend_from_slice(&hdr);
        self.buf.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.buf.extend(std::iter::repeat_n(0u8, pad));
    }

    /// 收尾（两个 512B 零块）并取走字节。
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.extend(std::iter::repeat_n(0u8, 1024));
        self.buf
    }
}

/// 名字 split：≤100 直接返回（"", name）；否则在最后一个 '/' 处拆（prefix ≤155）。
fn split_ustar_name(name: &str) -> (&str, &str) {
    if name.len() <= 100 {
        return ("", name);
    }
    if let Some(pos) = name.rfind('/') {
        let (p, n) = (&name[..pos], &name[pos + 1..]);
        if p.len() <= 155 && n.len() <= 100 {
            return (p, n);
        }
    }
    // 无法拆分：截断保底（调用方应避免超长名）。
    ("", &name[name.len() - 100..])
}

/// 8 字节八进制字段（"0000644\0" 风格）。
fn write_octal(field: &mut [u8], v: u64) {
    let s = format!("{:0width$o}", v, width = field.len() - 1);
    field[..s.len()].copy_from_slice(s.as_bytes());
    field[field.len() - 1] = 0;
}

/// 12 字节八进制字段（11 位 + NUL；超 8 GB 时截断为 max——sysdump 不可能到）。
fn write_octal12(field: &mut [u8], v: u64) {
    let clamped = v.min(0o777_7777_7777);
    let s = format!("{clamped:011o}");
    field[..s.len()].copy_from_slice(s.as_bytes());
    field[field.len() - 1] = 0;
}

/// 校验和字段：6 位八进制 + NUL + 空格（GNU tar 风格）。
fn write_checksum(field: &mut [u8], sum: u32) {
    let s = format!("{sum:06o}");
    field[..s.len()].copy_from_slice(s.as_bytes());
    field[6] = 0;
    field[7] = b' ';
}

/// stored-deflate 解压（仅本模块产物；测试自证用，非通用解压器）。
/// 暴露给 crate 内其他测试（日志轮转验证复用同一份格式知识）。
#[cfg(test)]
pub(crate) fn gunzip_store(data: &[u8]) -> Vec<u8> {
    assert_eq!(&data[..3], &[0x1f, 0x8b, 0x08], "gzip magic/CM");
    assert_eq!(data[3], 0, "FLG 必须为 0（无可选头）");
    let mut i = 10;
    let mut out = Vec::new();
    loop {
        let hdr = data[i];
        i += 1;
        let final_block = hdr & 1 == 1;
        assert_eq!(hdr & 0b110, 0, "BTYPE 必须是 stored");
        let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        let nlen = u16::from_le_bytes([data[i + 2], data[i + 3]]);
        assert_eq!(!(len as u16), nlen, "LEN/NLEN 互补");
        i += 4;
        out.extend_from_slice(&data[i..i + len]);
        i += len;
        if final_block {
            break;
        }
    }
    let crc = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    let isize = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
    assert_eq!(crc, crc32fast::hash(&out), "CRC32 必须匹配");
    assert_eq!(isize as usize, out.len(), "ISIZE 必须匹配");
    assert_eq!(i + 8, data.len(), "不得有尾随字节");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_store_roundtrip() {
        for case in [
            vec![],
            b"hello".to_vec(),
            vec![0xAB; 65535],
            vec![7u8; 65535 * 2 + 17], // 跨多块 + 非整块尾
        ] {
            let gz = gzip_store(&case);
            assert_eq!(gunzip_store(&gz), case);
        }
    }

    #[test]
    fn tar_ustar_layout_and_checksum() {
        let mut t = TarWriter::new();
        t.add("net/routes.txt", b"default via 10.0.0.1\n", 1_700_000_000);
        t.add("status.json", b"{}", 1_700_000_000);
        let bytes = t.finish();
        // 头 + 数据（512 对齐）+ 尾（1024）
        assert_eq!(bytes.len(), 512 * 3 + 512 + 1024); // 2 个文件头+数据块（各 1024） + 尾部 1024
        assert_eq!(&bytes[0..15], b"net/routes.txt\0");
        assert_eq!(&bytes[257..263], b"ustar\0");
        assert_eq!(bytes[156], b'0');
        // 校验和验证：按 tar 规则重算（chksum 字段按空格）。
        let mut hdr = bytes[..512].to_vec();
        let stored = String::from_utf8_lossy(&hdr[148..154]).to_string();
        for b in &mut hdr[148..156] {
            *b = b' ';
        }
        let sum: u32 = hdr.iter().map(|b| *b as u32).sum();
        assert_eq!(format!("{sum:06o}"), stored);
        // 第一个文件的数据区（长度 = 原始数据 21 字节；其余是补零）
        assert_eq!(&bytes[512..512 + 21], b"default via 10.0.0.1\n");
        assert!(
            bytes[512 + 21..1024].iter().all(|b| *b == 0),
            "数据区补零到 512 对齐"
        );
        // 第二个文件头在 512*2 处
        assert_eq!(&bytes[1024..1024 + 11], b"status.json");
    }

    #[test]
    fn tar_long_name_uses_prefix() {
        let long = format!("{}/dump.txt", "a".repeat(120));
        let mut t = TarWriter::new();
        t.add(&long, b"x", 0);
        let bytes = t.finish();
        assert_eq!(&bytes[345..345 + 120], "a".repeat(120).as_bytes());
        assert_eq!(&bytes[0..8], b"dump.txt");
    }
}

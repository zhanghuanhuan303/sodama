// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! P38：**确定性变异模糊测试**（A1 #19「fuzz 目标」的可运行形态）。
//!
//! 为什么不用 cargo-fuzz：本仓库的验证约束是「不引入不可复现的工具链」——libFuzzer
//! 目标是 nightly + 外部工具（`cargo fuzz`），在软路由/CI 场景难保一致。这里用同一
//! 思想的**可复现**形态：固定种子的 xorshift 变异器 + 真实语料种子，逐轮喂给所有
//! 对「外部字节」开放的解析器，断言**不 panic / 不越界 / 不长时间卡死**。
//!
//! 覆盖（对应清点里的「.dae 解析 / DNS 报文 / CH 解析」）：
//! - `.dae` 配置：`config::load` + `config::validate`（含 include 展开、schema 诊断）
//! - DNS：`parse_query` / `parse_rrs` / `query_edns` / `parse_ecs_echo` / `truncate_for_udp`
//! - 出站链接：`outbound::parse`（ss/vless/trojan/vmess/ssr/anytls/naive/链式… 全家族）
//! - 订阅：`subscribe::decode_body` + `parse_subscription`（含 SIP008 判定）
//! - 嗅探：TLS ClientHello（`sniffer::parse_client_hello_body`）/ QUIC Initial（`quicsniff`）
//! - HTTP/2：HPACK Huffman 解码（`hpack::huffman_decode`）
//!
//! 迭代规模：`SODAMA_FUZZ_ITERS`（默认 4000；release 下约 1-2s）。
#![cfg(test)]

use crate::{config, dns, hpack, outbound, quicsniff, sniffer, subscribe};

/// 固定种子 xorshift64（可复现；不引入 rand 依赖）。
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// 语料种子：每类解析器的“近合法”输入（变异从它出发更易打到深路径）。
fn seeds() -> Vec<Vec<u8>> {
    vec![
        // .dae 配置（含 group/routing/dns/node）
        b"global { tproxy_port: 12345\n lan_interface: auto }\nrouting { dip(10.0.0.0/8) -> direct\n domain(suffix: a.com) -> proxy\n fallback: direct }\n"
            .to_vec(),
        b"include { conf.d/*.dae }\n"
            .to_vec(),
        // DNS 查询（RD+QD）
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 1, b'a', 3, b'c', b'o', b'm', 0,
            0, 1, 0, 1,
        ],
        // ss 链接
        b"ss://YWVzLTEyOC1nY206cHc=@1.1.1.1:8388#node".to_vec(),
        // vless + reality 参数
        b"vless://00000000-0000-0000-0000-000000000000@1.1.1.1:443?security=reality&sni=a.com&pbk=AAAA&sid=01&type=ws&path=/x"
            .to_vec(),
        // vmess（base64 JSON）
        b"vmess://eyJ2IjoiMiIsImFkZCI6IjEuMS4xLjEiLCJwb3J0IjoiNDQzIiwiaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJhaWQiOiIwIiwic2N5IjoiYXV0byJ9"
            .to_vec(),
        // SIP008 JSON
        br#"{"version":1,"servers":[{"remarks":"n","server":"1.1.1.1","server_port":8388,"method":"aes-128-gcm","password":"pw"}]}"#
            .to_vec(),
        // 订阅 base64 正文
        b"c3M6Ly9hZXMtMTI4LWdjbTpwd0AxLjEuMS4xOjgzODg=".to_vec(),
        // TLS ClientHello（真正的手工 DNS 最小 CH 由 runtime 变异覆盖）
        vec![0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00, 0x4c, 0x03, 0x03],
        // QUIC Initial 形态
        {
            let mut v = vec![0u8; 1350];
            v[0] = 0xC3;
            v
        },
        // HPACK Huffman 全 1（最长码）
        vec![0xff; 32],
    ]
}

fn mutate(rng: &mut Rng, base: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(base);
    if out.is_empty() {
        out.push(0);
    }
    let ops = 1 + rng.below(8);
    for _ in 0..ops {
        if out.is_empty() {
            out.push(rng.next() as u8);
        }
        match rng.below(5) {
            0 => {
                // 位翻转
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            1 => {
                // 字节替换
                let i = rng.below(out.len());
                out[i] = rng.next() as u8;
            }
            2 => {
                // 截断
                let n = rng.below(out.len());
                out.truncate(n);
            }
            3 => {
                // 插入（含 0 / 边界值）
                let i = rng.below(out.len() + 1);
                out.insert(i, [0u8, 0xff, 0x7f, 0x80][rng.below(4)]);
            }
            _ => {
                // 追加随机块
                let n = 1 + rng.below(16);
                let start_len = out.len();
                out.resize(start_len + n, 0);
                for b in &mut out[start_len..] {
                    *b = rng.next() as u8;
                }
            }
        }
        if out.len() > 4096 {
            out.truncate(4096);
        }
    }
}

/// 全部解析器对「任意字节」都必须不 panic（返回 Err/None 都算通过）。
fn run_all(data: &[u8]) {
    // DNS（字节路径）
    let _ = dns::parse_query(data);
    let _ = dns::parse_rrs(data);
    let _ = dns::query_edns(data);
    let _ = dns::parse_ecs_echo(data);
    let _ = dns::truncate_for_udp(data, 512);
    let _ = dns::first_answer_ttl(data);
    let _ = dns::empty_noerror(data);
    let _ = dns::servfail(data);
    let _ = dns::answer_a_and_aaaa_records(data);
    let _ = dns::add_ecs(data, ("10.0.0.1".parse().unwrap(), 24));
    // 嗅探
    let _ = sniffer::parse_client_hello_body(data);
    let _ = quicsniff::sniff(data);
    // HTTP/2 HPACK Huffman
    let _ = hpack::huffman_decode(data);
    let _ = hpack::qpack_decode(data);
    // 订阅（文本路径；decode_body 后按行解析，SIP008 也走这里）
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = subscribe::decode_body(data);
        let _ = subscribe::parse_sip008(text);
        let _ = subscribe::parse_subscription(text, "fuzz");
    }
    // 出站链接全家族
    if let Ok(text) = std::str::from_utf8(data) {
        if text.len() <= 512 {
            let _ = outbound::parse(text);
        }
    }
}

#[test]
fn fuzz_parsers_never_panic() {
    let iters: usize = std::env::var("SODAMA_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4000);
    let mut rng = Rng(0x5ada_4e0f_2026_1016u64 ^ 0x9e37_79b9_7f4a_7c15);
    let seeds = seeds();
    let mut buf = Vec::new();
    for i in 0..iters {
        let base = &seeds[i % seeds.len()];
        mutate(&mut rng, base, &mut buf);
        run_all(&buf);
    }
    // 每条种子本身也必须干净
    for s in &seeds {
        run_all(s);
    }
}

/// `.dae` 配置走文件路径（含 include 展开/循环检测：临时目录 + 随机正文）。
#[test]
fn fuzz_config_load_never_panics() {
    let iters: usize = std::env::var("SODAMA_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    let iters = (iters / 10).max(50);
    let dir = std::env::temp_dir().join(format!("sodama-fuzz-cfg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let mut rng = Rng(0xdead_beef_cafe_2026);
    let seeds = seeds();
    let mut buf = Vec::new();
    for i in 0..iters {
        mutate(&mut rng, &seeds[i % seeds.len()], &mut buf);
        let path = dir.join("fuzz.dae");
        let _ = std::fs::write(&path, &buf);
        if let Ok(cfg) = config::load(&path) {
            let _ = config::validate(&cfg);
            let _ = config::extract_routing(&cfg);
            let _ = config::to_json(&cfg);
            let _ = config::groups(&cfg);
            let _ = config::inline_nodes(&cfg);
            let _ = config::subscriptions(&cfg);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

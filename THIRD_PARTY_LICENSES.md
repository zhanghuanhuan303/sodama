# Third-Party Licenses and Notices

本项目以 **AGPL-3.0-only** 发布。以下列出随仓库分发或生成物中涉及的第三方组件；完整的 Rust 依赖树以 `Cargo.lock` 为准，发布前用 `cargo metadata` / `cargo deny` 生成并核对。

## 随仓库/生成物包含的第三方内容

| 组件 | 用途 | 许可证 | 来源 |
|---|---|---|---|
| dae | 数据面/规则编译/配置/协议行为参考 | AGPL-3.0 | https://github.com/daeuniverse/dae |
| daeuniverse/outbound | 出站协议行为参考与互操作测试 | AGPL-3.0 | https://github.com/daeuniverse/outbound |
| golang.org/x/net | HPACK/Huffman 表（生成到 `sodama/loader/src/huffman_table.rs`） | BSD-3-Clause | https://pkg.go.dev/golang.org/x/net |
| olicesx/qpack | QPACK 静态表（生成到 `sodama/loader/src/huffman_table.rs`） | 见上游仓库 | https://github.com/olicesx/qpack |

> 上游 dae/outbound 源码树未随本仓库分发；仅在需要运行规则对拍/跨实现测试时按文档自行 clone。

## 仅用于互操作测试/研究、未随仓库分发的项目

以下项目在文档、lab 脚本或测试中被引用，但本仓库不包含其源码：

- sing-box（GPL-3.0）
- Xray-core（MPL-2.0）
- v2ray-core（MIT）
- mihomo / Clash.Meta（GPL-3.0）
- quic-go（MIT）
- sing-shadowtls（GPL-3.0）
- shadowsocks-rust（MIT）

如果你从这些项目复制代码或数据到本仓库，必须同时更新本文件与 `NOTICE`，并确认许可证兼容性。

## Rust 依赖

直接/传递依赖由 `sodama/Cargo.lock`、`sodama/ebpf-rs/Cargo.lock`、`panel/Cargo.lock` 锁定。发布前运行：

```bash
cargo metadata --format-version 1 --locked
cargo deny check licenses advisories
```

并将生成的依赖清单（包名、版本、许可证）追加到本文件，或由发布流程生成 `THIRD_PARTY_LICENSES.generated.md`。

## 规则/名单数据

`packaging/arch/rules/*.txt`、`install/openwrt/files/rules/*.txt`、`packaging/arch/blocklist.txt` 与 `sodama/lab/blocklist.txt` 是项目自建的示例/最小兜底名单，不包含第三方 geosite/geoip 数据库。需要完整分流时，请自行准备 `geoip.dat` / `geosite.dat` 并遵守其来源许可证。

## Rust dependency inventory

以下清单由 `cargo metadata --locked` 从三个 workspace 的 `Cargo.lock` 生成；已排除本仓库 workspace 成员。`UNKNOWN` 表示 crate 元数据未声明 license，发布前需人工核对上游仓库。

- 包数量（去重后）：314
- 许可证分布：MIT OR Apache-2.0 × 164, MIT × 59, Apache-2.0 OR MIT × 26, Unicode-3.0 × 18, MIT/Apache-2.0 × 9, Zlib × 6, Unlicense OR MIT × 3, BSD-3-Clause × 3, Apache-2.0 OR ISC OR MIT × 2, ISC × 2, Unlicense/MIT × 2, CDLA-Permissive-2.0 × 2, BSD-2-Clause OR Apache-2.0 OR MIT × 2, CC0-1.0 × 1, CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception × 1, Apache-2.0/MIT × 1, CC0-1.0 OR MIT-0 OR Apache-2.0 × 1, MIT OR Apache-2.0 OR BSD-1-Clause × 1, Apache-2.0 / MIT × 1, MIT OR Apache-2.0 OR Zlib × 1, MIT AND BSD-3-Clause × 1, MIT OR Apache-2.0 OR LGPL-2.1-or-later × 1, Apache-2.0 AND ISC × 1, Apache-2.0 OR BSL-1.0 × 1, Apache-2.0 × 1, Zlib OR Apache-2.0 OR MIT × 1, (MIT OR Apache-2.0) AND Unicode-3.0 × 1, Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT × 1, BSL-1.0 × 1

| Crate | Version | License |
|---|---|---|
| `aead` | 0.5.2 | MIT OR Apache-2.0 |
| `aes` | 0.8.4 | MIT OR Apache-2.0 |
| `aes-gcm` | 0.10.3 | Apache-2.0 OR MIT |
| `aho-corasick` | 1.1.5 | Unlicense OR MIT |
| `any_spawner` | 0.3.0 | MIT |
| `anyhow` | 1.0.104 | MIT OR Apache-2.0 |
| `arrayvec` | 0.7.8 | MIT OR Apache-2.0 |
| `assert_matches` | 1.5.0 | MIT/Apache-2.0 |
| `async-lock` | 3.4.2 | Apache-2.0 OR MIT |
| `async-once-cell` | 0.5.4 | MIT OR Apache-2.0 |
| `async-trait` | 0.1.92 | MIT OR Apache-2.0 |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT |
| `attribute-derive` | 0.11.0 | MIT OR Apache-2.0 |
| `attribute-derive-macro` | 0.11.0 | MIT |
| `axum` | 0.8.9 | MIT |
| `axum-core` | 0.5.6 | MIT |
| `aya` | 0.14.0 | MIT OR Apache-2.0 |
| `aya-build` | 0.2.0 | MIT OR Apache-2.0 |
| `aya-ebpf` | 0.2.1 | MIT OR Apache-2.0 |
| `aya-ebpf-bindings` | 0.2.0 | MIT OR Apache-2.0 |
| `aya-ebpf-cty` | 0.3.0 | MIT OR Apache-2.0 |
| `aya-ebpf-macros` | 0.2.0 | MIT OR Apache-2.0 |
| `aya-obj` | 0.3.0 | MIT OR Apache-2.0 |
| `base16` | 0.2.1 | CC0-1.0 |
| `base64` | 0.22.1 | MIT OR Apache-2.0 |
| `bitflags` | 2.13.2 | MIT OR Apache-2.0 |
| `blake2` | 0.10.6 | MIT OR Apache-2.0 |
| `blake3` | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 |
| `bumpalo` | 3.20.3 | MIT OR Apache-2.0 |
| `bytes` | 1.12.1 | MIT |
| `camino` | 1.2.6 | MIT OR Apache-2.0 |
| `cargo-platform` | 0.3.3 | MIT OR Apache-2.0 |
| `cargo_metadata` | 0.23.1 | MIT |
| `cc` | 1.6.0 | MIT OR Apache-2.0 |
| `cfg-if` | 1.0.5 | MIT OR Apache-2.0 |
| `cfg_aliases` | 0.2.2 | MIT |
| `chacha20` | 0.10.2 | MIT OR Apache-2.0 |
| `chacha20` | 0.9.1 | Apache-2.0 OR MIT |
| `chacha20poly1305` | 0.10.1 | Apache-2.0 OR MIT |
| `cipher` | 0.4.4 | MIT OR Apache-2.0 |
| `codee` | 0.3.5 | MIT OR Apache-2.0 |
| `collection_literals` | 1.0.3 | MIT |
| `config` | 0.15.27 | MIT OR Apache-2.0 |
| `console_error_panic_hook` | 0.1.7 | Apache-2.0/MIT |
| `const-str` | 1.1.0 | MIT |
| `const_format` | 0.2.36 | Zlib |
| `const_format_proc_macros` | 0.2.34 | Zlib |
| `const_str_slice_concat` | 0.1.0 | MIT |
| `constant_time_eq` | 0.4.2 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| `convert_case` | 0.11.0 | MIT |
| `convert_case` | 0.6.0 | MIT |
| `convert_case_extras` | 0.2.0 | MIT |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 |
| `cpufeatures` | 0.3.1 | MIT OR Apache-2.0 |
| `crc32fast` | 1.5.2 | MIT OR Apache-2.0 |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 |
| `ctr` | 0.9.2 | MIT OR Apache-2.0 |
| `curve25519-dalek` | 4.1.3 | BSD-3-Clause |
| `curve25519-dalek-derive` | 0.1.1 | MIT/Apache-2.0 |
| `deranged` | 0.5.8 | MIT OR Apache-2.0 |
| `derive-where` | 1.7.0 | MIT OR Apache-2.0 |
| `digest` | 0.10.7 | MIT OR Apache-2.0 |
| `displaydoc` | 0.2.7 | MIT OR Apache-2.0 |
| `drain_filter_polyfill` | 0.1.3 | MIT OR Apache-2.0 |
| `either` | 1.18.0 | MIT OR Apache-2.0 |
| `either_of` | 0.1.9 | MIT |
| `equivalent` | 1.0.2 | Apache-2.0 OR MIT |
| `erased` | 0.1.2 | MIT |
| `errno` | 0.3.14 | MIT OR Apache-2.0 |
| `event-listener` | 5.4.2 | Apache-2.0 OR MIT |
| `event-listener-strategy` | 0.5.4 | Apache-2.0 OR MIT |
| `fiat-crypto` | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| `find-msvc-tools` | 0.1.14 | MIT OR Apache-2.0 |
| `fnv` | 1.0.7 | Apache-2.0 / MIT |
| `foldhash` | 0.2.0 | Zlib |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 |
| `futures` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-channel` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-core` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-executor` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-io` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-macro` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-sink` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-task` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-util` | 0.3.34 | MIT OR Apache-2.0 |
| `generic-array` | 0.14.7 | MIT |
| `getrandom` | 0.2.17 | MIT OR Apache-2.0 |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 |
| `ghash` | 0.5.1 | Apache-2.0 OR MIT |
| `gloo-net` | 0.6.0 | MIT OR Apache-2.0 |
| `gloo-net` | 0.7.0 | MIT OR Apache-2.0 |
| `gloo-storage` | 0.3.0 | MIT OR Apache-2.0 |
| `gloo-timers` | 0.4.0 | MIT OR Apache-2.0 |
| `gloo-utils` | 0.2.0 | MIT OR Apache-2.0 |
| `gloo-utils` | 0.3.0 | MIT OR Apache-2.0 |
| `guardian` | 1.3.0 | MIT OR Apache-2.0 |
| `h2` | 0.4.19 | MIT |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 |
| `hkdf` | 0.12.4 | MIT OR Apache-2.0 |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 |
| `html-escape` | 0.2.15 | MIT |
| `http` | 1.5.0 | MIT OR Apache-2.0 |
| `http-body` | 1.1.0 | MIT |
| `http-body-util` | 0.1.5 | MIT |
| `httparse` | 1.10.1 | MIT OR Apache-2.0 |
| `httpdate` | 1.0.3 | MIT OR Apache-2.0 |
| `hybrid-array` | 0.2.3 | MIT OR Apache-2.0 |
| `hydration_context` | 0.3.2 | MIT |
| `hyper` | 1.11.1 | MIT |
| `hyper-util` | 0.1.21 | MIT |
| `icu_collections` | 2.3.0 | Unicode-3.0 |
| `icu_locale_core` | 2.3.0 | Unicode-3.0 |
| `icu_normalizer` | 2.3.0 | Unicode-3.0 |
| `icu_normalizer_data` | 2.3.0 | Unicode-3.0 |
| `icu_properties` | 2.3.0 | Unicode-3.0 |
| `icu_properties_data` | 2.3.0 | Unicode-3.0 |
| `icu_provider` | 2.3.1 | Unicode-3.0 |
| `idna` | 1.1.0 | MIT OR Apache-2.0 |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT |
| `indexmap` | 2.14.2 | Apache-2.0 OR MIT |
| `inout` | 0.1.4 | MIT OR Apache-2.0 |
| `interpolator` | 0.5.0 | MIT OR Apache-2.0 |
| `itertools` | 0.14.0 | MIT OR Apache-2.0 |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 |
| `js-sys` | 0.3.106 | MIT OR Apache-2.0 |
| `keccak` | 0.1.6 | Apache-2.0 OR MIT |
| `kem` | 0.3.0-pre.0 | Apache-2.0 OR MIT |
| `konst` | 0.2.20 | Zlib |
| `konst_macro_rules` | 0.2.19 | Zlib |
| `leptos` | 0.8.22 | MIT |
| `leptos_config` | 0.8.10 | MIT |
| `leptos_dom` | 0.8.8 | MIT |
| `leptos_hot_reload` | 0.8.7 | MIT |
| `leptos_macro` | 0.8.19 | MIT |
| `leptos_server` | 0.8.8 | MIT |
| `libc` | 0.2.190 | MIT OR Apache-2.0 |
| `litemap` | 0.8.3 | Unicode-3.0 |
| `log` | 0.4.34 | MIT OR Apache-2.0 |
| `lru-slab` | 0.1.3 | MIT OR Apache-2.0 OR Zlib |
| `manyhow` | 0.14.0 | MIT OR Apache-2.0 |
| `manyhow-macros` | 0.14.0 | MIT OR Apache-2.0 |
| `matchit` | 0.8.4 | MIT AND BSD-3-Clause |
| `md-5` | 0.10.6 | MIT OR Apache-2.0 |
| `memchr` | 2.8.3 | Unlicense OR MIT |
| `mime` | 0.3.17 | MIT OR Apache-2.0 |
| `mio` | 1.2.3 | MIT |
| `mio` | 1.2.4 | MIT |
| `ml-kem` | 0.2.3 | Apache-2.0 OR MIT |
| `next_tuple` | 0.1.0 | MIT |
| `num-conv` | 0.2.2 | MIT OR Apache-2.0 |
| `object` | 0.39.1 | Apache-2.0 OR MIT |
| `oco_ref` | 0.2.1 | MIT |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 |
| `opaque-debug` | 0.3.1 | MIT OR Apache-2.0 |
| `or_poisoned` | 0.1.0 | MIT |
| `parking` | 2.2.1 | Apache-2.0 OR MIT |
| `paste` | 1.0.15 | MIT OR Apache-2.0 |
| `pathdiff` | 0.2.3 | MIT/Apache-2.0 |
| `pem` | 3.0.6 | MIT |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 |
| `pin-project` | 1.1.13 | Apache-2.0 OR MIT |
| `pin-project-internal` | 1.1.13 | Apache-2.0 OR MIT |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT |
| `poly1305` | 0.8.0 | Apache-2.0 OR MIT |
| `polyval` | 0.6.2 | Apache-2.0 OR MIT |
| `potential_utf` | 0.1.6 | Unicode-3.0 |
| `powerfmt` | 0.2.1 | MIT OR Apache-2.0 |
| `ppv-lite86` | 0.2.21 | MIT OR Apache-2.0 |
| `prettyplease` | 0.3.0 | MIT OR Apache-2.0 |
| `proc-macro-utils` | 0.10.0 | MIT OR Apache-2.0 |
| `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 |
| `proc-macro2-diagnostics` | 0.10.1 | MIT/Apache-2.0 |
| `proc-macro2-diagnostics` | 0.11.0 | MIT/Apache-2.0 |
| `quinn` | 0.11.12 | MIT OR Apache-2.0 |
| `quinn-proto` | 0.11.19 | MIT OR Apache-2.0 |
| `quinn-udp` | 0.5.16 | MIT OR Apache-2.0 |
| `quote` | 1.0.47 | MIT OR Apache-2.0 |
| `quote-use` | 0.9.0 | MIT |
| `quote-use-macros` | 0.9.0 | MIT |
| `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| `rand` | 0.10.3 | MIT OR Apache-2.0 |
| `rand` | 0.8.8 | MIT OR Apache-2.0 |
| `rand_chacha` | 0.3.1 | MIT OR Apache-2.0 |
| `rand_core` | 0.10.1 | MIT OR Apache-2.0 |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 |
| `rand_pcg` | 0.10.2 | MIT OR Apache-2.0 |
| `rcgen` | 0.13.2 | MIT OR Apache-2.0 |
| `reactive_graph` | 0.2.15 | MIT |
| `reactive_stores` | 0.4.4 | MIT |
| `reactive_stores_macro` | 0.4.4 | MIT |
| `regex` | 1.13.1 | MIT OR Apache-2.0 |
| `regex-automata` | 0.4.18 | MIT OR Apache-2.0 |
| `regex-syntax` | 0.8.11 | MIT OR Apache-2.0 |
| `ring` | 0.17.14 | Apache-2.0 AND ISC |
| `rstml` | 0.13.1 | MIT |
| `rustc-hash` | 2.1.3 | Apache-2.0 OR MIT |
| `rustc_version` | 0.4.1 | MIT OR Apache-2.0 |
| `rustls` | 0.23.45 | Apache-2.0 OR ISC OR MIT |
| `rustls-pemfile` | 2.2.0 | Apache-2.0 OR ISC OR MIT |
| `rustls-pki-types` | 1.15.1 | MIT OR Apache-2.0 |
| `rustls-webpki` | 0.103.15 | ISC |
| `rustversion` | 1.0.23 | MIT OR Apache-2.0 |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| `same-file` | 1.0.6 | Unlicense/MIT |
| `scopeguard` | 1.2.0 | MIT OR Apache-2.0 |
| `semver` | 1.0.28 | MIT OR Apache-2.0 |
| `send_wrapper` | 0.6.0 | MIT/Apache-2.0 |
| `serde` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_core` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_derive` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 |
| `serde_path_to_error` | 0.1.20 | MIT OR Apache-2.0 |
| `serde_qs` | 0.15.0 | MIT/Apache-2.0 |
| `serde_spanned` | 1.1.1 | MIT OR Apache-2.0 |
| `serde_urlencoded` | 0.7.1 | MIT/Apache-2.0 |
| `server_fn` | 0.8.13 | MIT |
| `server_fn_macro` | 0.8.12 | MIT |
| `server_fn_macro_default` | 0.8.6 | MIT |
| `sha1` | 0.10.7 | MIT OR Apache-2.0 |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 |
| `sha3` | 0.10.9 | MIT OR Apache-2.0 |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 |
| `signal-hook-registry` | 1.4.8 | MIT OR Apache-2.0 |
| `slab` | 0.4.12 | MIT |
| `slotmap` | 1.1.1 | Zlib |
| `smallvec` | 1.16.2 | MIT OR Apache-2.0 |
| `socket2` | 0.6.5 | MIT OR Apache-2.0 |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 |
| `subtle` | 2.6.1 | BSD-3-Clause |
| `syn` | 2.0.119 | MIT OR Apache-2.0 |
| `syn` | 3.0.6 | MIT OR Apache-2.0 |
| `sync_wrapper` | 1.0.2 | Apache-2.0 |
| `synstructure` | 0.14.0 | MIT |
| `tachys` | 0.2.19 | MIT |
| `thiserror` | 1.0.69 | MIT OR Apache-2.0 |
| `thiserror` | 2.0.21 | MIT OR Apache-2.0 |
| `thiserror-impl` | 1.0.69 | MIT OR Apache-2.0 |
| `thiserror-impl` | 2.0.21 | MIT OR Apache-2.0 |
| `throw_error` | 0.3.1 | MIT |
| `time` | 0.3.55 | MIT OR Apache-2.0 |
| `time-core` | 0.1.9 | MIT OR Apache-2.0 |
| `tinystr` | 0.8.4 | Unicode-3.0 |
| `tinyvec` | 1.13.3 | Zlib OR Apache-2.0 OR MIT |
| `tokio` | 1.53.2 | MIT |
| `tokio-macros` | 2.7.2 | MIT |
| `tokio-rustls` | 0.26.6 | MIT OR Apache-2.0 |
| `tokio-util` | 0.7.19 | MIT |
| `toml` | 1.1.6+spec-1.1.0 | MIT OR Apache-2.0 |
| `toml_datetime` | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 |
| `toml_parser` | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 |
| `toml_writer` | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 |
| `tower` | 0.5.3 | MIT |
| `tower-layer` | 0.3.3 | MIT |
| `tower-service` | 0.3.3 | MIT |
| `tracing` | 0.1.44 | MIT |
| `tracing-core` | 0.1.36 | MIT |
| `typed-builder` | 0.23.2 | MIT OR Apache-2.0 |
| `typed-builder-macro` | 0.23.2 | MIT OR Apache-2.0 |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 |
| `unicode-ident` | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `unicode-segmentation` | 1.13.3 | MIT OR Apache-2.0 |
| `unicode-xid` | 0.2.6 | MIT OR Apache-2.0 |
| `universal-hash` | 0.5.1 | MIT OR Apache-2.0 |
| `untrusted` | 0.9.0 | ISC |
| `url` | 2.5.8 | MIT OR Apache-2.0 |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT |
| `uuid` | 1.27.0 | Apache-2.0 OR MIT |
| `version_check` | 0.9.5 | MIT/Apache-2.0 |
| `walkdir` | 2.5.0 | Unlicense/MIT |
| `wasi` | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| `wasm-bindgen` | 0.2.129 | MIT OR Apache-2.0 |
| `wasm-bindgen-futures` | 0.4.79 | MIT OR Apache-2.0 |
| `wasm-bindgen-macro` | 0.2.129 | MIT OR Apache-2.0 |
| `wasm-bindgen-macro-support` | 0.2.129 | MIT OR Apache-2.0 |
| `wasm-bindgen-shared` | 0.2.129 | MIT OR Apache-2.0 |
| `wasm-streams` | 0.5.0 | MIT OR Apache-2.0 |
| `wasm_split_helpers` | 0.2.3 | MIT OR Apache-2.0 |
| `wasm_split_macros` | 0.2.2 | MIT OR Apache-2.0 |
| `web-sys` | 0.3.106 | MIT OR Apache-2.0 |
| `web-time` | 1.1.0 | MIT OR Apache-2.0 |
| `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 |
| `webpki-roots` | 1.0.9 | CDLA-Permissive-2.0 |
| `which` | 8.0.6 | MIT |
| `winapi-util` | 0.1.11 | Unlicense OR MIT |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 |
| `windows-sys` | 0.52.0 | MIT OR Apache-2.0 |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 |
| `windows-targets` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_aarch64_gnullvm` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_aarch64_msvc` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_i686_gnu` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_i686_gnullvm` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_i686_msvc` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_x86_64_gnu` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_x86_64_gnullvm` | 0.52.6 | MIT OR Apache-2.0 |
| `windows_x86_64_msvc` | 0.52.6 | MIT OR Apache-2.0 |
| `winnow` | 1.0.4 | MIT |
| `writeable` | 0.6.4 | Unicode-3.0 |
| `x25519-dalek` | 2.0.1 | BSD-3-Clause |
| `xxhash-rust` | 0.8.19 | BSL-1.0 |
| `yasna` | 0.5.2 | MIT OR Apache-2.0 |
| `yoke` | 0.8.3 | Unicode-3.0 |
| `yoke-derive` | 0.8.4 | Unicode-3.0 |
| `zerocopy` | 0.8.59 | BSD-2-Clause OR Apache-2.0 OR MIT |
| `zerocopy-derive` | 0.8.59 | BSD-2-Clause OR Apache-2.0 OR MIT |
| `zerofrom` | 0.1.8 | Unicode-3.0 |
| `zerofrom-derive` | 0.1.8 | Unicode-3.0 |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT |
| `zeroize_derive` | 1.5.0 | Apache-2.0 OR MIT |
| `zerotrie` | 0.2.5 | Unicode-3.0 |
| `zerovec` | 0.11.8 | Unicode-3.0 |
| `zerovec-derive` | 0.11.6 | Unicode-3.0 |
| `zmij` | 1.0.23 | MIT |

// SPDX-License-Identifier: AGPL-3.0-only
//! 构建期信息注入（A2 #1 `--version`）：git 短 sha 与仓库状态。
//!
//! 只做**尽力而为**的注入：`git` 不可用 / 不在 git 工作树里 / 沙箱无 git 时，
//! 注入 "unknown" 而不是让构建失败（发布包在无 .git 的环境里也要能构建）。
//! 重跑条件：`.git/HEAD` 与 `.git/refs` 变化时（cargo 无法只对 refs 目录生效，
//! 这里对 HEAD 与 packed-refs 给 rerun-if-changed，够用且不引入额外依赖）。
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // dirty 只看**已跟踪文件**的改动：未跟踪的开发目录（如本地 config/、console/target）
    // 不应把发布构建标成 -dirty（2026-10-20 生产部署版本曾因此显示 -dirty）。
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    println!("cargo:rustc-env=SODAMA_GIT_SHA={sha}");
    println!(
        "cargo:rustc-env=SODAMA_GIT_DIRTY={}",
        if dirty { "1" } else { "0" }
    );
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=SODAMA_BUILD_PROFILE={profile}");
    // 版本构成：`<pkg version>-g<sha>[-dirty]`（对照 dae Makefile 的 git describe 注入）。
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".into());
    let full = format!("{ver}-g{sha}{}", if dirty { "-dirty" } else { "" });
    println!("cargo:rustc-env=SODAMA_VERSION_FULL={full}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
}

/* tests/smoke.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * End-to-end test: build the smoke firmware (EC and EF) with the
 * mipsel-linux-gnu cross toolchain, then run each ELF through the
 * pic32mz-sim binary and assert it reaches its pass marker. Skipped
 * if the cross compiler is not on PATH, so a `cargo test` on a host
 * without it still passes.
 */

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for runner-bin is .../pic32mz-sim/runner-bin
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn has_cross_compiler() -> bool {
    Command::new("mipsel-linux-gnu-gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn build_firmware(dir: &Path) -> bool {
    let status = Command::new("make")
        .arg("-C")
        .arg(dir)
        .status()
        .expect("make spawn");
    status.success()
}

fn sim_binary() -> PathBuf {
    let root = workspace_root();
    let release = root.join("pic32mz-sim/target/release/pic32mz-sim");
    let debug = root.join("pic32mz-sim/target/debug/pic32mz-sim");
    if release.exists() {
        return release;
    }
    debug
}

fn run_sim(chip: &str, elf: &Path) -> (bool, String) {
    let out = Command::new(sim_binary())
        .arg("--chip").arg(chip)
        .arg("--timeout").arg("10")
        .arg("--exit-on").arg("test_complete")
        .arg("--result-symbol").arg("test_result")
        .arg(elf)
        .output()
        .expect("sim spawn");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), format!("{stdout}{stderr}"))
}

#[test]
fn smoke_firmware_ef_passes() {
    if !has_cross_compiler() {
        eprintln!("mipsel-linux-gnu-gcc not on PATH - skipping EF smoke test");
        return;
    }
    let fw_dir = workspace_root().join("firmware/smoke-test-ef");
    assert!(build_firmware(&fw_dir), "make smoke-test-ef failed");
    let elf = fw_dir.join("smoke.elf");
    let (ok, log) = run_sim("pic32mz2048efh144", &elf);
    assert!(ok, "sim run failed:\n{log}");
    assert!(log.contains("=== smoke test passed ==="), "missing pass marker:\n{log}");
    assert!(log.contains("AES-128 ECB round-trip OK"), "missing AES marker:\n{log}");
    assert!(log.contains("SHA-256 \"abc\" OK"), "missing SHA marker:\n{log}");
}

#[test]
fn smoke_firmware_ec_passes() {
    if !has_cross_compiler() {
        eprintln!("mipsel-linux-gnu-gcc not on PATH - skipping EC smoke test");
        return;
    }
    let fw_dir = workspace_root().join("firmware/smoke-test-ec");
    assert!(build_firmware(&fw_dir), "make smoke-test-ec failed");
    let elf = fw_dir.join("smoke.elf");
    let (ok, log) = run_sim("pic32mz2048ech144", &elf);
    assert!(ok, "sim run failed:\n{log}");
    assert!(log.contains("=== smoke test passed ==="), "missing pass marker:\n{log}");
    assert!(log.contains("AES-128 ECB (EC) OK"), "missing AES marker:\n{log}");
    assert!(log.contains("SHA-256 (EC) OK"), "missing SHA marker:\n{log}");
}

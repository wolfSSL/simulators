/* tests/smoke.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * End-to-end test: builds the smoke firmware via `make` (skipped if the
 * cross toolchain is missing), runs it through stm32-sim, and asserts
 * the firmware reaches its pass marker.
 */

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at runner-bin/; STM32Sim/ is two levels up.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // stm32-sim
    p.pop(); // STM32Sim
    p
}

fn smoke_dir() -> PathBuf {
    workspace_root().join("firmware").join("smoke-test-h7")
}

fn u5_smoke_dir() -> PathBuf {
    workspace_root().join("firmware").join("smoke-test-u5")
}

fn mp135_smoke_dir() -> PathBuf {
    workspace_root().join("firmware").join("smoke-test-mp135")
}

fn have_arm_gcc() -> bool {
    Command::new("arm-none-eabi-gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn smoke_firmware_passes() {
    if !have_arm_gcc() {
        eprintln!("skipping: arm-none-eabi-gcc not on PATH");
        return;
    }

    let dir = smoke_dir();
    let make = Command::new("make")
        .current_dir(&dir)
        .status()
        .expect("failed to invoke make");
    assert!(make.success(), "smoke firmware build failed");

    let elf = dir.join("smoke.elf");
    let bin = env!("CARGO_BIN_EXE_stm32-sim");
    let out = Command::new(bin)
        .args([
            "--chip",
            "stm32h753",
            "--timeout",
            "10",
            "--exit-on",
            "test_complete",
            "--result-symbol",
            "test_result",
        ])
        .arg(&elf)
        .output()
        .expect("failed to invoke stm32-sim");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "stm32-sim exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains("=== smoke test passed ==="),
        "stdout missing pass marker:\n{stdout}"
    );
    assert!(
        stdout.contains("rng[0] = 0x"),
        "RNG output missing:\n{stdout}"
    );
    assert!(
        stdout.contains("AES-128 ECB round-trip OK"),
        "CRYP AES round-trip missing:\n{stdout}"
    );
    assert!(
        stdout.contains("SHA-256 \"abc\" OK"),
        "HASH SHA-256 missing:\n{stdout}"
    );
}

#[test]
fn u5_smoke_firmware_passes() {
    if !have_arm_gcc() {
        eprintln!("skipping: arm-none-eabi-gcc not on PATH");
        return;
    }

    let dir = u5_smoke_dir();
    let make = Command::new("make")
        .current_dir(&dir)
        .status()
        .expect("failed to invoke make for u5 firmware");
    assert!(make.success(), "u5 firmware build failed");

    let elf = dir.join("smoke.elf");
    let bin = env!("CARGO_BIN_EXE_stm32-sim");
    let out = Command::new(bin)
        .args([
            "--chip",
            "stm32u575",
            "--timeout",
            "10",
            "--exit-on",
            "test_complete",
            "--result-symbol",
            "test_result",
        ])
        .arg(&elf)
        .output()
        .expect("failed to invoke stm32-sim for u5");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "u5 stm32-sim exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains("U5 AES-128 ECB OK"),
        "U5 CRYP v2 result missing:\n{stdout}"
    );
    assert!(
        stdout.contains("U5 SHA-256 \"abc\" OK"),
        "U5 HASH v2 result missing:\n{stdout}"
    );
    assert!(
        stdout.contains("=== U5 smoke test passed ==="),
        "U5 pass marker missing:\n{stdout}"
    );
}

#[test]
fn mp135_smoke_firmware_passes() {
    if !have_arm_gcc() {
        eprintln!("skipping: arm-none-eabi-gcc not on PATH");
        return;
    }

    let dir = mp135_smoke_dir();
    let make = Command::new("make")
        .current_dir(&dir)
        .status()
        .expect("failed to invoke make for mp135 firmware");
    assert!(make.success(), "mp135 firmware build failed");

    let elf = dir.join("smoke.elf");
    let bin = env!("CARGO_BIN_EXE_stm32-sim");
    let out = Command::new(bin)
        .args([
            "--chip",
            "stm32mp135",
            "--timeout",
            "10",
            "--exit-on",
            "test_complete",
            "--result-symbol",
            "test_result",
        ])
        .arg(&elf)
        .output()
        .expect("failed to invoke stm32-sim for mp135");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "mp135 stm32-sim exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains("=== STM32Sim MP135 smoke test ==="),
        "MP135 banner missing:\n{stdout}"
    );
    assert!(
        stdout.contains("rng[0] = 0x"),
        "MP135 RNG output missing:\n{stdout}"
    );
    assert!(
        stdout.contains("AES-128 ECB round-trip OK"),
        "MP135 CRYP AES round-trip missing:\n{stdout}"
    );
    assert!(
        stdout.contains("SHA-256 \"abc\" OK"),
        "MP135 HASH SHA-256 missing:\n{stdout}"
    );
    assert!(
        stdout.contains("SHA3-256 \"abc\" OK"),
        "MP135 HASH SHA3-256 missing:\n{stdout}"
    );
    assert!(
        stdout.contains("=== smoke test passed ==="),
        "MP135 pass marker missing:\n{stdout}"
    );
}

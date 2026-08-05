// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Native C harness for the scx_mlfq pure-logic layer.
//!
//! Compiles `mlfq_math_test.c` (which `#include`s the production `intf.h`
//! with MLFQ_CHECK forced on) with the host C compiler and runs it. This
//! tests the real BPF math rather than a Rust reimplementation; it needs no
//! kernel, BTF, or BPF privileges.

use std::process::Command;

fn host_cc() -> String {
    if let Ok(cc) = std::env::var("CC") {
        return cc;
    }
    // CI ships clang-19; prefer it, then fall back to the system compiler.
    for cand in ["clang", "cc", "gcc"] {
        if Command::new(cand).arg("--version").status().is_ok() {
            return cand.to_string();
        }
    }
    "cc".to_string()
}

#[test]
fn mlfq_pure_math_native_harness() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src = format!("{manifest_dir}/tests/mlfq_math_test.c");
    let intf_dir = format!("{manifest_dir}/src/bpf");
    let out_dir = std::env::temp_dir().join("scx_mlfq_math_test");
    std::fs::create_dir_all(&out_dir).unwrap();
    let exe = out_dir.join("mlfq_math_test");

    let status = Command::new(host_cc())
        .args(["-O2", "-Wall", "-Werror", "-std=c11"])
        .args(["-I", &intf_dir])
        .arg(&src)
        .args(["-o", exe.to_str().unwrap()])
        .status()
        .expect("failed to compile mlfq_math_test.c");

    assert!(status.success(), "native harness failed to compile");

    let output = Command::new(&exe)
        .output()
        .expect("failed to run the native harness");

    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");

    assert!(
        output.status.success(),
        "native harness failed:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("All tests passed"),
        "native harness did not report success"
    );
}

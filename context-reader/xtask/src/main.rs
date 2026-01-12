use anyhow::{Context, Result};
use std::process::Command;

fn main() -> Result<()> {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("build-ebpf") => build_ebpf()?,
        Some("build") => {
            build_ebpf()?;
            build_userspace()?;
        }
        Some("test") => test()?,
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    println!("Usage: cargo xtask <TASK>");
    println!();
    println!("Tasks:");
    println!("  build-ebpf    Build the eBPF program");
    println!("  build         Build everything (eBPF + userspace)");
    println!("  test          Run all tests");
}

fn build_ebpf() -> Result<()> {
    println!("Building eBPF program...");

    let status = Command::new("cargo")
        .args(&[
            "+nightly",
            "build",
            "--release",
            "--manifest-path=ebpf/Cargo.toml",
            "--target=bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status()
        .context("Failed to execute cargo build for eBPF")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }

    println!("✓ eBPF build complete");
    Ok(())
}

fn build_userspace() -> Result<()> {
    println!("Building userspace...");

    let status = Command::new("cargo")
        .args(&["build", "--workspace"])
        .status()
        .context("Failed to execute cargo build for userspace")?;

    if !status.success() {
        anyhow::bail!("Userspace build failed");
    }

    println!("✓ Userspace build complete");
    Ok(())
}

fn test() -> Result<()> {
    println!("Running tests...");

    let status = Command::new("cargo")
        .args(&["test", "--workspace"])
        .status()
        .context("Failed to execute cargo test")?;

    if !status.success() {
        anyhow::bail!("Tests failed");
    }

    println!("✓ All tests passed");
    Ok(())
}

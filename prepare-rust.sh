#!/bin/bash
set -e

echo "=== Preparing Rust environment for eBPF development ==="

# Install nightly toolchain (required for eBPF builds)
echo "Installing nightly toolchain..."
rustup toolchain install nightly

# Add rust-src component (required for -Z build-std)
echo "Adding rust-src component to nightly..."
rustup component add rust-src --toolchain nightly

# Install bpf-linker (required for linking eBPF programs)
echo "Installing bpf-linker..."
cargo install bpf-linker

# Ensure stable is up to date
echo "Updating stable toolchain..."
rustup update stable

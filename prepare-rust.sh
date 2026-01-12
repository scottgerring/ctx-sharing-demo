#!/bin/bash
set -e

echo "=== Preparing Rust environment for eBPF development ==="

# Install rustup if not present
if ! command -v rustup &> /dev/null; then
    echo "Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

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

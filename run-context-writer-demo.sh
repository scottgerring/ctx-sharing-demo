#!/bin/bash
set -e

# Parse arguments
USE_EBPF=false
if [[ "$1" == "--ebpf" ]]; then
    USE_EBPF=true
    echo "Using eBPF mode"
fi

# Set logging levels - reduce noise from elf_reader symbol scanning
export RUST_LOG="warn"

# Build both projects first to avoid race conditions
echo "Building context-writer"
cd "context-writer"
cargo build

echo "Building context-reader..."
cd "../context-reader"

if [[ "$USE_EBPF" == "true" ]]; then
    echo "Building eBPF program..."
    cd ebpf
    cargo build --release
    cd ..
fi

cargo build

# Now start context-writer in the background
echo "Starting context-writer..."
../context-writer/target/debug/context-writer 2>&1 > /dev/null &
WRITER_PID=$!

echo "context-writer started with PID: $WRITER_PID"

# Give context-writer a moment to fully start up
echo "Waiting for context-writer to initialize..."
sleep 5

# Start context-reader to monitor context-writer
echo "Starting context-reader to monitor PID $WRITER_PID..."
if [[ "$USE_EBPF" == "true" ]]; then
    sudo ./target/debug/context-reader "$WRITER_PID" --mode ebpf --interval 99
else
    sudo ./target/debug/context-reader "$WRITER_PID" --interval 1000
fi
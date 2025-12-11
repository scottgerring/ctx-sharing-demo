#!/bin/bash
set -e

# Set logging levels - reduce noise from elf_reader symbol scanning
export RUST_LOG="${RUST_LOG:-info,context_reader::tls_symbols::elf_reader=warn}"

# Build both projects first to avoid race conditions
echo "Building context-writer"
cd "context-writer"
cargo build

echo "Building context-reader..."
cd "../context-reader"
cargo build

# Now start context-writer in the background
echo "Starting context-writer..."
../context-writer/target/debug/context-writer 2>&1 > /dev/null &
WRITER_PID=$!

echo "context-writer started with PID: $WRITER_PID"

# Give context-writer a moment to fully start up
echo "Waiting for context-writer to initialize..."
sleep 2

# Start context-reader to monitor context-writer
echo "Starting context-reader to monitor PID $WRITER_PID..."
./target/debug/context-reader "$WRITER_PID" --interval 1000
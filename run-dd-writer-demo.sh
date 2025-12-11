#!/bin/bash
set -e

# Set logging levels - reduce noise from elf_reader symbol scanning
export RUST_LOG="${RUST_LOG:-info,context_reader::tls_symbols::elf_reader=warn}"

# Build both projects first to avoid race conditions
echo "Building datadog/async-web"
cd "datadog/async-web"
cargo build

echo "Building context-reader..."
cd "../../context-reader"
cargo build

# Now start async-web in the background
echo "Starting async-web..."
cd "../datadog/async-web"
cargo run 2>&1 > /dev/null &
WRITER_PID=$!

echo "async-web started with PID: $WRITER_PID"

# Give async-web a moment to fully start up
echo "Waiting for async-web to initialize..."
sleep 2

# Start context-reader to monitor async-web
echo "Starting context-reader to monitor PID $WRITER_PID..."
cd "../../context-reader"
cargo run -- "$WRITER_PID" --interval 1000

cd ..

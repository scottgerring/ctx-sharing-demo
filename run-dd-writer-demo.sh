#!/bin/bash
set -e

# Parse arguments
USE_EBPF=false
READERS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --ebpf)
            USE_EBPF=true
            echo "Using eBPF mode"
            shift
            ;;
        --readers)
            READERS="$2"
            echo "Using readers: $READERS"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--ebpf] [--readers both|v1|v2]"
            exit 1
            ;;
    esac
done

# Set logging levels - reduce noise from elf_reader symbol scanning
export RUST_LOG="${RUST_LOG:-info,context_reader::tls_symbols::elf_reader=warn}"

# Build both projects first to avoid race conditions
echo "Building datadog/async-web"
cd "datadog/async-web"
cargo build

echo "Building context-reader..."
cd "../../context-reader"

if [[ "$USE_EBPF" == "true" ]]; then
    cargo xtask build
else
    cargo build
fi

# Now start async-web in the background
echo "Starting async-web..."
../datadog/async-web/target/debug/async-web 2>&1 > /dev/null &
WRITER_PID=$!

echo "async-web started with PID: $WRITER_PID"

# Give async-web a moment to fully start up
echo "Waiting for async-web to initialize..."
sleep 2

# Start context-reader to monitor async-web
echo "Starting context-reader to monitor PID $WRITER_PID..."
if [[ "$USE_EBPF" == "true" ]]; then
    READER_ARGS="--mode ebpf --interval 99"
    if [[ -n "$READERS" ]]; then
        READER_ARGS="$READER_ARGS --readers $READERS"
    fi
    sudo env RUST_LOG=info ./target/debug/context-reader "$WRITER_PID" $READER_ARGS
else
    ./target/debug/context-reader "$WRITER_PID" --interval 1000
fi

#!/bin/bash
set -e

# Set logging levels - reduce noise from elf_reader symbol scanning
export RUST_LOG="${RUST_LOG:-info,context_reader::tls_symbols::elf_reader=warn}"

# Build context-reader first
echo "Building context-reader..."
cd "context-reader"
cargo build

cd ..

# Start Java demo in the background
echo "Starting Java CustomLabelDemo..."
java -cp java-demo/ddprof-1.35.0-SNAPSHOT.jar com.datadoghq.profiler.CustomLabelDemo 2>&1 > /dev/null &
JAVA_PID=$!

echo "Java demo started with PID: $JAVA_PID"

# Give Java a moment to fully start up
echo "Waiting for Java demo to initialize..."
sleep 10

# Start context-reader to monitor the Java process
echo "Starting context-reader to monitor PID $JAVA_PID..."
sudo ./context-reader/target/debug/context-reader "$JAVA_PID" --interval 1000

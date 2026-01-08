#!/bin/bash
# Helper script to run the minimal ringbuf test

echo "Finding EVENTS ringbuf map..."
MAP_INFO=$(sudo bpftool map list | grep "name EVENTS")

if [ -z "$MAP_INFO" ]; then
    echo "ERROR: No EVENTS ringbuf map found!"
    echo "Make sure context-reader is running with --mode ebpf"
    exit 1
fi

# Extract map ID (first number before the colon)
MAP_ID=$(echo "$MAP_INFO" | head -1 | awk '{print $1}' | cut -d: -f1)

echo "Found EVENTS map with ID: $MAP_ID"
echo "Starting ringbuf test..."
echo

sudo ./target/debug/ringbuf-test "$MAP_ID"

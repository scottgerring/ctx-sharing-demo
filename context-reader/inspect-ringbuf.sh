#!/bin/bash
# Script to inspect eBPF maps while context-reader is running

echo "=== eBPF Programs ==="
sudo bpftool prog list | grep -A5 "name on_cpu_sample"

echo -e "\n=== eBPF Maps ==="
sudo bpftool map list | grep -i "ring\|events"

echo -e "\n=== EVENTS map details ==="
# Find the EVENTS map ID
MAP_ID=$(sudo bpftool map list | grep "name EVENTS" | awk '{print $1}' | cut -d: -f1)

if [ -n "$MAP_ID" ]; then
    echo "Found EVENTS map with ID: $MAP_ID"
    sudo bpftool map show id "$MAP_ID"
    echo -e "\n=== Trying to dump map ==="
    sudo bpftool map dump id "$MAP_ID" 2>&1 | head -20
else
    echo "EVENTS map not found"
fi

# Minimal RingBuf Test Tool

This is a minimal debugging tool that polls an existing EVENTS ringbuf map.

## Purpose

Isolates ringbuf polling logic from the rest of the eBPF setup. Helps debug whether:
- The issue is with ringbuf polling itself
- Or with how the eBPF program is being loaded/configured

## Usage

### Step 1: Start context-reader with eBPF mode

In terminal 1:
```bash
./run-context-writer-demo.sh --ebpf
```

Leave this running. It will load the eBPF program and create the EVENTS ringbuf map.

### Step 2: Run the minimal ringbuf test

In terminal 2:
```bash
cd context-reader
./run-ringbuf-test.sh
```

This will:
1. Find the EVENTS ringbuf map ID using bpftool
2. Open the map directly by ID
3. Poll it in a loop
4. Print any events received

### Manual Usage

If you want to run it manually:

```bash
# Find the map ID
sudo bpftool map list | grep EVENTS

# Run the test with that ID
sudo cargo run --bin ringbuf-test -- <map_id>
```

## What to Look For

- **If events appear**: RingBuf polling works! The issue is elsewhere in the setup.
- **If no events appear**: The BPF program isn't emitting events OR there's a fundamental issue with ringbuf.
- Check BPF logs (from terminal 1) to confirm events are being emitted with "V1 event emitted successfully"

## Output Format

```
[Event 1] Received 1040 bytes:
  First 64 bytes (hex): [ff, ee, dd, ...]
  Parsed: tid=12345, format_version=1, data_len=24
```

The tool will print:
- Event number
- Total bytes received
- First 64 bytes in hex
- If it looks like a LabelEvent (1040+ bytes), parsed tid/format/data_len

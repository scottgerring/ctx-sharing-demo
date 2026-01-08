# Claude Session State - eBPF Context Reader

## Summary
Added eBPF reading mode to context-reader alongside the existing ptrace mode. The eBPF mode uses perf_event CPU sampling (like Parca/Pyroscope profilers) to read TLS labels.

## What Was Done

### New Files Created
- `context-reader/common/` - Shared types crate for BPF maps
  - `Cargo.toml`
  - `src/lib.rs` - `TlsConfig`, `LabelEvent` structs

- `context-reader/ebpf/` - eBPF program crate
  - `Cargo.toml` - targets `bpfel-unknown-none`
  - `.cargo/config.toml` - BPF build config
  - `src/main.rs` - perf_event handler for V1 and V2 label formats

- `context-reader/src/ebpf_loader.rs` - Userspace BPF loader

### Modified Files
- `context-reader/Cargo.toml` - Added aya, tokio, context-reader-common deps
- `context-reader/src/main.rs` - Added `--mode ptrace|ebpf` CLI arg
- `context-reader/README.md` - Documented both modes

## Current State
- Code compiles on macOS (Linux-specific code behind `#[cfg(target_os = "linux")]`)
- **NOT YET TESTED** on Linux - needs:
  1. BPF toolchain installed
  2. BPF program compiled
  3. Running against a test process

## To Test in Devcontainer

### 1. Update devcontainer for eBPF (if needed)
Add to `.devcontainer/arm64/devcontainer.json`:
```json
{
  "runArgs": ["--privileged"],
  "postCreateCommand": "... && rustup target add bpfel-unknown-none && cargo install bpf-linker"
}
```

### 2. Check BTF support
```bash
ls /sys/kernel/btf/vmlinux
```
If missing, eBPF won't work in the container - use a cloud VM instead.

### 3. Build and test
```bash
cd context-reader

# Build BPF program first
cd ebpf && cargo build --release && cd ..

# Build userspace
cargo build --release

# Test ptrace mode (should work)
sudo ./target/release/context-reader <pid> --mode ptrace

# Test eBPF mode (needs BTF)
sudo ./target/release/context-reader <pid> --mode ebpf --interval 99
```

## Known Issues to Address

1. **Hardcoded kernel offsets**: `ebpf/src/main.rs` has hardcoded offsets for `task->thread.fsbase` (x86_64) and `task->thread.uw.tp_value` (aarch64). These vary by kernel version. For production, use BTF/CO-RE with aya's `#[repr(C)]` bindings.

2. **V1 pointer chasing**: BPF only reads labelset header; userspace still uses `process_vm_readv` to read actual label strings. Could optimize by reading more in BPF.

3. **Error handling**: BPF program silently drops errors. Could add counters/metrics.

## Architecture Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                         Userspace                                │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │ Symbol Discovery │────▶│ ebpf_loader.rs                   │  │
│  │ (ELF parsing)    │     │ - Load BPF program               │  │
│  │ (TLS offsets)    │     │ - Configure maps with TLS info   │  │
│  └──────────────────┘     │ - Process events from ringbuf    │  │
│                           │ - Chase V1 pointers              │  │
│                           └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │         BPF Maps              │
                    │  - TARGET_PID                 │
                    │  - V1_TLS_CONFIG              │
                    │  - V2_TLS_CONFIG              │
                    │  - EVENTS (ringbuf)           │
                    └───────────────┬───────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────┐
│                         Kernel (eBPF)                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ on_cpu_sample (perf_event)                               │   │
│  │ - Check if current PID matches target                    │   │
│  │ - Read thread pointer from task_struct                   │   │
│  │ - Compute TLS addresses                                  │   │
│  │ - bpf_probe_read_user() labelset/record                  │   │
│  │ - Emit to ringbuf                                        │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Files Quick Reference
```
context-reader/
├── Cargo.toml              # Updated with aya deps
├── common/
│   ├── Cargo.toml
│   └── src/lib.rs          # TlsConfig, LabelEvent
├── ebpf/
│   ├── .cargo/config.toml  # BPF target
│   ├── Cargo.toml
│   └── src/main.rs         # BPF program
└── src/
    ├── main.rs             # --mode ptrace|ebpf
    ├── ebpf_loader.rs      # NEW - BPF loader
    ├── v1_reader.rs        # ptrace V1 reader
    ├── v2_reader.rs        # ptrace V2 reader
    └── tls_symbols/        # Shared ELF/TLS logic
```

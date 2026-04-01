# Context Reader

An out-of-process reader for the [polar signals custom-labels](https://github.com/polarsignals/custom-labels/tree/master)
_Thread Local Storage Format_, as well as our own TLS v2 proposal, as well as the [OTEP-4719](https://github.com/open-telemetry/opentelemetry-specification/pull/4719/changes)
_Process Context Format_. 

When you launch the process pointed at a particular PID, it loads the processes maps from `/proc/<pid>/maps`, hunts
around for process context mappings, as well as custom-labels v1 and v2 TLS variables.

It then loops forever, printing out any v1 and v2 labels on the process threads periodically. 

It needs:

* Linux 
* ELF binaries
* ARM64 or X86-64
* **Root or `CAP_SYS_PTRACE`** - required for `process_vm_readv` to read process context and TLS from the target process. On Ubuntu/Debian, the default Yama ptrace scope (`kernel.yama.ptrace_scope=1`) restricts this to child processes only.

## Reading Modes

The tool supports two reading modes:

### ptrace mode (default)
```bash
context-reader <pid> --mode ptrace
```
Uses ptrace to attach to threads and read TLS. More compatible but stops threads briefly.

### eBPF mode
```bash
context-reader <pid> --mode ebpf
```
Uses eBPF perf events to read TLS on CPU samples. Lower overhead, doesn't stop threads.

**Requirements for eBPF mode:**
- Linux kernel 5.8+ with BTF support
- `CAP_BPF` and `CAP_PERFMON` capabilities (or root)
- Build the eBPF program first (see below)

## Building

### Standard build (ptrace mode only)
```bash
cargo build --release
```

### With eBPF support
First, install the Rust BPF toolchain:
```bash
rustup target add bpfel-unknown-none
cargo install bpf-linker
```

Then build the eBPF program and userspace:
```bash
# Build eBPF program
cd ebpf && cargo build --release && cd ..

# Build userspace
cargo build --release
```

## How's it work?

At startup, we hunt for configuration for the two label formats, and then having found at least one of them,
read them out of the running process.

### ptrace mode
* We use [procfs](http://docs.rs/procfs/latest/procfs/) to read the current threads out of the process
* For each thread:
  * Use `ptrace` to attach to the thread, and wait for it to stop
  * Read the pointer to the current label set out of the TL location we discovered at startup
  * If it's _not_ `0`, we've got thread labels!
    * Use `process_vm_readv` via the [nix](https://docs.rs/nix/latest/nix/) crate to read out our TL, and then
      chase the pointers back.
    * Print it to screen!

### eBPF mode
* Uses [Aya](https://aya-rs.dev/) to load an eBPF program
* The eBPF program attaches to `perf_event` (CPU clock sampling)
* On each sample, if the current process matches our target PID:
  * Read the thread pointer from `task_struct`
  * Compute TLS addresses using the same logic as ptrace mode
  * Read labelset/record pointers using `bpf_probe_read_user()`
  * Emit raw data to userspace via ring buffer
* Userspace parses the raw data and chases remaining pointers with `process_vm_readv`


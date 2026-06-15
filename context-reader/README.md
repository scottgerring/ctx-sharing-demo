# Context Reader — TLS publisher conformance toolkit

Validates implementations of the [OTel thread-local storage spec](https://github.com/open-telemetry/opentelemetry-specification/pull/4947)
and the [OTEP-4719 Process Context Format](https://github.com/open-telemetry/opentelemetry-specification/pull/4719/changes).

Check whether your binary publishes TLS the way the spec requires, run end-to-end label reads against a running process, and inspect the raw symbols and access models any ELF on disk exposes.

## Discovery

The TLS symbol must be properly published (`STT_TLS`, `STB_GLOBAL`/`STB_WEAK`, `STV_DEFAULT`) and accessed via **TLSDESC** in a shared library. **Static TLS** is the equivalent for symbols in a main executable or a fully-static binary; the tools accept it as the main-executable fallback. Anything else — General Dynamic, Initial Exec, Local Dynamic, or Local Exec from a `.so` — is non-conformant.

## Commands

```sh
# Check what a binary on disk publishes, whether executable or .so.
# Use dump-symbols <pid> to inspect symbols in all loaded binaries.
check-elf ./libfoo.so                         # all published TLS symbols
check-elf ./libfoo.so --symbol my_tls_var     # one specific symbol
check-elf ./exe --executable                  # treat ET_DYN as PIE main exe

# Once `check-elf` passes, confirm end-to-end reads work:
# exits with 0 the first time we manage to read labels, 1 on timeout or failure
sudo validate <pid> --timeout 15            # ptrace mode
sudo validate <pid> --mode ebpf             # eBPF mode

# Use tail to log labels periodically.
sudo tail <pid>                             # strict; rejects non-conformant
sudo tail <pid> --tolerate-gd-tls           # accept GD with a warn (escape hatch)
```

## Requirements

* Linux, ARM64 or x86-64, ELF.
* Generally, `root` is needed as well 

## Development

### Building

```sh
cargo build --release                                # everything except eBPF
rustup target add bpfel-unknown-none
cargo install bpf-linker
cd ebpf && cargo build --release && cd ..            # eBPF prereqs
```

### How it works

Read `/proc/<pid>/maps`, parse every loaded ELF, look for any
process-context memfd mapping, and locate v1/v2 TLS symbols
(`custom_labels_current_set`, `otel_thread_ctx_v1`). For each TLS
symbol classify the access model from the binary's relocations
(`R_*_TLSDESC` → TLSDESC; `R_*_DTPMOD64/DTPOFF64` → GD; etc.) and
reject non-conformant ones unless `--tolerate-gd-tls` is set.

In ptrace mode, for each thread attach via `ptrace`, read the thread
pointer (`fs_base` on x86-64, `TPIDR_EL0` on aarch64), detach, then
`process_vm_readv` the TLS slot and chase the label pointers.

In eBPF mode, [Aya](https://aya-rs.dev/) loads a small eBPF program
attached to `perf_event` CPU sampling. On each sample the program
reads the thread pointer from `task_struct`, computes the TLS address
with the same logic as ptrace mode, reads the labelset/record pointer
via `bpf_probe_read_user`, and emits raw bytes to userspace through a
ring buffer; userspace chases the remaining pointers via
`process_vm_readv`.

### Self-test

The parent project ships demo publishers and a validation harness that
builds the seven `simple-writer` variants (static / dynamic / dlopen ×
glibc / musl, plus `exhaust-static-tls`), runs each, and confirms
`validate` reads labels successfully:

```sh
cd .. && ./run-simple-writer-demo.sh --validate-all       # C writers
cd .. && ./run-java-demo.sh                               # dd-java-agent
```

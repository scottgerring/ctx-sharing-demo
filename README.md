# TLS Context Sharing Demo

Demonstrates reading and writing thread-local observability context (trace IDs, span IDs, custom attributes) via TLS variables that profilers can read out-of-process.

**Linux only.** Use the `.devcontainer` or Lima VMs in `lima/` if you're not on Linux yourself!

## custom-labels

Fork of [polarsignals/custom-labels](https://github.com/polarsignals/custom-labels) with two additions:

1. **v2 TLS format** - Adds `custom_labels_current_set_v2` symbol supporting arbitrary string attributes plus trace context. See [custom-labels/README.md](custom-labels/README.md).

2. **Process Context** - Rust implementation of [OTEP-4719](https://github.com/open-telemetry/opentelemetry-specification/pull/4719) for publishing key tables via named memory mappings.

## context-reader

Out-of-process reader for custom-labels v1/v2. Three binaries:

| Binary | Purpose |
|--------|---------|
| `dump-symbols` | Debug TLS symbol resolution for a process |
| `validate` | One-shot validation that labels can be read |
| `tail` | Continuous monitoring via ptrace or eBPF |

Requires root or `CAP_SYS_PTRACE`. See [context-reader/README.md](context-reader/README.md).

## simple-writer

Test programs that write custom-labels across different linking scenarios (static/dynamic/dlopen, glibc/musl). Used to verify context-reader works in all TLS configurations including DTV fallback.

See [simple-writer/README.md](simple-writer/README.md).

## Quick Start

```bash
# Run simple-writer with context-reader validation (builds everything)
# Optional: add --ebpf to use the ebpf reading path
./run-simple-writer-demo.sh --validate

# Test all linking variants
./run-simple-writer-demo.sh --validate-all

# Interactive monitoring
./run-simple-writer-demo.sh --labels dynamic
```

## Other Components

| Directory | Description |
|-----------|-------------|
| `context-writer` | Rust app that spawns threads writing webserver-style context |
| `datadog` | Actix web app using modified dd-trace-rs for automatic context capture |
| `tls-filler` | Helper libraries to exhaust static TLS space for testing DTV path |
| `lima` | VM templates for arm64/amd64 testing |

## Scripts

| Script | Purpose |
|--------|---------|
| `run-simple-writer-demo.sh` | Build and test simple-writer variants |
| `run-context-writer-demo.sh` | Run context-writer with context-reader |
| `run-dd-writer-demo.sh` | Run datadog demo |
| `run-java-demo.sh` | Run Java demo | 

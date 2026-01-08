#!/bin/bash
set -e

# Generate C header from kernel BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Extract just the types we need
cat > vmlinux_minimal.h << 'CHEADER'
#include "vmlinux.h"

// Just the types we need for bindgen
struct task_struct;
struct thread_struct;
CHEADER

# Use bindgen to generate Rust bindings
bindgen vmlinux_minimal.h -o src/vmlinux.rs \
    --allowlist-type task_struct \
    --allowlist-type thread_struct \
    --no-layout-tests \
    --no-doc-comments \
    --with-derive-default \
    -- -I.

echo "Generated src/vmlinux.rs"

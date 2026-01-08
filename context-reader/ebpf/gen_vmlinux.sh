#!/bin/bash
# Generate minimal vmlinux.rs with just the types we need

cat > src/vmlinux.rs << 'RUST'
#![allow(non_camel_case_types, non_snake_case, dead_code, non_upper_case_globals)]

// Minimal kernel type definitions for CO-RE
// Generated from kernel BTF

pub type __u64 = u64;
pub type __u32 = u32;
pub type __u16 = u16;
pub type __u8 = u8;

#[repr(C)]
pub struct task_struct {
    _bindgen_opaque_blob: [u64; 0],
}

#[repr(C)]
pub struct thread_struct {
    _bindgen_opaque_blob: [u64; 0],
}

// For BPF CO-RE field access, we use the bpf_core_field_offset helper
// The kernel structures don't need full definitions - CO-RE handles it
RUST

echo "Generated src/vmlinux.rs"

//! Shared types between eBPF program and userspace loader.
//!
//! These types are used in BPF maps and ringbuf events.
//! They must be `#[repr(C)]` for consistent memory layout.

#![cfg_attr(not(feature = "std"), no_std)]

/// Maximum size of label data we can transfer per event
pub const MAX_LABEL_DATA_SIZE: usize = 1024;

/// TLS configuration for a symbol.
/// Passed from userspace to BPF via map.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TlsConfig {
    /// For shared libraries: the module ID in the DTV
    pub module_id: u64,
    /// Offset within the TLS block
    pub offset: u64,
    /// Non-zero if this is the main executable (uses static TLS offset)
    pub is_main_executable: u8,
    /// Padding for alignment
    pub _pad: [u8; 7],
    /// Maximum size of V2 records (from process context)
    /// Set to 0 for V1 (not applicable)
    pub max_record_size: u64,
}

/// Kernel structure offsets for thread pointer access.
/// Calculated from BTF in userspace and passed to BPF.
/// This provides kernel version portability without hardcoding offsets.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct KernelOffsets {
    /// Offset of thread field in task_struct
    pub task_struct_thread_offset: u64,
    /// Offset of fsbase field in thread_struct (x86_64)
    pub thread_struct_fsbase_offset: u64,
    /// Whether these offsets are valid
    pub valid: u8,
    pub _pad: [u8; 7],
}

/// Label event sent from BPF to userspace via ringbuf.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LabelEvent {
    /// Thread ID that had labels
    pub tid: u32,
    /// Format version: 1 = V1 (custom-labels), 2 = V2 (binary record)
    pub format_version: u8,
    /// Padding
    pub _pad: [u8; 1],
    /// Length of valid data in `data` field
    pub data_len: u16,
    /// Pointer to the original data in the target process (for chasing pointers)
    pub ptr: u64,
    /// Raw data read from the target process
    /// For V1: labelset header (storage ptr, count, capacity)
    /// For V2: raw binary record
    pub data: [u8; MAX_LABEL_DATA_SIZE],
}

impl Default for LabelEvent {
    fn default() -> Self {
        Self {
            tid: 0,
            format_version: 0,
            _pad: [0; 1],
            data_len: 0,
            ptr: 0,
            data: [0; MAX_LABEL_DATA_SIZE],
        }
    }
}

#[cfg(feature = "std")]
mod std_impls {
    use super::*;

    impl std::fmt::Debug for TlsConfig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TlsConfig")
                .field("module_id", &self.module_id)
                .field("offset", &format_args!("{:#x}", self.offset))
                .field("is_main_executable", &(self.is_main_executable != 0))
                .field("max_record_size", &self.max_record_size)
                .finish()
        }
    }

    impl std::fmt::Debug for LabelEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LabelEvent")
                .field("tid", &self.tid)
                .field("format_version", &self.format_version)
                .field("data_len", &self.data_len)
                .field("ptr", &format_args!("{:#x}", self.ptr))
                .finish()
        }
    }
}

// Implement aya's Pod trait for our types (only when aya is available)
#[cfg(feature = "std")]
unsafe impl aya::Pod for TlsConfig {}
#[cfg(feature = "std")]
unsafe impl aya::Pod for LabelEvent {}
#[cfg(feature = "std")]
unsafe impl aya::Pod for KernelOffsets {}

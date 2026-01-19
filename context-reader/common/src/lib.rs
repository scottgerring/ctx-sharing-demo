//! Shared types between eBPF program and userspace loader.
//!
//! These types are used in BPF maps and ringbuf events.
//! They must be `#[repr(C)]` for consistent memory layout.

#![cfg_attr(not(feature = "std"), no_std)]

/// Maximum size of label data we can transfer per event
pub const MAX_LABEL_DATA_SIZE: usize = 2048;

/// Target architecture for TLS calculations
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86_64 = 0,
    Aarch64 = 1,
}

/// Reader mode configuration - controls which readers are enabled.
/// This is passed to the eBPF program to skip work for disabled readers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReaderMode {
    /// Read both V1 and V2 labels (default)
    #[default]
    Both = 0,
    /// Only read V1 labels
    V1Only = 1,
    /// Only read V2 labels
    V2Only = 2,
}

impl ReaderMode {
    /// Returns true if V1 reading is enabled
    #[inline]
    pub fn v1_enabled(&self) -> bool {
        matches!(self, ReaderMode::Both | ReaderMode::V1Only)
    }

    /// Returns true if V2 reading is enabled
    #[inline]
    pub fn v2_enabled(&self) -> bool {
        matches!(self, ReaderMode::Both | ReaderMode::V2Only)
    }
}

/// Get the current architecture at compile time
#[cfg(target_arch = "x86_64")]
pub const CURRENT_ARCH: Architecture = Architecture::X86_64;

#[cfg(target_arch = "aarch64")]
pub const CURRENT_ARCH: Architecture = Architecture::Aarch64;

// When building for BPF target, provide a fallback definition.
// NOTE: The eBPF program should get the actual architecture from KernelOffsets
// passed by userspace, not from this compile-time constant.
#[cfg(all(target_arch = "bpf", target_endian = "little"))]
pub const CURRENT_ARCH: Architecture = Architecture::X86_64;

#[cfg(all(target_arch = "bpf", target_endian = "big"))]
pub const CURRENT_ARCH: Architecture = Architecture::Aarch64;

/// Calculate the TLS offset for a symbol in the main executable's static TLS block.
///
/// This handles the architecture-specific differences in TLS layout:
/// - x86-64 (TLS variant II): Thread pointer points to end of TLS block, variables
///   are at negative offsets. Offset = tls_block_size - st_value
/// - aarch64 (TLS variant I): Thread pointer points to TCB, variables are at positive
///   offsets after TCB. Offset = st_value
#[inline]
pub fn calculate_static_tls_offset(
    st_value: u64,
    tls_block_size: Option<u64>,
    arch: Architecture,
) -> u64 {
    match arch {
        Architecture::X86_64 => {
            // TLS variant II: Thread pointer points to END of TLS block
            // Variables are at NEGATIVE offsets from TP
            if let Some(block_size) = tls_block_size {
                block_size.saturating_sub(st_value)
            } else {
                st_value
            }
        }
        Architecture::Aarch64 => {
            // TLS variant I: st_value IS the offset
            st_value
        }
    }
}

/// Calculate the absolute address of a TLS variable using static TLS.
///
/// This applies the architecture-specific formula to get from the thread pointer
/// to the actual TLS variable address.
#[inline]
pub fn calculate_static_tls_address(
    thread_pointer: u64,
    offset: u64,
    arch: Architecture,
) -> u64 {
    match arch {
        Architecture::X86_64 => {
            // TLS variant II: subtract offset from thread pointer
            thread_pointer.wrapping_sub(offset)
        }
        Architecture::Aarch64 => {
            // TLS variant I: add TCB size and offset to thread pointer
            const AARCH64_TCB_SIZE: u64 = 16;
            thread_pointer
                .wrapping_add(AARCH64_TCB_SIZE)
                .wrapping_add(offset)
        }
    }
}

/// Calculate the final TLS address from thread pointer and TLS configuration.
/// Handles both main executable (static TLS) and shared library (DTV) cases.
///
/// For shared libraries, the DTV lookup must be done by the caller - this function
/// just handles the address arithmetic once you have the TLS block pointer.
#[inline]
pub fn compute_tls_address_static(thread_pointer: u64, offset: u64) -> u64 {
    // For now assume x86_64, but caller should use calculate_static_tls_address with proper arch
    calculate_static_tls_address(thread_pointer, offset, CURRENT_ARCH)
}

/// TLS configuration for a symbol.
/// Passed from userspace to BPF via map.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TlsConfig {
    /// For shared libraries: the module ID in the DTV
    pub module_id: u64,
    /// Offset within the TLS block (symbol offset)
    pub offset: u64,
    /// l_tls_offset for static TLS calculation in shared libraries
    pub tls_offset: u64,
    /// Non-zero if this is the main executable (uses static TLS offset)
    pub is_main_executable: u8,
    /// Non-zero if eBPF should use static TLS for shared libraries (fast path)
    /// Set by userspace based on whether tls_offset is valid
    pub use_static_tls: u8,
    /// Padding for alignment
    pub _pad: [u8; 6],
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
    /// Offset of thread pointer field in thread_struct
    /// - x86_64: fsbase field
    /// - aarch64: tp_value field
    pub thread_struct_fsbase_offset: u64,
    /// Whether these offsets are valid
    pub valid: u8,
    /// Target architecture (0 = x86_64, 1 = aarch64)
    pub arch: u8,
    pub _pad: [u8; 6],
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
    /// Timestamp when eBPF processing started (nanoseconds from bpf_ktime_get_ns)
    pub start_time_ns: u64,
    /// Timestamp when eBPF processing completed (nanoseconds from bpf_ktime_get_ns)
    pub end_time_ns: u64,
    /// Raw data read from the target process
    /// For V1: packed labels in format [count: u8][for each: [key_len: u16][key_data][value_len: u16][value_data]]
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
            start_time_ns: 0,
            end_time_ns: 0,
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
                .field("tls_offset", &format_args!("{:#x}", self.tls_offset))
                .field("is_main_executable", &(self.is_main_executable != 0))
                .field("use_static_tls", &(self.use_static_tls != 0))
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
#[cfg(feature = "std")]
unsafe impl aya::Pod for ReaderMode {}

#[cfg(test)]
mod tests {
    use super::*;

    // Test x86-64 static TLS offset calculation
    #[test]
    fn test_x86_64_static_tls_offset_with_pt_tls() {
        // Real example from context-writer:
        // PT_TLS p_memsz = 0x158 (344 bytes)
        // custom_labels_current_set_v2 st_value = 0x110 (272)
        // Correct behavior: offset = tls_block_size - st_value = 0x158 - 0x110 = 0x48
        let offset = calculate_static_tls_offset(0x110, Some(0x158), Architecture::X86_64);
        assert_eq!(offset, 0x48);
    }

    #[test]
    fn test_x86_64_static_tls_offset_without_pt_tls() {
        // Fallback when PT_TLS not found: use st_value
        let offset = calculate_static_tls_offset(0x110, None, Architecture::X86_64);
        assert_eq!(offset, 0x110);
    }

    #[test]
    fn test_x86_64_static_tls_offset_at_block_start() {
        // Variable at start of TLS block (st_value = 0)
        // Offset = tls_block_size - 0 = tls_block_size
        let offset = calculate_static_tls_offset(0, Some(0x158), Architecture::X86_64);
        assert_eq!(offset, 0x158);
    }

    #[test]
    fn test_x86_64_static_tls_offset_at_block_end() {
        // Variable at end of TLS block (st_value = tls_block_size = 0x158)
        // Offset = tls_block_size - tls_block_size = 0
        let offset = calculate_static_tls_offset(0x158, Some(0x158), Architecture::X86_64);
        assert_eq!(offset, 0);
    }

    // Test aarch64 static TLS offset calculation
    #[test]
    fn test_aarch64_static_tls_offset() {
        // For aarch64, st_value is used directly as the offset
        let offset = calculate_static_tls_offset(0x110, Some(0x158), Architecture::Aarch64);
        assert_eq!(offset, 0x110);
    }

    #[test]
    fn test_aarch64_static_tls_offset_ignores_block_size() {
        // aarch64 doesn't use tls_block_size, only st_value
        let offset = calculate_static_tls_offset(0x110, None, Architecture::Aarch64);
        assert_eq!(offset, 0x110);
    }

    // Test x86-64 TLS address calculation
    #[test]
    fn test_x86_64_tls_address_calculation() {
        // With correct offset after fix
        // Thread pointer = 0x7f73963fe6c0
        // Offset = 0x48 (correct after fix)
        // Expected address: 0x7f73963fe6c0 - 0x48 = 0x7f73963fe678
        let thread_pointer = 0x7f73963fe6c0;
        let offset = 0x48;
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::X86_64);
        assert_eq!(addr, 0x7f73963fe678);
    }

    #[test]
    fn test_x86_64_tls_address_with_zero_offset() {
        // Variable at the thread pointer location
        let thread_pointer = 0x7f73963fe6c0;
        let addr = calculate_static_tls_address(thread_pointer, 0, Architecture::X86_64);
        assert_eq!(addr, thread_pointer);
    }

    // Test aarch64 TLS address calculation
    #[test]
    fn test_aarch64_tls_address_calculation() {
        // Thread pointer = 0x7f73963fe6c0
        // TCB size = 16 (0x10)
        // Offset = 0x110
        // Expected: 0x7f73963fe6c0 + 0x10 + 0x110 = 0x7f73963fe7e0
        let thread_pointer = 0x7f73963fe6c0;
        let offset = 0x110;
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::Aarch64);
        assert_eq!(addr, 0x7f73963fe7e0);
    }

    #[test]
    fn test_aarch64_tls_address_with_zero_offset() {
        // Variable right after TCB
        let thread_pointer = 0x7f73963fe6c0;
        let addr = calculate_static_tls_address(thread_pointer, 0, Architecture::Aarch64);
        assert_eq!(addr, thread_pointer + 16); // Just after 16-byte TCB
    }

    // Test wrapping behavior (important for address arithmetic)
    #[test]
    fn test_x86_64_address_wrapping() {
        // Ensure we handle address wrapping correctly
        let thread_pointer = 0x100;
        let offset = 0x200; // Larger than thread_pointer
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::X86_64);
        // Should wrap: 0x100 - 0x200 = 0xffffff...00 (in 64-bit)
        assert_eq!(addr, thread_pointer.wrapping_sub(offset));
    }

    #[test]
    fn test_aarch64_address_wrapping() {
        // Ensure we handle address wrapping correctly
        let thread_pointer = u64::MAX - 100;
        let offset = 200;
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::Aarch64);
        // Should wrap around
        assert_eq!(
            addr,
            thread_pointer.wrapping_add(16).wrapping_add(offset)
        );
    }

    // Integration test: full calculation pipeline
    #[test]
    fn test_x86_64_full_pipeline() {
        // Real-world example from context-writer
        let st_value = 0x110;
        let tls_block_size = Some(0x158);
        let thread_pointer = 0x7f73963fe6c0;

        // Step 1: Calculate offset (correct after fix)
        let offset = calculate_static_tls_offset(st_value, tls_block_size, Architecture::X86_64);
        assert_eq!(offset, 0x48); // Correct: 0x158 - 0x110 = 0x48

        // Step 2: Calculate address (correct after fix)
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::X86_64);
        assert_eq!(addr, 0x7f73963fe678); // Correct: 0x7f73963fe6c0 - 0x48 = 0x7f73963fe678
    }

    #[test]
    fn test_aarch64_full_pipeline() {
        let st_value = 0x110;
        let tls_block_size = Some(0x158);
        let thread_pointer = 0x7f73963fe6c0;

        // Step 1: Calculate offset (just st_value for aarch64)
        let offset = calculate_static_tls_offset(st_value, tls_block_size, Architecture::Aarch64);
        assert_eq!(offset, 0x110);

        // Step 2: Calculate address (TP + TCB + offset)
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::Aarch64);
        assert_eq!(addr, 0x7f73963fe7e0);
    }
}

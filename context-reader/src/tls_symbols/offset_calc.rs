//! Pure, testable TLS offset and address calculations.
//!
//! This module contains architecture-specific TLS calculations extracted into
//! pure functions that can be tested on any host architecture.

/// Target architecture for TLS calculations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

/// Calculate the TLS offset for a symbol in the main executable's static TLS block.
///
/// This handles the architecture-specific differences in TLS layout:
/// - x86-64 (TLS variant II): Thread pointer points to end of TLS block, variables
///   are at negative offsets. Offset = tls_block_size - st_value
/// - aarch64 (TLS variant I): Thread pointer points to TCB, variables are at positive
///   offsets after TCB. Offset = st_value
///
/// # Arguments
/// * `st_value` - The symbol's st_value from the ELF symbol table
/// * `tls_block_size` - The size of the TLS block from PT_TLS (p_memsz)
/// * `arch` - Target architecture
///
/// # Returns
/// The offset to use when calculating the TLS variable address
pub fn calculate_static_tls_offset(
    st_value: usize,
    _tls_block_size: Option<usize>,
    arch: Architecture,
) -> usize {
    match arch {
        Architecture::X86_64 => {
            // Current (incorrect) behavior: just use st_value directly
            // This is wrong for x86-64 TLS variant II, but represents current state
            st_value
        }
        Architecture::Aarch64 => {
            // TLS variant I: Thread pointer points to TCB
            // Variables are at POSITIVE offsets from TP (after the TCB)
            // The st_value IS the offset from the start of the TLS block
            st_value
        }
    }
}

/// Calculate the absolute address of a TLS variable using static TLS.
///
/// This applies the architecture-specific formula to get from the thread pointer
/// to the actual TLS variable address.
///
/// # Arguments
/// * `thread_pointer` - The thread pointer register value (FS_BASE on x86-64, TPIDR_EL0 on aarch64)
/// * `offset` - The TLS offset (from calculate_static_tls_offset)
/// * `arch` - Target architecture
///
/// # Returns
/// The absolute memory address of the TLS variable
pub fn calculate_static_tls_address(
    thread_pointer: usize,
    offset: usize,
    arch: Architecture,
) -> usize {
    match arch {
        Architecture::X86_64 => {
            // TLS variant II: subtract offset from thread pointer
            thread_pointer.wrapping_sub(offset)
        }
        Architecture::Aarch64 => {
            // TLS variant I: add TCB size and offset to thread pointer
            const AARCH64_TCB_SIZE: usize = 16;
            thread_pointer
                .wrapping_add(AARCH64_TCB_SIZE)
                .wrapping_add(offset)
        }
    }
}

/// Get the current architecture at compile time
#[cfg(target_arch = "x86_64")]
pub const CURRENT_ARCH: Architecture = Architecture::X86_64;

#[cfg(target_arch = "aarch64")]
pub const CURRENT_ARCH: Architecture = Architecture::Aarch64;

#[cfg(test)]
mod tests {
    use super::*;

    // Test x86-64 static TLS offset calculation (CURRENT BROKEN BEHAVIOR)
    #[test]
    fn test_x86_64_static_tls_offset_with_pt_tls() {
        // Real example from context-writer:
        // PT_TLS p_memsz = 0x158 (344 bytes)
        // custom_labels_current_set_v2 st_value = 0x110 (272)
        // Current (incorrect) behavior: offset = st_value = 0x110
        // NOTE: This is WRONG! Should be 0x158 - 0x110 = 0x48
        let offset = calculate_static_tls_offset(0x110, Some(0x158), Architecture::X86_64);
        assert_eq!(offset, 0x110); // TODO: Should be 0x48 after fix
    }

    #[test]
    fn test_x86_64_static_tls_offset_without_pt_tls() {
        // Current behavior: just use st_value
        let offset = calculate_static_tls_offset(0x110, None, Architecture::X86_64);
        assert_eq!(offset, 0x110);
    }

    #[test]
    fn test_x86_64_static_tls_offset_at_block_start() {
        // Variable at start of TLS block (st_value = 0)
        // Current (incorrect): offset = st_value = 0
        // NOTE: Should be tls_block_size = 0x158 after fix
        let offset = calculate_static_tls_offset(0, Some(0x158), Architecture::X86_64);
        assert_eq!(offset, 0); // TODO: Should be 0x158 after fix
    }

    #[test]
    fn test_x86_64_static_tls_offset_at_block_end() {
        // Variable at end of TLS block (st_value = tls_block_size = 0x158)
        // Current (incorrect): offset = st_value = 0x158
        // NOTE: Should be 0 after fix
        let offset = calculate_static_tls_offset(0x158, Some(0x158), Architecture::X86_64);
        assert_eq!(offset, 0x158); // TODO: Should be 0 after fix
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
        // With INCORRECT offset (current behavior uses st_value = 0x110)
        // Thread pointer = 0x7f73963fe6c0
        // Offset = 0x110 (WRONG! Should be 0x48)
        // Calculated address: 0x7f73963fe6c0 - 0x110 = 0x7f73963fe5b0 (WRONG!)
        // Expected address should be: 0x7f73963fe6c0 - 0x48 = 0x7f73963fe678
        let thread_pointer = 0x7f73963fe6c0;
        let offset = 0x110; // Current broken offset
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::X86_64);
        assert_eq!(addr, 0x7f73963fe5b0); // Wrong address due to wrong offset
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
        let thread_pointer = usize::MAX - 100;
        let offset = 200;
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::Aarch64);
        // Should wrap around
        assert_eq!(
            addr,
            thread_pointer.wrapping_add(16).wrapping_add(offset)
        );
    }

    // Integration test: full calculation pipeline (CURRENT BROKEN BEHAVIOR)
    #[test]
    fn test_x86_64_full_pipeline() {
        // Real-world example from context-writer
        let st_value = 0x110;
        let tls_block_size = Some(0x158);
        let thread_pointer = 0x7f73963fe6c0;

        // Step 1: Calculate offset (WRONG! Should be 0x158 - 0x110 = 0x48)
        let offset = calculate_static_tls_offset(st_value, tls_block_size, Architecture::X86_64);
        assert_eq!(offset, 0x110); // TODO: Should be 0x48 after fix

        // Step 2: Calculate address (WRONG due to wrong offset!)
        // Gets: 0x7f73963fe6c0 - 0x110 = 0x7f73963fe5b0
        // Should be: 0x7f73963fe6c0 - 0x48 = 0x7f73963fe678
        let addr = calculate_static_tls_address(thread_pointer, offset, Architecture::X86_64);
        assert_eq!(addr, 0x7f73963fe5b0); // TODO: Should be 0x7f73963fe678 after fix
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

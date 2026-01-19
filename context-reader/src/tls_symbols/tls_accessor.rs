///
/// Generic TLS (Thread-Local Storage) variable accessor for Linux processes.
/// Provides architecture-aware TLS address calculation independent of any
/// specific application logic.
///
use anyhow::{Context, Result};
use nix::unistd::Pid;
use tracing::debug;

use super::memory::read_memory;

/// Describes where a TLS variable is located
#[derive(Debug, Clone)]
pub enum TlsLocation {
    /// TLS in main executable (static offset from thread pointer)
    MainExecutable { offset: usize },
    /// TLS in shared library (try static TLS first, fall back to DTV)
    /// Static TLS is faster (single pointer arithmetic) and always valid if the library
    /// has a static TLS slot. DTV lookup is used as fallback for dlopen'd libraries.
    SharedLibrary {
        module_id: usize,
        offset: usize,
        /// l_tls_offset from link_map - used for static TLS calculation
        tls_offset: usize,
    },
    /// TLS via static offset from thread pointer (legacy, prefer SharedLibrary)
    /// This is used when module_id is 0 but tls_offset is valid
    StaticTls { tls_offset: usize, symbol_offset: usize },
}

/// Get the memory address of a TLS variable in a specific thread.
/// This version reads the thread pointer via ptrace internally.
pub fn get_tls_variable_address(pid: i32, tid: i32, location: &TlsLocation) -> Result<usize> {
    let thread_pointer = get_thread_pointer(tid)?;
    get_tls_variable_address_with_thread_pointer(pid, thread_pointer, location)
}

/// Get the memory address of a TLS variable using a pre-computed thread pointer.
/// Use this when you've already read the thread pointer via ptrace to avoid
/// repeated attach/detach cycles.
pub fn get_tls_variable_address_with_thread_pointer(
    pid: i32,
    thread_pointer: usize,
    location: &TlsLocation,
) -> Result<usize> {
    match location {
        TlsLocation::MainExecutable { offset } => {
            get_tls_via_static_offset_with_tp(thread_pointer, *offset)
        }
        TlsLocation::SharedLibrary { module_id, offset, tls_offset } => {
            // Try static TLS first (faster), fall back to DTV if unavailable
            get_tls_for_shared_library(pid, thread_pointer, *module_id, *offset, *tls_offset)
        }
        TlsLocation::StaticTls { tls_offset, symbol_offset } => {
            get_tls_via_static_with_tp(thread_pointer, *tls_offset, *symbol_offset)
        }
    }
}

/// Get TLS address for main executable using static offset (with pre-computed thread pointer).
fn get_tls_via_static_offset_with_tp(thread_pointer: usize, tls_offset: usize) -> Result<usize> {
    use context_reader_common::{calculate_static_tls_address, CURRENT_ARCH};

    // Use the pure calculation function with the current architecture
    let tls_addr = calculate_static_tls_address(
        thread_pointer as u64,
        tls_offset as u64,
        CURRENT_ARCH,
    );

    Ok(tls_addr as usize)
}

/// Check if a tls_offset value is valid for static TLS calculation.
/// Invalid values include:
/// - 0: No TLS offset set
/// - usize::MAX: glibc marker for "use DTV" (dynamic TLS only)
/// - Values > 1GB: Likely invalid pointers, not offsets
fn is_valid_static_tls_offset(tls_offset: usize) -> bool {
    const MAX_REASONABLE_TLS_OFFSET: usize = 0x40000000; // 1GB
    tls_offset != 0 && tls_offset != usize::MAX && tls_offset <= MAX_REASONABLE_TLS_OFFSET
}

/// Get TLS address for shared library, trying static TLS first, then DTV.
/// Static TLS is faster (single pointer arithmetic) and always valid if the
/// library has a static TLS slot. DTV lookup is used as fallback for dlopen'd
/// libraries where static TLS may not be available.
fn get_tls_for_shared_library(
    pid: i32,
    thread_pointer: usize,
    module_id: usize,
    symbol_offset: usize,
    tls_offset: usize,  // l_tls_offset from link_map for static TLS
) -> Result<usize> {
    // Try static TLS first (if tls_offset is valid)
    if is_valid_static_tls_offset(tls_offset) {
        match get_tls_via_static_with_tp(thread_pointer, tls_offset, symbol_offset) {
            Ok(addr) => return Ok(addr),
            Err(e) => {
                debug!(
                    "Static TLS failed for module {}: {}. Trying DTV lookup.",
                    module_id, e
                );
            }
        }
    }

    // Fall back to DTV lookup
    get_tls_via_dtv_with_tp(pid, thread_pointer, module_id, symbol_offset)
}

/// Get TLS address for shared library using DTV (with pre-computed thread pointer).
fn get_tls_via_dtv_with_tp(
    pid: i32,
    thread_pointer: usize,
    module_id: usize,
    tls_offset: usize,
) -> Result<usize> {
    // Read the DTV pointer from the thread control block
    // The offset differs by architecture due to different tcbhead_t layouts:
    //
    // glibc x86-64 tcbhead_t (sysdeps/x86_64/nptl/tls.h):
    //   typedef struct { void *tcb; dtv_t *dtv; void *self; ... } tcbhead_t;
    //   DTV is at offset 8 (second field)
    //
    // glibc aarch64 tcbhead_t (sysdeps/aarch64/nptl/tls.h):
    //   typedef struct { dtv_t *dtv; void *private; } tcbhead_t;
    //   DTV is at offset 0 (first field)

    #[cfg(target_arch = "x86_64")]
    let dtv_ptr_addr = thread_pointer + 8;  // DTV is second field in tcbhead_t

    #[cfg(target_arch = "aarch64")]
    let dtv_ptr_addr = thread_pointer;  // DTV is first field in tcbhead_t

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let dtv_ptr_addr = {
        anyhow::bail!("Unsupported architecture for DTV access");
    };

    // Read DTV pointer (pointer-sized value)
    const POINTER_SIZE: usize = std::mem::size_of::<usize>();
    let mut dtv_ptr_bytes = [0u8; POINTER_SIZE];
    read_memory(pid, dtv_ptr_addr, &mut dtv_ptr_bytes)?;
    let dtv_ptr = usize::from_ne_bytes(dtv_ptr_bytes);

    debug!("DTV pointer: {:#x}", dtv_ptr);

    if dtv_ptr == 0 {
        anyhow::bail!("DTV pointer is null");
    }

    // DTV layout in glibc:
    // dtv[0] = generation counter
    // dtv[1] = first module's TLS block
    // dtv[module_id] = this module's TLS block
    //
    // IMPORTANT: Each dtv_t entry is 16 bytes on 64-bit systems, not 8!
    // The structure is: struct { void *val; bool is_static; } with padding
    const DTV_ENTRY_SIZE: usize = 16;  // sizeof(dtv_t) on 64-bit
    let dtv_entry_addr = dtv_ptr + (module_id * DTV_ENTRY_SIZE);

    debug!(
        "Reading DTV entry at {:#x} for module {}",
        dtv_entry_addr, module_id
    );

    // Read the pointer to this module's TLS block
    let mut tls_block_ptr_bytes = [0u8; POINTER_SIZE];
    read_memory(pid, dtv_entry_addr, &mut tls_block_ptr_bytes)?;
    let tls_block = usize::from_ne_bytes(tls_block_ptr_bytes);

    debug!("TLS block for module {}: {:#x}", module_id, tls_block);

    // Check for special "not allocated" marker value (-1)
    // glibc uses TLS_DTV_UNALLOCATED which is ((void *) -1)
    if tls_block == usize::MAX {
        anyhow::bail!(
            "TLS block not allocated for module {} (thread hasn't accessed this TLS yet)",
            module_id
        );
    }

    if tls_block == 0 {
        anyhow::bail!(
            "TLS block pointer is null for module {}",
            module_id
        );
    }

    // Final address is TLS block base + symbol offset
    let tls_addr = tls_block + tls_offset;
    debug!("TLS address for module {}: {:#x} (block {:#x} + offset {:#x})",
           module_id, tls_addr, tls_block, tls_offset);

    Ok(tls_addr)
}

/// Get TLS address using static TLS method (direct offset from thread pointer).
/// This is the fast path for shared libraries with a static TLS slot.
///
/// Architecture differences:
/// - x86-64: fs_base points to the TCB, TLS grows downward (before TCB)
///   Formula: thread_pointer - tls_offset + symbol_offset
/// - aarch64: TPIDR points to TLS block start, TLS grows upward
///   Formula: thread_pointer + tls_offset + symbol_offset
fn get_tls_via_static_with_tp(
    thread_pointer: usize,
    tls_offset: usize,
    symbol_offset: usize,
) -> Result<usize> {
    // For static TLS, the TLS is at a direct offset from the thread pointer
    // tls_offset comes from l_tls_offset in link_map
    // symbol_offset is the offset of the specific symbol within the TLS block

    #[cfg(target_arch = "x86_64")]
    let tls_addr = thread_pointer - tls_offset + symbol_offset;

    #[cfg(target_arch = "aarch64")]
    let tls_addr = thread_pointer + tls_offset + symbol_offset;

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for static TLS calculation");

    #[cfg(target_arch = "x86_64")]
    debug!(
        "Static TLS address: {:#x} (tp {:#x} - tls_offset {:#x} + sym_offset {:#x})",
        tls_addr, thread_pointer, tls_offset, symbol_offset
    );

    #[cfg(target_arch = "aarch64")]
    debug!(
        "Static TLS address: {:#x} (tp {:#x} + tls_offset {:#x} + sym_offset {:#x})",
        tls_addr, thread_pointer, tls_offset, symbol_offset
    );

    Ok(tls_addr)
}

/// Get the thread pointer register value for a thread.
/// Requires the thread to be ptrace-attached.
/// - x86-64: FS_BASE register
/// - aarch64: TPIDR_EL0 register
pub fn get_thread_pointer(tid: i32) -> Result<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        get_fs_base(tid)
    }

    #[cfg(target_arch = "aarch64")]
    {
        get_tpidr(tid)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        anyhow::bail!("Unsupported architecture");
    }
}

/// Get FS_BASE register on x86-64 (thread pointer)
#[cfg(target_arch = "x86_64")]
fn get_fs_base(tid: i32) -> Result<usize> {
    // On x86-64, FS_BASE must be read using PTRACE_ARCH_PRCTL with ARCH_GET_FS
    // These constants are not in the nix crate, so we use libc directly
    const PTRACE_ARCH_PRCTL: libc::c_uint = 30;
    const ARCH_GET_FS: libc::c_ulong = 0x1003;

    let mut fs_base: libc::c_ulong = 0;

    let result = unsafe {
        libc::ptrace(
            PTRACE_ARCH_PRCTL as libc::c_uint,
            tid,
            &mut fs_base as *mut _ as libc::c_ulong,
            ARCH_GET_FS,
        )
    };

    if result == -1 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("Failed to read fs_base register: {}", err);
    }

    Ok(fs_base as usize)
}

/// Get TPIDR_EL0 register on aarch64 (thread pointer)
#[cfg(target_arch = "aarch64")]
fn get_tpidr(tid: i32) -> Result<usize> {
    // On arm64, the register in question is TPIDR_EL0
    // This is part of the NT_ARM_TLS regset (regset 0x401)
    const NT_ARM_TLS: i32 = 0x401;

    // TPIDR is an 8-byte value
    let mut tpidr_buf = [0u8; 8];

    // Use libc directly for ptrace with GETREGSET
    #[repr(C)]
    struct iovec {
        iov_base: *mut libc::c_void,
        iov_len: libc::size_t,
    }

    let mut iov = iovec {
        iov_base: tpidr_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: tpidr_buf.len(),
    };

    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            tid,
            NT_ARM_TLS as libc::c_ulong,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };

    if result == -1 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("Failed to read TPIDR_EL0 register: {}", err);
    }

    let tpidr = u64::from_ne_bytes(tpidr_buf);
    Ok(tpidr as usize)
}

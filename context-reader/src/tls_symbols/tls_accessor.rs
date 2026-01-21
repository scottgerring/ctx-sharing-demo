///
/// Generic TLS (Thread-Local Storage) variable accessor for Linux processes.
/// Provides architecture-aware TLS address calculation independent of any
/// specific application logic.
///
use anyhow::{Context, Result};
use tracing::{debug, info};

use super::memory::read_memory;

/// Describes where a TLS variable is located
#[derive(Debug, Clone)]
pub enum TlsLocation {
    /// TLS in main executable (static offset from thread pointer)
    MainExecutable { offset: usize },
    /// TLS in shared library (try static TLS first, then TLSDESC, then DTV)
    /// Resolution order:
    /// 1. Static TLS (using l_tls_offset from link_map) - fastest, for early-loaded libs
    /// 2. TLSDESC (from GOT entry) - medium, for libs using TLS descriptors
    /// 3. DTV lookup - slowest, for dlopen'd libraries
    SharedLibrary {
        module_id: usize,
        offset: usize,
        /// l_tls_offset from link_map - used for static TLS calculation
        tls_offset: usize,
        /// Optional TLSDESC info for DTV lookup when static TLS unavailable
        tlsdesc: Option<TlsDescInfo>,
    },
    /// TLS via static offset from thread pointer (legacy, prefer SharedLibrary)
    /// This is used when module_id is 0 but tls_offset is valid
    StaticTls { tls_offset: usize, symbol_offset: usize },
}

/// Information needed to resolve TLS via TLSDESC mechanism
#[derive(Debug, Clone)]
pub struct TlsDescInfo {
    /// Path to the library (needed to find base address)
    pub library_path: std::path::PathBuf,
    /// GOT entry offset within the library
    pub got_offset: usize,
    /// Symbol name (for logging)
    pub symbol_name: String,
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
        TlsLocation::SharedLibrary { module_id, offset, tls_offset, tlsdesc } => {
            // Try static TLS first (faster), then TLSDESC, finally DTV
            get_tls_for_shared_library(pid, thread_pointer, *module_id, *offset, *tls_offset, tlsdesc.as_ref())
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

/// Get TLS address for shared library using resolution order: static → TLSDESC → DTV.
///
/// Resolution order:
/// 1. Static TLS (using l_tls_offset from link_map) - fastest, for early-loaded libs
/// 2. TLSDESC (from GOT entry) - medium, for libs using TLS descriptors
/// 3. DTV lookup - slowest, for dlopen'd libraries
///
/// For validation purposes, all three methods are tried and their results compared.
fn get_tls_for_shared_library(
    pid: i32,
    thread_pointer: usize,
    module_id: usize,
    symbol_offset: usize,
    tls_offset: usize,  // l_tls_offset from link_map for static TLS
    tlsdesc: Option<&TlsDescInfo>,
) -> Result<usize> {
    let mut static_tls_addr: Option<usize> = None;
    let mut tlsdesc_addr: Option<usize> = None;
    let mut dtv_addr: Option<usize> = None;

    // Step 1: Try static TLS first (if tls_offset is valid)
    if is_valid_static_tls_offset(tls_offset) {
        match get_tls_via_static_with_tp(thread_pointer, tls_offset, symbol_offset) {
            Ok(addr) => {
                debug!(
                    "Static TLS calculation: tp={:#x} - tls_offset={:#x} + sym_offset={:#x} = {:#x}",
                    thread_pointer, tls_offset, symbol_offset, addr
                );
                static_tls_addr = Some(addr);
            }
            Err(e) => {
                debug!(
                    "Static TLS failed for module {}: {}",
                    module_id, e
                );
            }
        }
    } else {
        debug!("Static TLS not available (tls_offset={:#x})", tls_offset);
    }

    // Step 2: Try TLSDESC resolution (if available)
    if let Some(desc_info) = tlsdesc {
        match resolve_tlsdesc(pid, thread_pointer, desc_info) {
            Ok(addr) => {
                debug!(
                    "TLSDESC resolution succeeded for {}: address={:#x}",
                    desc_info.symbol_name, addr
                );
                tlsdesc_addr = Some(addr);
            }
            Err(e) => {
                debug!(
                    "TLSDESC resolution failed for {}: {}",
                    desc_info.symbol_name, e
                );
            }
        }
    }

    // Step 3: Try DTV lookup for validation (always try if we have module_id)
    if module_id > 0 {
        match get_tls_via_dtv_with_tp(pid, thread_pointer, module_id, symbol_offset) {
            Ok(addr) => {
                debug!(
                    "DTV lookup succeeded for module {}: address={:#x}",
                    module_id, addr
                );
                dtv_addr = Some(addr);
            }
            Err(e) => {
                debug!(
                    "DTV lookup failed for module {}: {}",
                    module_id, e
                );
            }
        }
    }

    // Step 4: Validate all three methods against each other
    validate_tls_methods(static_tls_addr, tlsdesc_addr, dtv_addr);

    // Return the first successful result (in order of preference: static, TLSDESC, DTV)
    if let Some(addr) = static_tls_addr {
        return Ok(addr);
    }

    if let Some(addr) = tlsdesc_addr {
        return Ok(addr);
    }

    if let Some(addr) = dtv_addr {
        return Ok(addr);
    }

    anyhow::bail!("All TLS resolution methods failed")
}

/// Validate and log agreement/mismatch between TLS resolution methods.
fn validate_tls_methods(
    static_tls: Option<usize>,
    tlsdesc: Option<usize>,
    dtv: Option<usize>,
) {
    // Count how many methods succeeded
    let count = [static_tls, tlsdesc, dtv].iter().filter(|x| x.is_some()).count();

    if count < 2 {
        // Nothing to compare
        return;
    }

    // Check if all available methods agree
    let all_match = match (static_tls, tlsdesc, dtv) {
        (Some(s), Some(t), Some(d)) => s == t && t == d,
        (Some(s), Some(t), None) => s == t,
        (Some(s), None, Some(d)) => s == d,
        (None, Some(t), Some(d)) => t == d,
        _ => true, // Only one or zero results
    };

    if all_match {
        match (static_tls, tlsdesc, dtv) {
            (Some(s), Some(t), Some(d)) => {
                debug!("VALIDATION: static TLS ({:#x}) == TLSDESC ({:#x}) == DTV ({:#x}) ✓", s, t, d);
            }
            (Some(s), Some(t), None) => {
                debug!("VALIDATION: static TLS ({:#x}) == TLSDESC ({:#x}) ✓", s, t);
            }
            (Some(s), None, Some(d)) => {
                debug!("VALIDATION: static TLS ({:#x}) == DTV ({:#x}) ✓", s, d);
            }
            (None, Some(t), Some(d)) => {
                debug!("VALIDATION: TLSDESC ({:#x}) == DTV ({:#x}) ✓", t, d);
            }
            _ => {}
        }
    } else {
        // Mismatch detected - this is important, keep at info level
        info!(
            "VALIDATION MISMATCH: static TLS={}, TLSDESC={}, DTV={}",
            static_tls.map(|a| format!("{:#x}", a)).unwrap_or_else(|| "N/A".to_string()),
            tlsdesc.map(|a| format!("{:#x}", a)).unwrap_or_else(|| "N/A".to_string()),
            dtv.map(|a| format!("{:#x}", a)).unwrap_or_else(|| "N/A".to_string()),
        );
    }
}

/// Resolve TLS address via TLSDESC mechanism.
///
/// TLSDESC (TLS Descriptor) is a GOT entry containing two pointer-sized values:
/// 1. Resolver function pointer
/// 2. Argument (for static TLSDESC, this is the offset from thread pointer)
///
/// For statically-linked TLS (libraries loaded at startup), the resolver is a
/// simple function that returns the argument directly. We can bypass calling the
/// resolver and use the argument as the thread-pointer offset.
///
/// For dynamically-linked TLS (dlopen'd libraries), the resolver allocates TLS
/// on first access, so TLSDESC won't give us a simple offset - it won't work.
fn resolve_tlsdesc(
    pid: i32,
    thread_pointer: usize,
    desc_info: &TlsDescInfo,
) -> Result<usize> {
    use super::elf_reader::find_library_base_address;

    // Step 1: Find library base address in target process
    let base_addr = find_library_base_address(pid, &desc_info.library_path)
        .context("Failed to find library base address for TLSDESC resolution")?;

    // Step 2: Calculate runtime address of GOT entry
    let got_runtime_addr = base_addr + desc_info.got_offset;

    debug!(
        "TLSDESC: reading GOT entry at {:#x} (base={:#x} + offset={:#x})",
        got_runtime_addr, base_addr, desc_info.got_offset
    );

    // Step 3: Read the TLSDESC GOT entry (two pointers)
    const POINTER_SIZE: usize = std::mem::size_of::<usize>();
    let mut resolver_bytes = [0u8; POINTER_SIZE];
    let mut argument_bytes = [0u8; POINTER_SIZE];

    read_memory(pid, got_runtime_addr, &mut resolver_bytes)
        .context("Failed to read TLSDESC resolver pointer")?;
    read_memory(pid, got_runtime_addr + POINTER_SIZE, &mut argument_bytes)
        .context("Failed to read TLSDESC argument")?;

    let resolver = usize::from_ne_bytes(resolver_bytes);
    let argument = usize::from_ne_bytes(argument_bytes);

    debug!(
        "TLSDESC GOT entry: resolver={:#x}, argument={:#x}",
        resolver, argument
    );

    // Step 4: Validate that this looks like a static TLSDESC
    // For static TLSDESC, the resolver should be a known function in ld.so
    // The argument should be a reasonable offset (not too large, not NULL for dynamic)
    if argument == 0 {
        anyhow::bail!(
            "TLSDESC argument is NULL - likely a dynamic TLSDESC (dlopen'd library)"
        );
    }

    // Check if argument looks like a valid TLS offset
    // For static TLSDESC on aarch64, argument is a positive offset from TP
    // For x86_64, it's typically a negative value (stored as unsigned, but represents negative offset)
    const MAX_REASONABLE_OFFSET: usize = 0x40000000; // 1GB

    // On x86_64, the argument might be a large value representing a negative offset
    #[cfg(target_arch = "x86_64")]
    let offset_valid = {
        // Check if it's a small positive or large negative (wrapping)
        argument <= MAX_REASONABLE_OFFSET || argument > (usize::MAX - MAX_REASONABLE_OFFSET)
    };

    #[cfg(target_arch = "aarch64")]
    let offset_valid = argument <= MAX_REASONABLE_OFFSET;

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let offset_valid = false;

    if !offset_valid {
        anyhow::bail!(
            "TLSDESC argument {:#x} doesn't look like a valid TLS offset",
            argument
        );
    }

    // Step 5: Calculate TLS address using the TLSDESC offset
    // The argument from TLSDESC is the offset to add to thread pointer
    // Note: This is different from l_tls_offset which is subtracted on x86_64
    #[cfg(target_arch = "x86_64")]
    let tls_addr = thread_pointer.wrapping_add(argument as usize);

    #[cfg(target_arch = "aarch64")]
    let tls_addr = thread_pointer.wrapping_add(argument);

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let tls_addr: usize = {
        anyhow::bail!("Unsupported architecture for TLSDESC resolution");
    };

    debug!(
        "TLSDESC resolved: tp={:#x} + arg={:#x} = {:#x}",
        thread_pointer, argument, tls_addr
    );

    Ok(tls_addr)
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

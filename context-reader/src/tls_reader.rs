use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::elf_reader::SymbolInfo;
use crate::label_parser::{self, CustomLabelsLabelSet, Label};

/// Result of reading labels from a single thread
#[derive(Debug, Clone)]
pub enum ThreadResult {
    /// Successfully read labels
    Found { tid: i32, labels: Vec<Label> },
    /// Thread had no labels or labelset pointer was null
    NotFound { tid: i32 },
    /// Error reading from this thread
    Error { tid: i32, error: String },
}

/// Read labels from all threads in a process
pub fn read_all_threads(pid: i32, symbol_info: &SymbolInfo) -> Result<Vec<ThreadResult>> {
    let tids = get_thread_ids(pid)?;
    let mut results = Vec::new();

    for tid in tids {
        match read_thread_labels(pid, tid, symbol_info) {
            Ok(labels) => {
                if labels.is_empty() {
                    results.push(ThreadResult::NotFound { tid });
                } else {
                    results.push(ThreadResult::Found { tid, labels });
                }
            }
            Err(e) => {
                results.push(ThreadResult::Error {
                    tid,
                    error: format!("{:#}", e),
                });
            }
        }
    }

    Ok(results)
}

/// Read labels from a single thread
fn read_thread_labels(pid: i32, tid: i32, symbol_info: &SymbolInfo) -> Result<Vec<Label>> {
    // Attach to the thread with ptrace
    let thread_pid = Pid::from_raw(tid);

    // Try to attach - this might fail if we don't have permissions
    ptrace::attach(thread_pid).context("Failed to attach with ptrace")?;

    // Wait for the thread to stop
    nix::sys::wait::waitpid(thread_pid, None).context("Failed to wait for thread")?;

    // Get the TLS address
    let result = (|| -> Result<Vec<Label>> {
        let tls_addr = get_tls_address(tid, symbol_info)?;

        // Read the pointer at the TLS location
        let mut ptr_bytes = [0u8; 8]; // 64-bit pointer
        read_memory(pid, tls_addr, &mut ptr_bytes)?;
        let labelset_ptr = usize::from_ne_bytes(ptr_bytes);

        // Null means no labelset attached to the thread
        if labelset_ptr == 0 {
            return Ok(Vec::new());
        }

        // Read the labelset structure
        let mut labelset_bytes = [0u8; std::mem::size_of::<CustomLabelsLabelSet>()];
        read_memory(pid, labelset_ptr, &mut labelset_bytes)?;

        let labelset = unsafe {
            std::ptr::read_unaligned(labelset_bytes.as_ptr() as *const CustomLabelsLabelSet)
        };

        // Parse the labels
        label_parser::parse_labels(pid, labelset)
    })();

    // Detach from thread, allowing it to resume once more.
    let _ = ptrace::detach(thread_pid, None);

    result
}

/// Get the TLS address for custom_labels_current_set
fn get_tls_address(tid: i32, symbol_info: &SymbolInfo) -> Result<usize> {
    // Get thread pointer register (FS_BASE on x86-64, TPIDR_EL0 on aarch64)
    let thread_pointer = get_fs_base(tid)?;
    let tls_offset = symbol_info.current_set_symbol.st_value as usize;

    // For now, we'll handle the main executable case
    if symbol_info.is_main_executable {
        // The TLS layout differs between architectures:
        //
        // x86-64 uses TLS variant II:
        //   - Thread pointer (fs_base) points to the thread control block (TCB)
        //   - TLS variables are at NEGATIVE offsets from the thread pointer
        //   - Formula: tls_addr = thread_pointer - tls_offset
        //
        // aarch64 uses TLS variant I:
        //   - Thread pointer (TPIDR_EL0) points to the Thread Control Block (TCB)
        //   - TCB is 16 bytes (2 pointers) on aarch64
        //   - TLS variables are located after the TCB
        //   - Formula: tls_addr = thread_pointer + TCB_SIZE + tls_offset

        #[cfg(target_arch = "x86_64")]
        let tls_addr = thread_pointer.wrapping_sub(tls_offset);

        #[cfg(target_arch = "aarch64")]
        let tls_addr = {
            const TCB_SIZE: usize = 16;
            thread_pointer
                .wrapping_add(TCB_SIZE)
                .wrapping_add(tls_offset)
        };

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let tls_addr = {
            anyhow::bail!("Unsupported architecture for TLS calculation");
        };

        Ok(tls_addr)
    } else {
        anyhow::bail!("TLS in shared libraries not implemented");
    }
}

///
/// Gets fs_base - the TL data offset - on an x86-64 machine.
///
#[cfg(target_arch = "x86_64")]
fn get_fs_base(tid: i32) -> Result<usize> {
    use nix::sys::ptrace;
    use nix::unistd::Pid;

    let thread_pid = Pid::from_raw(tid);

    // Use ptrace to get registers. fs is the segment register,
    // and it is used for TL storage.
    // fs_base is at offset 0x1f8 in the user struct on x86-64
    const FS_BASE_OFFSET: i64 = 0x1f8;

    let value = ptrace::read(thread_pid, FS_BASE_OFFSET as *mut _)
        .context("Failed to read fs_base register")?;

    Ok(value as usize)
}

///
/// gets fs_base on an arm64 machine.
///
#[cfg(target_arch = "aarch64")]
fn get_fs_base(tid: i32) -> Result<usize> {
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

/// Read memory from remote process
fn read_memory(pid: i32, addr: usize, buffer: &mut [u8]) -> Result<()> {
    use nix::sys::uio::{process_vm_readv, RemoteIoVec};
    use nix::unistd::Pid;
    use std::io::IoSliceMut;

    let remote = [RemoteIoVec {
        base: addr,
        len: buffer.len(),
    }];

    let mut local = [IoSliceMut::new(buffer)];

    let nread = process_vm_readv(Pid::from_raw(pid), &mut local, &remote)
        .context("Failed to read process memory")?;

    if nread != buffer.len() {
        anyhow::bail!("Short read: expected {} bytes, got {}", buffer.len(), nread);
    }

    Ok(())
}

/// Get all threads for the given process
fn get_thread_ids(pid: i32) -> Result<Vec<i32>> {
    let proc = procfs::process::Process::new(pid)?;
    let tasks = proc.tasks().context("Failed to read tasks")?;

    let mut tids = Vec::new();
    for task in tasks.flatten() {
        tids.push(task.tid);
    }

    Ok(tids)
}

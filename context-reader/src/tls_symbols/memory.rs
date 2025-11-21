///
/// Shared memory reading utilities for process introspection.
///
use anyhow::{Context, Result};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use std::io::IoSliceMut;

/// Read memory from a remote process using process_vm_readv
///
/// This is a low-level primitive used by various introspection modules.
/// It reads exactly `buffer.len()` bytes from the target process, or fails.
///
/// # Arguments
/// * `pid` - Process ID to read from
/// * `addr` - Memory address in the target process
/// * `buffer` - Buffer to read into
///
/// # Errors
/// Returns an error if:
/// - The process_vm_readv syscall fails (permission denied, invalid address, etc.)
/// - A short read occurs (fewer bytes read than requested)
pub fn read_memory(pid: i32, addr: usize, buffer: &mut [u8]) -> Result<()> {
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

#[cfg(target_os = "linux")]
use crate::encoding;
#[cfg(target_os = "linux")]
use crate::model::{Error, ProcessContext, Result, PROCESS_CTX_VERSION, SIGNATURE};

#[cfg(target_os = "linux")]
use std::ptr;
#[cfg(target_os = "linux")]
use std::sync::atomic::{fence, Ordering};
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::info;

#[cfg(target_os = "linux")]
use libc::{
    c_void, madvise, mmap, mprotect, munmap, prctl, sysconf, MADV_DONTFORK, MAP_ANONYMOUS,
    MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, _SC_PAGESIZE,
};

// prctl constants for naming anonymous mappings (Linux 5.17+)
#[cfg(target_os = "linux")]
const PR_SET_VMA: i32 = 0x53564d41;
#[cfg(target_os = "linux")]
const PR_SET_VMA_ANON_NAME: u64 = 0;

/// The header structure written at the start of the mapping.
/// This must match the C implementation exactly.
#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct MappingHeader {
    signature: [u8; 8],
    version: u32,
    payload_size: u32,
    published_at_ns: u64,
    payload_ptr: *const u8,
}

/// Get the mapping size (2 pages, as per C implementation)
#[cfg(target_os = "linux")]
fn mapping_size() -> Result<usize> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    if page_size < 4096 {
        return Err(Error::MappingFailed("failed to get page size".to_string()));
    }
    Ok((page_size as usize) * 2)
}

/// Get current time in nanoseconds since epoch
#[cfg(target_os = "linux")]
fn time_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Writer for publishing process context.
///
/// This creates an anonymous memory mapping that can be discovered by external
/// readers via `/proc/self/maps`. The mapping is named `[anon:OTEL_CTX]` on
/// kernels that support `PR_SET_VMA_ANON_NAME`.
///
/// # Safety
///
/// This is NOT thread-safe. Only one thread should publish/drop at a time.
#[cfg(target_os = "linux")]
pub struct ProcessContextWriter {
    mapping: *mut c_void,
    mapping_size: usize,
    payload: Vec<u8>,
    publisher_pid: libc::pid_t,
}

#[cfg(target_os = "linux")]
impl ProcessContextWriter {
    /// Publish a process context.
    ///
    /// This creates an anonymous memory mapping containing the encoded context.
    /// The mapping can be discovered by external readers via `/proc/self/maps`.
    ///
    /// # Safety
    ///
    /// This is NOT thread-safe!
    pub fn publish(ctx: &ProcessContext) -> Result<Self> {
        info!("Publishing process context");
        let size = mapping_size()?;

        // Encode the payload
        let payload = encoding::encode(ctx)?;
        info!(payload_size = payload.len(), "Encoded process context payload");

        // Create anonymous mapping
        let mapping = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mapping == MAP_FAILED {
            return Err(Error::MappingFailed("mmap failed".to_string()));
        }
        info!(mapping_addr = ?mapping, mapping_size = size, "Created anonymous mapping");

        // Set MADV_DONTFORK so children don't inherit this mapping
        if unsafe { madvise(mapping, size, MADV_DONTFORK) } == -1 {
            unsafe { munmap(mapping, size) };
            return Err(Error::MappingFailed("madvise MADV_DONTFORK failed".to_string()));
        }

        let published_at_ns = time_now_ns();
        if published_at_ns == 0 {
            unsafe { munmap(mapping, size) };
            return Err(Error::MappingFailed("failed to get current time".to_string()));
        }

        // Write the header (without signature first)
        let header = mapping as *mut MappingHeader;
        unsafe {
            (*header).signature = [0; 8]; // Will be set after fence
            (*header).version = PROCESS_CTX_VERSION;
            (*header).payload_size = payload.len() as u32;
            (*header).published_at_ns = published_at_ns;
            (*header).payload_ptr = payload.as_ptr();
        }

        // Memory fence to ensure header is written before signature
        fence(Ordering::SeqCst);

        // Now write the signature
        unsafe {
            ptr::copy_nonoverlapping(SIGNATURE.as_ptr(), (*header).signature.as_mut_ptr(), 8);
        }
        info!("Wrote header with signature OTEL_CTX");

        // Change mapping to read-only
        if unsafe { mprotect(mapping, size, PROT_READ) } == -1 {
            unsafe { munmap(mapping, size) };
            return Err(Error::MappingFailed("mprotect failed".to_string()));
        }
        info!("Changed mapping to read-only");

        // Try to name the mapping (optional, may fail on older kernels)
        let name = b"OTEL_CTX\0";
        let prctl_result = unsafe {
            prctl(
                PR_SET_VMA,
                PR_SET_VMA_ANON_NAME,
                mapping,
                size,
                name.as_ptr(),
            )
        };
        if prctl_result == 0 {
            info!("Named mapping [anon:OTEL_CTX]");
        } else {
            info!("Could not name mapping (older kernel), will be discoverable by signature");
        }

        info!("Process context published successfully");
        Ok(Self {
            mapping,
            mapping_size: size,
            payload,
            publisher_pid: unsafe { libc::getpid() },
        })
    }

    /// Drop/unpublish the current process context.
    ///
    /// This unmaps the memory and frees resources.
    pub fn drop_context(&mut self) -> Result<()> {
        if self.mapping.is_null() {
            return Ok(());
        }

        // Only unmap if we're in the same process that created it
        // (due to MADV_DONTFORK, children won't have this mapping anyway)
        let current_pid = unsafe { libc::getpid() };
        if current_pid == self.publisher_pid {
            if unsafe { munmap(self.mapping, self.mapping_size) } == -1 {
                return Err(Error::MappingFailed("munmap failed".to_string()));
            }
        }

        self.mapping = ptr::null_mut();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProcessContextWriter {
    fn drop(&mut self) {
        let _ = self.drop_context();
    }
}

// Non-Linux stub implementation
#[cfg(not(target_os = "linux"))]
use crate::model::{Error, ProcessContext, Result};

#[cfg(not(target_os = "linux"))]
pub struct ProcessContextWriter;

#[cfg(not(target_os = "linux"))]
impl ProcessContextWriter {
    pub fn publish(_ctx: &ProcessContext) -> Result<Self> {
        info!("Process context publishing not supported on this platform (Linux only)");
        Err(Error::PlatformNotSupported)
    }

    pub fn drop_context(&mut self) -> Result<()> {
        Err(Error::PlatformNotSupported)
    }
}

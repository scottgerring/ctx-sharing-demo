#[cfg(target_os = "linux")]
use super::encoding;
#[cfg(target_os = "linux")]
use super::model::{Error, ProcessContext, Result, PROCESS_CTX_VERSION, SIGNATURE};

#[cfg(target_os = "linux")]
use std::ptr;
#[cfg(target_os = "linux")]
use std::sync::atomic::{fence, Ordering};
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::info;

#[cfg(target_os = "linux")]
use libc::{
    c_void, close, ftruncate, madvise, mmap, munmap, prctl, sysconf, MADV_DONTFORK, MAP_ANONYMOUS,
    MAP_FAILED, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE, _SC_PAGESIZE,
};

// prctl constants for naming anonymous mappings (Linux 5.17+)
#[cfg(target_os = "linux")]
const PR_SET_VMA: i32 = 0x53564d41;
#[cfg(target_os = "linux")]
const PR_SET_VMA_ANON_NAME: u64 = 0;

// memfd_create flags
#[cfg(target_os = "linux")]
const MFD_CLOEXEC: libc::c_uint = 0x0001;
#[cfg(target_os = "linux")]
const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;
#[cfg(target_os = "linux")]
const MFD_NOEXEC_SEAL: libc::c_uint = 0x0008; // Linux 6.3+

/// Wrapper for memfd_create syscall
#[cfg(target_os = "linux")]
unsafe fn memfd_create(name: *const libc::c_char, flags: libc::c_uint) -> libc::c_int {
    libc::syscall(libc::SYS_memfd_create, name, flags) as libc::c_int
}

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

/// Get the mapping size (1 page, as per PR #34)
#[cfg(target_os = "linux")]
fn mapping_size() -> Result<usize> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    if page_size < 4096 {
        return Err(Error::MappingFailed("failed to get page size".to_string()));
    }
    Ok(page_size as usize)
}

/// Get current time in nanoseconds since epoch
#[cfg(target_os = "linux")]
fn time_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Result of create_mapping: the mapping pointer and optional memfd
#[cfg(target_os = "linux")]
struct MappingResult {
    mapping: *mut c_void,
    memfd: Option<i32>,
}

/// Create the memory mapping, trying memfd first, then falling back to anonymous.
#[cfg(target_os = "linux")]
fn create_mapping(size: usize) -> Result<MappingResult> {
    let memfd_name = b"OTEL_CTX\0";

    // Try memfd_create with MFD_NOEXEC_SEAL first (Linux 6.3+)
    let mut fd = unsafe {
        memfd_create(
            memfd_name.as_ptr() as *const libc::c_char,
            MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL,
        )
    };

    if fd < 0 {
        // Retry without MFD_NOEXEC_SEAL for older kernels
        fd = unsafe {
            memfd_create(
                memfd_name.as_ptr() as *const libc::c_char,
                MFD_CLOEXEC | MFD_ALLOW_SEALING,
            )
        };
    }

    if fd >= 0 {
        // Set the size of the memfd
        if unsafe { ftruncate(fd, size as libc::off_t) } == -1 {
            info!("ftruncate failed on memfd, falling back to anonymous mapping");
            unsafe { close(fd) };
        } else {
            // Map the memfd - use MAP_SHARED so it shows in /proc/pid/maps
            let mapping = unsafe {
                mmap(
                    ptr::null_mut(),
                    size,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    fd,
                    0,
                )
            };

            if mapping != MAP_FAILED {
                info!("Created memfd mapping (will appear as /memfd:OTEL_CTX in maps)");
                return Ok(MappingResult {
                    mapping,
                    memfd: Some(fd),
                });
            }

            // mmap failed, close fd and fall through to anonymous
            info!("mmap of memfd failed, falling back to anonymous mapping");
            unsafe { close(fd) };
        }
    } else {
        info!("memfd_create not available, using anonymous mapping");
    }

    // Fallback to anonymous mapping
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

    info!("Created anonymous mapping");
    Ok(MappingResult {
        mapping,
        memfd: None,
    })
}

/// Writer for publishing process context.
///
/// This creates a memory mapping that can be discovered by external readers
/// via `/proc/self/maps`. The implementation tries memfd first (which shows
/// as `/memfd:OTEL_CTX` in maps), falling back to anonymous mapping with
/// prctl naming (`[anon:OTEL_CTX]`).
///
/// The mapping stays writable to support in-place updates via `update()`.
///
/// # Safety
///
/// This is NOT thread-safe. Only one thread should publish/update/drop at a time.
#[cfg(target_os = "linux")]
pub struct ProcessContextWriter {
    mapping: *mut c_void,
    mapping_size: usize,
    payload: Vec<u8>,
    publisher_pid: libc::pid_t,
    memfd: Option<i32>,
}

#[cfg(target_os = "linux")]
impl ProcessContextWriter {
    /// Publish a process context.
    ///
    /// This creates a memory mapping containing the encoded context.
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

        // Create mapping (memfd preferred, fallback to anonymous)
        let MappingResult { mapping, memfd } = create_mapping(size)?;
        info!(mapping_addr = ?mapping, mapping_size = size, "Created mapping");

        // Set MADV_DONTFORK so children don't inherit this mapping
        if unsafe { madvise(mapping, size, MADV_DONTFORK) } == -1 {
            if let Some(fd) = memfd {
                unsafe { close(fd) };
            }
            unsafe { munmap(mapping, size) };
            return Err(Error::MappingFailed(
                "madvise MADV_DONTFORK failed".to_string(),
            ));
        }

        let published_at_ns = time_now_ns();
        if published_at_ns == 0 {
            if let Some(fd) = memfd {
                unsafe { close(fd) };
            }
            unsafe { munmap(mapping, size) };
            return Err(Error::MappingFailed(
                "failed to get current time".to_string(),
            ));
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

        // NOTE: We no longer make the mapping read-only (removed mprotect call)
        // This allows in-place updates via the update() method

        // For anonymous mappings, try to name it (optional, may fail on older kernels)
        // memfd mappings don't need this - the name shows in /proc/pid/maps automatically
        if memfd.is_none() {
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
        }

        info!("Process context published successfully");
        Ok(Self {
            mapping,
            mapping_size: size,
            payload,
            publisher_pid: unsafe { libc::getpid() },
            memfd,
        })
    }

    /// Update the process context in place.
    ///
    /// This uses the atomic update protocol from PR #34:
    /// 1. Zero `published_at_ns` to signal update in progress
    /// 2. Memory fence
    /// 3. Update payload pointer and size
    /// 4. Memory fence
    /// 5. Write new timestamp to signal completion
    ///
    /// Readers should check if `published_at_ns == 0` and retry/skip.
    ///
    /// # Safety
    ///
    /// This is NOT thread-safe within the same process.
    pub fn update(&mut self, ctx: &ProcessContext) -> Result<()> {
        info!("Updating process context in place");

        // Encode new payload
        let new_payload = encoding::encode(ctx)?;
        info!(payload_size = new_payload.len(), "Encoded new payload");

        let header = self.mapping as *mut MappingHeader;

        // Step 1: Zero published_at_ns to signal update in progress
        // Use raw pointer arithmetic to avoid taking reference to packed struct field
        unsafe {
            let published_at_ns_ptr = ptr::addr_of_mut!((*header).published_at_ns);
            ptr::write_volatile(published_at_ns_ptr, 0);
        }

        // Step 2: Memory fence
        fence(Ordering::SeqCst);

        // Step 3: Update payload - store new payload and update header
        self.payload = new_payload;
        unsafe {
            (*header).payload_ptr = self.payload.as_ptr();
            (*header).payload_size = self.payload.len() as u32;
        }

        // Step 4: Memory fence
        fence(Ordering::SeqCst);

        // Step 5: Write new timestamp to signal completion
        let published_at_ns = time_now_ns();
        if published_at_ns == 0 {
            return Err(Error::MappingFailed(
                "failed to get current time".to_string(),
            ));
        }
        unsafe {
            let published_at_ns_ptr = ptr::addr_of_mut!((*header).published_at_ns);
            ptr::write_volatile(published_at_ns_ptr, published_at_ns);
        }

        info!("Process context updated successfully");
        Ok(())
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

            // Close memfd if we have one
            if let Some(fd) = self.memfd.take() {
                unsafe { close(fd) };
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
use super::model::{Error, ProcessContext, Result};

#[cfg(not(target_os = "linux"))]
pub struct ProcessContextWriter;

#[cfg(not(target_os = "linux"))]
impl ProcessContextWriter {
    pub fn publish(_ctx: &ProcessContext) -> Result<Self> {
        info!("Process context publishing not supported on this platform (Linux only)");
        Err(Error::PlatformNotSupported)
    }

    pub fn update(&mut self, _ctx: &ProcessContext) -> Result<()> {
        Err(Error::PlatformNotSupported)
    }

    pub fn drop_context(&mut self) -> Result<()> {
        Err(Error::PlatformNotSupported)
    }
}

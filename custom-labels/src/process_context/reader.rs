#[cfg(target_os = "linux")]
use super::encoding;
#[cfg(target_os = "linux")]
use super::model::{Error, ProcessContext, Result, PROCESS_CTX_VERSION, SIGNATURE};

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};

#[cfg(target_os = "linux")]
use libc::sysconf;
#[cfg(target_os = "linux")]
use libc::_SC_PAGESIZE;

/// The header structure at the start of the mapping.
#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct MappingHeader {
    signature: [u8; 8],
    version: u32,
    payload_size: u32,
    published_at_ns: u64,
    payload_ptr: *const u8,
}

/// Get the page size
#[cfg(target_os = "linux")]
fn get_page_size() -> Option<usize> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    if page_size < 4096 {
        return None;
    }
    Some(page_size as usize)
}

/// Parse the start address from a /proc/self/maps line
#[cfg(target_os = "linux")]
fn parse_mapping_start(line: &str) -> Option<usize> {
    let addr_part = line.split('-').next()?;
    usize::from_str_radix(addr_part, 16).ok()
}

/// Parse start and end addresses from a /proc/self/maps line
#[cfg(target_os = "linux")]
fn parse_mapping_range(line: &str) -> Option<(usize, usize)> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let mut addrs = range.split('-');
    let start = usize::from_str_radix(addrs.next()?, 16).ok()?;
    let end = usize::from_str_radix(addrs.next()?, 16).ok()?;
    Some((start, end))
}

/// Check if a /proc/self/maps line is a potential OTEL_CTX mapping
///
/// Accepts both read-only (" r--p ") and read-write (" rw-p "/" rw-s ") permissions
/// for backwards compatibility (old writers used read-only, new writers use read-write).
/// memfd mappings use MAP_SHARED so they show as " rw-s ".
/// Also accepts both 1-page (new) and 2-page (old) mapping sizes.
#[cfg(target_os = "linux")]
fn is_otel_mapping_candidate(line: &str, page_size: usize) -> bool {
    // Accept read-only (old), read-write private (anon), and read-write shared (memfd)
    let has_valid_perms =
        line.contains(" r--p ") || line.contains(" rw-p ") || line.contains(" rw-s ");
    if !has_valid_perms {
        return false;
    }

    // Check size matches expected (accept both 1-page new and 2-page old mappings)
    if let Some((start, end)) = parse_mapping_range(line) {
        let size = end.saturating_sub(start);
        // Accept 1 page (new format) or 2 pages (old format)
        if size != page_size && size != page_size * 2 {
            return false;
        }
    } else {
        return false;
    }

    true
}

/// Check if a mapping line refers to the OTEL_CTX mapping by name
///
/// Handles both anonymous naming (`[anon:OTEL_CTX]`) and memfd naming
/// (`/memfd:OTEL_CTX` which may have ` (deleted)` suffix).
#[cfg(target_os = "linux")]
fn is_named_otel_mapping(line: &str) -> bool {
    let trimmed = line.trim_end();
    // Check for anonymous naming: [anon:OTEL_CTX] or [anon_shmem:OTEL_CTX]
    if trimmed.ends_with("[anon:OTEL_CTX]") || trimmed.ends_with("[anon_shmem:OTEL_CTX]") {
        return true;
    }
    // Check for memfd naming: /memfd:OTEL_CTX (possibly with " (deleted)" suffix)
    if trimmed.contains("/memfd:OTEL_CTX") || trimmed.contains("memfd:OTEL_CTX") {
        return true;
    }
    false
}

/// Check if a mapping line refers to the OTEL_CTX memfd mapping
#[cfg(target_os = "linux")]
fn is_memfd_otel_mapping(line: &str) -> bool {
    line.contains("/memfd:OTEL_CTX")
}

/// Read the signature from a memory address to verify it's an OTEL_CTX mapping
#[cfg(target_os = "linux")]
fn verify_signature_at(addr: usize) -> bool {
    let ptr = addr as *const [u8; 8];
    // Safety: We're reading from our own process memory at an address
    // we found in /proc/self/maps. This should be safe as long as the
    // mapping exists and has read permissions.
    let signature = unsafe { std::ptr::read_volatile(ptr) };
    signature == *SIGNATURE
}

/// Find the OTEL_CTX mapping in /proc/self/maps
#[cfg(target_os = "linux")]
fn find_otel_mapping() -> Result<usize> {
    let page_size =
        get_page_size().ok_or_else(|| Error::MappingFailed("failed to get page size".to_string()))?;

    let file = File::open("/proc/self/maps")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;

        if !is_otel_mapping_candidate(&line, page_size) {
            continue;
        }

        // First check if it's named
        if is_named_otel_mapping(&line) {
            if let Some(addr) = parse_mapping_start(&line) {
                return Ok(addr);
            }
        }

        // Check if it's a memfd mapping
        if is_memfd_otel_mapping(&line) {
            if let Some(addr) = parse_mapping_start(&line) {
                return Ok(addr);
            }
        }

        // For unnamed mappings, verify by reading the signature
        if let Some(addr) = parse_mapping_start(&line) {
            if verify_signature_at(addr) {
                return Ok(addr);
            }
        }
    }

    Err(Error::NotFound)
}

/// Read the process context from the current process.
///
/// This searches `/proc/self/maps` for an OTEL_CTX mapping and decodes its contents.
///
/// # Returns
///
/// Returns the decoded `ProcessContext` if found, or an error if:
/// - No OTEL_CTX mapping was found
/// - The mapping has an invalid signature or version
/// - An update is in progress (`published_at_ns == 0`)
/// - The payload failed to decode
#[cfg(target_os = "linux")]
pub fn read_process_context() -> Result<ProcessContext> {
    let mapping_addr = find_otel_mapping()?;
    let header_ptr = mapping_addr as *const MappingHeader;

    // Read and validate header
    // Safety: We found this address in /proc/self/maps and verified the signature
    let (signature, version, payload_size, published_at_ns, payload_ptr) = unsafe {
        let header = std::ptr::read_volatile(header_ptr);
        (
            header.signature,
            header.version,
            header.payload_size,
            header.published_at_ns,
            header.payload_ptr,
        )
    };

    // Validate signature
    if signature != *SIGNATURE {
        return Err(Error::DecodingFailed("invalid signature".to_string()));
    }

    // Check for update in progress (PR #34 protocol)
    if published_at_ns == 0 {
        return Err(Error::DecodingFailed("update in progress".to_string()));
    }

    // Validate version
    if version != PROCESS_CTX_VERSION {
        return Err(Error::DecodingFailed(format!(
            "unsupported version: {} (expected {})",
            version, PROCESS_CTX_VERSION
        )));
    }

    // Read the payload
    // Safety: The payload pointer was set by the writer in our process space
    let payload = unsafe { std::slice::from_raw_parts(payload_ptr, payload_size as usize) };

    // Decode the payload
    encoding::decode(payload)
}

/// Find the OTEL_CTX mapping in /proc/<pid>/maps for another process
#[cfg(target_os = "linux")]
fn find_otel_mapping_for_pid(pid: i32) -> Result<usize> {
    use tracing::{debug, info};

    let page_size =
        get_page_size().ok_or_else(|| Error::MappingFailed("failed to get page size".to_string()))?;

    debug!(pid = pid, page_size = page_size, "Searching for OTEL_CTX mapping");

    let maps_path = format!("/proc/{}/maps", pid);
    let file = File::open(&maps_path)?;
    let reader = BufReader::new(file);

    let mut candidates: Vec<(usize, String)> = Vec::new();

    for line in reader.lines() {
        let line = line?;

        if !is_otel_mapping_candidate(&line, page_size) {
            continue;
        }

        debug!(line = %line, "Found candidate mapping (right size + valid permissions)");

        // First check if it's named (memfd or anon)
        if is_named_otel_mapping(&line) {
            if let Some(addr) = parse_mapping_start(&line) {
                info!(addr = format!("0x{:x}", addr), "Found named OTEL_CTX mapping");
                return Ok(addr);
            }
        }

        // Check if it's a memfd mapping
        if is_memfd_otel_mapping(&line) {
            if let Some(addr) = parse_mapping_start(&line) {
                info!(addr = format!("0x{:x}", addr), "Found memfd OTEL_CTX mapping");
                return Ok(addr);
            }
        }

        // Collect unnamed anonymous mappings as candidates
        // Check if the line has no path (anonymous mapping)
        let parts: Vec<&str> = line.split_whitespace().collect();
        // /proc/pid/maps format: address perms offset dev inode [pathname]
        // Anonymous mappings have 5 fields (no pathname)
        // Skip special kernel mappings like [vvar], [vdso], [stack], [heap]
        let pathname = parts.get(5).copied().unwrap_or("");
        let is_special_kernel = pathname.starts_with('[') && !pathname.contains("anon:OTEL");
        let is_file_backed = !pathname.is_empty()
            && !pathname.starts_with('[')
            && !pathname.contains("memfd:OTEL");
        let is_true_anonymous = parts.len() <= 5 || pathname.is_empty();

        if is_special_kernel {
            debug!(pathname = pathname, "Skipping special kernel mapping");
            continue;
        }

        if is_file_backed {
            debug!(pathname = pathname, "Skipping file-backed mapping");
            continue;
        }

        if is_true_anonymous {
            if let Some(addr) = parse_mapping_start(&line) {
                debug!(addr = format!("0x{:x}", addr), "Found anonymous candidate");
                candidates.push((addr, line.clone()));
            }
        }
    }

    info!(count = candidates.len(), "Found anonymous mapping candidates");
    for (addr, line) in &candidates {
        debug!(addr = format!("0x{:x}", addr), line = %line, "Candidate mapping");
    }

    // Return first candidate - caller will verify signature
    if let Some((addr, _)) = candidates.first() {
        return Ok(*addr);
    }

    Err(Error::NotFound)
}

/// Read the process context from another process by PID.
///
/// This searches `/proc/<pid>/maps` for an OTEL_CTX mapping and reads its contents
/// using `process_vm_readv`.
///
/// # Returns
///
/// Returns the decoded `ProcessContext` if found, or an error if:
/// - No OTEL_CTX mapping was found
/// - Failed to read from the target process
/// - The mapping has an invalid signature or version
/// - An update is in progress (`published_at_ns == 0`)
/// - The payload failed to decode
#[cfg(target_os = "linux")]
pub fn read_process_context_from_pid(pid: i32) -> Result<ProcessContext> {
    use libc::{c_void, iovec, pid_t, process_vm_readv};
    use std::mem::size_of;

    let mapping_addr = find_otel_mapping_for_pid(pid)?;

    // Read the header from the remote process
    let mut header_buf = [0u8; size_of::<MappingHeader>()];
    let local_iov = iovec {
        iov_base: header_buf.as_mut_ptr() as *mut c_void,
        iov_len: header_buf.len(),
    };
    let remote_iov = iovec {
        iov_base: mapping_addr as *mut c_void,
        iov_len: header_buf.len(),
    };

    let nread = unsafe { process_vm_readv(pid as pid_t, &local_iov, 1, &remote_iov, 1, 0) };

    if nread < 0 {
        return Err(Error::MappingFailed(format!(
            "process_vm_readv failed for header: {}",
            std::io::Error::last_os_error()
        )));
    }

    if nread as usize != header_buf.len() {
        return Err(Error::MappingFailed(format!(
            "short read for header: {} of {}",
            nread,
            header_buf.len()
        )));
    }

    // Parse the header
    let signature: [u8; 8] = header_buf[0..8].try_into().unwrap();
    let version = u32::from_ne_bytes(header_buf[8..12].try_into().unwrap());
    let payload_size = u32::from_ne_bytes(header_buf[12..16].try_into().unwrap());
    let published_at_ns = u64::from_ne_bytes(header_buf[16..24].try_into().unwrap());
    let payload_ptr =
        usize::from_ne_bytes(header_buf[24..24 + size_of::<usize>()].try_into().unwrap());

    // Validate signature
    if signature != *SIGNATURE {
        return Err(Error::DecodingFailed("invalid signature".to_string()));
    }

    // Check for update in progress (PR #34 protocol)
    if published_at_ns == 0 {
        return Err(Error::DecodingFailed("update in progress".to_string()));
    }

    // Validate version
    if version != PROCESS_CTX_VERSION {
        return Err(Error::DecodingFailed(format!(
            "unsupported version: {} (expected {})",
            version, PROCESS_CTX_VERSION
        )));
    }

    // Read the payload from the remote process
    let mut payload_buf = vec![0u8; payload_size as usize];
    let local_iov = iovec {
        iov_base: payload_buf.as_mut_ptr() as *mut c_void,
        iov_len: payload_buf.len(),
    };
    let remote_iov = iovec {
        iov_base: payload_ptr as *mut c_void,
        iov_len: payload_buf.len(),
    };

    let nread = unsafe { process_vm_readv(pid as pid_t, &local_iov, 1, &remote_iov, 1, 0) };

    if nread < 0 {
        return Err(Error::MappingFailed(format!(
            "process_vm_readv failed for payload: {}",
            std::io::Error::last_os_error()
        )));
    }

    if nread as usize != payload_buf.len() {
        return Err(Error::MappingFailed(format!(
            "short read for payload: {} of {}",
            nread,
            payload_buf.len()
        )));
    }

    // Decode the payload
    encoding::decode(&payload_buf)
}

// Non-Linux stub implementations
#[cfg(not(target_os = "linux"))]
use super::model::{Error, ProcessContext, Result};

#[cfg(not(target_os = "linux"))]
pub fn read_process_context() -> Result<ProcessContext> {
    Err(Error::PlatformNotSupported)
}

#[cfg(not(target_os = "linux"))]
pub fn read_process_context_from_pid(_pid: i32) -> Result<ProcessContext> {
    Err(Error::PlatformNotSupported)
}

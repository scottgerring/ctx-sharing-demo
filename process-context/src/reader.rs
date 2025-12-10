#[cfg(target_os = "linux")]
use crate::encoding;
#[cfg(target_os = "linux")]
use crate::model::{Error, ProcessContext, Result, PROCESS_CTX_VERSION, SIGNATURE};

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

/// Get the expected mapping size (2 pages)
#[cfg(target_os = "linux")]
fn expected_mapping_size() -> Option<usize> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    if page_size < 4096 {
        return None;
    }
    Some((page_size as usize) * 2)
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
#[cfg(target_os = "linux")]
fn is_otel_mapping_candidate(line: &str, expected_size: usize) -> bool {
    // Must have read-only, private permissions
    if !line.contains(" r--p ") {
        return false;
    }

    // Check size matches expected
    if let Some((start, end)) = parse_mapping_range(line) {
        if end <= start || (end - start) != expected_size {
            return false;
        }
    } else {
        return false;
    }

    true
}

/// Check if a mapping line refers to the OTEL_CTX mapping by name
#[cfg(target_os = "linux")]
fn is_named_otel_mapping(line: &str) -> bool {
    line.trim_end().ends_with("[anon:OTEL_CTX]")
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
    let expected_size = expected_mapping_size()
        .ok_or_else(|| Error::MappingFailed("failed to get page size".to_string()))?;

    let file = File::open("/proc/self/maps")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;

        if !is_otel_mapping_candidate(&line, expected_size) {
            continue;
        }

        // First check if it's named
        if is_named_otel_mapping(&line) {
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
/// - The payload failed to decode
#[cfg(target_os = "linux")]
pub fn read_process_context() -> Result<ProcessContext> {
    let mapping_addr = find_otel_mapping()?;
    let header_ptr = mapping_addr as *const MappingHeader;

    // Read and validate header
    // Safety: We found this address in /proc/self/maps and verified the signature
    let (signature, version, payload_size, payload_ptr) = unsafe {
        let header = std::ptr::read_volatile(header_ptr);
        (
            header.signature,
            header.version,
            header.payload_size,
            header.payload_ptr,
        )
    };

    // Validate signature
    if signature != *SIGNATURE {
        return Err(Error::DecodingFailed("invalid signature".to_string()));
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
    let payload = unsafe {
        std::slice::from_raw_parts(payload_ptr, payload_size as usize)
    };

    // Decode the payload
    encoding::decode(payload)
}

// Non-Linux stub implementation
#[cfg(not(target_os = "linux"))]
use crate::model::{Error, ProcessContext, Result};

#[cfg(not(target_os = "linux"))]
pub fn read_process_context() -> Result<ProcessContext> {
    Err(Error::PlatformNotSupported)
}

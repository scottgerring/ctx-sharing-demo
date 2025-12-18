///
/// Generic dynamic linker introspection for Linux processes.
/// Provides link_map walking and module ID resolution independent of any
/// specific TLS variable or application logic.
/// 
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

use super::memory::read_memory;

/// Represents a loaded library in the target process
#[derive(Debug, Clone)]
pub struct LoadedLibrary {
    pub path: PathBuf,
    /// Base address where the library is loaded in memory
    /// Useful for future features like relative address calculations
    pub base_address: usize,
    /// TLS module ID assigned by the dynamic linker
    pub module_id: usize,
}

/// link_map structure from glibc (partial - only the fields we need)
/// See: glibc/include/link.h and glibc/sysdeps/generic/ldsodefs.h
///
/// The full structure is much larger, but we only read the initial fields
/// and then seek to l_tls_modid at a known offset.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LinkMap {
    l_addr: usize,    // Base address where object is loaded
    l_name: usize,    // Pointer to name string
    l_ld: usize,      // Pointer to dynamic section
    l_next: usize,    // Pointer to next link_map
    l_prev: usize,    // Pointer to previous link_map
}

/// r_debug structure from glibc
/// See: glibc/include/link.h
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RDebug {
    r_version: i32,   // Version number for this protocol
    r_map: usize,     // Pointer to link_map chain
    r_brk: usize,     // Address of r_brk function
    r_state: i32,     // RT_CONSISTENT, RT_ADD, or RT_DELETE
    r_ldbase: usize,  // Base address of ld.so
}

/// Find the address of the _r_debug symbol in the target process.
/// This symbol is defined by the dynamic linker (ld.so) and contains the link_map chain.
pub fn find_r_debug_address(pid: i32) -> Result<usize> {
    use goblin::elf::Elf;
    use procfs::process::{MMapPath, Process};

    let proc = Process::new(pid).context("Failed to open process")?;
    let maps = proc.maps().context("Failed to read memory maps")?;

    // Find the dynamic linker (ld.so) in the memory maps
    // It's usually named ld-linux-*.so.* or ld.so.*
    for map in maps.iter() {
        if let MMapPath::Path(ref path) = map.pathname {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filename.starts_with("ld-linux") || filename.starts_with("ld.so") {
                info!("Found dynamic linker: {:?}", path);

                // Read and parse the dynamic linker
                let buffer = std::fs::read(path).context("Failed to read dynamic linker")?;
                let elf = Elf::parse(&buffer).context("Failed to parse dynamic linker ELF")?;

                // Look for _r_debug in dynamic symbols
                for sym in elf.dynsyms.iter() {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if name == "_r_debug" {
                            info!("Found _r_debug symbol at offset: {:#x}", sym.st_value);

                            // ld.so is always ET_DYN, need to add base address
                            let base = map.address.0 as usize;
                            let addr = base + sym.st_value as usize;
                            info!("_r_debug address: {:#x} (base {:#x} + offset {:#x})", addr, base, sym.st_value);
                            return Ok(addr);
                        }
                    }
                }

                return Err(anyhow!("_r_debug symbol not found in dynamic linker {:?}", path));
            }
        }
    }

    Err(anyhow!("Dynamic linker (ld.so) not found in process memory maps"))
}

/// Walk the link_map chain starting from r_debug and return all loaded libraries
pub fn walk_link_map_chain(pid: i32, r_debug_addr: usize) -> Result<Vec<LoadedLibrary>> {
    // Read the r_debug structure
    let r_debug = read_r_debug(pid, r_debug_addr)?;

    debug!("r_debug version: {}, r_map: {:#x}", r_debug.r_version, r_debug.r_map);

    if r_debug.r_version != 1 {
        return Err(anyhow!("Unsupported r_debug version: {}", r_debug.r_version));
    }

    let mut libraries = Vec::new();
    let mut current_addr = r_debug.r_map;
    let mut position = 1; // Just for logging

    // Walk the linked list
    while current_addr != 0 {
        let link_map = read_link_map(pid, current_addr)?;

        // Read the actual l_tls_modid from the link_map structure
        let tls_modid = read_tls_modid(pid, current_addr)?;

        // Read the library name
        let name = if link_map.l_name != 0 {
            read_string_from_process(pid, link_map.l_name)?
        } else {
            String::new() // Main executable has empty name
        };

        debug!(
            "link_map[{}]: base={:#x}, l_tls_modid={}, name={:?}",
            position, link_map.l_addr, tls_modid, name
        );

        // Add to list if it has a name (skip main executable with empty name)
        // Only include libraries that have TLS (tls_modid > 0)
        if !name.is_empty() {
            libraries.push(LoadedLibrary {
                path: PathBuf::from(name),
                base_address: link_map.l_addr,
                module_id: tls_modid,
            });
        } else if position == 1 {
            // First entry is main executable
            use procfs::process::Process;
            let proc = Process::new(pid)?;
            let exe_path = proc.exe()?;
            libraries.push(LoadedLibrary {
                path: exe_path,
                base_address: link_map.l_addr,
                module_id: tls_modid,
            });
        }

        current_addr = link_map.l_next;
        position += 1;

        // Sanity check to avoid infinite loops
        if position > 10000 {
            return Err(anyhow!("Too many libraries in link_map chain (possible corruption)"));
        }
    }

    info!("Found {} loaded libraries", libraries.len());
    Ok(libraries)
}

/// Read a value from link_map that we can use to derive the DTV index.
///
/// The glibc link_map structure contains TLS-related fields we can use 
/// to find this.
/// 
/// The magic numbers in here were found from glibc 2.39 on aarch64, 
/// and also work on same glibc amd64.
/// 
/// There's got to be a more robust way of doing this!
///
fn read_tls_modid(pid: i32, link_map_addr: usize) -> Result<usize> {
    const TLS_FIELD_OFFSET: usize = 0x310;

    let field_addr = link_map_addr + TLS_FIELD_OFFSET;
    let mut buffer = [0u8; std::mem::size_of::<usize>()];
    read_memory(pid, field_addr, &mut buffer)?;
    let stored_value = usize::from_ne_bytes(buffer);

    // Empirically, we need to add 1 to get the correct DTV index
    let dtv_index = if stored_value > 0 { stored_value + 1 } else { 0 };

    debug!("link_map {:#x}: offset {:#x} value={}, dtv_index={}",
           link_map_addr, TLS_FIELD_OFFSET, stored_value, dtv_index);

    Ok(dtv_index)
}

/// Resolve the module ID for a specific library path
pub fn resolve_module_id(pid: i32, library_path: &Path) -> Result<usize> {
    let r_debug_addr = find_r_debug_address(pid)
        .context("Failed to find _r_debug address")?;
    let libraries = walk_link_map_chain(pid, r_debug_addr)
        .context("Failed to walk link_map chain")?;

    info!("Looking for library {:?} in {} loaded libraries", library_path, libraries.len());

    // Match by path - try exact match first
    for lib in &libraries {
        if lib.path == library_path {
            info!("Resolved module ID {} for {:?}", lib.module_id, library_path);
            return Ok(lib.module_id);
        }
    }

    // Try matching by filename only (for dlopen'd libraries that may have different paths)
    let target_filename = library_path.file_name();
    if let Some(target_name) = target_filename {
        for lib in &libraries {
            if lib.path.file_name() == Some(target_name) {
                info!("Resolved module ID {} for {:?} (matched by filename)", lib.module_id, library_path);
                return Ok(lib.module_id);
            }
        }
    }

    // Log all libraries for debugging
    info!("Libraries in link_map chain:");
    for lib in &libraries {
        info!("  module_id={}: {:?}", lib.module_id, lib.path);
    }

    Err(anyhow!("Library {:?} not found in link_map chain", library_path))
}

/// Read r_debug structure from process memory
fn read_r_debug(pid: i32, addr: usize) -> Result<RDebug> {
    let mut buffer = [0u8; std::mem::size_of::<RDebug>()];
    read_memory(pid, addr, &mut buffer)?;

    let r_debug = unsafe {
        std::ptr::read_unaligned(buffer.as_ptr() as *const RDebug)
    };

    Ok(r_debug)
}

/// Read link_map structure from process memory
fn read_link_map(pid: i32, addr: usize) -> Result<LinkMap> {
    let mut buffer = [0u8; std::mem::size_of::<LinkMap>()];
    read_memory(pid, addr, &mut buffer)?;

    let link_map = unsafe {
        std::ptr::read_unaligned(buffer.as_ptr() as *const LinkMap)
    };

    Ok(link_map)
}

/// Read a null-terminated string from process memory
fn read_string_from_process(pid: i32, addr: usize) -> Result<String> {
    let mut result = Vec::new();
    let mut current_addr = addr;
    let chunk_size = 256;

    loop {
        let mut buffer = vec![0u8; chunk_size];
        read_memory(pid, current_addr, &mut buffer)?;

        // Find null terminator
        if let Some(pos) = buffer.iter().position(|&b| b == 0) {
            result.extend_from_slice(&buffer[..pos]);
            break;
        } else {
            result.extend_from_slice(&buffer);
            current_addr += chunk_size;
        }

        // Sanity check
        if result.len() > 4096 {
            return Err(anyhow!("String too long (possible corruption)"));
        }
    }

    String::from_utf8(result).context("Invalid UTF-8 in library name")
}

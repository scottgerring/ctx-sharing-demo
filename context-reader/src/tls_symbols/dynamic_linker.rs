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

/// link_map structure from glibc
/// See: glibc/include/link.h
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
/// This symbol is defined by the dynamic linker and contains the link_map chain.
pub fn find_r_debug_address(pid: i32) -> Result<usize> {
    use goblin::elf::Elf;
    use procfs::process::Process;

    let proc = Process::new(pid).context("Failed to open process")?;
    let exe_path = proc.exe().context("Failed to get executable path")?;

    // Read and parse the main executable
    let buffer = std::fs::read(&exe_path).context("Failed to read executable")?;
    let elf = Elf::parse(&buffer).context("Failed to parse ELF")?;

    // Look for _r_debug in dynamic symbols
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "_r_debug" {
                info!("Found _r_debug symbol at offset: {:#x}", sym.st_value);

                // For ET_EXEC, address is absolute
                // For ET_DYN (PIE), we need to add base address
                if elf.header.e_type == goblin::elf::header::ET_DYN {
                    // Find base address from maps
                    let base = find_executable_base_address(pid, &exe_path)?;
                    return Ok(base + sym.st_value as usize);
                } else {
                    return Ok(sym.st_value as usize);
                }
            }
        }
    }

    Err(anyhow!("_r_debug symbol not found in executable"))
}

/// Find the base address of the main executable in memory
fn find_executable_base_address(pid: i32, exe_path: &Path) -> Result<usize> {
    use procfs::process::{MMapPath, Process};

    let proc = Process::new(pid)?;
    let maps = proc.maps()?;

    // Find the first mapping for this executable
    for map in maps {
        if let MMapPath::Path(ref path) = map.pathname {
            if path == exe_path {
                return Ok(map.address.0 as usize);
            }
        }
    }

    Err(anyhow!("Executable not found in memory maps"))
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
    let mut module_id = 1; // Module IDs start at 1

    // Walk the linked list
    while current_addr != 0 {
        let link_map = read_link_map(pid, current_addr)?;

        // Read the library name
        let name = if link_map.l_name != 0 {
            read_string_from_process(pid, link_map.l_name)?
        } else {
            String::new() // Main executable has empty name
        };

        debug!(
            "link_map[{}]: base={:#x}, name={:?}",
            module_id, link_map.l_addr, name
        );

        // Add to list if it has a name (skip main executable with empty name)
        if !name.is_empty() {
            libraries.push(LoadedLibrary {
                path: PathBuf::from(name),
                base_address: link_map.l_addr,
                module_id,
            });
        } else if module_id == 1 {
            // First entry is main executable
            use procfs::process::Process;
            let proc = Process::new(pid)?;
            let exe_path = proc.exe()?;
            libraries.push(LoadedLibrary {
                path: exe_path,
                base_address: link_map.l_addr,
                module_id,
            });
        }

        current_addr = link_map.l_next;
        module_id += 1;

        // Sanity check to avoid infinite loops
        if module_id > 10000 {
            return Err(anyhow!("Too many libraries in link_map chain (possible corruption)"));
        }
    }

    info!("Found {} loaded libraries", libraries.len());
    Ok(libraries)
}

/// Resolve the module ID for a specific library path
pub fn resolve_module_id(pid: i32, library_path: &Path) -> Result<usize> {
    let r_debug_addr = find_r_debug_address(pid)?;
    let libraries = walk_link_map_chain(pid, r_debug_addr)?;

    // Match by path
    for lib in libraries {
        if lib.path == library_path {
            info!("Resolved module ID {} for {:?}", lib.module_id, library_path);
            return Ok(lib.module_id);
        }
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

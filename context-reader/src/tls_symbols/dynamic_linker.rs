///
/// Generic dynamic linker introspection for Linux processes.
/// Provides link_map walking and module ID resolution independent of any
/// specific TLS variable or application logic.
/// 
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use tracing::debug;

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
    /// TLS offset from thread pointer (l_tls_offset for static TLS calculation)
    pub tls_offset: usize,
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

/// Cached offsets for link_map TLS fields.
/// These vary by glibc version and must be discovered at runtime.
#[derive(Debug, Clone, Copy)]
struct TlsFieldOffsets {
    l_tls_modid_offset: usize,
    l_tls_offset_offset: usize,
}

/// Discover link_map TLS field offsets from glibc's thread_db symbols.
///
/// The offsets of l_tls_modid and l_tls_offset within link_map vary by glibc version.
/// We read `_thread_db_link_map_l_tls_*` symbols from libc.so to get the correct offsets.
fn discover_tls_field_offsets() -> Result<TlsFieldOffsets> {
    use goblin::elf::Elf;
    use procfs::process::{MMapPath, Process};
    use std::fs;

    // Find libc.so from our own memory maps
    let proc = Process::myself().context("Failed to open /proc/self")?;
    let maps = proc.maps().context("Failed to read memory maps")?;

    let libc_path = maps
        .iter()
        .filter_map(|map| {
            if let MMapPath::Path(ref path) = map.pathname {
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if filename.starts_with("libc.so") || filename.starts_with("libc-") {
                    return Some(path.clone());
                }
            }
            None
        })
        .next()
        .ok_or_else(|| anyhow!("Could not find libc.so in /proc/self/maps"))?;

    debug!("Reading TLS field offsets from {:?}", libc_path);

    let buffer = fs::read(libc_path)
        .context("Failed to read libc.so")?;
    let elf = Elf::parse(&buffer)
        .context("Failed to parse libc.so ELF")?;

    // Find the symbols in dynamic symbol table
    let mut modid_sym_value: Option<u64> = None;
    let mut offset_sym_value: Option<u64> = None;

    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            match name {
                "_thread_db_link_map_l_tls_modid" => {
                    modid_sym_value = Some(sym.st_value);
                    debug!("Found _thread_db_link_map_l_tls_modid at offset {:#x}", sym.st_value);
                }
                "_thread_db_link_map_l_tls_offset" => {
                    offset_sym_value = Some(sym.st_value);
                    debug!("Found _thread_db_link_map_l_tls_offset at offset {:#x}", sym.st_value);
                }
                _ => {}
            }
        }
    }

    let modid_addr = modid_sym_value
        .ok_or_else(|| anyhow!("_thread_db_link_map_l_tls_modid symbol not found"))?;
    let offset_addr = offset_sym_value
        .ok_or_else(|| anyhow!("_thread_db_link_map_l_tls_offset symbol not found"))?;

    // Find the .rodata section to read the symbol data
    let rodata_section = elf.section_headers.iter()
        .find(|sh| {
            elf.shdr_strtab.get_at(sh.sh_name)
                .map(|name| name == ".rodata")
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!(".rodata section not found"))?;

    let rodata_offset = rodata_section.sh_offset as usize;
    let rodata_addr = rodata_section.sh_addr as usize;
    let rodata_size = rodata_section.sh_size as usize;

    // Symbol data is a 12-byte struct: { u32 indx, u32 num, u32 offset }
    // We want the offset field (byte offset of the TLS field in link_map)
    let read_offset_data = |sym_addr: u64| -> Result<usize> {
        let file_offset = rodata_offset + (sym_addr as usize - rodata_addr);
        if file_offset + 12 > rodata_offset + rodata_size {
            anyhow::bail!("Symbol data outside .rodata section");
        }

        // Read the 12-byte structure
        let data = &buffer[file_offset..file_offset + 12];
        let indx = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let num = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        debug!("  indx={}, num={}, offset={} ({:#x})", indx, num, offset, offset);
        Ok(offset as usize)
    };

    let l_tls_modid_offset = read_offset_data(modid_addr)
        .context("Failed to read l_tls_modid offset")?;
    let l_tls_offset_offset = read_offset_data(offset_addr)
        .context("Failed to read l_tls_offset offset")?;

    debug!(
        "Discovered TLS field offsets: l_tls_modid at {:#x}, l_tls_offset at {:#x}",
        l_tls_modid_offset, l_tls_offset_offset
    );

    Ok(TlsFieldOffsets {
        l_tls_modid_offset,
        l_tls_offset_offset,
    })
}

/// Get TLS field offsets, using cached values after first call.
///
/// This function ensures we only discover the offsets once per process execution,
/// caching them for subsequent calls.
fn get_tls_field_offsets() -> Result<TlsFieldOffsets> {
    use std::sync::OnceLock;

    static OFFSETS: OnceLock<TlsFieldOffsets> = OnceLock::new();

    // Try to get cached value first
    if let Some(offsets) = OFFSETS.get() {
        return Ok(*offsets);
    }

    // Discover offsets or use fallback
    let offsets = match discover_tls_field_offsets() {
        Ok(offsets) => offsets,
        Err(e) => {
            // Fall back to hardcoded defaults with a warning
            // These work for older glibc versions but may be incorrect for others
            #[cfg(target_arch = "x86_64")]
            let defaults = TlsFieldOffsets {
                l_tls_modid_offset: 0x490,  // glibc 2.31 default
                l_tls_offset_offset: 0x488,
            };

            #[cfg(target_arch = "aarch64")]
            let defaults = TlsFieldOffsets {
                l_tls_modid_offset: 0x498,
                l_tls_offset_offset: 0x490,
            };

            tracing::warn!(
                "Failed to discover TLS field offsets dynamically: {}. Using hardcoded defaults which may be incorrect for this glibc version.",
                e
            );

            defaults
        }
    };

    // Cache for next time (ignore error if another thread already set it)
    let _ = OFFSETS.set(offsets);

    Ok(offsets)
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
                debug!("Found dynamic linker: {:?}", path);

                // Read and parse the dynamic linker
                let buffer = std::fs::read(path).context("Failed to read dynamic linker")?;
                let elf = Elf::parse(&buffer).context("Failed to parse dynamic linker ELF")?;

                // Look for _r_debug in dynamic symbols
                for sym in elf.dynsyms.iter() {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if name == "_r_debug" {
                            debug!("Found _r_debug symbol at offset: {:#x}", sym.st_value);

                            // ld.so is always ET_DYN, need to add base address
                            let base = map.address.0 as usize;
                            let addr = base + sym.st_value as usize;
                            debug!("_r_debug address: {:#x} (base {:#x} + offset {:#x})", addr, base, sym.st_value);
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

        // Read l_tls_offset (used for static TLS calculation)
        let tls_offset = read_tls_offset(pid, current_addr)?;

        // Read the library name
        let name = if link_map.l_name != 0 {
            read_string_from_process(pid, link_map.l_name)?
        } else {
            String::new() // Main executable has empty name
        };

        debug!(
            "link_map[{}]: base={:#x}, l_tls_modid={}, l_tls_offset={:#x}, name={:?}",
            position, link_map.l_addr, tls_modid, tls_offset, name
        );

        // Add to list if it has a name (skip main executable with empty name)
        // Only include libraries that have TLS (tls_modid > 0)
        if !name.is_empty() {
            libraries.push(LoadedLibrary {
                path: PathBuf::from(name),
                base_address: link_map.l_addr,
                module_id: tls_modid,
                tls_offset,
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
                tls_offset,
            });
        }

        current_addr = link_map.l_next;
        position += 1;

        // Sanity check to avoid infinite loops
        if position > 10000 {
            return Err(anyhow!("Too many libraries in link_map chain (possible corruption)"));
        }
    }

    debug!("Found {} loaded libraries", libraries.len());
    Ok(libraries)
}

/// Read l_tls_modid from link_map structure (module ID for DTV indexing).
fn read_tls_modid(pid: i32, link_map_addr: usize) -> Result<usize> {
    let offsets = get_tls_field_offsets()?;
    let tls_modid_offset = offsets.l_tls_modid_offset;

    let field_addr = link_map_addr + tls_modid_offset;
    let mut buffer = [0u8; std::mem::size_of::<usize>()];
    read_memory(pid, field_addr, &mut buffer)?;
    let module_id = usize::from_ne_bytes(buffer);

    debug!("link_map {:#x}: l_tls_modid at offset {:#x} = {}",
           link_map_addr, tls_modid_offset, module_id);

    Ok(module_id)
}

/// Read l_tls_offset from link_map structure (offset from thread pointer for static TLS).
fn read_tls_offset(pid: i32, link_map_addr: usize) -> Result<usize> {
    let offsets = get_tls_field_offsets()?;

    let tls_offset_offset = offsets.l_tls_offset_offset;

    let field_addr = link_map_addr + tls_offset_offset;
    let mut buffer = [0u8; std::mem::size_of::<usize>()];
    read_memory(pid, field_addr, &mut buffer)?;
    let tls_offset = usize::from_ne_bytes(buffer);

    debug!("link_map {:#x}: l_tls_offset at offset {:#x} = {:#x}",
           link_map_addr, tls_offset_offset, tls_offset);

    Ok(tls_offset)
}

/// TLS resolution info for a library
#[derive(Debug, Clone)]
pub struct TlsResolution {
    pub module_id: usize,
    pub tls_offset: usize,
}

/// Resolve the module ID and TLS offset for a specific library path
pub fn resolve_tls_info(pid: i32, library_path: &Path) -> Result<TlsResolution> {
    let r_debug_addr = find_r_debug_address(pid)
        .context("Failed to find _r_debug address")?;
    let libraries = walk_link_map_chain(pid, r_debug_addr)
        .context("Failed to walk link_map chain")?;

    debug!("Looking for library {:?} in {} loaded libraries", library_path, libraries.len());

    // Match by path - try exact match first
    for lib in &libraries {
        if lib.path == library_path {
            debug!("Resolved TLS info for {:?}: module_id={}, tls_offset={:#x}",
                  library_path, lib.module_id, lib.tls_offset);
            return Ok(TlsResolution {
                module_id: lib.module_id,
                tls_offset: lib.tls_offset,
            });
        }
    }

    // Try matching by filename only (for dlopen'd libraries that may have different paths)
    let target_filename = library_path.file_name();
    if let Some(target_name) = target_filename {
        for lib in &libraries {
            if lib.path.file_name() == Some(target_name) {
                debug!("Resolved TLS info for {:?} (matched by filename): module_id={}, tls_offset={:#x}",
                      library_path, lib.module_id, lib.tls_offset);
                return Ok(TlsResolution {
                    module_id: lib.module_id,
                    tls_offset: lib.tls_offset,
                });
            }
        }
    }

    // Log all libraries for debugging
    debug!("Libraries in link_map chain:");
    for lib in &libraries {
        debug!("  module_id={}, tls_offset={:#x}: {:?}", lib.module_id, lib.tls_offset, lib.path);
    }

    Err(anyhow!("Library {:?} not found in link_map chain", library_path))
}

/// Resolve the module ID for a specific library path (legacy function)
pub fn resolve_module_id(pid: i32, library_path: &Path) -> Result<usize> {
    resolve_tls_info(pid, library_path).map(|info| info.module_id)
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

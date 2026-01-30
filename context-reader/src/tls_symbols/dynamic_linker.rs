///
/// Generic dynamic linker introspection for Linux processes.
/// Provides link_map walking and module ID resolution independent of any
/// specific TLS variable or application logic.
///
/// Supports both glibc and musl:
/// - glibc: Uses `_r_debug` → `r_map` → `link_map` chain with `l_tls_modid`
/// - musl: Uses `_dl_debug_addr` → `head` → `struct dso` chain with `tls_id`
///
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use tracing::debug;

use super::memory::read_memory;

/// Detected C library type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Libc {
    Glibc,
    Musl,
}

/// Detect whether the target process uses glibc or musl.
/// This is done by examining the dynamic linker in the process memory maps.
///
/// Detection strategies:
/// - glibc: dynamic linker named `ld-linux-*.so.*` or `ld.so.*`
/// - musl: dynamic linker named `ld-musl-*.so.*` OR path contains `-linux-musl/libc.so`
///   (Ubuntu's musl-tools resolves symlink to /usr/lib/aarch64-linux-musl/libc.so)
///
/// Note: This can't detect statically linked musl binaries (no dynamic linker visible),
/// but that probably doesn't matter since static musl binaries have no DSO chain to
/// walk anyway. If needed, we could try symbol scanning (musl exports `_dl_debug_addr`,
/// glibc exports `_r_debug`).
pub fn detect_libc(pid: i32) -> Result<Libc> {
    use procfs::process::{MMapPath, Process};

    debug!("Detecting libc type for process {}", pid);

    let proc = Process::new(pid).context("Failed to open process")?;
    let maps = proc.maps().context("Failed to read memory maps")?;

    for map in maps.iter() {
        if let MMapPath::Path(ref path) = map.pathname {
            let path_str = path.to_string_lossy();
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Check for musl dynamic linker
            // - Standard: ld-musl-aarch64.so.1, ld-musl-x86_64.so.1
            // - Ubuntu musl-tools: /usr/lib/aarch64-linux-musl/libc.so (resolved symlink)
            if filename.starts_with("ld-musl")
                || (path_str.contains("-linux-musl/") && filename == "libc.so")
            {
                debug!("Detected musl libc (found {:?})", path);
                return Ok(Libc::Musl);
            }

            // Check for glibc dynamic linker
            if filename.starts_with("ld-linux") || filename.starts_with("ld.so") {
                debug!("Detected glibc (found {})", filename);
                return Ok(Libc::Glibc);
            }
        }
    }

    Err(anyhow!("Could not detect libc type from process memory maps"))
}

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

/// Resolve the module ID and TLS offset for a specific library path.
/// Automatically detects glibc vs musl and uses the appropriate method.
pub fn resolve_tls_info(pid: i32, library_path: &Path) -> Result<TlsResolution> {
    match detect_libc(pid)? {
        Libc::Glibc => resolve_tls_info_glibc(pid, library_path),
        Libc::Musl => resolve_tls_info_musl(pid, library_path),
    }
}

/// Resolve TLS info using glibc's link_map chain
fn resolve_tls_info_glibc(pid: i32, library_path: &Path) -> Result<TlsResolution> {
    let r_debug_addr = find_r_debug_address(pid)
        .context("Failed to find _r_debug address")?;
    let libraries = walk_link_map_chain(pid, r_debug_addr)
        .context("Failed to walk link_map chain")?;

    find_library_in_list(&libraries, library_path)
}

/// Find a library in the loaded libraries list by path
fn find_library_in_list(libraries: &[LoadedLibrary], library_path: &Path) -> Result<TlsResolution> {
    debug!("Looking for library {:?} in {} loaded libraries", library_path, libraries.len());

    // Match by path - try exact match first
    for lib in libraries {
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
        for lib in libraries {
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
    debug!("Libraries in loaded list:");
    for lib in libraries {
        debug!("  module_id={}, tls_offset={:#x}: {:?}", lib.module_id, lib.tls_offset, lib.path);
    }

    Err(anyhow!("Library {:?} not found in loaded libraries", library_path))
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

// ============================================================================
// musl-specific implementation
// ============================================================================

/// musl's debug structure (from ldso/dynlink.c).
/// musl exports `_dl_debug_addr` which points to this struct containing
/// the head of the DSO (Dynamic Shared Object) chain.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MuslDebug {
    ver: i32,
    _pad: i32,
    head: usize,    // struct dso *
    bp: usize,      // void (*bp)(void)
    state: i32,
    _pad2: i32,
    base: usize,
}

/// Header fields from musl's struct dso (from ldso/dynlink.c).
/// We only read the initial fields needed for chain walking; tls_id is read
/// separately at MUSL_DSO_TLS_ID_OFFSET since its position varies by version.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MuslDsoHeader {
    base: usize,    // unsigned char *base
    name: usize,    // char *name
    dynv: usize,    // size_t *dynv
    next: usize,    // struct dso *next
    prev: usize,    // struct dso *prev
}

/// Offset of tls_id field in musl's struct dso.
///
/// Unlike glibc, which exports `_thread_db_link_map_l_tls_*` symbols for dynamic
/// offset discovery, musl treats struct dso as an internal implementation detail
/// and provides no introspection mechanism (musl intentionally doesn't implement
/// libthread_db: https://inbox.vuxu.org/musl/20220210213219.GF7074@brightrain.aerifal.cx/).
/// musl's suggested alternative is to call `__tls_get_addr()` in the target, but
/// this isn't possible from eBPF. We're stuck with hardcoded offsets here - would
/// be happy to be wrong!
///
/// These offsets were determined empirically for musl 1.2.x and may need
/// adjustment for other versions.
#[cfg(target_arch = "aarch64")]
const MUSL_DSO_TLS_ID_OFFSET: usize = 0xc0;

#[cfg(target_arch = "x86_64")]
const MUSL_DSO_TLS_ID_OFFSET: usize = 0xc0;

/// Find the address of musl's _dl_debug_addr symbol in the target process.
/// musl's dynamic linker can be:
/// - Standard: ld-musl-*.so.1
/// - Ubuntu musl-tools: /usr/lib/aarch64-linux-musl/libc.so (resolved symlink)
pub fn find_musl_debug_address(pid: i32) -> Result<usize> {
    use goblin::elf::Elf;
    use procfs::process::{MMapPath, Process};

    let proc = Process::new(pid).context("Failed to open process")?;
    let maps = proc.maps().context("Failed to read memory maps")?;

    // Find musl's dynamic linker in the memory maps
    for map in maps.iter() {
        if let MMapPath::Path(ref path) = map.pathname {
            let path_str = path.to_string_lossy();
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Match musl dynamic linker paths
            let is_musl_linker = filename.starts_with("ld-musl")
                || (path_str.contains("-linux-musl/") && filename == "libc.so");

            if is_musl_linker {
                debug!("Found musl dynamic linker: {:?}", path);

                // Read and parse the dynamic linker
                let buffer = std::fs::read(path).context("Failed to read musl dynamic linker")?;
                let elf = Elf::parse(&buffer).context("Failed to parse musl dynamic linker ELF")?;

                // Look for _dl_debug_addr in dynamic symbols
                for sym in elf.dynsyms.iter() {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if name == "_dl_debug_addr" {
                            debug!("Found _dl_debug_addr symbol at offset: {:#x}", sym.st_value);

                            // ld-musl is ET_DYN, need to add base address
                            let base = map.address.0 as usize;
                            let addr = base + sym.st_value as usize;
                            debug!("_dl_debug_addr address: {:#x} (base {:#x} + offset {:#x})", addr, base, sym.st_value);
                            return Ok(addr);
                        }
                    }
                }

                return Err(anyhow!("_dl_debug_addr symbol not found in musl dynamic linker {:?}", path));
            }
        }
    }

    Err(anyhow!("musl dynamic linker not found in process memory maps"))
}

/// Walk musl's DSO chain and return all loaded libraries
pub fn walk_musl_dso_chain(pid: i32, debug_addr: usize) -> Result<Vec<LoadedLibrary>> {
    // _dl_debug_addr is a pointer to struct debug, so we need to read it first
    let mut ptr_buffer = [0u8; std::mem::size_of::<usize>()];
    read_memory(pid, debug_addr, &mut ptr_buffer)?;
    let debug_struct_addr = usize::from_ne_bytes(ptr_buffer);

    debug!("musl _dl_debug_addr points to debug struct at {:#x}", debug_struct_addr);

    // Read the debug structure
    let musl_debug = read_musl_debug(pid, debug_struct_addr)?;
    debug!("musl debug: ver={}, head={:#x}, state={}", musl_debug.ver, musl_debug.head, musl_debug.state);

    let mut libraries = Vec::new();
    let mut current_addr = musl_debug.head;
    let mut position = 1;

    // Walk the linked list
    while current_addr != 0 {
        let dso_header = read_musl_dso_header(pid, current_addr)?;

        // Read tls_id from the DSO structure
        let tls_id = read_musl_tls_id(pid, current_addr)?;

        debug!(
            "musl dso_header: base={:#x}, name_ptr={:#x}, next={:#x}",
            dso_header.base, dso_header.name, dso_header.next
        );

        // Read the library name
        let name = if dso_header.name != 0 {
            match read_string_from_process(pid, dso_header.name) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to read DSO name from {:#x}: {}", dso_header.name, e);
                    String::from("<error reading name>")
                }
            }
        } else {
            String::new()
        };

        debug!(
            "musl dso[{}]: base={:#x}, tls_id={}, next={:#x}, name={:?}",
            position, dso_header.base, tls_id, dso_header.next, name
        );

        // Add to list
        if !name.is_empty() {
            libraries.push(LoadedLibrary {
                path: PathBuf::from(&name),
                base_address: dso_header.base,
                module_id: tls_id,
                tls_offset: 0, // musl doesn't expose l_tls_offset equivalent
            });
        } else if position == 1 {
            // First entry is main executable
            use procfs::process::Process;
            let proc = Process::new(pid)?;
            let exe_path = proc.exe()?;
            libraries.push(LoadedLibrary {
                path: exe_path,
                base_address: dso_header.base,
                module_id: tls_id,
                tls_offset: 0,
            });
        }

        current_addr = dso_header.next;
        position += 1;

        // Sanity check
        if position > 10000 {
            return Err(anyhow!("Suspiciously large number of DSOs in musl chain; giving up"));
        }
    }

    debug!("Found {} loaded libraries (musl)", libraries.len());
    Ok(libraries)
}

/// Read musl's debug structure from process memory
fn read_musl_debug(pid: i32, addr: usize) -> Result<MuslDebug> {
    let mut buffer = [0u8; std::mem::size_of::<MuslDebug>()];
    read_memory(pid, addr, &mut buffer)?;

    let debug = unsafe {
        std::ptr::read_unaligned(buffer.as_ptr() as *const MuslDebug)
    };

    Ok(debug)
}

/// Read musl's dso header from process memory
fn read_musl_dso_header(pid: i32, addr: usize) -> Result<MuslDsoHeader> {
    let mut buffer = [0u8; std::mem::size_of::<MuslDsoHeader>()];
    read_memory(pid, addr, &mut buffer)?;

    let dso = unsafe {
        std::ptr::read_unaligned(buffer.as_ptr() as *const MuslDsoHeader)
    };

    Ok(dso)
}

/// Read tls_id from musl's struct dso
fn read_musl_tls_id(pid: i32, dso_addr: usize) -> Result<usize> {
    let field_addr = dso_addr + MUSL_DSO_TLS_ID_OFFSET;
    let mut buffer = [0u8; std::mem::size_of::<usize>()];
    read_memory(pid, field_addr, &mut buffer)?;
    let tls_id = usize::from_ne_bytes(buffer);

    debug!("musl dso {:#x}: tls_id at offset {:#x} = {}",
           dso_addr, MUSL_DSO_TLS_ID_OFFSET, tls_id);

    Ok(tls_id)
}

/// Resolve TLS info using musl's DSO chain
fn resolve_tls_info_musl(pid: i32, library_path: &Path) -> Result<TlsResolution> {
    let debug_addr = find_musl_debug_address(pid)
        .context("Failed to find musl _dl_debug_addr")?;
    let libraries = walk_musl_dso_chain(pid, debug_addr)
        .context("Failed to walk musl DSO chain")?;

    find_library_in_list(&libraries, library_path)
}

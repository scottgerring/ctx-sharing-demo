use anyhow::{anyhow, Context, Result};
use goblin::elf::{Elf, Sym};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::debug;

// TLSDESC relocation types by architecture
#[cfg(target_arch = "x86_64")]
const R_TLS_DESC: u32 = 36; // R_X86_64_TLSDESC

#[cfg(target_arch = "aarch64")]
const R_TLS_DESC: u32 = 1031; // R_AARCH64_TLSDESC

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const R_TLS_DESC: u32 = 0; // Unsupported

/// Information about a symbol and where it was found
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    pub sym: Sym,
    pub is_dynamic: bool, // true if from dynsyms (exported), false if from syms (debug/internal)
}

/// Information about symbols found in a binary
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub symbols: HashMap<String, SymbolEntry>,
    pub is_main_executable: bool,
    pub tls_block_size: Option<usize>, // Size of TLS block from PT_TLS (for static TLS)
}

/// Find all TLS and TLS-related data symbols in an ELF binary at the given path.
/// Returns information about which symbols were found and whether they were found
/// in the executable itself, or in a shared library. This affects how we look them
/// up later.
///
/// This returns:
/// - All TLS symbols (type STT_TLS) - thread-local variables
/// - All OBJECT symbols (type STT_OBJECT) - global constants/variables
///
/// This combination allows finding TLS functionality that includes both thread-local
/// storage and associated metadata/constants (like ABI version fields).
pub fn find_symbols_in_binary(path: &Path) -> Result<SymbolInfo> {
    let buffer = fs::read(path).context("Failed to read binary")?;
    let elf = Elf::parse(&buffer).context("Failed to parse ELF")?;

    // Find all TLS and OBJECT symbols (data symbols)
    let mut symbols = HashMap::new();

    // Check dynamic symbols (exported)
    for sym in elf.dynsyms.iter() {
        let sym_type = sym.st_type();
        if sym_type == goblin::elf::sym::STT_TLS || sym_type == goblin::elf::sym::STT_OBJECT {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                debug!("Found {} symbol {} in dynsyms",
                    if sym_type == goblin::elf::sym::STT_TLS { "TLS" } else { "OBJECT" },
                    name);
                symbols.insert(name.to_string(), SymbolEntry {
                    sym,
                    is_dynamic: true,
                });
            }
        }
    }

    // Check regular symbols (debug/internal) - only if not already found in dynsyms
    for sym in elf.syms.iter() {
        let sym_type = sym.st_type();
        if sym_type == goblin::elf::sym::STT_TLS || sym_type == goblin::elf::sym::STT_OBJECT {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                // Only add if not already present from dynsyms
                symbols.entry(name.to_string()).or_insert_with(|| {
                    debug!("Found {} symbol {} in syms",
                        if sym_type == goblin::elf::sym::STT_TLS { "TLS" } else { "OBJECT" },
                        name);
                    SymbolEntry {
                        sym,
                        is_dynamic: false,
                    }
                });
            }
        }
    }

    // Determine if this is definitely the main executable
    // ET_EXEC = traditional non-PIE executable (definitely main executable)
    // ET_DYN = could be either a PIE executable OR a shared library
    // For ET_DYN, we default to false (shared library) and let the caller
    // determine if this is actually the main executable by checking /proc/pid/exe
    let is_main_executable = elf.header.e_type == goblin::elf::header::ET_EXEC;

    // Find PT_TLS program header to get TLS block size (needed for static TLS offset calculation)
    let tls_block_size = elf.program_headers.iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_TLS)
        .map(|ph| ph.p_memsz as usize);

    if let Some(size) = tls_block_size {
        debug!("Found PT_TLS header: memsz={:#x} ({})", size, size);
    }

    Ok(SymbolInfo {
        symbols,
        is_main_executable,
        tls_block_size,
    })
}

#[cfg(test)]
mod test {
    use std::path::Path;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    use super::find_symbols_in_binary;

    // Test symbol extraction from an ELF binary
    #[test]
    #[ignore]
    pub fn extract_symbols() -> anyhow::Result<()> {
        tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true),
            )
            .init();

        let result = find_symbols_in_binary(Path::new("../test-data/async-web"))?;
        println!("Found {} TLS/OBJECT symbols", result.symbols.len());

        // Verify we found the expected custom labels symbols
        // custom_labels_current_set is TLS
        let current_set = result.symbols.get("custom_labels_current_set");
        assert!(current_set.is_some(), "Should find custom_labels_current_set (TLS)");
        println!("custom_labels_current_set is_dynamic: {}", current_set.unwrap().is_dynamic);

        // custom_labels_abi_version is OBJECT
        let abi_version = result.symbols.get("custom_labels_abi_version");
        assert!(abi_version.is_some(), "Should find custom_labels_abi_version (OBJECT)");
        println!("custom_labels_abi_version is_dynamic: {}", abi_version.unwrap().is_dynamic);

        Ok(())
    }

    // Test symbol extraction from a library with LOCAL TLS symbols (not exported)
    #[test]
    #[ignore]
    pub fn extract_local_tls_symbols() -> anyhow::Result<()> {
        tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true),
            )
            .init();

        let result = find_symbols_in_binary(Path::new("bins/libjavaProfiler.so"))?;
        println!("Found {} TLS/OBJECT symbols in libjavaProfiler.so", result.symbols.len());

        // Print all symbols found
        for (name, entry) in &result.symbols {
            println!("Symbol: {} (is_dynamic: {}, st_type: {})",
                name, entry.is_dynamic, entry.sym.st_type());
        }

        // Should find at least some TLS symbols (they're all LOCAL in this library)
        assert!(result.symbols.len() > 0, "Should find at least some TLS/OBJECT symbols");

        // Check for specific known symbols from the readelf output
        // These are LOCAL TLS symbols that should be found in the regular symbol table
        let has_tls = result.symbols.iter().any(|(_, entry)| {
            entry.sym.st_type() == goblin::elf::sym::STT_TLS
        });
        assert!(has_tls, "Should find at least one TLS symbol");

        println!("Successfully found LOCAL TLS symbols from regular symbol table");
        Ok(())
    }
}

/// Information about a TLSDESC relocation for a TLS symbol
#[derive(Debug, Clone)]
pub struct TlsDescRelocation {
    /// Address in GOT where the TLSDESC entry is stored (file offset, not runtime address)
    pub got_offset: usize,
    /// Symbol index this relocation refers to
    pub symbol_index: usize,
    /// Addend for the relocation (usually the symbol's TLS offset)
    pub addend: i64,
}

/// Find TLSDESC relocation for a specific TLS symbol in an ELF binary.
///
/// TLSDESC (TLS Descriptor) is a TLS access model where:
/// - The GOT contains a descriptor: {resolver_function, argument}
/// - For statically-linked TLS, the argument is the offset from thread pointer
/// - For dynamically-linked TLS (dlopen), the resolver allocates TLS on first access
///
/// This function finds the GOT entry offset for a given symbol so we can read
/// the resolved descriptor from the target process at runtime.
pub fn find_tlsdesc_relocation(path: &Path, symbol_name: &str) -> Result<Option<TlsDescRelocation>> {
    let buffer = fs::read(path).context("Failed to read binary")?;
    let elf = Elf::parse(&buffer).context("Failed to parse ELF")?;

    // First, find the symbol index for our symbol in dynsyms
    let symbol_index = elf.dynsyms.iter()
        .position(|sym| {
            elf.dynstrtab.get_at(sym.st_name)
                .map(|name| name == symbol_name)
                .unwrap_or(false)
        });

    let symbol_index = match symbol_index {
        Some(idx) => idx,
        None => {
            debug!("Symbol {} not found in dynsyms, cannot find TLSDESC relocation", symbol_name);
            return Ok(None);
        }
    };

    debug!("Looking for TLSDESC relocation for symbol {} (dynsym index {})",
           symbol_name, symbol_index);

    // Search through all relocation sections
    // goblin provides pltrelocs and dynrels

    // Check PLT relocations (used by some TLSDESC implementations)
    for reloc in elf.pltrelocs.iter() {
        if reloc.r_type == R_TLS_DESC && reloc.r_sym == symbol_index {
            debug!("Found TLSDESC in PLT relocs: offset={:#x}, sym={}, addend={}",
                   reloc.r_offset, reloc.r_sym, reloc.r_addend.unwrap_or(0));
            return Ok(Some(TlsDescRelocation {
                got_offset: reloc.r_offset as usize,
                symbol_index: reloc.r_sym,
                addend: reloc.r_addend.unwrap_or(0),
            }));
        }
    }

    // Check dynamic relocations
    for reloc in elf.dynrels.iter() {
        if reloc.r_type == R_TLS_DESC && reloc.r_sym == symbol_index {
            debug!("Found TLSDESC in dynamic relocs: offset={:#x}, sym={}, addend={}",
                   reloc.r_offset, reloc.r_sym, reloc.r_addend.unwrap_or(0));
            return Ok(Some(TlsDescRelocation {
                got_offset: reloc.r_offset as usize,
                symbol_index: reloc.r_sym,
                addend: reloc.r_addend.unwrap_or(0),
            }));
        }
    }

    // Also check shdr_relocs if available
    for (_, relocs) in elf.shdr_relocs.iter() {
        for reloc in relocs.iter() {
            if reloc.r_type == R_TLS_DESC && reloc.r_sym == symbol_index {
                debug!("Found TLSDESC in section relocs: offset={:#x}, sym={}, addend={}",
                       reloc.r_offset, reloc.r_sym, reloc.r_addend.unwrap_or(0));
                return Ok(Some(TlsDescRelocation {
                    got_offset: reloc.r_offset as usize,
                    symbol_index: reloc.r_sym,
                    addend: reloc.r_addend.unwrap_or(0),
                }));
            }
        }
    }

    debug!("No TLSDESC relocation found for symbol {}", symbol_name);
    Ok(None)
}

/// Find the base address where a library is loaded in a target process.
/// This is needed to convert file offsets (like GOT entry offsets) to runtime addresses.
#[cfg(target_os = "linux")]
pub fn find_library_base_address(pid: i32, library_path: &Path) -> Result<usize> {
    use procfs::process::{MMapPath, Process};

    let proc = Process::new(pid).context("Failed to open process")?;
    let maps = proc.maps().context("Failed to read memory maps")?;

    let lib_filename = library_path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid library path"))?;

    // Find the first mapping for this library (should be the base)
    for map in maps.iter() {
        if let MMapPath::Path(ref path) = map.pathname {
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename == lib_filename || path == library_path {
                    debug!("Found {} loaded at base {:#x}", lib_filename, map.address.0);
                    return Ok(map.address.0 as usize);
                }
            }
        }
    }

    Err(anyhow!("Library {} not found in process maps", lib_filename))
}

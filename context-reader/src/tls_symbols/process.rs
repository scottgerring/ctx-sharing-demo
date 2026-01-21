use anyhow::{bail, Context, Result};
use procfs::process::{MMapPath, Process};
use std::path::PathBuf;
use tracing::{debug, info};

use super::dynamic_linker;
use super::elf_reader::{find_tlsdesc_relocation, resolve_tlsdesc_offset, SymbolInfo};
use super::tls_accessor::{TlsDescInfo, TlsLocation};

/// Check if a tls_offset value is valid for static TLS calculation.
/// Set FORCE_DTV=1 to force DTV lookup (for testing).
fn is_valid_static_tls_offset(tls_offset: usize) -> bool {
    // Allow forcing DTV path for testing
    if std::env::var("FORCE_DTV").is_ok() {
        return false;
    }
    const MAX_REASONABLE_TLS_OFFSET: usize = 0x40000000; // 1GB
    tls_offset != 0 && tls_offset != usize::MAX && tls_offset <= MAX_REASONABLE_TLS_OFFSET
}

/// Information about a TLS symbol found in a loaded binary (executable or shared library)
#[derive(Debug, Clone)]
pub struct LoadedTlsSymbol {
    pub path: PathBuf,
    pub tls_location: TlsLocation,
    pub symbol_info: SymbolInfo,
}

/// Find all TLS symbols in a process by scanning all loaded binaries - both the exe itself, and any
/// loaded libs.
///
/// Returns information about all symbols found in all loaded binaries.
///
/// # Arguments
/// * `pid` - Process ID to scan
///
/// # Returns
/// A vector of `FoundSymbols`, one for each binary that contains any TLS symbols.
pub fn find_symbols_in_process(pid: i32) -> Result<Vec<FoundSymbols>> {
    let proc = Process::new(pid)?;
    let maps = proc.maps().context("Failed to read memory maps")?;

    // Get the main executable path to distinguish PIE executables from shared libraries
    let exe_path = proc.exe().ok();

    let mut results = Vec::new();
    let mut seen_paths = std::collections::HashSet::new();

    // Check all memory-mapped binaries
    for map in maps.iter() {
        if let MMapPath::Path(ref path) = map.pathname {
            // Skip if we've already checked this path
            if !seen_paths.insert(path.clone()) {
                continue;
            }

            // Try to find all TLS and OBJECT symbols in this binary
            if let Ok(mut symbol_info) = super::elf_reader::find_symbols_in_binary(path) {
                // If this is a PIE executable (ET_DYN that wasn't marked as main executable),
                // check if it's actually the main executable by comparing with /proc/pid/exe
                if !symbol_info.is_main_executable {
                    if let Some(ref exe) = exe_path {
                        if exe == path {
                            debug!("Marking {:?} as main executable (PIE binary)", path);
                            symbol_info.is_main_executable = true;
                        }
                    }
                }

                if !symbol_info.symbols.is_empty() {
                    debug!("Found {} TLS/OBJECT symbols in: {:?} (is_main_exe: {})",
                        symbol_info.symbols.len(), path, symbol_info.is_main_executable);
                    results.push(FoundSymbols {
                        pid,
                        path: path.clone(),
                        symbol_info,
                    });
                }
            }
        }
    }

    Ok(results)
}

/// Find TLS symbols in a process that match a specific set of required symbols.
///
/// This is a filtered version of `find_symbols_in_process` that validates exactly one binary
/// contains all the required symbols.
///
/// # Arguments
/// * `pid` - Process ID to scan
/// * `required_symbols` - All symbols that must be present for a binary to be considered a match
///
/// # Returns
/// Error if no binaries have all required symbols, or if multiple binaries have them.
pub fn find_known_symbols_in_process(pid: i32, required_symbols: &[&str]) -> Result<FoundSymbols> {
    let all_symbols = find_symbols_in_process(pid)?;

    // Filter to binaries that have all required symbols
    let mut candidates: Vec<FoundSymbols> = all_symbols
        .into_iter()
        .filter(|found| {
            required_symbols
                .iter()
                .all(|&sym| found.symbol_info.symbols.contains_key(sym))
        })
        .collect();

    // Validate exactly one binary has the symbols
    match candidates.len() {
        0 => bail!(
            "No binaries found with required symbols: {:?}",
            required_symbols
        ),
        1 => Ok(candidates.pop().unwrap()),
        _ => {
            let paths: Vec<_> = candidates
                .iter()
                .map(|f| f.path.display().to_string())
                .collect();
            bail!(
                "Multiple binaries found with required symbols {:?}: {}",
                required_symbols,
                paths.join(", ")
            )
        }
    }
}

/// Symbols found in a loaded binary
#[derive(Debug, Clone)]
pub struct FoundSymbols {
    pub pid: i32,
    pub path: PathBuf,
    pub symbol_info: SymbolInfo,
}

impl FoundSymbols {
    /// Compute the TLS location for a specific symbol
    pub fn tls_location_for(&self, symbol_name: &str) -> Result<LoadedTlsSymbol> {
        let symbol_entry = self
            .symbol_info
            .symbols
            .get(symbol_name)
            .ok_or_else(|| anyhow::anyhow!("Symbol '{}' not found", symbol_name))?;

        let symbol = &symbol_entry.sym;

        // Determine TLS location
        let tls_location = if self.symbol_info.is_main_executable {
            // Main executable: use static offset calculation
            let st_value = symbol.st_value as u64;

            // Use the shared calculation function with current architecture
            let offset = context_reader_common::calculate_static_tls_offset(
                st_value,
                self.symbol_info.tls_block_size.map(|s| s as u64),
                context_reader_common::CURRENT_ARCH,
            ) as usize;

            debug!(
                "Main executable TLS: st_value={:#x}, tls_block_size={:?}, offset={:#x}",
                st_value, self.symbol_info.tls_block_size, offset
            );

            TlsLocation::MainExecutable { offset }
        } else {
            // Shared library: need to resolve module ID and TLS offset
            debug!("Resolving TLS info for shared library: {:?}", self.path);
            let tls_info = dynamic_linker::resolve_tls_info(self.pid, &self.path)
                .context("Failed to resolve TLS info for shared library")?;

            if tls_info.module_id == 0 {
                // module_id == 0 means this library's TLS is in static TLS space
                // (allocated at program startup), not in the DTV
                let st_value = symbol.st_value as u64;
                let offset = context_reader_common::calculate_static_tls_offset(
                    st_value,
                    self.symbol_info.tls_block_size.map(|s| s as u64),
                    context_reader_common::CURRENT_ARCH,
                ) as usize;
                debug!(
                    "Shared library with module_id=0: st_value={:#x}, tls_block_size={:?}, offset={:#x}",
                    st_value, self.symbol_info.tls_block_size, offset
                );
                TlsLocation::MainExecutable { offset }
            } else {
                let offset = symbol.st_value as usize;
                let mut tls_offset = tls_info.tls_offset;
                let mut tls_offset_source = if is_valid_static_tls_offset(tls_offset) {
                    "l_tls_offset"
                } else {
                    "invalid"
                };

                // Try to find TLSDESC relocation for this symbol
                let tlsdesc = match find_tlsdesc_relocation(&self.path, symbol_name) {
                    Ok(Some(reloc)) => {
                        debug!(
                            "Found TLSDESC relocation for {}: got_offset={:#x}",
                            symbol_name, reloc.got_offset
                        );
                        Some(TlsDescInfo {
                            library_path: self.path.clone(),
                            got_offset: reloc.got_offset,
                            symbol_name: symbol_name.to_string(),
                        })
                    }
                    Ok(None) => {
                        debug!("No TLSDESC relocation found for {} in {:?}", symbol_name, self.path);
                        None
                    }
                    Err(e) => {
                        debug!("Error looking up TLSDESC relocation for {}: {}", symbol_name, e);
                        None
                    }
                };

                // If tls_offset from link_map is invalid, try to resolve via TLSDESC
                if !is_valid_static_tls_offset(tls_offset) {
                    if let Some(ref desc_info) = tlsdesc {
                        match resolve_tlsdesc_offset(self.pid, &desc_info.library_path, desc_info.got_offset) {
                            Ok(tlsdesc_arg) => {
                                // TLSDESC arg = tls_offset + symbol_offset (on aarch64)
                                // So: tls_offset = tlsdesc_arg - symbol_offset
                                let computed_tls_offset = tlsdesc_arg.wrapping_sub(offset);
                                debug!(
                                    "Resolved tls_offset via TLSDESC for {}: tlsdesc_arg={:#x} - symbol_offset={:#x} = {:#x}",
                                    symbol_name, tlsdesc_arg, offset, computed_tls_offset
                                );
                                tls_offset = computed_tls_offset;
                                tls_offset_source = "TLSDESC";
                            }
                            Err(e) => {
                                debug!(
                                    "TLSDESC resolution failed for {}, will use DTV at runtime: {}",
                                    symbol_name, e
                                );
                            }
                        }
                    }
                }

                // Determine the resolution method for logging
                let resolution_method = if is_valid_static_tls_offset(tls_offset) {
                    format!("static TLS (via {})", tls_offset_source)
                } else if tlsdesc.is_some() {
                    "TLSDESC → DTV fallback".to_string()
                } else {
                    "DTV only".to_string()
                };

                info!(
                    "TLS for {}: {} [module_id={}, tls_offset={:#x}]",
                    symbol_name, resolution_method, tls_info.module_id, tls_offset
                );
                TlsLocation::SharedLibrary {
                    module_id: tls_info.module_id,
                    offset,
                    tls_offset,
                    tlsdesc,
                }
            }
        };

        Ok(LoadedTlsSymbol {
            path: self.path.clone(),
            tls_location,
            symbol_info: self.symbol_info.clone(),
        })
    }
}

use anyhow::{bail, Context, Result};
use procfs::process::{MMapPath, Process};
use std::path::PathBuf;
use tracing::info;

use super::dynamic_linker;
use super::elf_reader::SymbolInfo;
use super::tls_accessor::TlsLocation;

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
            if let Ok(symbol_info) = super::elf_reader::find_symbols_in_binary(path) {
                if !symbol_info.symbols.is_empty() {
                    info!("Found {} TLS/OBJECT symbols in: {:?}", symbol_info.symbols.len(), path);
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
            // Main executable: use static offset
            let offset = symbol.st_value as usize;
            info!(
                "Using static TLS offset for main executable: {:#x}",
                offset
            );
            TlsLocation::MainExecutable { offset }
        } else {
            // Shared library: need to resolve module ID
            info!("Resolving module ID for shared library: {:?}", self.path);
            let module_id = dynamic_linker::resolve_module_id(self.pid, &self.path)
                .context("Failed to resolve module ID for shared library")?;
            let offset = symbol.st_value as usize;
            info!(
                "Using DTV lookup: module_id={}, offset={:#x}",
                module_id, offset
            );
            TlsLocation::SharedLibrary { module_id, offset }
        };

        Ok(LoadedTlsSymbol {
            path: self.path.clone(),
            tls_location,
            symbol_info: self.symbol_info.clone(),
        })
    }
}

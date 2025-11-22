use anyhow::{Context, Result};
use goblin::elf::{Elf, Sym};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;

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
                info!("Found {} symbol {} in dynsyms",
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
                    info!("Found {} symbol {} in syms",
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

    // Determine if this is the main executable or a shared library
    // Note: Modern executables use Position Independent Executable (PIE) format,
    // which appears as ET_DYN - the same as a shared library.
    // We treat these both as executables, and the caller can work it out by looking
    // at /proc/pid/exe.
    let is_main_executable = elf.header.e_type == goblin::elf::header::ET_EXEC
        || elf.header.e_type == goblin::elf::header::ET_DYN;

    Ok(SymbolInfo {
        symbols,
        is_main_executable,
    })
}

#[cfg(test)]
mod test {
    use std::path::Path;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    use super::find_symbols_in_binary;

    // Test symbol extraction from an ELF binary
    #[test]
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

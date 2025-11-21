use anyhow::{Context, Result};
use goblin::elf::{Elf, Sym};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;

/// Information about symbols found in a binary
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub symbols: HashMap<String, Sym>,
    pub is_main_executable: bool,
}

/// Find multiple symbols in an ELF binary at the given path.
/// Returns information about which symbols were found and whether they were found
/// in the executable itself, or in a shared library. This affects how we look them
/// up later.
pub fn find_symbols_in_binary(path: &Path, symbol_names: &[&str]) -> Result<SymbolInfo> {
    let buffer = fs::read(path).context("Failed to read binary")?;
    let elf = Elf::parse(&buffer).context("Failed to parse ELF")?;

    // Find requested symbols
    let mut symbols = HashMap::new();
    for &name in symbol_names {
        if let Some(sym) = find_symbol(&elf, name) {
            symbols.insert(name.to_string(), sym);
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

/// Find a symbol by name in the ELF file
pub fn find_symbol(elf: &Elf, name: &str) -> Option<Sym> {
    // Check dynamic symbols
    for sym in elf.dynsyms.iter() {
        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            if sym_name == name {
                info!("Found symbol {} in dynsyms", sym_name);
                return Some(sym);
            }
        }
    }

    // Check regular symbols
    // We ... shouldn't end up here, at least in the rust case.
    for sym in elf.syms.iter() {
        if let Some(sym_name) = elf.strtab.get_at(sym.st_name) {
            if sym_name == name {
                info!("Found symbol {} in syms", sym_name);
                return Some(sym);
            }
        }
    }

    None
}

#[cfg(test)]
mod test {
    use std::path::Path;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    use crate::elf_reader::find_symbols_in_binary;

    // Helpful placeholder to test symbol extraction from an ELF binary.
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

        let symbols = &["custom_labels_current_set", "custom_labels_abi_version"];
        let result = find_symbols_in_binary(Path::new("../test-data/async-web"), symbols)?;
        println!("Found {} symbols", result.symbols.len());
        Ok(())
    }
}

use anyhow::{anyhow, bail, Context, Result};
use goblin::elf::{Elf, Sym};
use std::fs;
use std::path::Path;
use tracing::info;
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub current_set_symbol: Sym,
    pub is_main_executable: bool,
}

// Finds the custom labels current set symbol in the ELF binary at the
// given path, if it exists.
pub fn find_custom_labels_symbol(path: &Path) -> Result<SymbolInfo> {
    let buffer = fs::read(path).context("Failed to read binary")?;
    let elf = Elf::parse(&buffer).context("Failed to parse ELF")?;

    // Find and validate ABI version
    let abi_version = read_abi_version(&elf, &buffer)?;
    if abi_version != 1 {
        bail!("Unsupported ABI version: {} (expected 1)", abi_version);
    }

    // Find custom_labels_current_set symbol
    let current_set_symbol = find_symbol(&elf, "custom_labels_current_set")
        .ok_or_else(|| anyhow!("Symbol 'custom_labels_current_set' not found"))?;

    // Determine if this is the main executable or a shared library
    let is_main_executable = elf.header.e_type == goblin::elf::header::ET_EXEC
        || elf.header.e_type == goblin::elf::header::ET_DYN; // Position independent executables (PIE) are actually ET_DYN ...

    Ok(SymbolInfo {
        current_set_symbol,
        is_main_executable,
    })
}

/// Read the custom labels ABI version from the binary
fn read_abi_version(elf: &Elf, buffer: &[u8]) -> Result<u32> {
    let sym = find_symbol(elf, "custom_labels_abi_version")
        .ok_or_else(|| anyhow!("Symbol 'custom_labels_abi_version' not found"))?;

    // The symbol should be 4 bytes
    if sym.st_size != 4 {
        bail!(
            "custom_labels_abi_version symbol has wrong size: {} (expected 4)",
            sym.st_size
        );
    }

    // Read the value
    let offset = sym.st_value as usize;
    if offset + 4 > buffer.len() {
        bail!("Symbol offset out of bounds");
    }

    let bytes = &buffer[offset..offset + 4];
    Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Find a symbol by name in the ELF file
fn find_symbol(elf: &Elf, name: &str) -> Option<Sym> {
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

mod test {
    use std::path::Path;

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    use crate::elf_reader::find_custom_labels_symbol;

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

        find_custom_labels_symbol(Path::new("../test-data/async-web"))?;
        Ok(())
    }
}

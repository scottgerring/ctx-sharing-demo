///
/// Custom Labels specific logic - this is basically a wrapper of the tls_symbols
/// module for the PolarSignals customLabels specific TL format.
///
use anyhow::{bail, Context, Result};
use std::fs;
use goblin::elf::Elf;
use tracing::info;

use crate::tls_symbols::process::{find_symbols_in_process, LoadedTlsSymbol};

// Custom labels symbol names
pub const CUSTOM_LABELS_CURRENT_SET: &str = "custom_labels_current_set";
pub const CUSTOM_LABELS_ABI_VERSION: &str = "custom_labels_abi_version";

// Expected ABI version
const EXPECTED_ABI_VERSION: u32 = 1;

/// Find and validate custom labels in a process.
///
/// This scans the process's main executable and all loaded libraries for custom labels
/// symbols, validates the ABI version, and returns information about where the symbols
/// were found.
///
/// # Errors
/// - If no binary contains custom labels symbols
/// - If multiple binaries contain custom labels symbols
/// - If the ABI version is unsupported
pub fn find_custom_labels(pid: i32) -> Result<LoadedTlsSymbol> {
    let required_symbols = &[CUSTOM_LABELS_CURRENT_SET, CUSTOM_LABELS_ABI_VERSION];

    let found = find_symbols_in_process(pid, required_symbols)
        .context("Failed to find custom labels symbols")?;

    // Validate ABI version
    let abi_version = read_abi_version(&found)?;
    if abi_version != EXPECTED_ABI_VERSION {
        bail!(
            "Unsupported custom labels ABI version: {} (expected {})",
            abi_version,
            EXPECTED_ABI_VERSION
        );
    }

    info!(
        "Found custom labels in: {} (ABI version: {})",
        found.path.display(),
        abi_version
    );

    // Now compute TLS location for the current_set symbol
    found
        .tls_location_for(CUSTOM_LABELS_CURRENT_SET)
        .context("Failed to compute TLS location")
}

/// Read and validate the custom labels ABI version from found symbols
fn read_abi_version(found: &crate::tls_symbols::process::FoundSymbols) -> Result<u32> {
    let abi_sym = found
        .symbol_info
        .symbols
        .get(CUSTOM_LABELS_ABI_VERSION)
        .ok_or_else(|| anyhow::anyhow!("ABI version symbol not found"))?;

    // The symbol should be 4 bytes
    if abi_sym.st_size != 4 {
        bail!(
            "custom_labels_abi_version symbol has wrong size: {} (expected 4)",
            abi_sym.st_size
        );
    }

    // Read the binary file
    let buffer = fs::read(&found.path).context("Failed to read binary")?;

    // Read the value at the symbol's offset
    let offset = abi_sym.st_value as usize;
    if offset + 4 > buffer.len() {
        bail!("ABI version symbol offset out of bounds");
    }

    let bytes = &buffer[offset..offset + 4];
    Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

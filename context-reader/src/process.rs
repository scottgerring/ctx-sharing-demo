use anyhow::{bail, Context, Result};
use std::path::PathBuf;

/// Find the binary containing custom-labels symbols
/// Assumes custom-labels is statically linked into the main executable
pub fn find_custom_labels_binary(pid: i32) -> Result<PathBuf> {
    let proc = procfs::process::Process::new(pid)?;

    // Check if main executable has the symbols (statically linked)
    let exe_path = proc.exe().context("Failed to get executable path")?;

    if has_custom_labels_symbols(&exe_path)? {
        return Ok(exe_path);
    }

    bail!("Main executable does not contain custom-labels symbols (expected statically linked)");
}

/// Quick check if a binary has custom-labels symbols
fn has_custom_labels_symbols(path: &PathBuf) -> Result<bool> {
    use std::fs;
    use goblin::Object;

    let buffer = fs::read(path)?;
    let obj = Object::parse(&buffer)?;

    if let Object::Elf(elf) = obj {
        // Look for custom_labels_abi_version symbol
        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name == "custom_labels_abi_version" {
                    return Ok(true);
                }
            }
        }

        // Also check regular symbol table
        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == "custom_labels_abi_version" {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

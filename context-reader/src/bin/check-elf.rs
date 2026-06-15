//! Statically check whether an ELF binary's TLS symbols comply with the
//! TLS access-model spec.
//!
//! The spec permits only:
//!
//! - **Static TLS** (symbol in the main executable's own TLS block), or
//! - **TLSDESC** (symbol in a shared library, accessed via an
//!   `R_*_TLSDESC` relocation).
//!
//! Anything else — General Dynamic, Local Dynamic, Initial Exec, Local Exec
//! from a shared library — fails the check.
//!
//! Unlike `validate`, this command does **not** attach to a running process.
//! It reads the ELF file on disk and classifies the access model purely from
//! the relocation tables. Useful for CI gating an artifact (a JAR, an `.so`,
//! an exe) before it ships.
//!
//! # Usage
//!
//! ```text
//! check-elf path/to/lib.so                       # check every published TLS symbol
//! check-elf path/to/lib.so --symbol my_tls_var   # check a single symbol
//! check-elf path/to/exe --executable             # treat ET_DYN as a PIE exe, not a .so
//!
//! "Published" means `STT_TLS` in `.dynsym`, or — for fully-static ELFs that
//! have no `.dynsym` section — `STT_TLS + STB_GLOBAL/WEAK + STV_DEFAULT` in
//! `.symtab` (the underlying property `.dynsym` membership normally proxies
//! for).
//! ```
//!
//! Exits 0 if all checked symbols are compliant, 1 otherwise.

use anyhow::{Context, Result};
use clap::Parser;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, Cell, ContentArrangement, Table};
use context_reader::tls_symbols::{access_model, elf_reader};
use goblin::elf::{
    section_header::SHT_DYNSYM, sym::STB_GLOBAL, sym::STB_WEAK, sym::STT_TLS, sym::STV_DEFAULT,
    Elf, Sym,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "check-elf")]
#[command(
    about = "Check TLS access models in an ELF binary against the spec (no running process needed)",
    long_about = None,
)]
struct Args {
    /// Path to the ELF file to inspect (an executable or a shared library).
    path: PathBuf,

    /// Only check this specific symbol. If omitted, every TLS symbol
    /// properly published by the binary is checked: that means every
    /// `STT_TLS` entry in `.dynsym`, and — only for fully-static ELFs that
    /// have no `.dynsym` at all — every `STT_TLS + STB_GLOBAL/WEAK +
    /// STV_DEFAULT` entry in `.symtab`.
    #[arg(long)]
    symbol: Option<String>,

    /// Treat an `ET_DYN` binary as a main executable (PIE), not a shared
    /// library. Affects how the classifier resolves "no TLS relocation"
    /// for a symbol (main-exe → Static TLS; shared library → Unknown).
    #[arg(long)]
    executable: bool,
}

/// Enumerate "properly published" TLS symbols in `path`.
///
/// Normally that means STT_TLS entries in `.dynsym`. For fully-static ELFs
/// (no `.dynsym` section at all), it falls back to `.symtab` and requires the
/// symbol to be `STT_TLS + STB_GLOBAL/WEAK + STV_DEFAULT` — the underlying
/// property that `.dynsym` membership normally proxies for.
///
/// The fallback only fires when the binary has no `.dynsym`, so it never
/// applies to shared libraries or to normal dynamic executables, where a
/// missing `.dynsym` entry genuinely means the developer didn't export the
/// symbol.
fn is_published_tls_symbol(sym: &Sym) -> bool {
    sym.st_type() == STT_TLS
        && matches!(sym.st_bind(), STB_GLOBAL | STB_WEAK)
        && sym.st_visibility() == STV_DEFAULT
}

fn enumerate_published_tls_symbols(path: &Path) -> Result<Vec<String>> {
    let buffer = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let elf = Elf::parse(&buffer).with_context(|| format!("parsing {}", path.display()))?;

    // First: properly-published TLS symbols in .dynsym.
    let mut out: Vec<String> = elf
        .dynsyms
        .iter()
        .filter(|sym| is_published_tls_symbol(sym))
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(str::to_owned))
        .collect();

    // Static-binary fallback: only if the file has NO .dynsym section.
    let has_dynsym = elf
        .section_headers
        .iter()
        .any(|sh| sh.sh_type == SHT_DYNSYM);

    if !has_dynsym {
        // `out` is empty here by construction (the .dynsym loop above found
        // zero entries because there is no .dynsym section), so we don't
        // need to dedupe against it.
        for sym in elf.syms.iter() {
            if !is_published_tls_symbol(&sym) {
                continue;
            }
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    out.push(name.to_owned());
                }
            }
        }
    }

    Ok(out)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let info = elf_reader::find_symbols_in_binary(&args.path)
        .with_context(|| format!("failed to parse {}", args.path.display()))?;

    // Caller can promote ET_DYN binaries to main-exe semantics; we cannot
    // tell from the file alone whether an ET_DYN is a PIE exe or a .so.
    let is_main_executable = info.is_main_executable || args.executable;

    println!(
        "Checking {} (is_main_executable={})",
        args.path.display(),
        is_main_executable
    );

    // Decide which symbols to check.
    let published_symbols = enumerate_published_tls_symbols(&args.path)
        .with_context(|| format!("enumerating TLS symbols in {}", args.path.display()))?;
    let candidates: Vec<String> = if let Some(name) = &args.symbol {
        if !published_symbols.iter().any(|published| published == name) {
            eprintln!(
                "FAIL: symbol {:?} is not a properly-published TLS symbol in {}",
                name,
                args.path.display()
            );
            std::process::exit(1);
        }
        vec![name.clone()]
    } else {
        published_symbols
    };

    if candidates.is_empty() {
        // If the user asked for "all", emit a clear message rather than a
        // silent pass. Better signal for CI.
        eprintln!(
            "FAIL: no properly-published TLS symbols found in {}",
            args.path.display()
        );
        std::process::exit(1);
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Symbol"),
            Cell::new("In .dynsym?"),
            Cell::new("Access Model"),
            Cell::new("Compliant"),
            Cell::new("Remediation"),
        ]);

    let mut any_fail = false;

    for sym_name in &candidates {
        // Note presence in .dynsym — the classifier only finds relocations
        // by .dynsym index, so a symbol that's only in .symtab can never
        // be classified as anything other than Unknown.
        let in_dynsym = info
            .symbols
            .get(sym_name)
            .map(|e| e.is_dynamic)
            .unwrap_or(false);

        let model = access_model::classify(&args.path, sym_name, is_main_executable)
            .with_context(|| format!("classify {sym_name:?}"))?;

        let compliant = model.is_compliant();
        if !compliant {
            any_fail = true;
        }

        table.add_row(vec![
            Cell::new(sym_name),
            Cell::new(if in_dynsym { "yes" } else { "no" }),
            Cell::new(model.name()),
            Cell::new(if compliant { "✓ PASS" } else { "✗ FAIL" }),
            Cell::new(model.remediation_hint().unwrap_or("-")),
        ]);
    }

    println!("{table}");

    if any_fail {
        eprintln!("\nFAIL: {} is NOT spec-compliant", args.path.display());
        std::process::exit(1);
    }

    println!(
        "\nPASS: all {} TLS symbol(s) in {} are spec-compliant",
        candidates.len(),
        args.path.display(),
    );
    Ok(())
}

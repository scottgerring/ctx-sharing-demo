//! Dump TLS symbols from a running process
//!
//! This binary discovers and displays TLS symbol information for debugging and development.

use anyhow::{Context, Result};
use clap::Parser;
use comfy_table::{Cell, ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "dump-symbols")]
#[command(about = "Dump TLS symbols from a running process", long_about = None)]
struct Args {
    /// Process ID to scan
    pid: i32,

    /// Include OBJECT symbols in addition to TLS
    #[arg(long)]
    include_obj: bool,

    /// Include internal symbols from symtab (default: only exported symbols from dynsym)
    #[arg(long)]
    include_symtab: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("dump-symbols only runs on Linux");
    }

    #[cfg(target_os = "linux")]
    {
        let args = Args::parse();
        run(args)
    }
}

#[cfg(target_os = "linux")]
enum SymbolFilter {
    TlsOnly,
    TlsAndObject,
}

#[cfg(target_os = "linux")]
fn run(args: Args) -> Result<()> {
    // Validate process exists
    let proc = procfs::process::Process::new(args.pid).context("Failed to find process")?;
    println!("\nScanning process {} ({})\n", args.pid, proc.stat()?.comm);

    let filter = if args.include_obj {
        SymbolFilter::TlsAndObject
    } else {
        SymbolFilter::TlsOnly
    };

    print_symbols(args.pid, filter, args.include_symtab)
}

#[cfg(target_os = "linux")]
fn print_symbols(pid: i32, filter: SymbolFilter, include_symtab: bool) -> Result<()> {
    use context_reader::tls_symbols;

    let filter_desc = match filter {
        SymbolFilter::TlsOnly => "TLS",
        SymbolFilter::TlsAndObject => "TLS/OBJECT",
    };

    let scope_desc = if include_symtab {
        "exported and internal"
    } else {
        "exported"
    };

    println!("Discovering {} {} symbols...\n", scope_desc, filter_desc);

    // Find all TLS/OBJECT symbols in all loaded binaries
    let all_symbols = tls_symbols::process::find_symbols_in_process(pid)
        .context("Failed to scan process for symbols")?;

    if all_symbols.is_empty() {
        println!("No symbols found in any loaded binaries.");
        return Ok(());
    }

    // Create table
    let mut table = Table::new();
    table
        .load_preset(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Symbol Name"),
            Cell::new("Type"),
            Cell::new("Source"),
            Cell::new("Binary"),
        ]);

    let mut total_symbols = 0;

    // Collect symbols for the table
    for found in &all_symbols {
        let binary_name = found.path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>");

        for (name, entry) in &found.symbol_info.symbols {
            let sym_type = entry.sym.st_type();
            let is_tls = sym_type == goblin::elf::sym::STT_TLS;
            let is_object = sym_type == goblin::elf::sym::STT_OBJECT;

            // Apply type filter
            let should_print = match filter {
                SymbolFilter::TlsOnly => is_tls,
                SymbolFilter::TlsAndObject => is_tls || is_object,
            };

            // Apply source filter (skip symtab-only symbols unless include_symtab is set)
            let should_print = should_print && (include_symtab || entry.is_dynamic);

            if should_print {
                let type_str = if is_tls { "TLS" } else { "OBJECT" };
                let source_str = if entry.is_dynamic { "dynsym" } else { "symtab" };
                table.add_row(vec![
                    Cell::new(name),
                    Cell::new(type_str),
                    Cell::new(source_str),
                    Cell::new(binary_name),
                ]);
                total_symbols += 1;
            }
        }
    }

    // Print the table
    println!("{}", table);

    // Print summary
    println!("\nFound {} {} symbols across {} binaries", total_symbols, filter_desc, all_symbols.len());

    Ok(())
}

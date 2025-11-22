use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Generic TLS symbol discovery infrastructure
// Note: elf_reader can work cross-platform for reading ELF files
mod tls_symbols;

// Application-specific modules
#[cfg(target_os = "linux")]
mod custom_labels;
#[cfg(target_os = "linux")]
mod label_parser;
#[cfg(target_os = "linux")]
mod output;
#[cfg(target_os = "linux")]
mod tls_reader;

#[derive(Parser, Debug)]
#[command(name = "context-reader")]
#[command(about = "Read custom labels from a running process", long_about = None)]
struct Args {
    // The process we're trying to read out of
    pid: i32,

    // How frequently to read in millis
    #[arg(short, long, default_value = "1000")]
    interval: u64,

    // Print TLS symbols found in the process and exit
    #[arg(long)]
    print_tls: bool,

    // Include OBJECT symbols in addition to TLS (only with --print-tls)
    #[arg(long, requires = "print_tls")]
    include_obj: bool,

    // Include internal symbols from symtab (default: only show exported symbols from dynsym)
    #[arg(long, requires = "print_tls")]
    include_symtab: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    // Pretty useless without linux
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("We only run on Linux! We need ELF binaries and ptrace magic.");
    }

    #[cfg(target_os = "linux")]
    {
        let args = Args::parse();
        run(args)
    }
}

#[cfg(target_os = "linux")]
fn run(args: Args) -> Result<()> {
    use anyhow::Context;
    use std::time::Duration;

    // Validate process exists
    let proc = procfs::process::Process::new(args.pid).context("Failed to find process")?;

    info!("Monitoring process {} ({})", args.pid, proc.stat()?.comm);

    // If --print-tls is set, print TLS symbols (and optionally OBJECT symbols) and exit
    if args.print_tls {
        let filter = if args.include_obj {
            SymbolFilter::TlsAndObject
        } else {
            SymbolFilter::TlsOnly
        };
        return print_symbols(args.pid, filter, args.include_symtab);
    }

    // Find the library (executable or .so) containing custom-labels symbols
    // This will scan all loaded libraries and ensure exactly one has the symbols
    let library = custom_labels::find_custom_labels(args.pid)
        .context("Failed to find custom-labels library or executable")?;

    info!(
        "Found custom-labels in: {} (TLS location: {:?})",
        library.path.display(),
        library.tls_location
    );

    let interval = Duration::from_millis(args.interval);
    let mut iteration = 0u64;
    let mut empty_iterations = 0u32;
    const MAX_EMPTY_ITERATIONS: u32 = 5;

    loop {
        iteration += 1;

        // Hackety hack - try check if process still exists
        // There's gotta be a better way to do this
        if procfs::process::Process::new(args.pid).is_err() {
            println!("\nProcess exited! finishing up.");
            break;
        }

        // Read labels from all threads
        let results = tls_reader::read_all_threads(args.pid, &library)
            .context("Failed to read thread labels")?;

        // Check if we found any labels
        let has_labels = results
            .iter()
            .any(|r| matches!(r, tls_reader::ThreadResult::Found { .. }));

        if !has_labels {
            empty_iterations += 1;
            if empty_iterations >= MAX_EMPTY_ITERATIONS {
                println!("\nNo labels found for {} consecutive iterations, process appears to be shutting down. Exiting.", MAX_EMPTY_ITERATIONS);
                break;
            }
        } else {
            empty_iterations = 0;
        }

        // Format and print output
        output::print_iteration(iteration, &results);

        std::thread::sleep(interval);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
enum SymbolFilter {
    TlsOnly,
    TlsAndObject,
}

#[cfg(target_os = "linux")]
fn print_symbols(pid: i32, filter: SymbolFilter, include_symtab: bool) -> Result<()> {
    use anyhow::Context;
    use comfy_table::{Table, Cell, ContentArrangement, modifiers::UTF8_ROUND_CORNERS};

    let filter_desc = match filter {
        SymbolFilter::TlsOnly => "TLS",
        SymbolFilter::TlsAndObject => "TLS/OBJECT",
    };

    let scope_desc = if include_symtab {
        "exported and internal"
    } else {
        "exported"
    };

    println!("\nDiscovering {} {} symbols in process {}...\n", scope_desc, filter_desc, pid);

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

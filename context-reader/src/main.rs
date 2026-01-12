use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Generic TLS symbol discovery infrastructure
// Note: elf_reader can work cross-platform for reading ELF files
mod tls_symbols;

// TLS reader trait and implementations
#[cfg(target_os = "linux")]
mod tls_reader_trait;
#[cfg(target_os = "linux")]
mod v1_reader;
#[cfg(target_os = "linux")]
mod v2_reader;

// eBPF-based reader
#[cfg(target_os = "linux")]
mod ebpf_loader;

// Output formatting
#[cfg(target_os = "linux")]
mod output;

/// Reading mode for TLS labels
#[derive(ValueEnum, Clone, Debug, Default)]
enum ReadMode {
    /// Use ptrace to attach and read TLS (default, more compatible)
    #[default]
    Ptrace,
    /// Use eBPF perf events to read TLS (lower overhead, requires newer kernel)
    Ebpf,
}

#[derive(Parser, Debug)]
#[command(name = "context-reader")]
#[command(about = "Read custom labels from a running process", long_about = None)]
struct Args {
    // The process we're trying to read out of
    pid: i32,

    // How frequently to read in millis (ptrace mode) or sample frequency in Hz (ebpf mode)
    #[arg(short, long, default_value = "1000")]
    interval: u64,

    /// Reading mode: ptrace (default) or ebpf
    #[arg(long, value_enum, default_value_t = ReadMode::Ptrace)]
    mode: ReadMode,

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
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
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
    use custom_labels::process_context;
    use tracing::info;

    // Validate process exists
    let proc = procfs::process::Process::new(args.pid).context("Failed to find process")?;

    info!("Monitoring process {} ({})", args.pid, proc.stat()?.comm);

    // Try to read process-context from the target process
    match process_context::read_process_context_from_pid(args.pid) {
        Ok(ctx) => {
            info!("Found process-context with {} resources:", ctx.resources.len());
            for kv in &ctx.resources {
                info!("  {} = {}", kv.key, kv.value);
            }
        }
        Err(process_context::Error::NotFound) => {
            info!("No process-context found in target process");
        }
        Err(e) => {
            info!("Failed to read process-context: {}", e);
        }
    }

    // If --print-tls is set, print TLS symbols (and optionally OBJECT symbols) and exit
    if args.print_tls {
        let filter = if args.include_obj {
            SymbolFilter::TlsAndObject
        } else {
            SymbolFilter::TlsOnly
        };
        return print_symbols(args.pid, filter, args.include_symtab);
    }

    // Branch based on reading mode
    match args.mode {
        ReadMode::Ptrace => run_ptrace_mode(args),
        ReadMode::Ebpf => run_ebpf_mode(args),
    }
}

#[cfg(target_os = "linux")]
fn run_ebpf_mode(args: Args) -> Result<()> {
    use tracing::info;

    info!("Starting eBPF mode with sample frequency {}Hz", args.interval);

    // eBPF requires a Tokio runtime for async operations
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        ebpf_loader::run_ebpf(args.pid, args.interval).await
    })
}

#[cfg(target_os = "linux")]
fn run_ptrace_mode(args: Args) -> Result<()> {
    use nix::sys::ptrace;
    use nix::unistd::Pid;
    use std::time::Duration;
    use tls_reader_trait::{get_thread_ids, ThreadContext, ThreadResult, TlsReader};
    use tls_symbols::tls_accessor;
    use tracing::{debug, info};

    // Try to set up readers - collect all that succeed
    let mut readers: Vec<Box<dyn TlsReader>> = Vec::new();

    match v1_reader::V1Reader::try_setup(args.pid) {
        Ok(reader) => {
            info!("V1 reader initialized successfully");
            readers.push(Box::new(reader));
        }
        Err(e) => {
            info!("V1 reader not available: {}", e);
        }
    }

    match v2_reader::V2Reader::try_setup(args.pid) {
        Ok(reader) => {
            info!("V2 reader initialized successfully");
            readers.push(Box::new(reader));
        }
        Err(e) => {
            info!("V2 reader not available: {}", e);
        }
    }

    if readers.is_empty() {
        anyhow::bail!("No TLS readers could be initialized for process {}", args.pid);
    }

    info!("Initialized {} TLS reader(s)", readers.len());

    let interval = Duration::from_millis(args.interval);
    let mut iteration = 0u64;
    let mut empty_iterations = 0u32;
    const MAX_EMPTY_ITERATIONS: u32 = 5;

    loop {
        iteration += 1;

        // Check if process still exists
        if procfs::process::Process::new(args.pid).is_err() {
            println!("\nProcess exited! finishing up.");
            break;
        }

        // Get all thread IDs once per iteration
        let tids = match get_thread_ids(args.pid) {
            Ok(tids) => tids,
            Err(e) => {
                info!("Failed to get thread IDs: {}", e);
                std::thread::sleep(interval);
                continue;
            }
        };

        // Collect thread contexts by attaching once per thread
        let mut thread_contexts: Vec<ThreadContext> = Vec::with_capacity(tids.len());
        let mut thread_errors: Vec<(i32, String)> = Vec::new();

        for tid in tids {
            let thread_pid = Pid::from_raw(tid);

            // Attach to thread
            if let Err(e) = ptrace::attach(thread_pid) {
                debug!("Failed to attach to thread {}: {}", tid, e);
                thread_errors.push((tid, format!("Failed to attach: {}", e)));
                continue;
            }

            // Wait for thread to stop
            if let Err(e) = nix::sys::wait::waitpid(thread_pid, None) {
                debug!("Failed to wait for thread {}: {}", tid, e);
                let _ = ptrace::detach(thread_pid, None);
                thread_errors.push((tid, format!("Failed to wait: {}", e)));
                continue;
            }

            // Read thread pointer while attached
            let thread_pointer = match tls_accessor::get_thread_pointer(tid) {
                Ok(tp) => tp,
                Err(e) => {
                    debug!("Failed to get thread pointer for {}: {}", tid, e);
                    let _ = ptrace::detach(thread_pid, None);
                    thread_errors.push((tid, format!("Failed to get thread pointer: {}", e)));
                    continue;
                }
            };

            // Detach immediately after reading thread pointer
            let _ = ptrace::detach(thread_pid, None);

            thread_contexts.push(ThreadContext { tid, thread_pointer });
        }

        let mut any_labels_found = false;

        // Now call each reader for each thread (no ptrace needed)
        for reader in &readers {
            let mut results: Vec<ThreadResult> = Vec::with_capacity(
                thread_contexts.len() + thread_errors.len(),
            );

            // Process successful thread contexts
            for ctx in &thread_contexts {
                let result = reader.read_thread(args.pid, ctx);
                if matches!(result, ThreadResult::Found { .. }) {
                    any_labels_found = true;
                }
                results.push(result);
            }

            // Add errors for threads we couldn't attach to
            for (tid, error) in &thread_errors {
                results.push(ThreadResult::Error {
                    tid: *tid,
                    error: error.clone(),
                });
            }

            output::print_iteration(iteration, reader.name(), &results);
        }

        if !any_labels_found {
            empty_iterations += 1;
            if empty_iterations >= MAX_EMPTY_ITERATIONS {
                println!("\nNo labels found for {} consecutive iterations, process appears to be shutting down. Exiting.", MAX_EMPTY_ITERATIONS);
                break;
            }
        } else {
            empty_iterations = 0;
        }

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

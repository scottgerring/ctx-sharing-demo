//! Validate label reading from a running process
//!
//! One-shot validation that labels can be read correctly. Exits with 0 on success,
//! or 1 on timeout/failure.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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
#[command(name = "validate")]
#[command(about = "Validate label reading from a running process", long_about = None)]
struct Args {
    /// Process ID to validate
    pid: i32,

    /// Reading mode: ptrace (default) or ebpf
    #[arg(long, value_enum, default_value_t = ReadMode::Ptrace)]
    mode: ReadMode,

    /// Timeout in seconds (default: 10)
    #[arg(long, default_value = "10")]
    timeout: u64,

    /// Sample interval in milliseconds (ptrace) or frequency in Hz (ebpf)
    #[arg(short, long, default_value = "500")]
    interval: u64,
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("validate only runs on Linux");
    }

    #[cfg(target_os = "linux")]
    {
        let args = Args::parse();
        run(args)
    }
}

#[cfg(target_os = "linux")]
fn run(args: Args) -> Result<()> {
    use tracing::info;

    // Validate process exists
    let proc = procfs::process::Process::new(args.pid).context("Failed to find process")?;
    info!("Validating process {} ({})", args.pid, proc.stat()?.comm);

    match args.mode {
        ReadMode::Ptrace => run_ptrace_validation(args),
        ReadMode::Ebpf => run_ebpf_validation(args),
    }
}

#[cfg(target_os = "linux")]
fn run_ptrace_validation(args: Args) -> Result<()> {
    use context_reader::tls_reader_trait::{get_thread_ids, ThreadContext, ThreadResult, TlsReader};
    use context_reader::tls_symbols::process::find_symbols_in_process;
    use context_reader::tls_symbols::tls_accessor;
    use context_reader::v1_reader::V1Reader;
    use context_reader::v2_reader::V2Reader;
    use custom_labels::process_context;
    use nix::sys::ptrace;
    use nix::unistd::Pid;
    use std::time::{Duration, Instant};
    use tracing::{debug, info};

    // Scan symbols once for all readers
    let all_symbols = find_symbols_in_process(args.pid)
        .context("Failed to scan process symbols")?;

    // Read process context once (needed for V2)
    let process_ctx = process_context::read_process_context_from_pid(args.pid).ok();

    // Try to set up readers - collect all that succeed
    let mut readers: Vec<Box<dyn TlsReader>> = Vec::new();

    match V1Reader::try_setup(&all_symbols) {
        Ok(reader) => {
            info!("V1 reader initialized successfully");
            readers.push(Box::new(reader));
        }
        Err(e) => {
            info!("V1 reader not available: {}", e);
        }
    }

    if let Some(ref ctx) = process_ctx {
        match V2Reader::try_setup(&all_symbols, ctx) {
            Ok(reader) => {
                info!("V2 reader initialized successfully");
                readers.push(Box::new(reader));
            }
            Err(e) => {
                info!("V2 reader not available: {}", e);
            }
        }
    } else {
        info!("V2 reader not available: no process-context found");
    }

    if readers.is_empty() {
        anyhow::bail!("No TLS readers could be initialized for process {}", args.pid);
    }

    info!("Initialized {} TLS reader(s)", readers.len());

    let interval = Duration::from_millis(args.interval);
    let timeout_duration = Duration::from_secs(args.timeout);
    let start_time = Instant::now();

    loop {
        // Check timeout
        if start_time.elapsed() > timeout_duration {
            eprintln!("VALIDATE FAILED: Timeout after {}s - no labels found", args.timeout);
            std::process::exit(1);
        }

        // Check if process still exists
        if procfs::process::Process::new(args.pid).is_err() {
            eprintln!("VALIDATE FAILED: Process exited before labels were found");
            std::process::exit(1);
        }

        // Get all thread IDs
        let tids = match get_thread_ids(args.pid) {
            Ok(tids) => tids,
            Err(e) => {
                debug!("Failed to get thread IDs: {}", e);
                std::thread::sleep(interval);
                continue;
            }
        };

        // Collect thread contexts by attaching once per thread
        let mut thread_contexts: Vec<ThreadContext> = Vec::with_capacity(tids.len());

        for tid in tids {
            let thread_pid = Pid::from_raw(tid);

            // Attach to thread
            if let Err(e) = ptrace::attach(thread_pid) {
                debug!("Failed to attach to thread {}: {}", tid, e);
                continue;
            }

            // Wait for thread to stop
            if let Err(e) = nix::sys::wait::waitpid(thread_pid, None) {
                debug!("Failed to wait for thread {}: {}", tid, e);
                let _ = ptrace::detach(thread_pid, None);
                continue;
            }

            // Read thread pointer while attached
            let thread_pointer = match tls_accessor::get_thread_pointer(tid) {
                Ok(tp) => tp,
                Err(e) => {
                    debug!("Failed to get thread pointer for {}: {}", tid, e);
                    let _ = ptrace::detach(thread_pid, None);
                    continue;
                }
            };

            // Detach immediately after reading thread pointer
            let _ = ptrace::detach(thread_pid, None);

            thread_contexts.push(ThreadContext { tid, thread_pointer });
        }

        // Check each reader for each thread
        for reader in &readers {
            for ctx in &thread_contexts {
                let result = reader.read_thread(args.pid, ctx);
                if let ThreadResult::Found { tid, labels } = result {
                    let summary = format!(
                        "[{}] thread={}, labels=[{}]",
                        reader.name(),
                        tid,
                        labels.iter().map(|l| format!("{}={}", l.key, l.value)).collect::<Vec<_>>().join(", ")
                    );
                    println!("VALIDATE OK: {}", summary);
                    std::process::exit(0);
                }
            }
        }

        std::thread::sleep(interval);
    }
}

#[cfg(target_os = "linux")]
fn run_ebpf_validation(args: Args) -> Result<()> {
    use context_reader_common::ReaderMode;
    use tracing::info;

    info!(
        "Starting eBPF validation with sample frequency {}Hz, timeout={}s",
        args.interval, args.timeout
    );

    // eBPF requires a Tokio runtime for async operations
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        context_reader::ebpf_loader::run_ebpf(
            args.pid,
            args.interval,
            ReaderMode::Both,
            true, // validate_only
            args.timeout,
        ).await
    })
}

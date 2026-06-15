//! Continuous monitoring of labels from a running process
//!
//! Supports both ptrace and eBPF modes for reading labels.

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

/// Which label readers to enable (only applies to eBPF mode)
#[derive(ValueEnum, Clone, Debug, Default)]
enum ReaderSelection {
    /// Enable both V1 and V2 readers (default)
    #[default]
    Both,
    /// Only enable V1 reader
    V1,
    /// Only enable V2 reader
    V2,
}

#[derive(Parser, Debug)]
#[command(name = "tail")]
#[command(about = "Continuously monitor labels from a running process", long_about = None)]
struct Args {
    /// Process ID to monitor
    pid: i32,

    /// Sample interval in milliseconds (ptrace) or frequency in Hz (ebpf)
    #[arg(short, long, default_value = "1000")]
    interval: u64,

    /// Reading mode: ptrace (default) or ebpf
    #[arg(long, value_enum, default_value_t = ReadMode::Ptrace)]
    mode: ReadMode,

    /// Which readers to enable: both (default), v1, or v2.
    /// Only applies to eBPF mode - controls which readers are active in the eBPF program.
    #[arg(long, value_enum, default_value_t = ReaderSelection::Both)]
    readers: ReaderSelection,

    /// Accept General Dynamic (GD) TLS access with a warning instead of
    /// failing. Other non-compliant access models still fail. By default, only
    /// TLSDESC (shared library) and Static TLS (main executable) are permitted,
    /// in line with the published spec. Use this flag if you need to read from
    /// a binary that was built without `-mtls-dialect=gnu2` (e.g. an older or
    /// non-conforming agent) and you accept the resulting risks.
    #[arg(long, default_value_t = false)]
    tolerate_gd_tls: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("tail only runs on Linux");
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
    info!("Monitoring process {} ({})", args.pid, proc.stat()?.comm);

    match args.mode {
        ReadMode::Ptrace => run_ptrace_mode(args),
        ReadMode::Ebpf => run_ebpf_mode(args),
    }
}

#[cfg(target_os = "linux")]
fn run_ptrace_mode(args: Args) -> Result<()> {
    use context_reader::output;
    use context_reader::tls_reader_trait::{
        get_thread_ids, ThreadContext, ThreadResult, TlsReader,
    };
    use context_reader::tls_symbols::process::{find_symbols_in_process, AccessModelPolicy};
    use context_reader::tls_symbols::tls_accessor;
    use context_reader::v1_reader::V1Reader;
    use context_reader::v2_reader::V2Reader;
    use custom_labels::process_context;
    use nix::sys::ptrace;
    use nix::unistd::Pid;
    use std::time::Duration;
    use tracing::{debug, info};

    let policy = if args.tolerate_gd_tls {
        AccessModelPolicy::tolerant()
    } else {
        AccessModelPolicy::strict()
    };

    // Scan symbols once for all readers
    let all_symbols =
        find_symbols_in_process(args.pid).context("Failed to scan process symbols")?;

    // Read process context once (needed for V2). We deliberately preserve the
    // underlying error so the operator can distinguish "no OTEL_CTX mapping at
    // all" from "mapping found but rejected" (wrong version, bad signature,
    // update in progress, ...). Previously this was `.ok()` and we logged a
    // misleading "no process-context found" message that masked the real cause.
    let process_ctx = process_context::read_process_context_from_pid(args.pid);

    // Try to set up readers - collect all that succeed
    let mut readers: Vec<Box<dyn TlsReader>> = Vec::new();

    match V1Reader::try_setup(&all_symbols, &policy) {
        Ok(reader) => {
            info!("V1 reader initialized successfully");
            readers.push(Box::new(reader));
        }
        Err(e) => {
            info!("V1 reader not available: {}", e);
        }
    }

    match &process_ctx {
        Ok(ctx) => match V2Reader::try_setup(&all_symbols, ctx, &policy) {
            Ok(reader) => {
                info!("V2 reader initialized successfully");
                readers.push(Box::new(reader));
            }
            Err(e) => {
                info!("V2 reader not available: {}", e);
            }
        },
        Err(e) => {
            info!("V2 reader not available: process-context not usable: {}", e);
        }
    }

    if readers.is_empty() {
        anyhow::bail!(
            "No TLS readers could be initialized for process {}",
            args.pid
        );
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

            thread_contexts.push(ThreadContext {
                tid,
                thread_pointer,
            });
        }

        let mut any_labels_found = false;

        // Now call each reader for each thread (no ptrace needed)
        for reader in &readers {
            let mut results: Vec<ThreadResult> =
                Vec::with_capacity(thread_contexts.len() + thread_errors.len());

            // Process successful thread contexts
            for ctx in &thread_contexts {
                let result = reader.read_thread(args.pid, ctx);
                if matches!(&result, ThreadResult::Found { .. }) {
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
fn run_ebpf_mode(args: Args) -> Result<()> {
    use context_reader::tls_symbols::process::AccessModelPolicy;
    use context_reader_common::ReaderMode;
    use tracing::info;

    // Convert CLI reader selection to the common ReaderMode type
    let reader_mode = match args.readers {
        ReaderSelection::Both => ReaderMode::Both,
        ReaderSelection::V1 => ReaderMode::V1Only,
        ReaderSelection::V2 => ReaderMode::V2Only,
    };
    let policy = if args.tolerate_gd_tls {
        AccessModelPolicy::tolerant()
    } else {
        AccessModelPolicy::strict()
    };

    info!(
        "Starting eBPF mode with sample frequency {}Hz, readers={:?}",
        args.interval, reader_mode
    );

    // eBPF requires a Tokio runtime for async operations
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        context_reader::ebpf_loader::run_ebpf(
            args.pid,
            args.interval,
            reader_mode,
            false, // validate_only
            0,     // timeout (not used when validate_only is false)
            policy,
        )
        .await
    })
}

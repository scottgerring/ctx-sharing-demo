use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Generic TLS symbol discovery infrastructure
#[cfg(target_os = "linux")]
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

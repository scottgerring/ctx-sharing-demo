use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod client_worker;
mod http_server;

fn init_tracing(writer_type: datadog_opentelemetry::ContextLabelWriterType) -> opentelemetry_sdk::trace::SdkTracerProvider {
    // Set up tracing subscriber with fmt layer for console output
    // Include debug level for dd_trace and context_labels to see context propagation
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("async_web=info,dd_trace=debug,datadog_opentelemetry=debug")
        }))
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true),
        )
        .init();

    // Initialize the log-to-tracing bridge to capture dd-trace-rs logs
    tracing_log::LogTracer::init().ok();

    // Initialize Datadog OpenTelemetry tracing with context labels
    let tracer_provider = datadog_opentelemetry::tracing()
        .with_config(
            dd_trace::Config::builder()
                .set_service("async-web".to_string())
                .set_env("dev".to_string())
                .set_log_level_filter(dd_trace::log::LevelFilter::Debug)
                .build(),
        )
        .with_context_labels(writer_type)
        .init();

    info!(
        "Datadog OpenTelemetry tracing initialized with context labels (service: async-web, env: dev, writer: {:?})",
        writer_type
    );

    // Verify dd-trace log level is set correctly
    println!(
        "=== dd-trace log level: {:?} ===",
        dd_trace::log::max_level()
    );

    tracer_provider
}

fn main() {
    // Parse command-line arguments to determine writer type
    let args: Vec<String> = env::args().collect();
    let writer_type = args.iter()
        .find(|arg| arg.starts_with("--writer="))
        .and_then(|arg| arg.strip_prefix("--writer="))
        .map(|value| match value {
            "logging" => datadog_opentelemetry::ContextLabelWriterType::Logging,
            _ => datadog_opentelemetry::ContextLabelWriterType::Custom,
        })
        .unwrap_or(datadog_opentelemetry::ContextLabelWriterType::Custom);

    // Initialize tracing with Datadog OpenTelemetry
    let tracer_provider = init_tracing(writer_type);

    // Create Tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();

    // Shared state for request counting and shutdown signaling
    let request_count = Arc::new(AtomicUsize::new(0));
    let shutdown_signal = Arc::new(AtomicBool::new(false));

    // Start the HTTP server as a background task
    let server = http_server::start_http_server();
    let server_handle = server.handle();

    // Spawn the server in the background so its worker threads start
    let server_task = rt.spawn(server);

    // Give the actix workers time to start up
    info!("Waiting for actix workers to start...");
    thread::sleep(Duration::from_secs(2));

    // Start the background client thread
    client_worker::background_client_thread(request_count.clone(), shutdown_signal.clone());
    thread::sleep(Duration::from_secs(1));

    // Start a thread that does nothing but sleep
    thread::spawn(|| {
        // This is interesting! I believe this will be interrupted by any signal,
        // but within the userland libc, which will immediately resume. The _upshot_
        // of this is that any interrupt itself causes us to consume CPU.
        thread::sleep(Duration::from_secs(60));
    });

    // Monitor for shutdown and manage server lifecycle
    rt.block_on(async move {
        let shutdown_signal_clone = shutdown_signal.clone();

        // Monitor for shutdown signal
        let shutdown_monitor = async move {
            loop {
                if shutdown_signal_clone.load(Ordering::Acquire) {
                    let count = request_count.load(Ordering::Acquire);
                    info!("Shutdown signal received after {} requests", count);
                    server_handle.stop(true).await;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        // Race between server and shutdown monitor
        tokio::select! {
            result = server_task => {
                match result {
                    Ok(Ok(_)) => info!("Server finished successfully"),
                    Ok(Err(e)) => eprintln!("Server error: {}", e),
                    Err(e) => eprintln!("Server task panicked: {}", e),
                }
            }
            _ = shutdown_monitor => {
                info!("Shutting down server...");
            }
        }
    });

    // Shutdown the tracer provider to flush any remaining spans
    info!("Shutting down Datadog OpenTelemetry tracer provider...");
    if let Err(e) = tracer_provider.shutdown() {
        eprintln!("Error shutting down tracer provider: {}", e);
    }
    info!("Application shutdown complete.");
}

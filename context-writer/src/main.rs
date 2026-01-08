use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use custom_labels::v2::process_context_ext::ProcessContextTlsExt;
use custom_labels::process_context::{ProcessContext, ProcessContextWriter};
use custom_labels::v2::{self, KeyHandle};
use rand::seq::SliceRandom;
use rand::Rng;
use tracing::{info, Level};

// Configuration
const THREAD_COUNT: usize = 4;
const MAX_RECORD_SIZE: u64 = 512;
const MIN_PAUSE_MS: u64 = 100;
const MAX_PAUSE_MS: u64 = 500;

// Key indices for TLS context
const METHOD_IDX: u8 = 0;
const ROUTE_IDX: u8 = 1;
const USER_IDX: u8 = 2;

// HTTP verbs
const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

// HTTP routes
const HTTP_ROUTES: &[&str] = &[
    "/api/users",
    "/api/users/{id}",
    "/api/orders",
    "/api/orders/{id}",
    "/api/products",
    "/api/products/{id}",
    "/api/cart",
    "/api/checkout",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/health",
    "/api/metrics",
    "/api/search",
    "/api/notifications",
    "/api/settings",
];

// User names
const USERNAMES: &[&str] = &[
    "alice",
    "bob",
    "charlie",
    "diana",
    "eve",
    "frank",
    "grace",
    "henry",
    "iris",
    "jack",
    "anonymous",
];

fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Set up process-context with service info and TLS configuration
    info!("Setting up process-context");
    let ctx = ProcessContext::new()
        .with_resource("service.name", "context-writer")
        .with_resource("service.version", "1.0.0")
        .with_resource("deployment.environment", "development")
        .with_tls_config(
            [
                (METHOD_IDX, "method"),
                (ROUTE_IDX, "route"),
                (USER_IDX, "user"),
            ],
            MAX_RECORD_SIZE,
        );

    // Publish the process context (Linux only, no-op on other platforms)
    let _writer = match ProcessContextWriter::publish(&ctx) {
        Ok(w) => {
            info!("Process context published successfully");
            Some(w)
        }
        Err(e) => {
            info!("Process context publishing not available: {}", e);
            None
        }
    };

    info!("Initializing custom-labels v2 with max_record_size={}", MAX_RECORD_SIZE);
    v2::writer::setup(MAX_RECORD_SIZE);

    // Set up ctrl-c handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("Received ctrl-c, shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting ctrl-c handler");

    info!("Starting {} worker threads", THREAD_COUNT);
    info!("Press ctrl-c to stop");

    // Spawn worker threads
    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let running = running.clone();
            thread::spawn(move || {
                worker_thread(thread_id, running);
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    info!("All threads stopped, exiting");
}

fn worker_thread(thread_id: usize, running: Arc<AtomicBool>) {
    let mut rng = rand::thread_rng();

    // Create key handles
    let method_key = KeyHandle::new(METHOD_IDX);
    let route_key = KeyHandle::new(ROUTE_IDX);
    let user_key = KeyHandle::new(USER_IDX);

    // Log the TLS variable address for debugging
    let tls_addr = v2::writer::get_tls_address();
    info!(thread_id, tls_addr = ?tls_addr, "Worker thread started");

    let mut request_count = 0u64;

    while running.load(Ordering::SeqCst) {
        // Pick random HTTP traffic data
        let method = HTTP_METHODS.choose(&mut rng).unwrap();
        let route = HTTP_ROUTES.choose(&mut rng).unwrap();
        let user = USERNAMES.choose(&mut rng).unwrap();

        // Generate a fake span/trace ID
        let span_id = rng.r#gen::<u64>().to_be_bytes();
        let trace_id: [u8; 16] = rng.r#gen();
        let root_span_id: [u8; 8] = rng.r#gen();

        request_count += 1;

        info!(
            thread_id,
            request_count,
            method,
            route,
            user,
            "Attaching context"
        );

        // Attach the context to TLS
        v2::writer::set_current_record(Some(&span_id), |builder| {
            builder.set_trace(&trace_id, &span_id, &root_span_id);
            builder.set_attr_str(method_key, method).unwrap();
            builder.set_attr_str(route_key, route).unwrap();
            builder.set_attr_str(user_key, user).unwrap();
        });

        // Simulate some work with the context attached
        let work_duration = rng.gen_range(MIN_PAUSE_MS..=MAX_PAUSE_MS);
        thread::sleep(Duration::from_millis(work_duration));

        // Detach the context
        info!(
            thread_id,
            request_count,
            work_duration_ms = work_duration,
            "Detaching context"
        );
        v2::writer::clear_current_record();

        // Brief pause between requests
        let pause_duration = rng.gen_range(MIN_PAUSE_MS / 2..=MAX_PAUSE_MS / 2);
        thread::sleep(Duration::from_millis(pause_duration));
    }

    info!(thread_id, total_requests = request_count, "Worker thread stopping");
}

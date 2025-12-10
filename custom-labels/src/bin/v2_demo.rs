use anyhow::Result;
use custom_labels::v2::{self, KeyHandle};
use process_context::{tls::ProcessContextTlsExt, ProcessContext, ProcessContextWriter};
use tracing::{info, Level};

// Key indices - these define the key table layout
const ROUTE_IDX: u8 = 0;
const USER_ID_IDX: u8 = 1;

// TLS configuration
const MAX_RECORD_SIZE: u64 = 512;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Set up process-context with service info and TLS configuration.
    info!("Setting up process-context");
    let ctx = ProcessContext::new()
        // Standard OTEL resource attributes
        .with_resource("service.name", "v2-demo")
        .with_resource("service.version", "1.0.0")
        .with_resource("service.instance.id", "demo-instance-001")
        .with_resource("deployment.environment", "development")
        // TLS key table configuration
        .with_tls_config(
            [
                (ROUTE_IDX, "route"),
                (USER_ID_IDX, "user_id"),
            ],
            MAX_RECORD_SIZE,
        );

    // Publish the process context (Linux only, no-op on other platforms)
    let _writer = ProcessContextWriter::publish(&ctx);
    info!("Process context published");

    // Initialize custom-labels with max record size
    info!("Initializing custom-labels v2 with max_record_size={}", MAX_RECORD_SIZE);
    v2::setup(MAX_RECORD_SIZE);

    // Create key handles from the defined indices
    let route_key = KeyHandle::new(ROUTE_IDX);
    let user_key = KeyHandle::new(USER_ID_IDX);
    info!("Created key handles: route={}, user_id={}", route_key.index(), user_key.index());

    // Great! Now we're doing _actual context work_.
    // Imagine we've just entered a span ...
    info!("Entering Span 123!");

    // The tracer hooks context attach to the thread, and immediately
    // copies the _relevant bits_ over to our CustomLabels type.
    // TL is null during the build, then set to the new record.
    let span_123_id = 123u64.to_be_bytes();
    v2::set_current_record(Some(&span_123_id), |b| {
        b.set_trace(&[0xAA; 16], &span_123_id, &[0xCC; 8]);
        b.set_attr_str(route_key, "/api/users").unwrap();
        b.set_attr_str(user_key, "user-123").unwrap();
    });

    // A new span appears on the thread! Let's attach it.
    info!("Entering span 456!");
    let span_456_id = 456u64.to_be_bytes();
    v2::set_current_record(Some(&span_456_id), |b| {
        b.set_trace(&[0x11; 16], &span_456_id, &[0x33; 8]);
        b.set_attr_str(route_key, "/api/orders").unwrap();
    });

    // Span 123 is back again!
    info!("Back into span 123!");
    let span_123_again_id = 123u64.to_be_bytes();
    v2::set_current_record(Some(&span_123_again_id), |b| {
        b.set_trace(&[0xAA; 16], &span_123_again_id, &[0xCC; 8]);
        b.set_attr_str(route_key, "/api/users").unwrap();
        b.set_attr_str(user_key, "user-123").unwrap();
    });

    // Now everything's done.
    // We tell the library it can clear up our spans ...

    // Span 456 completes
    info!("Completing span 456!");
    v2::release_context(&span_456_id);

    // Span 123 completes
    info!("Completing span 123!");
    v2::clear_current_record();
    v2::release_context(&span_123_id);

    info!("done");

    Ok(())
}

use anyhow::Result;
use custom_labels::v2::{self, ProcessConfigBuilder};
use tracing::{info, Level};

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Process-level setup: register keys and initialize.
    // The tracing library would do this on load.
    info!("initializing process config");
    let mut config = ProcessConfigBuilder::new(512);  // max_record_size
    let route_key = config.register_key("route")?;
    let user_key = config.register_key("user_id")?;
    config.init()?;
    info!("process initialized with keys: route={}, user_id={}", route_key.index(), user_key.index());

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
    // You can imagine that we're calling this method with the fields referenced
    // straight off of the context. Because the TL library in this instance can
    // cache for us by the span_id key, the lambda would not be invoked, and the
    // reattach devolves to a simple update of the TL to point to the cached context
    // record.
    // IRL we've not implemented the caching, but you get the point ...
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

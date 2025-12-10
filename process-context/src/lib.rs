//! Process Context Library
//!
//! A Rust port of the OpenTelemetry process context sharing mechanism.
//! This library allows processes to publish context information that can be
//! discovered by external profilers and observability tools.
//!
//! # Platform Support
//!
//! This library only supports Linux. On other platforms, the writer and reader
//! functions will return `Error::PlatformNotSupported`.
//!
//! # Example
//!
//! ```no_run
//! use process_context::{ProcessContext, ProcessContextWriter, read_process_context};
//!
//! // Create and publish a process context with generic key-value resources
//! let ctx = ProcessContext::new()
//!     .with_resource("service.name", "my-service")
//!     .with_resource("service.version", "1.0.0")
//!     .with_resource("service.instance.id", "instance-abc123")
//!     .with_resource("deployment.environment", "production");
//!
//! let writer = ProcessContextWriter::publish(&ctx).expect("failed to publish");
//!
//! // Read the context back (for debugging/testing)
//! let read_ctx = read_process_context().expect("failed to read");
//!
//! // Context is automatically unpublished when writer is dropped
//! drop(writer);
//! ```
//!
//! # Wire Format
//!
//! The process context is stored in an anonymous memory mapping with the following format:
//!
//! | Offset | Size | Content |
//! |--------|------|---------|
//! | 0 | 8 | Signature "OTEL_CTX" |
//! | 8 | 4 | Version (currently 2) |
//! | 12 | 4 | Payload size |
//! | 16 | 8 | Published timestamp (nanoseconds since epoch) |
//! | 24 | 8 | Pointer to payload |
//!
//! The payload is encoded using a minimal protobuf format compatible with the
//! OpenTelemetry Resource message.

pub mod encoding;
pub mod model;
pub mod reader;
pub mod tls;
pub mod writer;

// Re-export main types for convenience
pub use model::{Error, KeyValue, ProcessContext, Result};
pub use reader::read_process_context;
pub use writer::ProcessContextWriter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = ProcessContext::new()
            .with_resource("service.name", "test-service")
            .with_resource("service.version", "1.0.0")
            .with_resource("custom.key", "custom.value");

        assert_eq!(ctx.resources.len(), 3);
        assert_eq!(ctx.resources[0].key, "service.name");
        assert_eq!(ctx.resources[0].value, "test-service");
        assert_eq!(ctx.resources[1].key, "service.version");
        assert_eq!(ctx.resources[1].value, "1.0.0");
        assert_eq!(ctx.resources[2].key, "custom.key");
        assert_eq!(ctx.resources[2].value, "custom.value");
    }

    #[test]
    fn test_encoding_roundtrip() {
        let ctx = ProcessContext::new()
            .with_resource("service.name", "my-service")
            .with_resource("service.version", "2.0.0")
            .with_resource("foo", "bar")
            .with_resource("baz", "qux");

        let encoded = encoding::encode(&ctx).unwrap();
        let decoded = encoding::decode(&encoded).unwrap();

        assert_eq!(ctx, decoded);
    }
}

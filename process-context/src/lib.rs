pub mod encoding;
pub mod model;
pub mod reader;
pub mod tls;
pub mod writer;

// Re-export main types for convenience
pub use model::{Error, KeyValue, ProcessContext, Result};
pub use reader::{read_process_context, read_process_context_from_pid};
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

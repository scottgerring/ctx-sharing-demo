mod encoding;
mod model;
mod reader;
mod writer;

// Re-export main types for convenience
pub use model::{Error, KeyValue, ProcessContext, Result, Value};
pub use reader::{read_process_context, read_process_context_from_pid};
pub use writer::ProcessContextWriter;

#[cfg(test)]
mod tests {
    use super::*;

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

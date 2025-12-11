// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::writer::{ContextLabelWriter, ExtractedSpanData};

/// Debug writer to dd-trace-rs logging subsytem
#[derive(Debug, Clone, Copy, Default)]
pub struct LoggingContextWriter;

impl LoggingContextWriter {
    /// Create a new LoggingContextWriter
    pub fn new() -> Self {
        Self
    }
}

impl ContextLabelWriter for LoggingContextWriter {
    fn write_labels(&self, data: &ExtractedSpanData) {
        dd_trace::dd_debug!(
            "trace context entered: trace_id={:032x}, span_id={:016x}, local_root_span_id={:016x}{}",
            u128::from_be_bytes(data.trace_id),
            u64::from_be_bytes(data.span_id),
            u64::from_be_bytes(data.local_root_span_id),
            data.http_route
                .map(|route| format!(", http_route={}", route))
                .unwrap_or_default()
        );
    }

    fn clear_labels(&self) {
        dd_trace::dd_debug!("trace context cleared");
    }
}

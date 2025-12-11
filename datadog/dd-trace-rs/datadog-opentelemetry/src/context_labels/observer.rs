// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::writer::{ContextLabelWriter, ExtractedSpanData};
use crate::TraceRegistry;
use opentelemetry::trace::TraceContextExt;
use opentelemetry::{context::ContextObserver, Context};

/// Observer that extracts trace context and writes labels on context changes
/// This is glue between OTel's ContextWriter and a configurable writer.
/// This makes it easy for us to plug in a debugging impl while we are hacking
/// about.
pub struct ContextLabelObserver<W> {
    writer: W,
    registry: TraceRegistry,
}

impl<W: ContextLabelWriter> ContextLabelObserver<W> {
    /// Create a new observer with the given writer and registry
    pub fn new(writer: W, registry: TraceRegistry) -> Self {
        Self { writer, registry }
    }

    /// Write trace context from an OTel context using zero-copy access
    ///
    /// Returns `false` if:
    /// - The context has no active span
    /// - The span context is invalid
    /// - The span is not sampled
    ///
    fn write_trace_context(&self, ctx: &Context) -> bool {
        if !ctx.has_active_span() {
            return false;
        }

        let span = ctx.span();
        let span_context = span.span_context();

        // Only export valid, sampled spans to reduce overhead
        if !span_context.is_valid() || !span_context.is_sampled() {
            return false;
        }

        let trace_id = span_context.trace_id().to_bytes();
        let span_id = span_context.span_id().to_bytes();

        // Get local root span ID from registry, falling back to current span ID if not available
        let local_root_span_id = self
            .registry
            .get_local_root_span_id(trace_id)
            .unwrap_or(span_id);

        // Use callback API for zero-copy access to metadata
        #[cfg(feature = "active-span-metadata")]
        {
            self.registry.with_extracted_span_data(
                trace_id,
                span_id,
                local_root_span_id,
                |http_route| {
                    let data = ExtractedSpanData {
                        trace_id,
                        span_id,
                        local_root_span_id,
                        http_route,
                    };
                    self.writer.write_labels(&data);
                },
            );
        }

        #[cfg(not(feature = "active-span-metadata"))]
        {
            let data = ExtractedSpanData {
                trace_id,
                span_id,
                local_root_span_id,
                http_route: None,
            };
            self.writer.write_labels(&data);
        }

        true
    }
}

impl<W: ContextLabelWriter> ContextObserver for ContextLabelObserver<W> {
    /// Called when entering a new context
    fn on_context_enter(&self, _from: &Context, to: &Context) {
        if !self.write_trace_context(to) {
            // No active span in the new context, clear labels
            self.writer.clear_labels();
        }
    }

    /// Called when exiting to a previous context
    fn on_context_exit(&self, _from: &Context, to: &Context) {
        if !self.write_trace_context(to) {
            // Returning to a context with no active span, clear labels
            self.writer.clear_labels();
        }
    }
}

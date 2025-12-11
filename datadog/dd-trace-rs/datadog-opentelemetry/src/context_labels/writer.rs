// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

/// Extracted span data with zero-copy access to trace information
///
/// This struct provides borrowed access to raw trace and span IDs,
/// avoiding allocations and cloning in the context switch hot path.
/// Writers are responsible for formatting IDs as needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractedSpanData<'a> {
    /// Full trace ID as 128-bit integer (16 bytes)
    pub trace_id: [u8; 16],

    /// Current span ID as 64-bit integer (8 bytes)
    pub span_id: [u8; 8],

    /// Local root span ID - the topmost span within this service for this trace
    pub local_root_span_id: [u8; 8],

    /// HTTP route (e.g., "/do_work")
    /// Capturing this as an example of something that will sometimes
    /// be there and will be useful on the reader side to make sense
    /// of the captured thread local data, even in the absence of
    /// a sampled trace to correlate to.
    pub http_route: Option<&'a str>,
}

/// A thing that consumes ExtractedSpanData and writes it out someplace. Typically this
/// someplace would be our polarsignals TL impl, or the console!
pub trait ContextLabelWriter: Send + Sync + 'static {
    /// Write labels. This is called every time we enter an OTel context, so
    /// impls should be snappy.
    ///
    /// The data parameter provides zero-copy borrowed access to pre-formatted
    /// trace IDs and metadata, avoiding allocations in the hot path.
    fn write_labels(&self, data: &ExtractedSpanData);

    /// Clear all labels
    ///
    /// Called when we leave a context and no active context remains.
    fn clear_labels(&self);
}

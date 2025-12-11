// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::writer::{ContextLabelWriter, ExtractedSpanData};
use custom_labels::v2::KeyHandle;
use custom_labels::v2::writer::{setup, set_current_record, clear_current_record};

/// Key index for http_route in the v2 key table
const HTTP_ROUTE_KEY_INDEX: u8 = 0;

/// Max record size for v2 TLS records
const V2_MAX_RECORD_SIZE: u64 = 512;

/// Writer implementation using Polar Signals custom-labels TL lib.
/// Writes to both v1 (labelset) and v2 (TLS record) formats.
#[cfg(feature = "context-observer")]
pub struct CustomLabelsWriter {
    /// KeyHandle for http_route attribute in v2 format
    http_route_key: KeyHandle,
}

#[cfg(feature = "context-observer")]
impl CustomLabelsWriter {
    /// Create a new CustomLabelsWriter and initialize v2 context sharing
    pub fn new() -> Self {
        // Initialize v2 with max record size
        setup(V2_MAX_RECORD_SIZE);
        dd_trace::dd_info!(
            "Initialized custom-labels v2 with max_record_size={}",
            V2_MAX_RECORD_SIZE
        );

        // Publish ProcessContext with TLS config for profiler discovery
        Self::publish_process_context();

        Self {
            http_route_key: KeyHandle::new(HTTP_ROUTE_KEY_INDEX),
        }
    }

    /// Publish the ProcessContext with TLS configuration
    fn publish_process_context() {
        use custom_labels::process_context::{ProcessContext, ProcessContextWriter};
        use custom_labels::v2::process_context_ext::ProcessContextTlsExt;

        // Build key table: only custom attributes (trace IDs are first-class in v2)
        let keys = [(HTTP_ROUTE_KEY_INDEX, "http_route")];

        let ctx = ProcessContext::new()
            .with_resource("service.name", "datadog-otel")
            .with_tls_config(keys, V2_MAX_RECORD_SIZE);

        match ProcessContextWriter::publish(&ctx) {
            Ok(writer) => {
                // Keep the writer alive by leaking it - it needs to persist for the process lifetime
                Box::leak(Box::new(writer));
                dd_trace::dd_info!("Published ProcessContext with v2 TLS config");
            }
            Err(e) => {
                dd_trace::dd_error!("Failed to publish ProcessContext: {}", e);
            }
        }
    }

    /// Write v1 labels using the labelset API
    fn write_v1_labels(&self, data: &ExtractedSpanData) {
        // Initialize the labelset if it doesn't exist for this thread yet
        unsafe {
            if custom_labels::sys::labelset_current().is_null() {
                let l = custom_labels::sys::labelset_new(0);
                if l.is_null() {
                    dd_trace::dd_error!("Failed to allocate v1 labelset");
                    return;
                }
                custom_labels::sys::labelset_replace(l);
            }
        }

        let labelset = &custom_labels::CURRENT_LABELSET;
        labelset.set("trace_id", &data.trace_id[..]);
        labelset.set("span_id", &data.span_id[..]);
        labelset.set("local_root_span_id", &data.local_root_span_id[..]);

        if let Some(route) = data.http_route {
            labelset.set("http_route", route);
        }
    }

    /// Clear v1 labels
    fn clear_v1_labels(&self) {
        unsafe {
            if custom_labels::sys::labelset_current().is_null() {
                return;
            }
        }

        let labelset = &custom_labels::CURRENT_LABELSET;
        labelset.delete("trace_id");
        labelset.delete("span_id");
        labelset.delete("local_root_span_id");
        labelset.delete("http_route");
    }

    /// Write v2 record using the TLS record API
    fn write_v2_record(&self, data: &ExtractedSpanData) {
        let http_route_key = self.http_route_key;
        let trace_id = data.trace_id;
        let span_id = data.span_id;
        let local_root_span_id = data.local_root_span_id;

        set_current_record(Some(&span_id), move |builder| {
            builder.set_trace(&trace_id, &span_id, &local_root_span_id);
            if let Some(route) = data.http_route {
                let _ = builder.set_attr_str(http_route_key, route);
            };
        });
    }

    /// Clear v2 record
    fn clear_v2_record(&self) {
        clear_current_record();
    }
}

#[cfg(feature = "context-observer")]
impl Default for CustomLabelsWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "context-observer")]
impl ContextLabelWriter for CustomLabelsWriter {
    fn write_labels(&self, data: &ExtractedSpanData) {
        let thread_id = std::thread::current().id();
        dd_trace::dd_debug!(
            "write_labels on thread {:?} - trace_id={:032x}, span_id={:016x}",
            thread_id,
            u128::from_be_bytes(data.trace_id),
            u64::from_be_bytes(data.span_id)
        );

        // Write to both v1 and v2 formats
        self.write_v1_labels(data);
        self.write_v2_record(data);

        dd_trace::dd_debug!("Labels written to v1 and v2");
    }

    fn clear_labels(&self) {
        dd_trace::dd_debug!("clear_labels called");

        // Clear both v1 and v2
        self.clear_v1_labels();
        self.clear_v2_record();

        dd_trace::dd_debug!("Labels cleared from v1 and v2");
    }
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod observer;
mod writer;

#[cfg(feature = "context-observer")]
mod custom_labels_writer;

mod logging_writer;

use dd_trace::dd_debug;
pub use observer::ContextLabelObserver;
pub use writer::{ContextLabelWriter, ExtractedSpanData};

#[cfg(feature = "context-observer")]
pub use custom_labels_writer::CustomLabelsWriter;

pub use logging_writer::LoggingContextWriter;

use crate::TraceRegistry;
use opentelemetry::context::GlobalContextObserver;
use std::sync::Arc;

// Fire up context labelling with default writer
#[cfg(feature = "context-observer")]
pub fn init_custom_labels_context(registry: TraceRegistry) {
    let writer = CustomLabelsWriter::new();
    let observer = Arc::new(ContextLabelObserver::new(writer, registry));
    GlobalContextObserver::set(observer);
}

// Fire it up with a custom writer
#[cfg(feature = "context-observer")]
pub fn init_custom_labels_context_with(writer: CustomLabelsWriter, registry: TraceRegistry) {
    let observer = Arc::new(ContextLabelObserver::new(writer, registry));
    GlobalContextObserver::set(observer);
}

pub fn init_context_labels<W: ContextLabelWriter>(writer: W, registry: TraceRegistry) {
    dd_debug!("Initializing context labels observer");
    let observer = Arc::new(ContextLabelObserver::new(writer, registry));
    GlobalContextObserver::set(observer);
    dd_debug!("Context labels observer registered successfully");
}

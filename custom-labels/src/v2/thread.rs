use std::ptr::NonNull;

use super::process::{get_process_ref_data_ptr, KeyHandle};
use super::{sys, Error, Result};
use tracing::info;

/// Builder for constructing an immutable Record.
pub struct RecordBuilder {
    raw: NonNull<sys::custom_labels_v2_tl_record_t>,
}

impl RecordBuilder {
    pub fn new() -> Self {
        let raw = unsafe { sys::custom_labels_v2_record_new() };
        Self {
            raw: NonNull::new(raw).expect("failed to allocate record; is ref_data set?"),
        }
    }

    pub fn set_trace(
        &mut self,
        trace_id: &[u8; 16],
        span_id: &[u8; 8],
        root_span_id: &[u8; 8],
    ) -> &mut Self {
        unsafe {
            sys::custom_labels_v2_record_set_trace(
                self.raw.as_ptr(),
                trace_id.as_ptr(),
                span_id.as_ptr(),
                root_span_id.as_ptr(),
            )
        }
        self
    }

    pub fn set_attr(&mut self, key: KeyHandle, value: &[u8]) -> Result<&mut Self> {
        // Value length must fit in u8 (max 255)
        if value.len() > u8::MAX as usize {
            return Err(Error::ValueTooLong(value.len()));
        }

        let result = unsafe {
            sys::custom_labels_v2_record_set_attr(
                self.raw.as_ptr(),
                key.0,
                value.as_ptr() as *const _,
                value.len() as u8,
            )
        };

        if result < 0 {
            Err(Error::SetAttribute)
        } else {
            Ok(self)
        }
    }

    pub fn set_attr_str(&mut self, key: KeyHandle, value: &str) -> Result<&mut Self> {
        self.set_attr(key, value.as_bytes())
    }

    pub fn build(self) -> Record {
        let record = Record { raw: self.raw };
        std::mem::forget(self);
        record
    }
}

impl Default for RecordBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RecordBuilder {
    fn drop(&mut self) {
        unsafe { sys::custom_labels_v2_record_free(self.raw.as_ptr()) }
    }
}

/// An immutable TL record containing trace context and inline attributes.
pub struct Record {
    raw: NonNull<sys::custom_labels_v2_tl_record_t>,
}

unsafe impl Send for Record {}

impl Record {
    pub(crate) fn into_raw(self) -> *mut sys::custom_labels_v2_tl_record_t {
        let ptr = self.raw.as_ptr();
        std::mem::forget(self);
        ptr
    }

    pub(crate) unsafe fn from_raw(ptr: *mut sys::custom_labels_v2_tl_record_t) -> Option<Self> {
        NonNull::new(ptr).map(|raw| Self { raw })
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        unsafe { sys::custom_labels_v2_record_free(self.raw.as_ptr()) }
    }
}

/// Ensure the current thread's ref_data TL points to the process global.
fn ensure_thread_ref_data() {
    let process_ptr = get_process_ref_data_ptr();
    let current_ptr = unsafe { sys::custom_labels_v2_get_ref_data() };
    if current_ptr != process_ptr {
        unsafe { sys::custom_labels_v2_set_ref_data(process_ptr) };
    }
}

/// Build and set a new record on the current thread via a lambda.
/// The TL is set to null during the build, then set to the new record.
/// Returns the previous record, if any.
///
/// We could use the `ctx_key_id` parameter to return a previously created
/// instance of the context, rather than creating it anew; that way,
/// reattaching an existing span to a thread is simply updating the TL pointer.
///
/// ... for now we don't :)
#[allow(unused_variables)]
pub fn set_current_record<F>(ctx_key_id: Option<&[u8; 8]>, f: F)
where
    F: FnOnce(&mut RecordBuilder),
{
    ensure_thread_ref_data();

    // 1. Detach current record (TL becomes null during update; no stale reads!)
    unsafe { sys::custom_labels_v2_set_current_record(std::ptr::null_mut()) };

    // 2. Build the new record via the lambda
    let mut builder = RecordBuilder::new();
    f(&mut builder);
    let new_record = builder.build();

    // 3. Attach the new record
    let new_ptr = new_record.into_raw();
    unsafe { sys::custom_labels_v2_set_current_record(new_ptr) };
    info!("set_current_record: TL = {:p}", new_ptr);
}

/// Attach an existing record to the current thread.
/// Returns the previous record, if any.
///
/// The `ctx_key_id` parameter is reserved for future caching (e.g., span_id).
#[allow(unused_variables)]
pub fn attach_record(ctx_key_id: Option<&[u8; 8]>, record: Record) -> Option<Record> {
    ensure_thread_ref_data();
    let old_ptr = unsafe { sys::custom_labels_v2_set_current_record(record.into_raw()) };
    unsafe { Record::from_raw(old_ptr) }
}

/// Clear the current record from the thread.
/// Returns the previous record, if any.
pub fn clear_current_record() -> Option<Record> {
    ensure_thread_ref_data();
    let old_ptr = unsafe { sys::custom_labels_v2_set_current_record(std::ptr::null_mut()) };
    unsafe { Record::from_raw(old_ptr) }
}

/// Signal that a context is complete and its resources can be released.
/// Call this when a span is closed so the library can free associated memory.
///
/// Currently a no-op; will be used for cache eviction when caching is implemented.
#[allow(unused_variables)]
pub fn release_context(ctx_key_id: &[u8; 8]) {
    // no-op!
}

/// Get the current TL record pointer (if any).
pub fn get_current_record() -> Option<*mut sys::custom_labels_v2_tl_record_t> {
    let ptr = unsafe { sys::custom_labels_v2_get_current_record() };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// Execute a function with the given record as the active record.
pub fn with_record<F, R>(record: Record, f: F) -> R
where
    F: FnOnce() -> R,
{
    struct Guard {
        old_record: Option<Record>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(record) = self.old_record.take() {
                attach_record(None, record);
            } else {
                clear_current_record();
            }
        }
    }

    let old_record = attach_record(None, record);
    let _guard = Guard { old_record };

    f()
}

/// Execute a function with the given attribute set on a new record.
pub fn with_attr<V, F, R>(key: KeyHandle, value: V, f: F) -> R
where
    V: AsRef<[u8]>,
    F: FnOnce() -> R,
{
    let mut builder = RecordBuilder::new();
    builder
        .set_attr(key, value.as_ref())
        .expect("failed to set attribute");
    with_record(builder.build(), f)
}

/// Execute a function with multiple attributes set on a new record.
pub fn with_attrs<I, V, F, R>(attrs: I, f: F) -> R
where
    I: IntoIterator<Item = (KeyHandle, V)>,
    V: AsRef<[u8]>,
    F: FnOnce() -> R,
{
    let mut builder = RecordBuilder::new();
    for (key, value) in attrs {
        builder
            .set_attr(key, value.as_ref())
            .expect("failed to set attribute");
    }
    with_record(builder.build(), f)
}

/// Execute a function with trace context and attributes set.
pub fn with_trace_and_attrs<I, V, F, R>(
    trace_id: &[u8; 16],
    span_id: &[u8; 8],
    root_span_id: &[u8; 8],
    attrs: I,
    f: F,
) -> R
where
    I: IntoIterator<Item = (KeyHandle, V)>,
    V: AsRef<[u8]>,
    F: FnOnce() -> R,
{
    let mut builder = RecordBuilder::new();
    builder.set_trace(trace_id, span_id, root_span_id);
    for (key, value) in attrs {
        builder
            .set_attr(key, value.as_ref())
            .expect("failed to set attribute");
    }
    with_record(builder.build(), f)
}

pub mod asynchronous {
    use super::*;
    use pin_project_lite::pin_project;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    pin_project! {
        pub struct LabeledV2<Fut> {
            #[pin]
            inner: Fut,
            record: Option<Record>,
        }
    }

    impl<Fut, Ret> Future for LabeledV2<Fut>
    where
        Fut: Future<Output = Ret>,
    {
        type Output = Ret;

        fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
            let this = self.project();

            if let Some(record) = this.record.take() {
                let old = attach_record(None, record);
                let result = this.inner.poll(cx);

                let current = if let Some(old_record) = old {
                    attach_record(None, old_record)
                } else {
                    clear_current_record()
                };
                if result.is_pending() {
                    *this.record = current;
                }

                result
            } else {
                this.inner.poll(cx)
            }
        }
    }

    pub trait LabelV2: Sized {
        fn with_record_v2(self, record: Record) -> LabeledV2<Self>;
        fn with_attr_v2<V: AsRef<[u8]>>(self, key: KeyHandle, value: V) -> LabeledV2<Self>;
    }

    impl<Fut: Future> LabelV2 for Fut {
        fn with_record_v2(self, record: Record) -> LabeledV2<Self> {
            LabeledV2 {
                inner: self,
                record: Some(record),
            }
        }

        fn with_attr_v2<V: AsRef<[u8]>>(self, key: KeyHandle, value: V) -> LabeledV2<Self> {
            let mut builder = RecordBuilder::new();
            builder
                .set_attr(key, value.as_ref())
                .expect("failed to set attribute");
            self.with_record_v2(builder.build())
        }
    }
}

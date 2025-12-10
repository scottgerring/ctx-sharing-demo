use thiserror::Error;

/// A key handle representing an index into the external key table.
/// The index must correspond to a key registered in the key table
/// managed by the application (e.g., stored in process-context).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub u8);

impl KeyHandle {
    /// Create a new KeyHandle from a known index.
    pub const fn new(index: u8) -> Self {
        KeyHandle(index)
    }

    /// Create a new KeyHandle from a known index (alias for new).
    pub const fn from_index(index: u8) -> Self {
        KeyHandle(index)
    }

    /// Get the index of this key handle.
    pub const fn index(&self) -> u8 {
        self.0
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("key name contains null byte")]
    KeyNameNullByte,
    #[error("failed to register key '{0}'")]
    KeyRegistration(String),
    #[error("too many keys (max 256)")]
    TooManyKeys,
    #[error("attribute value too long ({0} bytes, max 255)")]
    ValueTooLong(usize),
    #[error("failed to set attribute")]
    SetAttribute,
    #[error("process already initialized")]
    AlreadyInitialized,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Low-level bindings to the V2 C library
pub mod sys {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/bindings_v2.rs"));
}

pub mod thread;

// Re-export commonly used types at the v2 level
pub use thread::{
    asynchronous, attach_record, clear_current_record, get_current_record, max_record_size,
    release_context, set_current_record, setup, with_attr, with_attrs, with_record,
    with_trace_and_attrs, Record, RecordBuilder,
};

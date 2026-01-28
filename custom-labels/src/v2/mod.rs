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

pub mod process_context_ext;
pub mod reader;
pub mod writer;
mod error;


/// Bindings to the V2 C library
mod sys {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/bindings_v2.rs"));
}

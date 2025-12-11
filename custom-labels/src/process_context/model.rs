use std::fmt;

/// Maximum size for keys and values (matching C implementation)
pub const KEY_VALUE_LIMIT: usize = 4096;

/// Maximum varint value (14 bits)
pub const UINT14_MAX: u16 = 16383;

/// Current version of the process context format
pub const PROCESS_CTX_VERSION: u32 = 2;

/// Signature bytes for identifying process context mappings
pub const SIGNATURE: &[u8; 8] = b"OTEL_CTX";

/// A key-value pair for resource attributes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

impl KeyValue {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Process context data that can be published and read.
///
/// This is a simple collection of key-value resource attributes.
/// Use `with_resource` to add any attribute you need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessContext {
    pub resources: Vec<KeyValue>,
}

impl ProcessContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resource attribute (key-value pair).
    pub fn with_resource(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.resources.push(KeyValue::new(key, value));
        self
    }
}

/// Errors that can occur during process context operations
#[derive(Debug)]
pub enum Error {
    /// Failed to create or manage memory mapping
    MappingFailed(String),
    /// Failed to encode process context data
    EncodingFailed(String),
    /// Failed to decode process context data
    DecodingFailed(String),
    /// No process context was found
    NotFound,
    /// An I/O error occurred
    IoError(std::io::Error),
    /// A string exceeded the maximum allowed length
    StringTooLong { field: String, len: usize },
    /// Platform not supported
    PlatformNotSupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MappingFailed(msg) => write!(f, "mapping failed: {}", msg),
            Error::EncodingFailed(msg) => write!(f, "encoding failed: {}", msg),
            Error::DecodingFailed(msg) => write!(f, "decoding failed: {}", msg),
            Error::NotFound => write!(f, "no process context found"),
            Error::IoError(e) => write!(f, "I/O error: {}", e),
            Error::StringTooLong { field, len } => {
                write!(f, "string too long: {} has length {} (max {})", field, len, KEY_VALUE_LIMIT)
            }
            Error::PlatformNotSupported => write!(f, "platform not supported (Linux only)"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

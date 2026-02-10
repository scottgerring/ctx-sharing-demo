use std::fmt;
use thiserror::Error;

/// Maximum size for keys and values
pub const KEY_VALUE_LIMIT: usize = 4096;

/// Maximum varint value (14 bits)
pub const UINT14_MAX: u16 = 16383;

/// Current version of the process context format
pub const PROCESS_CTX_VERSION: u32 = 2;

/// Signature bytes for identifying process context mappings
pub const SIGNATURE: &[u8; 8] = b"OTEL_CTX";

/// Value types for resource attributes (subset of OTEL AnyValue)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// String value (AnyValue.string_value)
    String(String),
    /// Integer value (AnyValue.int_value)
    Int(i64),
    /// Key-value list (AnyValue.kvlist_value)
    KvList(Vec<KeyValue>),
    /// Array value (AnyValue.array_value)
    Array(Vec<Value>),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}

impl From<i32> for Value {
    fn from(i: i32) -> Self {
        Value::Int(i as i64)
    }
}

impl From<u64> for Value {
    fn from(i: u64) -> Self {
        Value::Int(i as i64)
    }
}

impl From<Vec<KeyValue>> for Value {
    fn from(kvs: Vec<KeyValue>) -> Self {
        Value::KvList(kvs)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Value {
    /// Returns the string value if this is a `Value::String`, otherwise `None`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the int value if this is a `Value::Int`, otherwise `None`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the kvlist value if this is a `Value::KvList`, otherwise `None`.
    pub fn as_kvlist(&self) -> Option<&[KeyValue]> {
        match self {
            Value::KvList(kvs) => Some(kvs.as_slice()),
            _ => None,
        }
    }

    /// Returns the array value if this is a `Value::Array`, otherwise `None`.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }
}

/// A key-value pair for resource attributes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key: String,
    pub value: Value,
}

impl KeyValue {
    pub fn new(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Create a string key-value pair
    pub fn string(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: Value::String(value.into()),
        }
    }

    /// Create an integer key-value pair
    pub fn int(key: impl Into<String>, value: i64) -> Self {
        Self {
            key: key.into(),
            value: Value::Int(value),
        }
    }

    /// Create a kvlist key-value pair
    pub fn kvlist(key: impl Into<String>, values: Vec<KeyValue>) -> Self {
        Self {
            key: key.into(),
            value: Value::KvList(values),
        }
    }
}

/// Process context data that can be published and read.
///
/// Contains OTEL resource attributes and optional extra attributes
/// for implementation-specific metadata (e.g. threadlocal config).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessContext {
    pub resources: Vec<KeyValue>,
    pub extra_attributes: Vec<KeyValue>,
}

impl ProcessContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resource attribute (key-value pair).
    pub fn with_resource(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.resources.push(KeyValue::new(key, value));
        self
    }

    /// Add an extra attribute (non-resource key-value pair).
    pub fn with_extra_attribute(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra_attributes.push(KeyValue::new(key, value));
        self
    }
}

/// Errors that can occur during process context operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("mapping failed: {0}")]
    MappingFailed(String),

    #[error("encoding failed: {0}")]
    EncodingFailed(String),

    #[error("decoding failed: {0}")]
    DecodingFailed(String),

    #[error("no process context found")]
    NotFound,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("string too long: {field} has length {len} (max {KEY_VALUE_LIMIT})")]
    StringTooLong { field: String, len: usize },

    #[error("platform not supported (Linux only)")]
    PlatformNotSupported,
}

pub type Result<T> = std::result::Result<T, Error>;

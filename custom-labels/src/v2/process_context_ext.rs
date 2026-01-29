//! Thread-Local Storage (TLS) context extension for ProcessContext.
//!
//! This module provides extension methods for configuring thread-local
//! context sharing (custom labels v2) metadata in the process context.

use crate::process_context::{ProcessContext, Value};
use tracing::info;

/// Parsed TLS configuration from a ProcessContext.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Key table mapping indices to attribute names.
    pub key_table: Vec<String>,
    /// Maximum size in bytes for TLS records.
    pub max_record_size: u64,
}

impl TlsConfig {
    /// Parse TLS configuration from a ProcessContext.
    ///
    /// Returns `None` if the required threadlocal.* resources are not present.
    pub fn from_process_context(ctx: &ProcessContext) -> Option<Self> {
        // Extract max record size (int)
        let max_record_size = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_MAX_RECORD_SIZE)
            .and_then(|r| r.value.as_int())? as u64;

        // Extract key table from array value (position = index)
        let key_map_array = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .and_then(|r| r.value.as_array())?;

        // Parse array into key table: position in array IS the index
        let key_table: Vec<String> = key_map_array
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        Some(TlsConfig {
            key_table,
            max_record_size,
        })
    }
}

/// Resource key for the TLS schema version (contains both type and version).
pub const THREADLOCAL_SCHEMA_VERSION: &str = "threadlocal.schema_version";

/// Resource key for the maximum TLS record size.
pub const THREADLOCAL_MAX_RECORD_SIZE: &str = "threadlocal.max_record_size";

/// Resource key for the attribute key map (index -> name mapping).
pub const THREADLOCAL_ATTRIBUTE_KEY_MAP: &str = "threadlocal.attribute_key_map";

/// Current schema version for TLS context sharing (includes type and version).
pub const SCHEMA_VERSION: &str = "tlsdesc_v1_dev";

/// Extension trait for ProcessContext to configure TLS context sharing.
pub trait ProcessContextTlsExt {
    /// Configure thread-local storage context sharing.
    ///
    /// This sets up the key table and max record size for TLS context sharing
    /// (custom labels v2 format). The key table maps key indices to key names,
    /// allowing profilers to decode the compact TLS records.
    ///
    fn with_tls_config<I, S>(self, keys: I, max_record_size: u64) -> Self
    where
        I: IntoIterator<Item = (u8, S)>,
        S: AsRef<str>;
}

impl ProcessContextTlsExt for ProcessContext {
    fn with_tls_config<I, S>(self, keys: I, max_record_size: u64) -> Self
    where
        I: IntoIterator<Item = (u8, S)>,
        S: AsRef<str>,
    {
        // Collect and sort keys by index
        let mut key_entries: Vec<(u8, String)> = keys
            .into_iter()
            .map(|(idx, name)| (idx, name.as_ref().to_string()))
            .collect();
        key_entries.sort_by_key(|(idx, _)| *idx);

        info!(
            num_keys = key_entries.len(),
            max_record_size = max_record_size,
            "Configuring TLS context"
        );
        for (idx, name) in &key_entries {
            info!(key_index = idx, key_name = %name, "Registered TLS key");
        }

        // Build the attribute key map as an array (position = index)
        // Format: ["http_route", "http_method", ...] where index 0 = "http_route", etc.
        let key_map: Vec<Value> = key_entries
            .iter()
            .map(|(_, name)| Value::String(name.clone()))
            .collect();

        self.with_resource(THREADLOCAL_SCHEMA_VERSION, SCHEMA_VERSION)
            .with_resource(THREADLOCAL_MAX_RECORD_SIZE, Value::Int(max_record_size as i64))
            .with_resource(THREADLOCAL_ATTRIBUTE_KEY_MAP, Value::Array(key_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_tls_config() {
        let ctx = ProcessContext::new().with_tls_config([(0, "route"), (1, "user_id")], 512);

        // Find the resources
        let schema_version = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_SCHEMA_VERSION)
            .expect("schema_version resource not found");
        let max_size = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_MAX_RECORD_SIZE)
            .expect("max_record_size resource not found");
        let key_map = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .expect("attribute_key_map resource not found");

        // Verify schema_version (now contains type+version as string)
        assert_eq!(
            schema_version.value,
            Value::String("tlsdesc_v1_dev".to_string())
        );

        // Verify max_record_size
        assert_eq!(max_size.value, Value::Int(512));

        // Verify key_map structure (now an array, position = index)
        if let Value::Array(values) = &key_map.value {
            assert_eq!(values.len(), 2);
            assert_eq!(values[0], Value::String("route".to_string()));
            assert_eq!(values[1], Value::String("user_id".to_string()));
        } else {
            panic!("expected Array for attribute_key_map");
        }
    }

    #[test]
    fn test_keys_sorted_by_index() {
        // Pass keys out of order
        let ctx =
            ProcessContext::new().with_tls_config([(2, "third"), (0, "first"), (1, "second")], 256);

        let key_map = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .expect("attribute_key_map resource not found");

        // Keys should be sorted by index (position = index)
        if let Value::Array(values) = &key_map.value {
            assert_eq!(values.len(), 3);
            assert_eq!(values[0], Value::String("first".to_string()));
            assert_eq!(values[1], Value::String("second".to_string()));
            assert_eq!(values[2], Value::String("third".to_string()));
        } else {
            panic!("expected Array for attribute_key_map");
        }
    }
}

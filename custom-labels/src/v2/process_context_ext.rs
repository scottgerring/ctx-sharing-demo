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
}

impl TlsConfig {
    /// Parse TLS configuration from a ProcessContext.
    ///
    /// Returns `None` if the required threadlocal.* resources are not present.
    pub fn from_process_context(ctx: &ProcessContext) -> Option<Self> {
        // Validate schema version matches what we understand
        let schema_version = ctx
            .extra_attributes
            .iter()
            .find(|r| r.key == THREADLOCAL_SCHEMA_VERSION)
            .and_then(|r| r.value.as_str())?;

        if schema_version != SCHEMA_VERSION {
            return None;
        }

        // Extract key table from array value (position = index) from extra_attributes
        let key_map_array = ctx
            .extra_attributes
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .and_then(|r| r.value.as_array())?;

        // Parse array into key table: position in array IS the index
        let key_table: Vec<String> = key_map_array
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        Some(TlsConfig { key_table })
    }
}

/// Resource key for the TLS schema version (contains both type and version).
pub const THREADLOCAL_SCHEMA_VERSION: &str = "threadlocal.schema_version";

/// Resource key for the attribute key map (index -> name mapping).
pub const THREADLOCAL_ATTRIBUTE_KEY_MAP: &str = "threadlocal.attribute_key_map";

/// Current schema version for TLS context sharing (includes type and version).
pub const SCHEMA_VERSION: &str = "tlsdesc_v1_dev";

/// Extension trait for ProcessContext to configure TLS context sharing.
pub trait ProcessContextTlsExt {
    /// Configure thread-local storage context sharing.
    ///
    /// This sets up the key table for TLS context sharing (custom labels v2
    /// format). The key table maps key indices to key names, allowing
    /// profilers to decode the compact TLS records.
    fn with_tls_config<I, S>(self, keys: I) -> Self
    where
        I: IntoIterator<Item = (u8, S)>,
        S: AsRef<str>;
}

impl ProcessContextTlsExt for ProcessContext {
    fn with_tls_config<I, S>(self, keys: I) -> Self
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

        self.with_extra_attribute(THREADLOCAL_SCHEMA_VERSION, SCHEMA_VERSION)
            .with_extra_attribute(THREADLOCAL_ATTRIBUTE_KEY_MAP, Value::Array(key_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_tls_config() {
        let ctx = ProcessContext::new().with_tls_config([(0, "route"), (1, "user_id")]);

        let schema_version = ctx
            .extra_attributes
            .iter()
            .find(|r| r.key == THREADLOCAL_SCHEMA_VERSION)
            .expect("schema_version not found");
        let key_map = ctx
            .extra_attributes
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .expect("attribute_key_map not found");

        // Verify schema_version
        assert_eq!(
            schema_version.value,
            Value::String("tlsdesc_v1_dev".to_string())
        );

        // Verify key_map structure (array, position = index)
        if let Value::Array(values) = &key_map.value {
            assert_eq!(values.len(), 2);
            assert_eq!(values[0], Value::String("route".to_string()));
            assert_eq!(values[1], Value::String("user_id".to_string()));
        } else {
            panic!("expected Array for attribute_key_map");
        }

        // Verify max_record_size is NOT published
        assert!(ctx
            .extra_attributes
            .iter()
            .find(|r| r.key == "threadlocal.max_record_size")
            .is_none());
    }

    #[test]
    fn test_keys_sorted_by_index() {
        // Pass keys out of order
        let ctx =
            ProcessContext::new().with_tls_config([(2, "third"), (0, "first"), (1, "second")]);

        let key_map = ctx
            .extra_attributes
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .expect("attribute_key_map not found");

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

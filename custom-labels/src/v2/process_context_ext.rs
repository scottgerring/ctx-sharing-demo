//! Thread-Local Storage (TLS) context extension for ProcessContext.
//!
//! This module provides extension methods for configuring thread-local
//! context sharing (custom labels v2) metadata in the process context.

use crate::process_context::{KeyValue, ProcessContext, Value};
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

        // Extract key table from kvlist
        let key_map_kvlist = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .and_then(|r| r.value.as_kvlist())?;

        // Parse kvlist into key table: keys are string indices "0", "1", etc.
        // Sort by index to ensure correct order
        let mut indexed_keys: Vec<(u8, String)> = key_map_kvlist
            .iter()
            .filter_map(|kv| {
                let idx: u8 = kv.key.parse().ok()?;
                let name = kv.value.as_str()?.to_string();
                Some((idx, name))
            })
            .collect();
        indexed_keys.sort_by_key(|(idx, _)| *idx);

        let key_table = indexed_keys.into_iter().map(|(_, name)| name).collect();

        Some(TlsConfig {
            key_table,
            max_record_size,
        })
    }
}

/// Resource key for the TLS schema type.
pub const THREADLOCAL_SCHEMA_TYPE: &str = "threadlocal.schema_type";

/// Resource key for the TLS schema version.
pub const THREADLOCAL_SCHEMA_VERSION: &str = "threadlocal.schema_version";

/// Resource key for the maximum TLS record size.
pub const THREADLOCAL_MAX_RECORD_SIZE: &str = "threadlocal.max_record_size";

/// Resource key for the attribute key map (index -> name mapping).
pub const THREADLOCAL_ATTRIBUTE_KEY_MAP: &str = "threadlocal.attribute_key_map";

/// Current schema type for TLS context sharing.
pub const SCHEMA_TYPE: &str = "tlsdesc";

/// Current schema version for TLS context sharing.
pub const SCHEMA_VERSION: i64 = 1;

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

        // Build the attribute key map as a kvlist
        // Format: [{ key: "0", value: "http_route" }, { key: "1", value: "http_method" }, ...]
        let key_map: Vec<KeyValue> = key_entries
            .iter()
            .map(|(idx, name)| KeyValue::string(idx.to_string(), name.clone()))
            .collect();

        self.with_resource(THREADLOCAL_SCHEMA_TYPE, SCHEMA_TYPE)
            .with_resource(THREADLOCAL_SCHEMA_VERSION, Value::Int(SCHEMA_VERSION))
            .with_resource(THREADLOCAL_MAX_RECORD_SIZE, Value::Int(max_record_size as i64))
            .with_resource(THREADLOCAL_ATTRIBUTE_KEY_MAP, Value::KvList(key_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_tls_config() {
        let ctx = ProcessContext::new()
            .with_tls_config([(0, "route"), (1, "user_id")], 512);

        // Find the resources
        let schema_type = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_SCHEMA_TYPE)
            .expect("schema_type resource not found");
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

        // Verify schema_type
        assert_eq!(schema_type.value, Value::String("tlsdesc".to_string()));

        // Verify schema_version
        assert_eq!(schema_version.value, Value::Int(1));

        // Verify max_record_size
        assert_eq!(max_size.value, Value::Int(512));

        // Verify key_map structure
        if let Value::KvList(kvs) = &key_map.value {
            assert_eq!(kvs.len(), 2);
            assert_eq!(kvs[0].key, "0");
            assert_eq!(kvs[0].value, Value::String("route".to_string()));
            assert_eq!(kvs[1].key, "1");
            assert_eq!(kvs[1].value, Value::String("user_id".to_string()));
        } else {
            panic!("expected KvList for attribute_key_map");
        }
    }

    #[test]
    fn test_keys_sorted_by_index() {
        // Pass keys out of order
        let ctx = ProcessContext::new()
            .with_tls_config([(2, "third"), (0, "first"), (1, "second")], 256);

        let key_map = ctx
            .resources
            .iter()
            .find(|r| r.key == THREADLOCAL_ATTRIBUTE_KEY_MAP)
            .expect("attribute_key_map resource not found");

        if let Value::KvList(kvs) = &key_map.value {
            assert_eq!(kvs.len(), 3);
            assert_eq!(kvs[0].key, "0");
            assert_eq!(kvs[0].value, Value::String("first".to_string()));
            assert_eq!(kvs[1].key, "1");
            assert_eq!(kvs[1].value, Value::String("second".to_string()));
            assert_eq!(kvs[2].key, "2");
            assert_eq!(kvs[2].value, Value::String("third".to_string()));
        } else {
            panic!("expected KvList for attribute_key_map");
        }
    }
}

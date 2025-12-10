//! Thread-Local Storage (TLS) context extension for ProcessContext.
//!
//! This module provides extension methods for configuring thread-local
//! context sharing (custom labels v2) metadata in the process context.

use crate::ProcessContext;
use tracing::info;

/// Resource key for the TLS key table (stored as length-prefixed key names).
pub const TLS_KEY_TABLE_RESOURCE: &str = "tls.key_table";

/// Resource key for the maximum TLS record size.
pub const TLS_MAX_RECORD_SIZE_RESOURCE: &str = "tls.max_record_size";

/// Extension trait for ProcessContext to configure TLS context sharing.
pub trait ProcessContextTlsExt {
    /// Configure thread-local storage context sharing.
    ///
    /// This sets up the key table and max record size for TLS context sharing
    /// (custom labels v2 format). The key table maps key indices to key names,
    /// allowing profilers to decode the compact TLS records.
    ///
    /// # Arguments
    ///
    /// * `keys` - Iterator of (index, key_name) tuples. The index determines
    ///   the position in the key table (indices should be sequential starting from 0).
    /// * `max_record_size` - Maximum size in bytes for TLS records.
    ///
    /// # Example
    ///
    /// ```rust
    /// use process_context::{ProcessContext, tls::ProcessContextTlsExt};
    ///
    /// let ctx = ProcessContext::new()
    ///     .with_resource("service.name", "my-service")
    ///     .with_tls_config(
    ///         [(0, "route"), (1, "user_id"), (2, "request_id")],
    ///         512
    ///     );
    /// ```
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

        // Build key table in v2 format: [len:1][name:len] for each key
        let key_table = build_key_table(&key_entries);
        info!(key_table_size = key_table.len(), "Built TLS key table");

        // Encode key table as hex string for storage in resources
        let key_table_hex = hex_encode(&key_table);

        self.with_resource(TLS_KEY_TABLE_RESOURCE, key_table_hex)
            .with_resource(TLS_MAX_RECORD_SIZE_RESOURCE, max_record_size.to_string())
    }
}

/// Build a key table in the v2 format.
/// Format: [len:1][key_name:len] for each key, concatenated in index order.
fn build_key_table(keys: &[(u8, String)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (_idx, name) in keys {
        let len = name.len().min(255) as u8;
        data.push(len);
        data.extend_from_slice(&name.as_bytes()[..len as usize]);
    }
    data
}

/// Simple hex encoding (avoids external dependency).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
}

/// Decode a hex-encoded key table back to bytes.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();

    for chunk in bytes.chunks(2) {
        let high = hex_char_to_nibble(chunk[0])?;
        let low = hex_char_to_nibble(chunk[1])?;
        result.push((high << 4) | low);
    }

    Some(result)
}

fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a key table from its binary format into a list of key names.
/// Returns keys in index order.
pub fn parse_key_table(data: &[u8]) -> Vec<String> {
    let mut keys = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let len = data[offset] as usize;
        offset += 1;

        if offset + len > data.len() {
            break;
        }

        if let Ok(name) = std::str::from_utf8(&data[offset..offset + len]) {
            keys.push(name.to_string());
        }
        offset += len;
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_key_table() {
        let keys = vec![
            (0, "route".to_string()),
            (1, "user_id".to_string()),
        ];
        let table = build_key_table(&keys);

        // Expected: [5, 'r', 'o', 'u', 't', 'e', 7, 'u', 's', 'e', 'r', '_', 'i', 'd']
        assert_eq!(table.len(), 14);
        assert_eq!(table[0], 5); // length of "route"
        assert_eq!(&table[1..6], b"route");
        assert_eq!(table[6], 7); // length of "user_id"
        assert_eq!(&table[7..14], b"user_id");
    }

    #[test]
    fn test_parse_key_table() {
        let keys = vec![
            (0, "route".to_string()),
            (1, "user_id".to_string()),
        ];
        let table = build_key_table(&keys);
        let parsed = parse_key_table(&table);

        assert_eq!(parsed, vec!["route", "user_id"]);
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![0x05, b'r', b'o', b'u', b't', b'e'];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_with_tls_config() {
        let ctx = ProcessContext::new()
            .with_tls_config([(0, "route"), (1, "user_id")], 512);

        // Find the resources
        let key_table_resource = ctx.resources.iter()
            .find(|r| r.key == TLS_KEY_TABLE_RESOURCE)
            .expect("key table resource not found");
        let max_size_resource = ctx.resources.iter()
            .find(|r| r.key == TLS_MAX_RECORD_SIZE_RESOURCE)
            .expect("max record size resource not found");

        // Verify max record size
        assert_eq!(max_size_resource.value, "512");

        // Verify key table can be decoded
        let table_bytes = hex_decode(&key_table_resource.value).unwrap();
        let keys = parse_key_table(&table_bytes);
        assert_eq!(keys, vec!["route", "user_id"]);
    }
}

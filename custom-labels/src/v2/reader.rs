//! V2 TLS record parsing utilities.
//!
//! This module provides types and functions for parsing v2 TLS records
//! from raw bytes.

/// V2 TL record header size (fixed portion).
/// Layout: trace_id[16] | span_id[8] | valid[1] | _padding[1] | attrs_data_size[2]
pub const V2_HEADER_SIZE: usize = 16 + 8 + 1 + 1 + 2; // 28 bytes

/// Errors that can occur when parsing a v2 TLS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer is too small to contain a valid record.
    BufferTooSmall { expected: usize, actual: usize },
    /// The record's valid flag is not set.
    NotValid,
    /// An attribute was truncated (not enough bytes for declared length).
    TruncatedAttribute { attr_index: usize },
}

/// A parsed attribute from a v2 TLS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAttribute {
    /// Index into the key table.
    pub key_index: u8,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

/// A parsed v2 TLS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    /// 16-byte trace ID.
    pub trace_id: [u8; 16],
    /// 8-byte span ID.
    pub span_id: [u8; 8],
    /// Parsed attributes.
    pub attributes: Vec<ParsedAttribute>,
}

impl ParsedRecord {
    /// Parse a v2 TLS record from raw bytes.
    ///
    /// Returns `Err(ParseError::NotValid)` if the record's valid flag is 0.
    /// Returns `Err(ParseError::BufferTooSmall)` if the buffer is smaller than the header.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < V2_HEADER_SIZE {
            return Err(ParseError::BufferTooSmall {
                expected: V2_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // Parse header fields
        let mut trace_id = [0u8; 16];
        trace_id.copy_from_slice(&data[0..16]);

        let mut span_id = [0u8; 8];
        span_id.copy_from_slice(&data[16..24]);

        let valid = data[24];
        // data[25] is padding byte, skip it
        let attrs_data_size = u16::from_le_bytes([data[26], data[27]]);

        // If not valid, return error
        if valid == 0 {
            return Err(ParseError::NotValid);
        }

        // Parse attributes: [key_index:1][length:1][value:length]
        // Use attrs_data_size to know when to stop parsing
        let attrs_data = &data[V2_HEADER_SIZE..];
        let attrs_end = attrs_data_size as usize;
        let mut offset = 0;
        let mut attributes = Vec::new();
        let mut attr_idx = 0;

        while offset < attrs_end {
            if offset + 2 > attrs_data.len() {
                return Err(ParseError::TruncatedAttribute { attr_index: attr_idx });
            }

            let key_index = attrs_data[offset];
            let value_len = attrs_data[offset + 1] as usize;
            offset += 2;

            if offset + value_len > attrs_data.len() {
                return Err(ParseError::TruncatedAttribute { attr_index: attr_idx });
            }

            let value = attrs_data[offset..offset + value_len].to_vec();
            offset += value_len;

            attributes.push(ParsedAttribute { key_index, value });
            attr_idx += 1;
        }

        Ok(ParsedRecord {
            trace_id,
            span_id,
            attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_record() {
        let mut data = vec![0u8; 64];
        // trace_id (bytes 0-15)
        data[0..16].copy_from_slice(&[1u8; 16]);
        // span_id (bytes 16-23)
        data[16..24].copy_from_slice(&[2u8; 8]);
        // valid = 1 (byte 24)
        data[24] = 1;
        // _padding (byte 25) - implicit zero
        // attrs_data_size = 10 (2 attrs, each 5 bytes: key+len+3 bytes value)
        // bytes 26-27 (little-endian u16)
        data[26] = 10;
        data[27] = 0;
        // attr 0: key=0, len=3, value="foo" (bytes 28-32)
        data[28] = 0;
        data[29] = 3;
        data[30..33].copy_from_slice(b"foo");
        // attr 1: key=1, len=3, value="bar" (bytes 33-37)
        data[33] = 1;
        data[34] = 3;
        data[35..38].copy_from_slice(b"bar");

        let record = ParsedRecord::parse(&data).unwrap();
        assert_eq!(record.trace_id, [1u8; 16]);
        assert_eq!(record.span_id, [2u8; 8]);
        assert_eq!(record.attributes.len(), 2);
        assert_eq!(record.attributes[0].key_index, 0);
        assert_eq!(record.attributes[0].value, b"foo");
        assert_eq!(record.attributes[1].key_index, 1);
        assert_eq!(record.attributes[1].value, b"bar");
    }

    #[test]
    fn test_parse_invalid_record() {
        let mut data = vec![0u8; 64];
        data[24] = 0; // valid = 0

        let result = ParsedRecord::parse(&data);
        assert_eq!(result, Err(ParseError::NotValid));
    }

    #[test]
    fn test_parse_buffer_too_small() {
        let data = vec![0u8; 10];

        let result = ParsedRecord::parse(&data);
        assert!(matches!(result, Err(ParseError::BufferTooSmall { .. })));
    }
}

///
/// A minimal protobuf implementation of what we need for encoding
/// process-context and not much more.
///

use crate::model::{Error, KeyValue, ProcessContext, Result, KEY_VALUE_LIMIT, UINT14_MAX};

/// Wire type for length-delimited fields (strings, nested messages)
const WIRE_TYPE_LEN: u8 = 2;

/// Calculate the size of a varint encoding (1 or 2 bytes for values up to UINT14_MAX)
fn varint_size(value: u16) -> usize {
    if value >= 128 { 2 } else { 1 }
}

/// Calculate the size of a protobuf record (tag + length varint + data)
fn record_size(data_len: usize) -> usize {
    1 + varint_size(data_len as u16) + data_len
}

/// Calculate the size of a protobuf string field
fn string_size(s: &str) -> usize {
    record_size(s.len())
}

/// Calculate the size of an OTEL KeyValue message (without the outer record wrapper)
fn keyvalue_size(key: &str, value: &str) -> usize {
    let key_field_size = string_size(key);
    // Value is nested: AnyValue message containing string_value
    let value_field_size = record_size(string_size(value));
    key_field_size + value_field_size
}

/// Write a varint to the buffer (supports values up to UINT14_MAX)
fn write_varint(buf: &mut Vec<u8>, value: u16) {
    if value < 128 {
        buf.push(value as u8);
    } else {
        // Two bytes: first byte has MSB set (continuation), second has remaining bits
        buf.push((value & 0x7F) as u8 | 0x80);
        buf.push((value >> 7) as u8);
    }
}

/// Write a protobuf tag (field number + wire type)
fn write_tag(buf: &mut Vec<u8>, field_number: u8) {
    buf.push((field_number << 3) | WIRE_TYPE_LEN);
}

/// Write a protobuf string field
fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as u16);
    buf.extend_from_slice(s.as_bytes());
}

/// Write a complete attribute (Resource.attributes field)
fn write_attribute(buf: &mut Vec<u8>, key: &str, value: &str) {
    // Resource.attributes (field 1) - KeyValue message
    write_tag(buf, 1);
    write_varint(buf, keyvalue_size(key, value) as u16);

    // KeyValue.key (field 1)
    write_tag(buf, 1);
    write_string(buf, key);

    // KeyValue.value (field 2) - AnyValue message
    write_tag(buf, 2);
    write_varint(buf, string_size(value) as u16);

    // AnyValue.string_value (field 1)
    write_tag(buf, 1);
    write_string(buf, value);
}

/// Validate a key-value pair
fn validate_kv(key: &str, value: &str) -> Result<()> {
    if key.len() > KEY_VALUE_LIMIT {
        return Err(Error::StringTooLong {
            field: key.to_string(),
            len: key.len(),
        });
    }
    if value.len() > KEY_VALUE_LIMIT {
        return Err(Error::StringTooLong {
            field: format!("value for '{}'", key),
            len: value.len(),
        });
    }
    Ok(())
}

/// Encode a ProcessContext to protobuf bytes
pub fn encode(ctx: &ProcessContext) -> Result<Vec<u8>> {
    // Validate all resources
    for kv in &ctx.resources {
        validate_kv(&kv.key, &kv.value)?;
    }

    // Calculate total size for pre-allocation
    let total_size: usize = ctx.resources
        .iter()
        .map(|kv| record_size(keyvalue_size(&kv.key, &kv.value)))
        .sum();

    let mut buf = Vec::with_capacity(total_size);

    // Write all attributes
    for kv in &ctx.resources {
        write_attribute(&mut buf, &kv.key, &kv.value);
    }

    Ok(buf)
}

/// Reader state for decoding
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::DecodingFailed("unexpected end of data".to_string()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_varint(&mut self) -> Result<u16> {
        let first = self.read_byte()?;
        if first < 128 {
            Ok(first as u16)
        } else {
            let second = self.read_byte()?;
            let value = ((first & 0x7F) as u16) | ((second as u16) << 7);
            if value > UINT14_MAX {
                return Err(Error::DecodingFailed("varint too large".to_string()));
            }
            Ok(value)
        }
    }

    fn read_tag(&mut self) -> Result<u8> {
        let tag = self.read_byte()?;
        let wire_type = tag & 0x07;
        if wire_type != WIRE_TYPE_LEN {
            return Err(Error::DecodingFailed(format!(
                "unexpected wire type: {} (expected {})",
                wire_type, WIRE_TYPE_LEN
            )));
        }
        Ok(tag >> 3)
    }

    fn read_string(&mut self) -> Result<String> {
        let len = self.read_varint()? as usize;
        if len > KEY_VALUE_LIMIT {
            return Err(Error::DecodingFailed("string too long".to_string()));
        }
        if self.pos + len > self.data.len() {
            return Err(Error::DecodingFailed("string extends past end".to_string()));
        }
        let s = std::str::from_utf8(&self.data[self.pos..self.pos + len])
            .map_err(|_| Error::DecodingFailed("invalid UTF-8".to_string()))?
            .to_string();
        self.pos += len;
        Ok(s)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(Error::DecodingFailed("bytes extend past end".to_string()));
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }
}

/// Decode protobuf bytes to a ProcessContext
pub fn decode(data: &[u8]) -> Result<ProcessContext> {
    let mut ctx = ProcessContext::new();
    let mut reader = Reader::new(data);

    while reader.remaining() > 0 {
        // Read Resource.attributes field (must be field 1)
        let field_number = reader.read_tag()?;
        if field_number != 1 {
            return Err(Error::DecodingFailed(format!(
                "unexpected field number: {} (expected 1)",
                field_number
            )));
        }

        // Read KeyValue message length and content
        let kv_len = reader.read_varint()? as usize;
        let kv_end = reader.pos + kv_len;
        if kv_end > reader.data.len() {
            return Err(Error::DecodingFailed("KeyValue extends past end".to_string()));
        }

        let mut key: Option<String> = None;
        let mut value: Option<String> = None;

        // Parse KeyValue fields
        while reader.pos < kv_end {
            let kv_field = reader.read_tag()?;
            match kv_field {
                1 => {
                    // KeyValue.key
                    key = Some(reader.read_string()?);
                }
                2 => {
                    // KeyValue.value (AnyValue message)
                    let any_len = reader.read_varint()? as usize;
                    let any_end = reader.pos + any_len;
                    if any_end > reader.data.len() {
                        return Err(Error::DecodingFailed("AnyValue extends past end".to_string()));
                    }

                    // Read AnyValue.string_value (field 1)
                    let any_field = reader.read_tag()?;
                    if any_field == 1 {
                        value = Some(reader.read_string()?);
                    } else {
                        // Skip unknown fields in AnyValue
                        let skip_len = reader.read_varint()? as usize;
                        reader.read_bytes(skip_len)?;
                    }

                    // Ensure we consumed the full AnyValue
                    reader.pos = any_end;
                }
                _ => {
                    // Skip unknown fields
                    let skip_len = reader.read_varint()? as usize;
                    reader.read_bytes(skip_len)?;
                }
            }
        }

        // Ensure we consumed exactly the KeyValue length
        reader.pos = kv_end;

        // Process the key-value pair
        let key = key.ok_or_else(|| Error::DecodingFailed("missing key".to_string()))?;
        let value = value.ok_or_else(|| Error::DecodingFailed("missing value".to_string()))?;

        ctx.resources.push(KeyValue::new(key, value));
    }

    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_minimal() {
        let ctx = ProcessContext::new();
        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_full() {
        let ctx = ProcessContext::new()
            .with_resource("service.name", "my-service")
            .with_resource("service.version", "1.2.3")
            .with_resource("deployment.environment", "production")
            .with_resource("custom.key", "custom-value");

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_string_too_long() {
        let long_string = "x".repeat(KEY_VALUE_LIMIT + 1);
        let ctx = ProcessContext::new().with_resource("key", long_string);
        let result = encode(&ctx);
        assert!(matches!(result, Err(Error::StringTooLong { .. })));
    }

    #[test]
    fn test_varint_encoding() {
        // Test single-byte varint
        let mut buf = Vec::new();
        write_varint(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        // Test two-byte varint
        buf.clear();
        write_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        // Test larger two-byte varint
        buf.clear();
        write_varint(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]); // 300 = 0x12C = (44 | 0x80), (2)
    }
}

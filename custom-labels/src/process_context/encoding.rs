///
/// A minimal protobuf implementation for encoding/decoding OTEL process-context.
/// Supports string, int64, and kvlist value types.
///

use super::model::{Error, KeyValue, ProcessContext, Result, Value, KEY_VALUE_LIMIT, UINT14_MAX};

/// Wire type for varint fields (int64, uint64, int32, etc.)
const WIRE_TYPE_VARINT: u8 = 0;
/// Wire type for length-delimited fields (strings, bytes, nested messages)
const WIRE_TYPE_LEN: u8 = 2;

// =============================================================================
// Varint encoding/decoding
// =============================================================================

/// Calculate the size of a varint encoding for u16 (1 or 2 bytes for values up to UINT14_MAX)
fn varint_size(value: u16) -> usize {
    if value >= 128 { 2 } else { 1 }
}

/// Write a varint to the buffer (supports values up to UINT14_MAX)
fn write_varint(buf: &mut Vec<u8>, value: u16) {
    if value < 128 {
        buf.push(value as u8);
    } else {
        buf.push((value & 0x7F) as u8 | 0x80);
        buf.push((value >> 7) as u8);
    }
}

/// Write an i64 as a varint. For positive values this is efficient.
/// Negative values require 10 bytes (two's complement), but we don't use them.
fn write_varint_i64(buf: &mut Vec<u8>, value: i64) {
    debug_assert!(value >= 0, "negative int64 values not supported");
    let mut v = value as u64;
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

// =============================================================================
// Tag encoding/decoding
// =============================================================================

/// Write a protobuf tag with wire type VARINT
fn write_tag_varint(buf: &mut Vec<u8>, field_number: u8) {
    buf.push((field_number << 3) | WIRE_TYPE_VARINT);
}

/// Write a protobuf tag with wire type LEN (length-delimited)
fn write_tag_len(buf: &mut Vec<u8>, field_number: u8) {
    buf.push((field_number << 3) | WIRE_TYPE_LEN);
}

// =============================================================================
// String encoding
// =============================================================================

/// Calculate the size of a protobuf string field (length varint + bytes)
fn string_field_size(s: &str) -> usize {
    varint_size(s.len() as u16) + s.len()
}

/// Write a protobuf string (length + bytes, without tag)
fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as u16);
    buf.extend_from_slice(s.as_bytes());
}

// =============================================================================
// AnyValue encoding
// =============================================================================

/// Encode an AnyValue message to bytes
fn encode_anyvalue(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    match value {
        Value::String(s) => {
            // string_value = field 1, wire type LEN
            write_tag_len(&mut buf, 1);
            write_string(&mut buf, s);
        }
        Value::Int(i) => {
            // int_value = field 3, wire type VARINT
            write_tag_varint(&mut buf, 3);
            write_varint_i64(&mut buf, *i);
        }
        Value::Array(values) => {
            // array_value = field 5, wire type LEN
            let array_bytes = encode_arrayvalue(values);
            write_tag_len(&mut buf, 5);
            write_varint(&mut buf, array_bytes.len() as u16);
            buf.extend(array_bytes);
        }
        Value::KvList(kvs) => {
            // kvlist_value = field 6, wire type LEN
            let kvlist_bytes = encode_kvlist(kvs);
            write_tag_len(&mut buf, 6);
            write_varint(&mut buf, kvlist_bytes.len() as u16);
            buf.extend(kvlist_bytes);
        }
    }
    buf
}

/// Encode an ArrayValue message to bytes
fn encode_arrayvalue(values: &[Value]) -> Vec<u8> {
    let mut buf = Vec::new();
    for val in values {
        // ArrayValue.values = field 1, wire type LEN
        let val_bytes = encode_anyvalue(val);
        write_tag_len(&mut buf, 1);
        write_varint(&mut buf, val_bytes.len() as u16);
        buf.extend(val_bytes);
    }
    buf
}

/// Encode a KeyValueList message to bytes
fn encode_kvlist(kvs: &[KeyValue]) -> Vec<u8> {
    let mut buf = Vec::new();
    for kv in kvs {
        // KeyValueList.values = field 1, wire type LEN
        let kv_bytes = encode_keyvalue(kv);
        write_tag_len(&mut buf, 1);
        write_varint(&mut buf, kv_bytes.len() as u16);
        buf.extend(kv_bytes);
    }
    buf
}

/// Encode a KeyValue message to bytes
fn encode_keyvalue(kv: &KeyValue) -> Vec<u8> {
    let mut buf = Vec::new();

    // KeyValue.key = field 1, wire type LEN
    write_tag_len(&mut buf, 1);
    write_string(&mut buf, &kv.key);

    // KeyValue.value = field 2, wire type LEN (AnyValue message)
    let anyvalue_bytes = encode_anyvalue(&kv.value);
    write_tag_len(&mut buf, 2);
    write_varint(&mut buf, anyvalue_bytes.len() as u16);
    buf.extend(anyvalue_bytes);

    buf
}

// =============================================================================
// Validation
// =============================================================================

/// Validate a value recursively
fn validate_value(key: &str, value: &Value) -> Result<()> {
    match value {
        Value::String(s) => {
            if s.len() > KEY_VALUE_LIMIT {
                return Err(Error::StringTooLong {
                    field: format!("value for '{}'", key),
                    len: s.len(),
                });
            }
        }
        Value::Int(_) => {}
        Value::Array(values) => {
            for val in values {
                validate_value(key, val)?;
            }
        }
        Value::KvList(kvs) => {
            for kv in kvs {
                validate_kv(kv)?;
            }
        }
    }
    Ok(())
}

/// Validate a key-value pair
fn validate_kv(kv: &KeyValue) -> Result<()> {
    if kv.key.len() > KEY_VALUE_LIMIT {
        return Err(Error::StringTooLong {
            field: kv.key.clone(),
            len: kv.key.len(),
        });
    }
    validate_value(&kv.key, &kv.value)
}

// =============================================================================
// Main encode function
// =============================================================================

/// Encode a ProcessContext to protobuf bytes.
///
/// The payload is a ProcessContext message:
///   field 1 (LEN): Resource { field 1 (LEN, repeated): KeyValue }
///   field 2 (LEN, repeated): KeyValue extra_attributes
pub fn encode(ctx: &ProcessContext) -> Result<Vec<u8>> {
    // Validate all resources
    for kv in &ctx.resources {
        validate_kv(kv)?;
    }
    // Validate all extra attributes
    for kv in &ctx.extra_attributes {
        validate_kv(kv)?;
    }

    let mut buf = Vec::new();

    // Encode Resource as field 1 of ProcessContext
    if !ctx.resources.is_empty() {
        let mut resource_buf = Vec::new();
        for kv in &ctx.resources {
            let kv_bytes = encode_keyvalue(kv);
            write_tag_len(&mut resource_buf, 1); // Resource.attributes = field 1
            write_varint(&mut resource_buf, kv_bytes.len() as u16);
            resource_buf.extend(kv_bytes);
        }
        write_tag_len(&mut buf, 1); // ProcessContext.resource = field 1
        write_varint(&mut buf, resource_buf.len() as u16);
        buf.extend(resource_buf);
    }

    // Encode extra_attributes as field 2 of ProcessContext (repeated)
    for kv in &ctx.extra_attributes {
        let kv_bytes = encode_keyvalue(kv);
        write_tag_len(&mut buf, 2); // ProcessContext.extra_attributes = field 2
        write_varint(&mut buf, kv_bytes.len() as u16);
        buf.extend(kv_bytes);
    }

    Ok(buf)
}

// =============================================================================
// Decoding
// =============================================================================

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

    /// Read a varint as u16 (for lengths, limited to UINT14_MAX)
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

    /// Read a varint as u64 (for int64 values)
    fn read_varint_u64(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.read_byte()?;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte < 0x80 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::DecodingFailed("varint too long".to_string()));
            }
        }
        Ok(result)
    }

    /// Read a tag and return (field_number, wire_type)
    fn read_tag_full(&mut self) -> Result<(u8, u8)> {
        let tag = self.read_byte()?;
        Ok((tag >> 3, tag & 0x07))
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

    fn skip_bytes(&mut self, len: usize) -> Result<()> {
        if self.pos + len > self.data.len() {
            return Err(Error::DecodingFailed("skip extends past end".to_string()));
        }
        self.pos += len;
        Ok(())
    }
}

/// Decode an AnyValue message
fn decode_anyvalue(reader: &mut Reader, len: usize) -> Result<Value> {
    let end = reader.pos + len;

    if reader.pos >= end {
        return Err(Error::DecodingFailed("empty AnyValue".to_string()));
    }

    let (field_number, wire_type) = reader.read_tag_full()?;

    let value = match (field_number, wire_type) {
        (1, WIRE_TYPE_LEN) => {
            // string_value
            Value::String(reader.read_string()?)
        }
        (3, WIRE_TYPE_VARINT) => {
            // int_value
            Value::Int(reader.read_varint_u64()? as i64)
        }
        (5, WIRE_TYPE_LEN) => {
            // array_value
            let array_len = reader.read_varint()? as usize;
            Value::Array(decode_arrayvalue(reader, array_len)?)
        }
        (6, WIRE_TYPE_LEN) => {
            // kvlist_value
            let kvlist_len = reader.read_varint()? as usize;
            Value::KvList(decode_kvlist(reader, kvlist_len)?)
        }
        _ => {
            return Err(Error::DecodingFailed(format!(
                "unsupported AnyValue field: {} wire_type: {}",
                field_number, wire_type
            )));
        }
    };

    // Ensure we consumed exactly the expected length
    reader.pos = end;
    Ok(value)
}

/// Decode a KeyValueList message
fn decode_kvlist(reader: &mut Reader, len: usize) -> Result<Vec<KeyValue>> {
    let end = reader.pos + len;
    let mut result = Vec::new();

    while reader.pos < end {
        let (field_number, wire_type) = reader.read_tag_full()?;
        if field_number != 1 || wire_type != WIRE_TYPE_LEN {
            return Err(Error::DecodingFailed(format!(
                "expected KeyValueList.values field, got field {} wire_type {}",
                field_number, wire_type
            )));
        }
        let kv_len = reader.read_varint()? as usize;
        let kv = decode_keyvalue(reader, kv_len)?;
        result.push(kv);
    }

    Ok(result)
}

/// Decode an ArrayValue message
fn decode_arrayvalue(reader: &mut Reader, len: usize) -> Result<Vec<Value>> {
    let end = reader.pos + len;
    let mut result = Vec::new();

    while reader.pos < end {
        let (field_number, wire_type) = reader.read_tag_full()?;
        if field_number != 1 || wire_type != WIRE_TYPE_LEN {
            return Err(Error::DecodingFailed(format!(
                "expected ArrayValue.values field, got field {} wire_type {}",
                field_number, wire_type
            )));
        }
        let val_len = reader.read_varint()? as usize;
        let val = decode_anyvalue(reader, val_len)?;
        result.push(val);
    }

    Ok(result)
}

/// Decode a KeyValue message
fn decode_keyvalue(reader: &mut Reader, len: usize) -> Result<KeyValue> {
    let end = reader.pos + len;
    let mut key: Option<String> = None;
    let mut value: Option<Value> = None;

    while reader.pos < end {
        let (field_number, wire_type) = reader.read_tag_full()?;
        match (field_number, wire_type) {
            (1, WIRE_TYPE_LEN) => {
                // KeyValue.key
                key = Some(reader.read_string()?);
            }
            (2, WIRE_TYPE_LEN) => {
                // KeyValue.value (AnyValue message)
                let any_len = reader.read_varint()? as usize;
                value = Some(decode_anyvalue(reader, any_len)?);
            }
            _ => {
                // Skip unknown fields
                if wire_type == WIRE_TYPE_LEN {
                    let skip_len = reader.read_varint()? as usize;
                    reader.skip_bytes(skip_len)?;
                } else if wire_type == WIRE_TYPE_VARINT {
                    reader.read_varint_u64()?;
                } else {
                    return Err(Error::DecodingFailed(format!(
                        "unknown wire type: {}",
                        wire_type
                    )));
                }
            }
        }
    }

    let key = key.ok_or_else(|| Error::DecodingFailed("missing key in KeyValue".to_string()))?;
    let value =
        value.ok_or_else(|| Error::DecodingFailed("missing value in KeyValue".to_string()))?;

    Ok(KeyValue { key, value })
}

/// Decode protobuf bytes to a ProcessContext.
///
/// The payload is a ProcessContext message:
///   field 1 (LEN): Resource { field 1 (LEN, repeated): KeyValue }
///   field 2 (LEN, repeated): KeyValue extra_attributes
pub fn decode(data: &[u8]) -> Result<ProcessContext> {
    let mut ctx = ProcessContext::new();
    let mut reader = Reader::new(data);

    while reader.remaining() > 0 {
        let (field_number, wire_type) = reader.read_tag_full()?;

        if wire_type != WIRE_TYPE_LEN {
            return Err(Error::DecodingFailed(format!(
                "expected LEN wire type, got wire_type {}",
                wire_type
            )));
        }

        let field_len = reader.read_varint()? as usize;

        match field_number {
            1 => {
                // ProcessContext.resource = Resource message
                let resource_end = reader.pos + field_len;
                while reader.pos < resource_end {
                    let (inner_field, inner_wire) = reader.read_tag_full()?;
                    if inner_field != 1 || inner_wire != WIRE_TYPE_LEN {
                        return Err(Error::DecodingFailed(format!(
                            "expected Resource.attributes field 1, got field {} wire_type {}",
                            inner_field, inner_wire
                        )));
                    }
                    let kv_len = reader.read_varint()? as usize;
                    let kv = decode_keyvalue(&mut reader, kv_len)?;
                    ctx.resources.push(kv);
                }
            }
            2 => {
                // ProcessContext.extra_attributes = KeyValue
                let kv = decode_keyvalue(&mut reader, field_len)?;
                ctx.extra_attributes.push(kv);
            }
            _ => {
                // Skip unknown fields
                reader.skip_bytes(field_len)?;
            }
        }
    }

    Ok(ctx)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_string_values() {
        let ctx = ProcessContext::new()
            .with_resource("service.name", "my-service")
            .with_resource("service.version", "1.2.3")
            .with_resource("deployment.environment", "production");

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_int_values() {
        let ctx = ProcessContext::new()
            .with_resource("process.pid", Value::Int(1234))
            .with_resource("host.cpu.count", Value::Int(8));

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_kvlist() {
        let kvlist = vec![
            KeyValue::string("0", "http_route"),
            KeyValue::string("1", "http_method"),
            KeyValue::string("2", "user_id"),
        ];
        let ctx = ProcessContext::new()
            .with_resource("some.kvlist", Value::KvList(kvlist));

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_array() {
        let ctx = ProcessContext::new().with_resource(
            "some.array",
            Value::Array(vec![
                Value::String("http_route".to_string()),
                Value::String("http_method".to_string()),
                Value::String("user_id".to_string()),
            ]),
        );

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_extra_attributes() {
        let ctx = ProcessContext::new()
            .with_extra_attribute("threadlocal.schema_version", "tlsdesc_v1_dev")
            .with_extra_attribute("some.int_attr", Value::Int(64));

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_resources_and_extra_attributes() {
        let ctx = ProcessContext::new()
            .with_resource("service.name", "test-service")
            .with_extra_attribute("threadlocal.schema_version", "tlsdesc_v1_dev")
            .with_extra_attribute("some.int_attr", Value::Int(64))
            .with_extra_attribute(
                "threadlocal.attribute_key_map",
                Value::Array(vec![
                    Value::String("http_route".to_string()),
                    Value::String("http_method".to_string()),
                    Value::String("user_id".to_string()),
                ]),
            );

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_empty_resources() {
        let ctx = ProcessContext::new()
            .with_extra_attribute("foo", "bar");

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_roundtrip_empty_extra_attributes() {
        let ctx = ProcessContext::new()
            .with_resource("service.name", "test");

        let encoded = encode(&ctx).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(ctx, decoded);
    }

    #[test]
    fn test_string_too_long() {
        let long_string = "x".repeat(KEY_VALUE_LIMIT + 1);
        let ctx = ProcessContext::new().with_resource("key", long_string.clone());
        assert!(matches!(encode(&ctx), Err(Error::StringTooLong { .. })));

        let ctx2 = ProcessContext::new().with_extra_attribute("key", long_string);
        assert!(matches!(encode(&ctx2), Err(Error::StringTooLong { .. })));
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
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_varint_i64_encoding() {
        let mut buf = Vec::new();
        write_varint_i64(&mut buf, 1);
        assert_eq!(buf, vec![0x01]);

        buf.clear();
        write_varint_i64(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);

        buf.clear();
        write_varint_i64(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        write_varint_i64(&mut buf, 512);
        assert_eq!(buf, vec![0x80, 0x04]);
    }
}

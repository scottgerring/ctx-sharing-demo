# Plan: Reader Integration for custom-labels

## Current State

**context-reader** does two things:
1. **TLS Location** - Symbol discovery, DTV lookup, ptrace attachment, memory reading
2. **Deserialization** - Parsing the label structures from raw bytes

**custom-labels** currently only provides:
- Writer-side API (create key tables, set records, etc.)
- No reader/deserializer support

## Goal

Split responsibilities so that:
- **context-reader** handles: TLS location, process attachment, raw memory reading
- **custom-labels** handles: Deserialization of the byte layouts it defines

This way, context-reader doesn't need to maintain its own parser that mirrors custom-labels' data structures.

---

## V2 Data Structures to Deserialize

### 1. Key Table (process-wide, read once)
```
+------------------+
| key_data_size    | uint32 - total bytes in key_data
+------------------+
| key_data[]       | variable-length entries:
|   [0].length     |   uint8 - key name length
|   [0].value      |   uint8[length] - key name bytes
|   [1].length     |   uint8
|   [1].value      |   uint8[length]
|   ...            |
+------------------+
```

### 2. Ref Data (process-wide, read once)
```
+------------------+
| schema_version   | uint8
+------------------+
| _reserved[7]     | padding
+------------------+
| key_table        | pointer (8 bytes) - address of key table
+------------------+
| max_record_size  | uint64
+------------------+
```

### 3. TL Record (per-thread, read frequently)
```
+------------------+
| trace_id[16]     | W3C trace ID
+------------------+
| span_id[8]       | W3C span ID
+------------------+
| root_span_id[8]  | local root span ID
+------------------+
| valid            | uint8 - 0 means ignore this record
+------------------+
| attrs_count      | uint8 - number of attributes
+------------------+
| attrs_data[]     | variable-length entries:
|   [0].key_index  |   uint8 - index into key table
|   [0].length     |   uint8 - value length
|   [0].value      |   uint8[length] - value bytes
|   ...            |
+------------------+
```

---

## Proposed API

### Module: `custom_labels::v2::reader`

```rust
/// Parsed key from the key table
pub struct Key<'a> {
    pub index: u8,
    pub name: &'a [u8],
}

/// Iterator over keys in a key table
pub struct KeyTableIter<'a> { ... }

/// Parse a key table from raw bytes.
/// Returns an iterator over (index, name) pairs.
pub fn parse_key_table(bytes: &[u8]) -> Result<KeyTableIter<'_>, ParseError>;

/// Get key by index (requires iteration - O(n))
pub fn get_key_by_index(bytes: &[u8], index: u8) -> Result<Option<&[u8]>, ParseError>;


/// Parsed ref_data header (pointers are addresses, not dereferenced)
pub struct RefDataHeader {
    pub schema_version: u8,
    pub key_table_addr: u64,
    pub max_record_size: u64,
}

/// Parse ref_data header from raw bytes.
pub fn parse_ref_data(bytes: &[u8]) -> Result<RefDataHeader, ParseError>;


/// Parsed attribute from a TL record
pub struct Attr<'a> {
    pub key_index: u8,
    pub value: &'a [u8],
}

/// Parsed TL record
pub struct ParsedRecord<'a> {
    pub trace_id: &'a [u8; 16],
    pub span_id: &'a [u8; 8],
    pub root_span_id: &'a [u8; 8],
    pub valid: bool,
    pub attrs: Vec<Attr<'a>>,
}

/// Parse a TL record from raw bytes.
/// `max_size` is the buffer size (from ref_data.max_record_size).
pub fn parse_record(bytes: &[u8]) -> Result<ParsedRecord<'_>, ParseError>;
```

---

## Integration Flow

```
context-reader                           custom-labels
     |                                        |
     |  1. Find custom_labels_current_ref_v2  |
     |     symbol, read TLS address           |
     |                                        |
     |  2. Read ref_data bytes                |
     |     ---------------------------------> |
     |                  parse_ref_data(bytes) |
     |     <--------------------------------- |
     |     RefDataHeader { key_table_addr, .. }
     |                                        |
     |  3. Read key_table bytes at addr       |
     |     ---------------------------------> |
     |                parse_key_table(bytes)  |
     |     <--------------------------------- |
     |     KeyTableIter [Key { index, name }] |
     |                                        |
     |  4. For each thread:                   |
     |     Read custom_labels_current_set_v2  |
     |     Follow pointer, read record bytes  |
     |     ---------------------------------> |
     |                   parse_record(bytes)  |
     |     <--------------------------------- |
     |     ParsedRecord { trace_id, attrs, .. }
     |                                        |
     |  5. Resolve attr key_index -> name     |
     |     using cached key table             |
     |                                        |
```

---

## Implementation Steps

1. **Add `src/v2/reader.rs` module**
   - Pure Rust, no FFI
   - Zero-copy where possible (return `&[u8]` slices into input)
   - No allocations for iteration

2. **Define error types**
   - `ParseError::BufferTooSmall`
   - `ParseError::InvalidKeyIndex`
   - `ParseError::MalformedData`

3. **Implement parsers**
   - `parse_key_table()` - iterate variable-length keys
   - `parse_ref_data()` - extract header fields + addresses
   - `parse_record()` - extract trace context + iterate attrs

4. **Add tests**
   - Round-trip: write with C API, parse with reader
   - Malformed input handling
   - Edge cases (empty tables, max attrs)

5. **Export from `v2` module**
   - `pub use reader::{...}`

---

## Open Questions

1. **Endianness**: Assume native (same-host reading). Document this.

2. **Pointer size**: The reader needs to know if it's parsing 32-bit or 64-bit
   process data. Could add `parse_ref_data_64()` / `parse_ref_data_32()` or
   take pointer size as parameter.

3. **Key table caching**: Should we provide a `KeyTable` struct that pre-parses
   all keys into a `Vec<&[u8]>` for O(1) index lookup? Trade memory for speed.

4. **ABI version check**: Should the reader also parse `custom_labels_abi_version_v2`
   and reject incompatible versions?

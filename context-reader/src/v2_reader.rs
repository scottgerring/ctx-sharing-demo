//! V2 TLS Reader - reads the custom-labels v2 format (binary TL records)
//!
//! V2 format has trace_id and span_id as first-class fields,
//! with custom attributes using indexed keys from the key table.

use anyhow::{Context, Result};
use custom_labels::process_context::ProcessContext;
use custom_labels::v2::process_context_ext::TlsConfig;
use custom_labels::v2::reader::{ParsedRecord, ParseError, V2_HEADER_SIZE};
use tracing::{debug, info};

use crate::tls_reader_trait::{Label, LabelValue, ThreadContext, ThreadResult, TlsReader};
use crate::tls_symbols::memory::read_memory;
use crate::tls_symbols::process::{FoundSymbols, LoadedTlsSymbol};
use crate::tls_symbols::tls_accessor;

// V2 symbol name
pub const OTEL_THREAD_CTX_V1: &str = "otel_thread_ctx_v1";

/// Symbols required for V2 reader
pub const REQUIRED_SYMBOLS: &[&str] = &[OTEL_THREAD_CTX_V1];

/// V2 TLS Reader for the binary TL record format
pub struct V2Reader {
    library: LoadedTlsSymbol,
    key_table: Vec<String>,
}

impl V2Reader {
    /// Try to set up the V2 reader from pre-scanned symbols and process context.
    pub fn try_setup(all_symbols: &[FoundSymbols], process_ctx: &ProcessContext) -> Result<Self> {
        // Parse TLS config from process-context
        let tls_config = TlsConfig::from_process_context(process_ctx)
            .ok_or_else(|| anyhow::anyhow!("No TLS config in process-context"))?;

        info!(
            num_keys = tls_config.key_table.len(),
            "V2 reader: parsed key table from process-context"
        );
        for (idx, name) in tls_config.key_table.iter().enumerate() {
            debug!(key_index = idx, key_name = %name, "V2 key");
        }

        // Find the binary that has our required symbol
        let found = all_symbols
            .iter()
            .find(|s| {
                REQUIRED_SYMBOLS
                    .iter()
                    .all(|sym| s.symbol_info.symbols.contains_key(*sym))
            })
            .ok_or_else(|| anyhow::anyhow!("No binary found with v2 custom labels symbol"))?;

        info!(
            "V2 reader: found {} in {}",
            OTEL_THREAD_CTX_V1,
            found.path.display()
        );

        let library = found
            .tls_location_for(OTEL_THREAD_CTX_V1)
            .context("Failed to compute TLS location for v2")?;

        Ok(Self {
            library,
            key_table: tls_config.key_table,
        })
    }
}

impl TlsReader for V2Reader {
    fn name(&self) -> &'static str {
        "v2"
    }

    fn read_thread(&self, pid: i32, ctx: &ThreadContext) -> ThreadResult {
        match self.read_thread_record(pid, ctx) {
            Ok(Some(labels)) => ThreadResult::Found {
                tid: ctx.tid,
                labels,
            },
            Ok(None) => ThreadResult::NotFound { tid: ctx.tid },
            Err(e) => ThreadResult::Error {
                tid: ctx.tid,
                error: format!("{:#}", e),
            },
        }
    }
}

impl V2Reader {
    /// Read v2 TL record from a single thread using pre-computed thread pointer.
    /// No ptrace attach/detach - that's handled by the caller.
    fn read_thread_record(&self, pid: i32, ctx: &ThreadContext) -> Result<Option<Vec<Label>>> {
        let start = std::time::Instant::now();
        let record_buf = self.read_record_memory(pid, ctx)?;
        let elapsed_ns = start.elapsed().as_nanos();

        let Some(record_buf) = record_buf else {
            debug!(tid = ctx.tid, elapsed_ns = elapsed_ns, "[v2] Memory read complete (null pointer)");
            return Ok(None);
        };

        debug!(tid = ctx.tid, elapsed_ns = elapsed_ns, "[v2] Memory read complete");

        // Parse the record
        self.parse_record(&record_buf)
    }

    /// Read the raw record bytes from process memory using a two-read approach:
    /// 1. Read the fixed 28-byte header to get validity and attrs_data_size
    /// 2. If valid and attrs_data_size > 0, read the attribute bytes
    /// Returns None if the record pointer is null.
    fn read_record_memory(&self, pid: i32, ctx: &ThreadContext) -> Result<Option<Vec<u8>>> {
        debug!("V2 thread_pointer for tid {}: {:#x}", ctx.tid, ctx.thread_pointer);
        debug!("V2 TLS location for tid {}: {:?}", ctx.tid, self.library.tls_location);

        let tls_addr = tls_accessor::get_tls_variable_address_with_thread_pointer(
            pid,
            ctx.thread_pointer,
            &self.library.tls_location,
        )?;

        debug!("V2 TLS addr for tid {}: {:#x}", ctx.tid, tls_addr);

        // Read the pointer to the v2 record
        let mut ptr_bytes = [0u8; 8];
        read_memory(pid, tls_addr, &mut ptr_bytes)?;
        let record_ptr = usize::from_ne_bytes(ptr_bytes);

        debug!("V2 record_ptr for tid {}: {:#x} (raw bytes: {:02x?})", ctx.tid, record_ptr, ptr_bytes);

        if record_ptr == 0 {
            return Ok(None);
        }

        // Read 1: fixed 28-byte header
        let mut header_buf = vec![0u8; V2_HEADER_SIZE];
        read_memory(pid, record_ptr, &mut header_buf)?;

        // Check valid flag (byte 24) before reading more
        let valid = header_buf[24];
        if valid != 1 {
            return Ok(Some(header_buf)); // Let ParsedRecord::parse handle the error
        }

        // Extract attrs_data_size (bytes 26-27, little-endian u16)
        let attrs_data_size = u16::from_le_bytes([header_buf[26], header_buf[27]]) as usize;

        // Sanity check: reject obviously corrupt sizes
        const MAX_ATTRS_SIZE: usize = 65536;
        if attrs_data_size > MAX_ATTRS_SIZE {
            anyhow::bail!(
                "attrs_data_size {} exceeds maximum {}",
                attrs_data_size,
                MAX_ATTRS_SIZE
            );
        }

        if attrs_data_size > 0 {
            // Read 2: attribute data
            let mut attrs_buf = vec![0u8; attrs_data_size];
            read_memory(pid, record_ptr + V2_HEADER_SIZE, &mut attrs_buf)?;
            header_buf.extend(attrs_buf);
        }

        Ok(Some(header_buf))
    }

    /// Parse a v2 TL record from raw bytes and convert to Labels
    fn parse_record(&self, data: &[u8]) -> Result<Option<Vec<Label>>> {
        let record = match ParsedRecord::parse(data) {
            Ok(r) => r,
            Err(ParseError::NotValid) => return Ok(None),
            Err(ParseError::BufferTooSmall { expected, actual }) => {
                anyhow::bail!("Record too small: {} bytes (need {})", actual, expected);
            }
            Err(ParseError::TruncatedAttribute { attr_index }) => {
                anyhow::bail!("Truncated attribute at index {}", attr_index);
            }
        };

        let mut labels = Vec::new();

        // Add first-class fields
        labels.push(Label {
            key: "trace_id".to_string(),
            value: LabelValue::Bytes(record.trace_id.to_vec()),
        });
        labels.push(Label {
            key: "span_id".to_string(),
            value: LabelValue::Bytes(record.span_id.to_vec()),
        });

        // Convert attributes to labels
        for attr in record.attributes {
            let key_name = self
                .key_table
                .get(attr.key_index as usize)
                .cloned()
                .unwrap_or_else(|| format!("key_{}", attr.key_index));

            // Try to interpret as UTF-8 text
            let value = match std::str::from_utf8(&attr.value) {
                Ok(s) => LabelValue::Text(s.to_string()),
                Err(_) => LabelValue::Bytes(attr.value),
            };

            labels.push(Label { key: key_name, value });
        }

        Ok(Some(labels))
    }
}

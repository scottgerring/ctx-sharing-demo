//! V2 TLS Reader - reads the custom-labels v2 format (binary TL records)
//!
//! V2 format has trace_id, span_id, root_span_id as first-class fields,
//! with custom attributes using indexed keys from the key table.

use anyhow::{Context, Result};
use custom_labels::process_context::{self};
use custom_labels::v2::process_context_ext::TlsConfig;
use custom_labels::v2::reader::{ParsedRecord, ParseError};
use tracing::{debug, info};

use crate::tls_reader_trait::{Label, LabelValue, ThreadContext, ThreadResult, TlsReader};
use crate::tls_symbols::memory::read_memory;
use crate::tls_symbols::process::LoadedTlsSymbol;
use crate::tls_symbols::tls_accessor;

// V2 symbol name
const CUSTOM_LABELS_CURRENT_SET_V2: &str = "custom_labels_current_set_v2";

/// V2 TLS Reader for the binary TL record format
pub struct V2Reader {
    library: LoadedTlsSymbol,
    key_table: Vec<String>,
    max_record_size: u64,
}

impl V2Reader {
    /// Try to set up the V2 reader for a target process.
    /// Reads the key table from process-context.
    pub fn try_setup(pid: i32) -> Result<Self> {
        use crate::tls_symbols::process::find_known_symbols_in_process;

        // Read process-context and parse TLS config
        let process_ctx = process_context::read_process_context_from_pid(pid)
            .context("Failed to read process-context for v2 setup")?;

        let tls_config = TlsConfig::from_process_context(&process_ctx)
            .ok_or_else(|| anyhow::anyhow!("No TLS config in process-context"))?;

        info!(
            num_keys = tls_config.key_table.len(),
            max_record_size = tls_config.max_record_size,
            "V2 reader: parsed key table from process-context"
        );
        for (idx, name) in tls_config.key_table.iter().enumerate() {
            debug!(key_index = idx, key_name = %name, "V2 key");
        }

        // Find the v2 TLS symbol
        let required_symbols = &[CUSTOM_LABELS_CURRENT_SET_V2];
        let found = find_known_symbols_in_process(pid, required_symbols)
            .context("Failed to find v2 custom labels symbol")?;

        info!(
            "V2 reader: found {} in {}",
            CUSTOM_LABELS_CURRENT_SET_V2,
            found.path.display()
        );

        let library = found
            .tls_location_for(CUSTOM_LABELS_CURRENT_SET_V2)
            .context("Failed to compute TLS location for v2")?;

        Ok(Self {
            library,
            key_table: tls_config.key_table,
            max_record_size: tls_config.max_record_size,
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

    /// Read the raw record bytes from process memory.
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

        // Read the full record (up to max_record_size)
        let mut record_buf = vec![0u8; self.max_record_size as usize];
        read_memory(pid, record_ptr, &mut record_buf)?;

        Ok(Some(record_buf))
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
        labels.push(Label {
            key: "local_root_span_id".to_string(),
            value: LabelValue::Bytes(record.root_span_id.to_vec()),
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

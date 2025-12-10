//! V2 TLS Reader - reads the custom-labels v2 format (binary TL records)
//!
//! V2 format has trace_id, span_id, root_span_id as first-class fields,
//! with custom attributes using indexed keys from the key table.

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;
use tracing::{debug, info};

use crate::tls_reader_trait::{get_thread_ids, Label, LabelValue, ThreadResult, TlsReader};
use crate::tls_symbols::memory::read_memory;
use crate::tls_symbols::process::LoadedTlsSymbol;
use crate::tls_symbols::tls_accessor;

// V2 symbol name
const CUSTOM_LABELS_CURRENT_SET_V2: &str = "custom_labels_current_set_v2";

/// V2 TL record header (fixed-size portion)
/// Layout: trace_id[16] | span_id[8] | root_span_id[8] | valid[1] | attrs_count[1]
const V2_HEADER_SIZE: usize = 16 + 8 + 8 + 1 + 1; // 34 bytes

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

        // First, read process-context to get key table
        let process_ctx = process_context::read_process_context_from_pid(pid)
            .context("Failed to read process-context for v2 setup")?;

        // Extract key table and max record size
        let key_table_hex = process_ctx
            .resources
            .iter()
            .find(|r| r.key == "tls.key_table")
            .map(|r| r.value.as_str())
            .ok_or_else(|| anyhow::anyhow!("No tls.key_table in process-context"))?;

        let max_record_size_str = process_ctx
            .resources
            .iter()
            .find(|r| r.key == "tls.max_record_size")
            .map(|r| r.value.as_str())
            .ok_or_else(|| anyhow::anyhow!("No tls.max_record_size in process-context"))?;

        let key_table_bytes = process_context::tls::hex_decode(key_table_hex)
            .ok_or_else(|| anyhow::anyhow!("Invalid hex in tls.key_table"))?;

        let key_table = process_context::tls::parse_key_table(&key_table_bytes);
        let max_record_size: u64 = max_record_size_str
            .parse()
            .context("Invalid tls.max_record_size")?;

        info!(
            num_keys = key_table.len(),
            max_record_size = max_record_size,
            "V2 reader: parsed key table from process-context"
        );
        for (idx, name) in key_table.iter().enumerate() {
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
            key_table,
            max_record_size,
        })
    }
}

impl TlsReader for V2Reader {
    fn name(&self) -> &'static str {
        "v2"
    }

    fn read_all_threads(&self, pid: i32) -> Result<Vec<ThreadResult>> {
        let tids = get_thread_ids(pid)?;
        let mut results = Vec::new();

        for tid in tids {
            match self.read_thread_record(pid, tid) {
                Ok(Some(labels)) => {
                    results.push(ThreadResult::Found { tid, labels });
                }
                Ok(None) => {
                    results.push(ThreadResult::NotFound { tid });
                }
                Err(e) => {
                    results.push(ThreadResult::Error {
                        tid,
                        error: format!("{:#}", e),
                    });
                }
            }
        }

        Ok(results)
    }
}

impl V2Reader {
    /// Read v2 TL record from a single thread
    fn read_thread_record(&self, pid: i32, tid: i32) -> Result<Option<Vec<Label>>> {
        let thread_pid = Pid::from_raw(tid);

        ptrace::attach(thread_pid).context("Failed to attach with ptrace")?;
        nix::sys::wait::waitpid(thread_pid, None).context("Failed to wait for thread")?;

        let result = (|| -> Result<Option<Vec<Label>>> {
            let tls_addr =
                tls_accessor::get_tls_variable_address(pid, tid, &self.library.tls_location)?;

            // Read the pointer to the v2 record
            let mut ptr_bytes = [0u8; 8];
            read_memory(pid, tls_addr, &mut ptr_bytes)?;
            let record_ptr = usize::from_ne_bytes(ptr_bytes);

            if record_ptr == 0 {
                return Ok(None);
            }

            // Read the full record (up to max_record_size)
            let mut record_buf = vec![0u8; self.max_record_size as usize];
            read_memory(pid, record_ptr, &mut record_buf)?;

            // Parse the record
            self.parse_record(&record_buf)
        })();

        let _ = ptrace::detach(thread_pid, None);
        result
    }

    /// Parse a v2 TL record from raw bytes
    fn parse_record(&self, data: &[u8]) -> Result<Option<Vec<Label>>> {
        if data.len() < V2_HEADER_SIZE {
            anyhow::bail!("Record too small: {} bytes", data.len());
        }

        // Parse header fields
        let trace_id = &data[0..16];
        let span_id = &data[16..24];
        let root_span_id = &data[24..32];
        let valid = data[32];
        let attrs_count = data[33];

        // If not valid, treat as not found
        if valid == 0 {
            return Ok(None);
        }

        let mut labels = Vec::new();

        // Add first-class fields
        labels.push(Label {
            key: "trace_id".to_string(),
            value: LabelValue::Bytes(trace_id.to_vec()),
        });
        labels.push(Label {
            key: "span_id".to_string(),
            value: LabelValue::Bytes(span_id.to_vec()),
        });
        labels.push(Label {
            key: "local_root_span_id".to_string(),
            value: LabelValue::Bytes(root_span_id.to_vec()),
        });

        // Parse attributes: [key_index:1][length:1][value:length]
        let attrs_data = &data[V2_HEADER_SIZE..];
        let mut offset = 0;

        for _ in 0..attrs_count {
            if offset + 2 > attrs_data.len() {
                break;
            }

            let key_index = attrs_data[offset] as usize;
            let value_len = attrs_data[offset + 1] as usize;
            offset += 2;

            if offset + value_len > attrs_data.len() {
                break;
            }

            let value_bytes = &attrs_data[offset..offset + value_len];
            offset += value_len;

            // Look up key name
            let key_name = self
                .key_table
                .get(key_index)
                .cloned()
                .unwrap_or_else(|| format!("key_{}", key_index));

            // Try to interpret as UTF-8 text
            let value = match std::str::from_utf8(value_bytes) {
                Ok(s) => LabelValue::Text(s.to_string()),
                Err(_) => LabelValue::Bytes(value_bytes.to_vec()),
            };

            labels.push(Label {
                key: key_name,
                value,
            });
        }

        Ok(Some(labels))
    }
}

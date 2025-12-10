//! V1 TLS Reader - reads the original custom-labels format (string-keyed labelset)

use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;
use tracing::info;

use crate::tls_reader_trait::{get_thread_ids, Label, LabelValue, ThreadResult, TlsReader};
use crate::tls_symbols::memory::read_memory;
use crate::tls_symbols::process::LoadedTlsSymbol;
use crate::tls_symbols::tls_accessor;

// Custom labels symbol names
const CUSTOM_LABELS_CURRENT_SET: &str = "custom_labels_current_set";
const CUSTOM_LABELS_ABI_VERSION: &str = "custom_labels_abi_version";

// Expected ABI version
const EXPECTED_ABI_VERSION: u32 = 1;

/// V1 label set structure from custom-labels
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CustomLabelsString {
    len: usize,
    buf: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CustomLabelsLabel {
    key: CustomLabelsString,
    value: CustomLabelsString,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CustomLabelsLabelSet {
    storage: usize,
    count: usize,
    capacity: usize,
}

/// V1 TLS Reader for the original custom-labels format
pub struct V1Reader {
    library: LoadedTlsSymbol,
}

impl V1Reader {
    /// Try to set up the V1 reader for a target process
    pub fn try_setup(pid: i32) -> Result<Self> {
        use crate::tls_symbols::process::find_known_symbols_in_process;
        use std::fs;

        let required_symbols = &[CUSTOM_LABELS_CURRENT_SET, CUSTOM_LABELS_ABI_VERSION];

        let found = find_known_symbols_in_process(pid, required_symbols)
            .context("Failed to find v1 custom labels symbols")?;

        // Validate ABI version
        let abi_entry = found
            .symbol_info
            .symbols
            .get(CUSTOM_LABELS_ABI_VERSION)
            .ok_or_else(|| anyhow::anyhow!("ABI version symbol not found"))?;

        let abi_sym = &abi_entry.sym;
        if abi_sym.st_size != 4 {
            anyhow::bail!(
                "custom_labels_abi_version symbol has wrong size: {} (expected 4)",
                abi_sym.st_size
            );
        }

        let buffer = fs::read(&found.path).context("Failed to read binary")?;
        let offset = abi_sym.st_value as usize;
        if offset + 4 > buffer.len() {
            anyhow::bail!("ABI version symbol offset out of bounds");
        }

        let bytes = &buffer[offset..offset + 4];
        let abi_version = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        if abi_version != EXPECTED_ABI_VERSION {
            anyhow::bail!(
                "Unsupported custom labels ABI version: {} (expected {})",
                abi_version,
                EXPECTED_ABI_VERSION
            );
        }

        info!(
            "V1 reader: found custom labels in {} (ABI version: {})",
            found.path.display(),
            abi_version
        );

        let library = found
            .tls_location_for(CUSTOM_LABELS_CURRENT_SET)
            .context("Failed to compute TLS location")?;

        Ok(Self { library })
    }
}

impl TlsReader for V1Reader {
    fn name(&self) -> &'static str {
        "v1"
    }

    fn read_all_threads(&self, pid: i32) -> Result<Vec<ThreadResult>> {
        let tids = get_thread_ids(pid)?;
        let mut results = Vec::new();

        for tid in tids {
            match read_thread_labels(pid, tid, &self.library) {
                Ok(labels) => {
                    if labels.is_empty() {
                        results.push(ThreadResult::NotFound { tid });
                    } else {
                        results.push(ThreadResult::Found { tid, labels });
                    }
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

/// Read labels from a single thread
fn read_thread_labels(pid: i32, tid: i32, library: &LoadedTlsSymbol) -> Result<Vec<Label>> {
    let thread_pid = Pid::from_raw(tid);

    ptrace::attach(thread_pid).context("Failed to attach with ptrace")?;
    nix::sys::wait::waitpid(thread_pid, None).context("Failed to wait for thread")?;

    let result = (|| -> Result<Vec<Label>> {
        let tls_addr = tls_accessor::get_tls_variable_address(pid, tid, &library.tls_location)?;

        let mut ptr_bytes = [0u8; 8];
        read_memory(pid, tls_addr, &mut ptr_bytes)?;
        let labelset_ptr = usize::from_ne_bytes(ptr_bytes);

        if labelset_ptr == 0 {
            return Ok(Vec::new());
        }

        let mut labelset_bytes = [0u8; std::mem::size_of::<CustomLabelsLabelSet>()];
        read_memory(pid, labelset_ptr, &mut labelset_bytes)?;

        let labelset = unsafe {
            std::ptr::read_unaligned(labelset_bytes.as_ptr() as *const CustomLabelsLabelSet)
        };

        parse_labels(pid, labelset)
    })();

    let _ = ptrace::detach(thread_pid, None);
    result
}

/// Parse labels from a labelset
fn parse_labels(pid: i32, labelset: CustomLabelsLabelSet) -> Result<Vec<Label>> {
    use std::collections::HashMap;

    if labelset.storage == 0 || labelset.count == 0 {
        return Ok(Vec::new());
    }

    let label_size = std::mem::size_of::<CustomLabelsLabel>();
    let mut buffer = vec![0u8; label_size * labelset.count];
    read_memory(pid, labelset.storage, &mut buffer)?;

    let mut labels = Vec::new();
    let mut seen_keys = HashMap::new();

    for i in 0..labelset.count {
        let offset = i * label_size;
        let label_bytes = &buffer[offset..offset + label_size];

        let label =
            unsafe { std::ptr::read_unaligned(label_bytes.as_ptr() as *const CustomLabelsLabel) };

        if label.key.buf == 0 {
            continue;
        }

        let key = read_string(pid, label.key)?.context("Label has null key")?;

        let value = match key.as_str() {
            "trace_id" | "span_id" | "local_root_span_id" => {
                let bytes = read_bytes(pid, label.value)?.context("Label has null value")?;
                LabelValue::Bytes(bytes)
            }
            _ => {
                let text = read_string(pid, label.value)?.context("Label has null value")?;
                LabelValue::Text(text)
            }
        };

        if !seen_keys.contains_key(&key) {
            seen_keys.insert(key.clone(), ());
            labels.push(Label { key, value });
        }
    }

    Ok(labels)
}

fn read_bytes(pid: i32, string: CustomLabelsString) -> Result<Option<Vec<u8>>> {
    if string.buf == 0 {
        return Ok(None);
    }
    if string.len == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut buffer = vec![0u8; string.len];
    read_memory(pid, string.buf, &mut buffer)?;
    Ok(Some(buffer))
}

fn read_string(pid: i32, string: CustomLabelsString) -> Result<Option<String>> {
    let bytes = read_bytes(pid, string)?;
    Ok(bytes.map(|b| {
        String::from_utf8(b.clone()).unwrap_or_else(|_| String::from_utf8_lossy(&b).into_owned())
    }))
}

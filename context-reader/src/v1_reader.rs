//! V1 TLS Reader - reads the original custom-labels format (string-keyed labelset)

use anyhow::{Context, Result};
use tracing::info;

use crate::tls_reader_trait::{Label, LabelValue, ThreadContext, ThreadResult, TlsReader};
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

    fn read_thread(&self, pid: i32, ctx: &ThreadContext) -> ThreadResult {
        match self.read_thread_labels(pid, ctx) {
            Ok(labels) => {
                if labels.is_empty() {
                    ThreadResult::NotFound { tid: ctx.tid }
                } else {
                    ThreadResult::Found {
                        tid: ctx.tid,
                        labels,
                    }
                }
            }
            Err(e) => ThreadResult::Error {
                tid: ctx.tid,
                error: format!("{:#}", e),
            },
        }
    }
}

impl V1Reader {
    /// Read labels from a single thread using pre-computed thread pointer.
    /// No ptrace attach/detach - that's handled by the caller.
    fn read_thread_labels(&self, pid: i32, ctx: &ThreadContext) -> Result<Vec<Label>> {
        use tracing::debug;

        debug!("V1 thread_pointer for tid {}: {:#x}", ctx.tid, ctx.thread_pointer);
        debug!("V1 TLS location for tid {}: {:?}", ctx.tid, self.library.tls_location);

        let tls_addr = tls_accessor::get_tls_variable_address_with_thread_pointer(
            pid,
            ctx.thread_pointer,
            &self.library.tls_location,
        )?;

        debug!("V1 TLS addr for tid {}: {:#x}", ctx.tid, tls_addr);

        let mut ptr_bytes = [0u8; 8];
        read_memory(pid, tls_addr, &mut ptr_bytes)?;
        let labelset_ptr = usize::from_ne_bytes(ptr_bytes);

        debug!("V1 labelset_ptr for tid {}: {:#x}", ctx.tid, labelset_ptr);

        if labelset_ptr == 0 {
            return Ok(Vec::new());
        }

        // Sanity check: pointer should look like a valid userspace address
        // On aarch64 Linux, user addresses are typically in the range 0x0000_0000_0000 to 0x0000_ffff_ffff_ffff
        // or with ASLR in ranges like 0xffff_xxxx_xxxx for stack/mmap regions
        // Reject obviously invalid pointers to avoid crashes
        #[cfg(target_arch = "aarch64")]
        if labelset_ptr < 0x1000 || (labelset_ptr > 0x0000_ffff_ffff_ffff && labelset_ptr < 0xffff_0000_0000_0000) {
            debug!("V1 labelset_ptr {:#x} looks invalid for tid {}, skipping", labelset_ptr, ctx.tid);
            return Ok(Vec::new());
        }

        #[cfg(target_arch = "x86_64")]
        if labelset_ptr < 0x1000 || labelset_ptr > 0x7fff_ffff_ffff {
            debug!("V1 labelset_ptr {:#x} looks invalid for tid {}, skipping", labelset_ptr, ctx.tid);
            return Ok(Vec::new());
        }

        let mut labelset_bytes = [0u8; std::mem::size_of::<CustomLabelsLabelSet>()];
        read_memory(pid, labelset_ptr, &mut labelset_bytes)?;

        let labelset = unsafe {
            std::ptr::read_unaligned(labelset_bytes.as_ptr() as *const CustomLabelsLabelSet)
        };

        parse_labels(pid, labelset)
    }
}

/// Parse labels from a labelset
fn parse_labels(pid: i32, labelset: CustomLabelsLabelSet) -> Result<Vec<Label>> {
    use std::collections::HashMap;
    use tracing::debug;

    if labelset.storage == 0 || labelset.count == 0 {
        return Ok(Vec::new());
    }

    // Sanity check: count should be reasonable (max ~1000 labels)
    if labelset.count > 1000 {
        debug!("Labelset count {} is unreasonably large, skipping", labelset.count);
        return Ok(Vec::new());
    }

    // Sanity check: storage pointer should look valid
    #[cfg(target_arch = "aarch64")]
    if labelset.storage < 0x1000 || (labelset.storage > 0x0000_ffff_ffff_ffff && labelset.storage < 0xffff_0000_0000_0000) {
        debug!("Labelset storage {:#x} looks invalid, skipping", labelset.storage);
        return Ok(Vec::new());
    }

    #[cfg(target_arch = "x86_64")]
    if labelset.storage < 0x1000 || labelset.storage > 0x7fff_ffff_ffff {
        debug!("Labelset storage {:#x} looks invalid, skipping", labelset.storage);
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

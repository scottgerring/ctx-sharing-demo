///
/// This is all the "labels from memory" reading bits. It is basically a rustified version
/// of what we find in [customlabels.h](https://github.com/polarsignals/custom-labels/blob/master/src/customlabels.h)
/// from the polarsignals code.
///
use anyhow::{Context, Result};
use std::collections::HashMap;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CustomLabelsString {
    pub len: usize, // Length of the data
    pub buf: usize, // Pointer to the data
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CustomLabelsLabel {
    pub key: CustomLabelsString,
    pub value: CustomLabelsString,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CustomLabelsLabelSet {
    pub storage: usize, // Pointer to array of labels
    pub count: usize,
    pub capacity: usize,
}

/// Parsed label as Rust strings
#[derive(Debug, Clone)]
pub struct Label {
    pub key: String,
    pub value: String,
}

/// Read a string from the memory of a particular process
pub fn read_string(pid: i32, string: CustomLabelsString) -> Result<Option<String>> {
    // Null pointer means absent value
    if string.buf == 0 {
        return Ok(None);
    }

    if string.len == 0 {
        return Ok(Some(String::new()));
    }

    // Read the string bytes from remote process
    let mut buffer = vec![0u8; string.len];
    read_memory(pid, string.buf, &mut buffer)?;

    // Try to parse as UTF-8, fall back to lossy conversion
    let s = String::from_utf8(buffer)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());

    Ok(Some(s))
}

/// Parse labels from a labelset
pub fn parse_labels(pid: i32, labelset: CustomLabelsLabelSet) -> Result<Vec<Label>> {
    if labelset.storage == 0 || labelset.count == 0 {
        return Ok(Vec::new());
    }

    // Read the array of labels
    let label_size = std::mem::size_of::<CustomLabelsLabel>();
    let mut buffer = vec![0u8; label_size * labelset.count];
    read_memory(pid, labelset.storage, &mut buffer)?;

    // Parse each label
    let mut labels = Vec::new();
    let mut seen_keys = HashMap::new();

    for i in 0..labelset.count {
        let offset = i * label_size;
        let label_bytes = &buffer[offset..offset + label_size];

        // Cast bytes to CustomLabelsLabel struct
        let label =
            unsafe { std::ptr::read_unaligned(label_bytes.as_ptr() as *const CustomLabelsLabel) };

        // If the key is a null, it's got no data
        if label.key.buf == 0 {
            continue;
        }

        // Read key and value
        let key = read_string(pid, label.key)?.context("Label has null key")?;
        let value = read_string(pid, label.value)?.context("Label has null value")?;

        // We only use the first instance of each key. It's probably worth
        // warning if we see more than one.
        if !seen_keys.contains_key(&key) {
            seen_keys.insert(key.clone(), ());
            labels.push(Label { key, value });
        }
    }

    Ok(labels)
}

/// Read memory from monitored process using process_vm_readv
fn read_memory(pid: i32, addr: usize, buffer: &mut [u8]) -> Result<()> {
    use nix::sys::uio::{process_vm_readv, RemoteIoVec};
    use nix::unistd::Pid;
    use std::io::IoSliceMut;

    let remote = [RemoteIoVec {
        base: addr,
        len: buffer.len(),
    }];

    let mut local = [IoSliceMut::new(buffer)];

    let nread = process_vm_readv(Pid::from_raw(pid), &mut local, &remote)
        .context("Failed to read process memory")?;

    if nread != buffer.len() {
        anyhow::bail!("Short read: expected {} bytes, got {}", buffer.len(), nread);
    }

    Ok(())
}

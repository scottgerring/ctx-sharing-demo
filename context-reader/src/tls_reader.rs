use anyhow::{Context, Result};
use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::label_parser::{self, CustomLabelsLabelSet, Label};
use crate::tls_symbols::memory::read_memory;
use crate::tls_symbols::process::LoadedTlsSymbol;
use crate::tls_symbols::tls_accessor;

/// Result of reading labels from a single thread
#[derive(Debug, Clone)]
pub enum ThreadResult {
    /// Successfully read labels
    Found { tid: i32, labels: Vec<Label> },
    /// Thread had no labels or labelset pointer was null
    NotFound { tid: i32 },
    /// Error reading from this thread
    Error { tid: i32, error: String },
}

/// Read labels from all threads in a process
pub fn read_all_threads(pid: i32, library: &LoadedTlsSymbol) -> Result<Vec<ThreadResult>> {
    let tids = get_thread_ids(pid)?;
    let mut results = Vec::new();

    for tid in tids {
        match read_thread_labels(pid, tid, library) {
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

/// Read labels from a single thread
fn read_thread_labels(pid: i32, tid: i32, library: &LoadedTlsSymbol) -> Result<Vec<Label>> {
    // Attach to the thread with ptrace
    let thread_pid = Pid::from_raw(tid);

    // Try to attach - this might fail if we don't have permissions
    ptrace::attach(thread_pid).context("Failed to attach with ptrace")?;

    // Wait for the thread to stop
    nix::sys::wait::waitpid(thread_pid, None).context("Failed to wait for thread")?;

    // Get the TLS address using the generic accessor
    let result = (|| -> Result<Vec<Label>> {
        let tls_addr = tls_accessor::get_tls_variable_address(pid, tid, &library.tls_location)?;

        // Read the pointer at the TLS location
        let mut ptr_bytes = [0u8; 8]; // 64-bit pointer
        read_memory(pid, tls_addr, &mut ptr_bytes)?;
        let labelset_ptr = usize::from_ne_bytes(ptr_bytes);

        // Null means no labelset attached to the thread
        if labelset_ptr == 0 {
            return Ok(Vec::new());
        }

        // Read the labelset structure
        let mut labelset_bytes = [0u8; std::mem::size_of::<CustomLabelsLabelSet>()];
        read_memory(pid, labelset_ptr, &mut labelset_bytes)?;

        let labelset = unsafe {
            std::ptr::read_unaligned(labelset_bytes.as_ptr() as *const CustomLabelsLabelSet)
        };

        // Parse the labels
        label_parser::parse_labels(pid, labelset)
    })();

    // Detach from thread, allowing it to resume once more.
    let _ = ptrace::detach(thread_pid, None);

    result
}

/// Get all threads for the given process
fn get_thread_ids(pid: i32) -> Result<Vec<i32>> {
    let proc = procfs::process::Process::new(pid)?;
    let tasks = proc.tasks().context("Failed to read tasks")?;

    let mut tids = Vec::new();
    for task in tasks.flatten() {
        tids.push(task.tid);
    }

    Ok(tids)
}

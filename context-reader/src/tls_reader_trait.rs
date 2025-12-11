//! Trait for TLS readers that can read thread-local context from a target process.
//!
//! This provides a common interface for different TLS formats (v1, v2, etc.)

use anyhow::Result;

/// Parsed label value - either text or raw bytes
#[derive(Debug, Clone)]
pub enum LabelValue {
    Text(String),
    Bytes(Vec<u8>),
}

/// Parsed label (key-value pair)
#[derive(Debug, Clone)]
pub struct Label {
    pub key: String,
    pub value: LabelValue,
}

/// Context for a single thread, including pre-computed thread pointer.
/// This is computed once per thread per iteration in main, avoiding
/// repeated ptrace attach/detach in each reader.
#[derive(Debug, Clone)]
pub struct ThreadContext {
    pub tid: i32,
    pub thread_pointer: usize,
}

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

/// Trait for TLS readers that can read thread-local context from a target process.
///
/// Implementations handle the setup and reading for a specific TLS format.
/// The ptrace attachment and thread pointer reading is handled by the caller;
/// readers receive a ThreadContext with the pre-computed thread pointer.
pub trait TlsReader: Send {
    /// Human-readable name for logging (e.g., "v1", "v2")
    fn name(&self) -> &'static str;

    /// Read current TLS data from a single thread.
    /// The thread_pointer in ctx has already been read via ptrace by the caller.
    fn read_thread(&self, pid: i32, ctx: &ThreadContext) -> ThreadResult;
}

/// Get all thread IDs for a process
pub fn get_thread_ids(pid: i32) -> Result<Vec<i32>> {
    let proc = procfs::process::Process::new(pid)?;
    let tasks = proc.tasks()?;

    let mut tids = Vec::new();
    for task in tasks.flatten() {
        tids.push(task.tid);
    }

    Ok(tids)
}

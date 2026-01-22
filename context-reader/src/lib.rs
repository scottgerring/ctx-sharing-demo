//! Context Reader Library
//!
//! Provides TLS symbol discovery and label reading infrastructure for reading
//! custom labels from running processes.

// Generic TLS symbol discovery infrastructure
// Note: elf_reader can work cross-platform for reading ELF files
pub mod tls_symbols;

// TLS reader trait and implementations (Linux only)
#[cfg(target_os = "linux")]
pub mod tls_reader_trait;
#[cfg(target_os = "linux")]
pub mod v1_reader;
#[cfg(target_os = "linux")]
pub mod v2_reader;

// eBPF-based reader (Linux only)
#[cfg(target_os = "linux")]
pub mod ebpf_loader;

// Output formatting (Linux only)
#[cfg(target_os = "linux")]
pub mod output;

// Re-export commonly used types
#[cfg(target_os = "linux")]
pub use tls_reader_trait::{Label, LabelValue, ThreadContext, ThreadResult, TlsReader};

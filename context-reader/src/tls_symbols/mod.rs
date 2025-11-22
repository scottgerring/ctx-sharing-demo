///
/// Generic TLS symbol discovery infrastructure.
///

// ELF reader works cross-platform (can read Linux ELF files on any OS)
pub mod elf_reader;

// These modules require Linux-specific features
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(target_os = "linux")]
pub mod dynamic_linker;
#[cfg(target_os = "linux")]
pub mod tls_accessor;
#[cfg(target_os = "linux")]
pub mod memory;

//! eBPF-based TLS reader loader and event processor.
//!
//! This module loads the eBPF program, configures it with TLS symbol locations
//! discovered from the target process, and processes label events from the
//! ring buffer.

use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, RingBuf},
    programs::PerfEvent,
    Ebpf,
};
use aya_log::EbpfLogger;
use context_reader_common::{KernelOffsets, LabelEvent, ReaderMode, TlsConfig};
use custom_labels::process_context;
use custom_labels::v2::process_context_ext::TlsConfig as V2TlsConfigExt;
use std::time::Duration;
use tracing::{info, warn};

use crate::output;
use crate::tls_reader_trait::{Label, LabelValue, ThreadResult};
use crate::tls_symbols::process::find_known_symbols_in_process;
use crate::tls_symbols::tls_accessor::TlsLocation;

// Symbol names for V1 and V2 formats
const V1_SYMBOL: &str = "custom_labels_current_set";
const V2_SYMBOL: &str = "custom_labels_current_set_v2";

/// Statistics for eBPF execution performance
struct FormatStats {
    count: u64,
    total_ns: u64,
    min_ns: u64,
    max_ns: u64,
}

impl FormatStats {
    fn new() -> Self {
        Self {
            count: 0,
            total_ns: 0,
            min_ns: u64::MAX,
            max_ns: 0,
        }
    }

    fn record(&mut self, elapsed_ns: u64) {
        self.count += 1;
        self.total_ns += elapsed_ns;
        self.min_ns = self.min_ns.min(elapsed_ns);
        self.max_ns = self.max_ns.max(elapsed_ns);
    }

    fn avg_ns(&self) -> u64 {
        if self.count > 0 {
            self.total_ns / self.count
        } else {
            0
        }
    }
}

/// Configuration for the eBPF loader
pub struct EbpfConfig {
    pub pid: i32,
    pub sample_frequency: u64,
}

/// Run the eBPF-based label reader
pub async fn run_ebpf(pid: i32, sample_freq: u64, reader_mode: ReaderMode, validate_only: bool, timeout_secs: u64) -> Result<()> {
    // Load the eBPF program from the build output path
    // The BPF program must be built first using:
    //   cd ebpf && cargo build --release
    info!("Loading eBPF program...");

    // Look for the BPF binary in expected locations
    let bpf_paths = [
        "ebpf/target/bpfel-unknown-none/release/context-reader-ebpf",
        "ebpf/target/bpfel-unknown-none/debug/context-reader-ebpf",
        "../ebpf/target/bpfel-unknown-none/release/context-reader-ebpf",
        "../ebpf/target/bpfel-unknown-none/debug/context-reader-ebpf",
    ];

    let bpf_bytes = bpf_paths
        .iter()
        .find_map(|path| std::fs::read(path).ok())
        .context(
            "Failed to find compiled eBPF program. \
             Build it first with: cd ebpf && cargo build --release"
        )?;

    let mut bpf = Ebpf::load(&bpf_bytes).context("Failed to load eBPF program")?;

    // Initialize eBPF logging
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Configure target PID
    let mut target_pid: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("TARGET_PID").context("TARGET_PID map not found")?)?;
    target_pid
        .insert(0, pid as u32, 0)
        .context("Failed to set target PID")?;
    info!("Configured target PID: {}", pid);

    // Configure reader mode
    let mut reader_mode_map: HashMap<_, u32, u8> =
        HashMap::try_from(bpf.map_mut("READER_MODE").context("READER_MODE map not found")?)?;
    reader_mode_map
        .insert(0, reader_mode as u8, 0)
        .context("Failed to set reader mode")?;
    info!("Configured reader mode: {:?}", reader_mode);

    // Calculate and configure kernel structure offsets from BTF
    configure_kernel_offsets(&mut bpf)?;

    // Discover TLS symbols and configure maps (only for enabled readers)
    configure_tls_maps(&mut bpf, pid, reader_mode)?;

    // Attach to perf events on all CPUs
    let program: &mut PerfEvent = bpf
        .program_mut("on_cpu_sample")
        .context("on_cpu_sample program not found")?
        .try_into()?;
    program.load().context("Failed to load perf_event program")?;

    let num_cpus = num_cpus()?;
    info!("Attaching to {} CPUs with frequency {}Hz", num_cpus, sample_freq);

    // CRITICAL: Must keep Link objects alive! If dropped, perf events detach.
    let mut _links = Vec::new();
    for cpu in 0..num_cpus {
        let link = program
            .attach(
                aya::programs::perf_event::PerfTypeId::Software,
                aya::programs::perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
                aya::programs::perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
                aya::programs::perf_event::SamplePolicy::Frequency(sample_freq),
                true, // inherit
            )
            .with_context(|| format!("Failed to attach to CPU {}", cpu))?;
        _links.push(link);
    }

    info!("eBPF program attached to {} CPUs, processing events...", _links.len());

    // Process events from ring buffer
    // KEY: Use map_mut() not take_map() so bpf stays alive (otherwise BPF program unloads!)
    let mut ring = RingBuf::try_from(bpf.map_mut("EVENTS").context("EVENTS map not found")?)?;

    info!("RingBuf initialized, starting event loop...");

    // Event processing loop
    let mut iteration = 0u64;
    let mut v1_stats = FormatStats::new();
    let mut v2_stats = FormatStats::new();

    let mut shutdown = false;
    let start_time = std::time::Instant::now();
    let timeout_duration = Duration::from_secs(timeout_secs);

    loop {
        // Check for Ctrl-C signal
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("\nReceived Ctrl-C, shutting down...");
                shutdown = true;
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }

        if shutdown {
            break;
        }

        iteration += 1;

        // Check timeout in validate-only mode
        if validate_only && start_time.elapsed() > timeout_duration {
            eprintln!("VALIDATE FAILED: Timeout after {}s - no labels found", timeout_secs);
            std::process::exit(1);
        }

        // Check if process still exists
        if procfs::process::Process::new(pid).is_err() {
            if validate_only {
                eprintln!("VALIDATE FAILED: Process exited before labels were found");
                std::process::exit(1);
            }
            println!("\nProcess exited!");
            break;
        }

        // Collect events for this iteration
        let mut v1_results: Vec<ThreadResult> = Vec::new();
        let mut v2_results: Vec<ThreadResult> = Vec::new();

        // Read events from ringbuf - simple pattern from aya-examples
        if let Some(item) = ring.next() {
            let item: &[u8] = &item;

            // DEBUG: Log what we actually received
            info!("Received ringbuf item: {} bytes (expected: {})",
                  item.len(), std::mem::size_of::<LabelEvent>());

            if item.len() >= std::mem::size_of::<LabelEvent>() {
                let event = unsafe { &*(item.as_ptr() as *const LabelEvent) };
                info!(
                    "Received event: tid={}, format={}, data_len={}",
                    event.tid, event.format_version, event.data_len
                );

                // Process based on format version
                match event.format_version {
                    1 => {
                        let elapsed_ns = event.end_time_ns.saturating_sub(event.start_time_ns);
                        v1_stats.record(elapsed_ns);
                        let result = process_v1_event(pid, event);
                        v1_results.push(result);
                    }
                    2 => {
                        let elapsed_ns = event.end_time_ns.saturating_sub(event.start_time_ns);
                        v2_stats.record(elapsed_ns);
                        let result = process_v2_event(event);
                        v2_results.push(result);
                    }
                    _ => {
                        warn!("Unknown format version: {}", event.format_version);
                    }
                }
            } else {
                warn!("Received undersized event: {} bytes", item.len());
            }
        }

        // Check for labels found (for validate-only mode)
        let mut any_labels_found = false;
        let mut found_labels_summary: Option<String> = None;

        for result in v1_results.iter().chain(v2_results.iter()) {
            if let ThreadResult::Found { tid, labels } = result {
                any_labels_found = true;
                if found_labels_summary.is_none() {
                    let reader_name = if v1_results.iter().any(|r| matches!(r, ThreadResult::Found { tid: t, .. } if t == tid)) {
                        "v1-ebpf"
                    } else {
                        "v2-ebpf"
                    };
                    found_labels_summary = Some(format!(
                        "[{}] thread={}, labels=[{}]",
                        reader_name,
                        tid,
                        labels.iter().map(|l| format!("{}={}", l.key, l.value)).collect::<Vec<_>>().join(", ")
                    ));
                }
            }
        }

        // In validate-only mode, exit successfully on first labels found
        if validate_only && any_labels_found {
            if let Some(summary) = found_labels_summary {
                println!("VALIDATE OK: {}", summary);
            }
            std::process::exit(0);
        }

        // Print results if we got any (unless in validate-only mode)
        if !validate_only {
            if !v1_results.is_empty() {
                output::print_iteration(iteration, "v1-ebpf", &v1_results);
            }
            if !v2_results.is_empty() {
                output::print_iteration(iteration, "v2-ebpf", &v2_results);
            }
        }
    }

    // Print statistics before exiting
    print_stats("v1-ebpf", &v1_stats);
    print_stats("v2-ebpf", &v2_stats);

    Ok(())
}

/// Calculate kernel struct offsets from BTF and configure the map.
/// This provides kernel version portability without hardcoded offsets.
/// TODO this is gross; find a better way 
fn configure_kernel_offsets(bpf: &mut Ebpf) -> Result<()> {
    // Use pahole to get offsets from BTF
    let task_struct_thread = std::process::Command::new("pahole")
        .args(&["-C", "task_struct", "/sys/kernel/btf/vmlinux"])
        .output()
        .context("Failed to run pahole - is it installed?")?;

    let thread_struct_output = std::process::Command::new("pahole")
        .args(&["-C", "thread_struct", "/sys/kernel/btf/vmlinux"])
        .output()
        .context("Failed to run pahole")?;

    // Parse pahole output to extract offsets
    let task_output = String::from_utf8_lossy(&task_struct_thread.stdout);
    let thread_output = String::from_utf8_lossy(&thread_struct_output.stdout);

    // Find "struct thread_struct       thread;               /*  OFFSET     SIZE */"
    let thread_offset = task_output
        .lines()
        .find(|line| line.contains("struct thread_struct") && line.contains("thread;"))
        .and_then(|line| {
            // Extract offset from comment "/*  5712   184 */"
            let parts: Vec<&str> = line.split("/*").nth(1)?.split_whitespace().collect();
            parts.first()?.parse::<u64>().ok()
        })
        .context("Failed to find thread field offset in task_struct")?;

    // Find the thread pointer offset - architecture specific:
    // - x86_64: "fsbase" field in thread_struct
    // - aarch64: "tp_value" field in thread_struct (inside uw substruct, but offset is from thread_struct start)
    let (tp_field_name, tp_offset) = if cfg!(target_arch = "x86_64") {
        let offset = thread_output
            .lines()
            .find(|line| line.contains("fsbase;"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split("/*").nth(1)?.split_whitespace().collect();
                parts.first()?.parse::<u64>().ok()
            })
            .context("Failed to find fsbase field offset in thread_struct")?;
        ("fsbase", offset)
    } else if cfg!(target_arch = "aarch64") {
        let offset = thread_output
            .lines()
            .find(|line| line.contains("tp_value;"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split("/*").nth(1)?.split_whitespace().collect();
                parts.first()?.parse::<u64>().ok()
            })
            .context("Failed to find tp_value field offset in thread_struct")?;
        ("tp_value", offset)
    } else {
        anyhow::bail!("Unsupported architecture for eBPF thread pointer access");
    };

    info!(
        "Calculated kernel offsets from BTF: task_struct.thread={}, thread_struct.{}={}",
        thread_offset, tp_field_name, tp_offset
    );

    // Configure the BPF map
    let mut offsets_map: HashMap<_, u32, KernelOffsets> =
        HashMap::try_from(bpf.map_mut("KERNEL_OFFSETS").context("KERNEL_OFFSETS map not found")?)?;

    let arch = if cfg!(target_arch = "x86_64") {
        0 // Architecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        1 // Architecture::Aarch64
    } else {
        0 // Default to x86_64
    };

    let offsets = KernelOffsets {
        task_struct_thread_offset: thread_offset,
        thread_struct_fsbase_offset: tp_offset,
        valid: 1,
        arch,
        _pad: [0; 6],
    };

    offsets_map
        .insert(0, offsets, 0)
        .context("Failed to set kernel offsets")?;

    info!("Kernel offsets configured: {:?}", offsets);

    Ok(())
}

/// Configure V1 and V2 TLS maps with discovered symbol locations
fn configure_tls_maps(bpf: &mut Ebpf, pid: i32, reader_mode: ReaderMode) -> Result<()> {
    // Try to find V1 symbols (only if V1 reader is enabled)
    if reader_mode.v1_enabled() {
        if let Ok(found) = find_known_symbols_in_process(pid, &[V1_SYMBOL]) {
            let location = found.tls_location_for(V1_SYMBOL)?;
            let config = tls_location_to_config(&location.tls_location, 0); // V1 doesn't use fixed-size records

            let mut v1_config: HashMap<_, u32, TlsConfig> =
                HashMap::try_from(bpf.map_mut("V1_TLS_CONFIG").context("V1_TLS_CONFIG map not found")?)?;
            v1_config
                .insert(0, config, 0)
                .context("Failed to set V1 TLS config")?;

            info!("V1 TLS configured: {:?}", config);
        } else {
            info!("V1 symbols not found in target process");
        }
    } else {
        info!("V1 reader disabled by --readers flag");
    }

    // Try to find V2 symbols (only if V2 reader is enabled)
    if reader_mode.v2_enabled() {
        if let Ok(found) = find_known_symbols_in_process(pid, &[V2_SYMBOL]) {
            let location = found.tls_location_for(V2_SYMBOL)?;

            // Read process context to get V2 max_record_size
            let max_record_size = match process_context::read_process_context_from_pid(pid) {
                Ok(proc_ctx) => {
                    V2TlsConfigExt::from_process_context(&proc_ctx)
                        .map(|cfg| cfg.max_record_size)
                        .unwrap_or(256) // Default if not found
                }
                Err(e) => {
                    warn!("Failed to read V2 process context: {}", e);
                    256 // Default size
                }
            };

            let config = tls_location_to_config(&location.tls_location, max_record_size);

            let mut v2_config: HashMap<_, u32, TlsConfig> =
                HashMap::try_from(bpf.map_mut("V2_TLS_CONFIG").context("V2_TLS_CONFIG map not found")?)?;
            v2_config
                .insert(0, config, 0)
                .context("Failed to set V2 TLS config")?;

            info!("V2 TLS configured: {:?}", config);
        } else {
            info!("V2 symbols not found in target process");
        }
    } else {
        info!("V2 reader disabled by --readers flag");
    }

    Ok(())
}

/// Check if a tls_offset value is valid for static TLS calculation.
/// This mirrors the check in tls_accessor.rs.
fn is_valid_static_tls_offset(tls_offset: usize) -> bool {
    const MAX_REASONABLE_TLS_OFFSET: usize = 0x40000000; // 1GB
    tls_offset != 0 && tls_offset != usize::MAX && tls_offset <= MAX_REASONABLE_TLS_OFFSET
}

/// Convert TlsLocation to TlsConfig for BPF map
fn tls_location_to_config(location: &TlsLocation, max_record_size: u64) -> TlsConfig {
    match location {
        TlsLocation::MainExecutable { offset } => TlsConfig {
            module_id: 0,
            offset: *offset as u64,
            tls_offset: 0,  // Not used for main executable
            is_main_executable: 1,
            use_static_tls: 0,  // Not applicable for main executable
            _pad: [0; 6],
            max_record_size,
        },
        TlsLocation::SharedLibrary { module_id, offset, tls_offset, .. } => {
            // Determine if eBPF should use static TLS based on tls_offset validity
            // Note: tlsdesc could also be used here - once resolved it's just another static offset
            let use_static = is_valid_static_tls_offset(*tls_offset);
            TlsConfig {
                module_id: *module_id as u64,
                offset: *offset as u64,
                tls_offset: *tls_offset as u64,
                is_main_executable: 0,
                use_static_tls: if use_static { 1 } else { 0 },
                _pad: [0; 6],
                max_record_size,
            }
        },
        TlsLocation::StaticTls { tls_offset, symbol_offset } => TlsConfig {
            // For static TLS, we always use static TLS path
            module_id: 0,
            offset: *symbol_offset as u64,
            tls_offset: *tls_offset as u64,
            is_main_executable: 0,
            use_static_tls: 1,  // Always use static TLS for this variant
            _pad: [0; 6],
            max_record_size,
        },
    }
}

/// Process a V1 format event
/// V1 events now contain packed label data in the format:
/// [count: u8][for each label: [key_len: u16][key_data][value_len: u16][value_data]]
fn process_v1_event(_pid: i32, event: &LabelEvent) -> ThreadResult {
    if event.data_len < 1 {
        return ThreadResult::Error {
            tid: event.tid as i32,
            error: "V1 event too small".to_string(),
        };
    }

    let data = &event.data[..event.data_len as usize];

    match parse_v1_packed_labels(data) {
        Ok(labels) if labels.is_empty() => ThreadResult::NotFound {
            tid: event.tid as i32,
        },
        Ok(labels) => ThreadResult::Found {
            tid: event.tid as i32,
            labels,
        },
        Err(e) => ThreadResult::Error {
            tid: event.tid as i32,
            error: format!("{:#}", e),
        },
    }
}

/// Parse V1 packed label format sent from eBPF
fn parse_v1_packed_labels(data: &[u8]) -> Result<Vec<Label>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let count = data[0] as usize;
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut labels = Vec::new();
    let mut pos = 1;

    for _ in 0..count {
        // Read key length (2 bytes, little-endian)
        if pos + 2 > data.len() {
            anyhow::bail!("Truncated key length at position {}", pos);
        }
        let key_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        // Read key data
        if pos + key_len > data.len() {
            anyhow::bail!("Truncated key data at position {}", pos);
        }
        let key = String::from_utf8_lossy(&data[pos..pos + key_len]).into_owned();
        pos += key_len;

        // Read value length (2 bytes, little-endian)
        if pos + 2 > data.len() {
            anyhow::bail!("Truncated value length at position {}", pos);
        }
        let value_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        // Read value data
        if pos + value_len > data.len() {
            anyhow::bail!("Truncated value data at position {}", pos);
        }

        let value = if matches!(key.as_str(), "trace_id" | "span_id" | "local_root_span_id") {
            LabelValue::Bytes(data[pos..pos + value_len].to_vec())
        } else {
            LabelValue::Text(String::from_utf8_lossy(&data[pos..pos + value_len]).into_owned())
        };
        pos += value_len;

        labels.push(Label { key, value });
    }

    Ok(labels)
}

/// Read V1 labels by chasing pointers from the storage array
fn read_v1_labels_from_storage(pid: i32, storage_ptr: usize, count: usize) -> Result<Vec<Label>> {
    use crate::tls_symbols::memory::read_memory;

    // V1 label structure: { key: { len, buf }, value: { len, buf } }
    // Each string is 16 bytes (len: usize, buf: *const u8)
    // Each label is 32 bytes
    const LABEL_SIZE: usize = 32;

    if count > 100 {
        anyhow::bail!("Unreasonable label count: {}", count);
    }

    let mut buffer = vec![0u8; LABEL_SIZE * count];
    read_memory(pid, storage_ptr, &mut buffer)?;

    let mut labels = Vec::new();

    for i in 0..count {
        let offset = i * LABEL_SIZE;

        // Key string: len at offset+0, buf at offset+8
        let key_len = usize::from_ne_bytes(buffer[offset..offset + 8].try_into()?);
        let key_buf = usize::from_ne_bytes(buffer[offset + 8..offset + 16].try_into()?);

        // Value string: len at offset+16, buf at offset+24
        let val_len = usize::from_ne_bytes(buffer[offset + 16..offset + 24].try_into()?);
        let val_buf = usize::from_ne_bytes(buffer[offset + 24..offset + 32].try_into()?);

        if key_buf == 0 {
            continue;
        }

        // Read key string
        let key = read_string_from_process(pid, key_buf, key_len)?;

        // Read value (as bytes or string depending on key)
        let value = if matches!(key.as_str(), "trace_id" | "span_id" | "local_root_span_id") {
            let bytes = read_bytes_from_process(pid, val_buf, val_len)?;
            LabelValue::Bytes(bytes)
        } else {
            let text = read_string_from_process(pid, val_buf, val_len)?;
            LabelValue::Text(text)
        };

        labels.push(Label { key, value });
    }

    Ok(labels)
}

/// Read a string from target process memory
fn read_string_from_process(pid: i32, addr: usize, len: usize) -> Result<String> {
    use crate::tls_symbols::memory::read_memory;

    if addr == 0 || len == 0 {
        return Ok(String::new());
    }

    let mut buffer = vec![0u8; len];
    read_memory(pid, addr, &mut buffer)?;

    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

/// Read bytes from target process memory
fn read_bytes_from_process(pid: i32, addr: usize, len: usize) -> Result<Vec<u8>> {
    use crate::tls_symbols::memory::read_memory;

    if addr == 0 || len == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; len];
    read_memory(pid, addr, &mut buffer)?;

    Ok(buffer)
}

/// Process a V2 format event
/// V2 events contain the raw binary record; parse it directly
fn process_v2_event(event: &LabelEvent) -> ThreadResult {
    use custom_labels::v2::reader::{ParseError, ParsedRecord};

    if event.data_len == 0 {
        return ThreadResult::NotFound {
            tid: event.tid as i32,
        };
    }

    let data = &event.data[..event.data_len as usize];

    match ParsedRecord::parse(data) {
        Ok(record) => {
            let mut labels = Vec::new();

            // First-class fields
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

            // Attributes
            for attr in record.attributes {
                let key = format!("attr_{}", attr.key_index);
                let value = match std::str::from_utf8(&attr.value) {
                    Ok(s) => LabelValue::Text(s.to_string()),
                    Err(_) => LabelValue::Bytes(attr.value),
                };
                labels.push(Label { key, value });
            }

            ThreadResult::Found {
                tid: event.tid as i32,
                labels,
            }
        }
        Err(ParseError::NotValid) => ThreadResult::NotFound {
            tid: event.tid as i32,
        },
        Err(e) => ThreadResult::Error {
            tid: event.tid as i32,
            error: format!("Parse error: {:?}", e),
        },
    }
}

/// Print eBPF execution performance statistics
fn print_stats(name: &str, stats: &FormatStats) {
    if stats.count == 0 {
        println!("\n[{}] No events processed", name);
        return;
    }

    println!("\n[{}] eBPF Execution Statistics:", name);
    println!("  Events processed: {}", stats.count);
    println!("  Min time:         {} ns ({:.3} µs)", stats.min_ns, stats.min_ns as f64 / 1000.0);
    println!("  Max time:         {} ns ({:.3} µs)", stats.max_ns, stats.max_ns as f64 / 1000.0);
    println!("  Avg time:         {} ns ({:.3} µs)", stats.avg_ns(), stats.avg_ns() as f64 / 1000.0);
}

/// Get the number of online CPUs
fn num_cpus() -> Result<u32> {
    let path = "/sys/devices/system/cpu/online";
    let content = std::fs::read_to_string(path).context("Failed to read CPU online info")?;

    // Parse format like "0-7" or "0,1,2,3"
    let mut max_cpu = 0u32;
    for part in content.trim().split(',') {
        if let Some((_, end)) = part.split_once('-') {
            max_cpu = max_cpu.max(end.parse().unwrap_or(0));
        } else {
            max_cpu = max_cpu.max(part.parse().unwrap_or(0));
        }
    }

    Ok(max_cpu + 1)
}

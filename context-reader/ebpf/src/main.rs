#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_perf_event_data,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel, bpf_probe_read_user,
    },
    macros::{map, perf_event},
    maps::{HashMap, RingBuf},
    programs::PerfEventContext,
    EbpfContext,
};
use aya_log_ebpf::debug;
use context_reader_common::{
    calculate_static_tls_address, Architecture, KernelOffsets, LabelEvent, ReaderMode, TlsConfig,
    MAX_LABEL_DATA_SIZE, V2_HEADER_SIZE,
};

/// Target PID we're monitoring (set by userspace)
#[map]
static TARGET_PID: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

/// V1 TLS configuration (custom_labels_current_set)
#[map]
static V1_TLS_CONFIG: HashMap<u32, TlsConfig> = HashMap::with_max_entries(1, 0);

/// V2 TLS configuration (otel_thread_ctx_v1)
#[map]
static V2_TLS_CONFIG: HashMap<u32, TlsConfig> = HashMap::with_max_entries(1, 0);

/// Kernel structure offsets (calculated from BTF in userspace)
/// This provides portability across kernel versions
#[map]
static KERNEL_OFFSETS: HashMap<u32, KernelOffsets> = HashMap::with_max_entries(1, 0);

/// Reader mode configuration (set by userspace)
/// Controls which readers are active to allow accurate overhead measurement
#[map]
static READER_MODE: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Ring buffer for sending label events to userspace
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch space for reading label data
#[map]
static SCRATCH: aya_ebpf::maps::PerCpuArray<[u8; MAX_LABEL_DATA_SIZE]> =
    aya_ebpf::maps::PerCpuArray::with_max_entries(1, 0);

#[perf_event]
pub fn on_cpu_sample(ctx: PerfEventContext) -> u32 {
    match try_on_cpu_sample(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_on_cpu_sample(ctx: &PerfEventContext) -> Result<(), i64> {
    // Get current PID/TID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // Check if this is our target process
    let target = unsafe { TARGET_PID.get(&0) };
    let Some(&target_pid) = target else {
        return Ok(());
    };
    if pid != target_pid {
        return Ok(());
    }

    debug!(ctx, "on_cpu_sample: pid={} tid={}", pid, tid);

    // Get reader mode configuration (default to Both if not set)
    let reader_mode = unsafe { READER_MODE.get(&0) }
        .copied()
        .unwrap_or(ReaderMode::Both as u8);

    // Get thread pointer and architecture from task_struct
    let (thread_pointer, arch) = get_thread_pointer_and_arch()?;

    // Try to read V2 labels (if enabled)
    // ReaderMode::Both = 0, ReaderMode::V2Only = 2
    if reader_mode == ReaderMode::Both as u8 || reader_mode == ReaderMode::V2Only as u8 {
        if let Some(config) = unsafe { V2_TLS_CONFIG.get(&0) } {
            let _ = read_and_emit_v2(ctx, tid, thread_pointer, config, arch);
        }
    }

    // Try to read V1 labels (if enabled)
    // ReaderMode::Both = 0, ReaderMode::V1Only = 1
    if reader_mode == ReaderMode::Both as u8 || reader_mode == ReaderMode::V1Only as u8 {
        if let Some(config) = unsafe { V1_TLS_CONFIG.get(&0) } {
            let _ = read_and_emit_v1(ctx, tid, thread_pointer, config, arch);
        }
    }

    Ok(())
}

/// Get thread pointer and architecture using kernel offsets provided by userspace.
/// This approach provides portability - userspace calculates offsets from BTF
/// and passes them to BPF, avoiding hardcoded values.
#[inline(always)]
fn get_thread_pointer_and_arch() -> Result<(u64, Architecture), i64> {
    // Get kernel offsets from map (calculated by userspace from BTF)
    let offsets = unsafe { KERNEL_OFFSETS.get(&0) };
    let Some(offsets) = offsets else {
        return Err(-2); // Offsets not configured
    };

    if offsets.valid == 0 {
        return Err(-3); // Offsets marked as invalid
    }

    // Get architecture from userspace-provided config
    let arch = if offsets.arch == 1 {
        Architecture::Aarch64
    } else {
        Architecture::X86_64
    };

    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return Err(-1);
    }

    // Read task_struct->thread.<tp_field> using offsets from userspace
    // - x86_64: thread.fsbase
    // - aarch64: thread.tp_value
    let thread_offset = offsets.task_struct_thread_offset as usize;
    let tp_field_offset = offsets.thread_struct_fsbase_offset as usize;
    let total_offset = thread_offset + tp_field_offset;

    let tp_ptr = unsafe { (task as *const u8).add(total_offset) as *const u64 };
    let thread_pointer = unsafe { bpf_probe_read_kernel(tp_ptr).map_err(|e| e as i64)? };

    Ok((thread_pointer, arch))
}

/// Calculate static TLS address for shared libraries.
/// Uses l_tls_offset from link_map for direct thread pointer arithmetic.
#[inline(always)]
fn calculate_shared_lib_static_tls(
    thread_pointer: u64,
    tls_offset: u64,
    symbol_offset: u64,
    arch: Architecture,
) -> u64 {
    match arch {
        Architecture::X86_64 => thread_pointer
            .wrapping_sub(tls_offset)
            .wrapping_add(symbol_offset),
        Architecture::Aarch64 => thread_pointer
            .wrapping_add(tls_offset)
            .wrapping_add(symbol_offset),
    }
}

/// Check if a tls_offset is valid for static TLS calculation.
#[inline(always)]
fn is_valid_static_tls_offset(tls_offset: u64) -> bool {
    const MAX_REASONABLE_TLS_OFFSET: u64 = 0x40000000; // 1GB
    tls_offset != 0 && tls_offset != u64::MAX && tls_offset <= MAX_REASONABLE_TLS_OFFSET
}

/// Compute TLS variable address from thread pointer and config.
/// For shared libraries, userspace tells us whether to use static TLS (fast) or DTV (safe).
#[inline(always)]
fn compute_tls_address(
    thread_pointer: u64,
    config: &TlsConfig,
    arch: Architecture,
) -> Result<u64, i64> {
    if config.is_main_executable != 0 {
        // Main executable: use static TLS calculation
        Ok(calculate_static_tls_address(
            thread_pointer,
            config.offset,
            arch,
        ))
    } else if config.use_static_tls != 0 {
        // Shared library with valid tls_offset: use static TLS (fast path)
        Ok(calculate_shared_lib_static_tls(
            thread_pointer,
            config.tls_offset,
            config.offset,
            arch,
        ))
    } else {
        // Shared library without valid tls_offset: use DTV lookup
        compute_tls_via_dtv(thread_pointer, config, arch)
    }
}

/// Compute TLS address via DTV lookup (fallback for dlopen'd libraries).
#[inline(always)]
fn compute_tls_via_dtv(
    thread_pointer: u64,
    config: &TlsConfig,
    arch: Architecture,
) -> Result<u64, i64> {
    // DTV pointer location varies by libc and architecture
    let dtv_ptr_addr: u64 = if config.libc_type == 1 {
        // musl
        match arch {
            // musl x86_64: DTV at TP + 8 (same as glibc)
            Architecture::X86_64 => thread_pointer + 8,
            // musl aarch64: DTV at TP - 8 (end of pthread struct, before TP)
            Architecture::Aarch64 => thread_pointer.wrapping_sub(8),
        }
    } else {
        // glibc (default)
        match arch {
            // glibc x86_64: DTV at TP + 8 (second field of tcbhead_t)
            Architecture::X86_64 => thread_pointer + 8,
            // glibc aarch64: DTV at TP + 0 (first field of tcbhead_t)
            Architecture::Aarch64 => thread_pointer,
        }
    };

    let dtv_ptr: u64 =
        unsafe { bpf_probe_read_user(dtv_ptr_addr as *const u64).map_err(|e| e as i64)? };

    if dtv_ptr == 0 {
        return Err(-1);
    }

    // DTV entry size: glibc uses 16 bytes, musl uses 8 bytes
    // glibc DTV entry: { void *val; void *to_free; } = 16 bytes
    // musl DTV entry: just a void* pointer = 8 bytes
    let dtv_entry_size: u64 = if config.libc_type == 1 { 8 } else { 16 };
    let dtv_entry_addr = dtv_ptr + (config.module_id * dtv_entry_size);

    // Read TLS block pointer from DTV entry
    let tls_block: u64 =
        unsafe { bpf_probe_read_user(dtv_entry_addr as *const u64).map_err(|e| e as i64)? };

    // Check for unallocated marker (-1)
    if tls_block == u64::MAX || tls_block == 0 {
        return Err(-1);
    }

    Ok(tls_block + config.offset)
}

/// Read V1 format labels and emit to ringbuf.
///
/// This walks the entire labelset structure in eBPF and packs the labels into a simple format:
/// ```
/// [count: u8]
/// For each label:
///   [key_len: u16 little-endian]
///   [key_data: key_len bytes]
///   [value_len: u16 little-endian]
///   [value_data: value_len bytes]
/// ```
/// All the work is done here in kernel space, so userspace just needs to unpack the data.
#[inline(always)]
fn read_and_emit_v1(
    ctx: &PerfEventContext,
    tid: u32,
    thread_pointer: u64,
    config: &TlsConfig,
    arch: Architecture,
) -> Result<(), i64> {
    debug!(ctx, "read_and_emit_v1: tid={}", tid);

    let start_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let tls_addr = compute_tls_address(thread_pointer, config, arch)?;

    // Read pointer to labelset
    let labelset_ptr: u64 =
        unsafe { bpf_probe_read_user(tls_addr as *const u64).map_err(|e| e as i64)? };

    if labelset_ptr == 0 {
        return Ok(()); // No labels set
    }

    // Get scratch buffer for building the packed label data
    let scratch = unsafe { SCRATCH.get_ptr_mut(0).ok_or(-1)? };
    let scratch = unsafe { &mut *scratch };

    // Read labelset header: { storage: *mut Label, count: usize, capacity: usize }
    let mut labelset_header = [0u64; 3];
    unsafe {
        for i in 0..3 {
            labelset_header[i] = bpf_probe_read_user((labelset_ptr + i as u64 * 8) as *const u64)
                .map_err(|e| e as i64)?;
        }
    }

    let storage_ptr = labelset_header[0];
    let count = labelset_header[1] as usize;

    if count == 0 || storage_ptr == 0 {
        return Ok(()); // Empty labelset
    }

    // Track write position in scratch buffer
    let mut write_pos: usize = 0;

    // Write label count (1 byte)
    scratch[write_pos] = count.min(255) as u8;
    write_pos += 1;

    // This seems to be empirically the limit on what we can do
    // and stay under the verifier complexity threshold
    const MAX_LABELS: usize = 8;

    #[inline(always)]
    fn read_label(
        storage_ptr: u64,
        index: usize,
        scratch: &mut [u8],
        write_pos: &mut usize,
    ) -> Result<(), i64> {
        let label_addr = storage_ptr + (index as u64 * 32);

        // Read label structure: [key_len, key_buf, value_len, value_buf]
        let key_len: u64 =
            unsafe { bpf_probe_read_user(label_addr as *const u64).map_err(|e| e as i64)? };
        let key_buf: u64 =
            unsafe { bpf_probe_read_user((label_addr + 8) as *const u64).map_err(|e| e as i64)? };
        let value_len: u64 =
            unsafe { bpf_probe_read_user((label_addr + 16) as *const u64).map_err(|e| e as i64)? };
        let value_buf: u64 =
            unsafe { bpf_probe_read_user((label_addr + 24) as *const u64).map_err(|e| e as i64)? };

        // Limit string sizes to ensure we fit in MAX_LABEL_DATA_SIZE (1024 bytes)
        // With MAX_STRING_LEN=32 and MAX_LABELS=8:
        // Worst case = 1 (count) + 8 × (2 + 32 + 2 + 32) = 545 bytes < 1024
        const MAX_STRING_LEN: usize = 32;
        let key_len = (key_len as usize).min(MAX_STRING_LEN);
        let value_len = (value_len as usize).min(MAX_STRING_LEN);

        // Check space
        if *write_pos + 2 + key_len + 2 + value_len > MAX_LABEL_DATA_SIZE {
            return Err(-1);
        }

        // Write key length (2 bytes)
        scratch[*write_pos] = (key_len & 0xFF) as u8;
        scratch[*write_pos + 1] = ((key_len >> 8) & 0xFF) as u8;
        *write_pos += 2;

        // Read key data
        unsafe {
            bpf_probe_read_user_buf(
                key_buf as *const u8,
                &mut scratch[*write_pos..*write_pos + key_len],
            )
            .map_err(|e| e as i64)?;
        }
        *write_pos += key_len;

        // Write value length (2 bytes)
        scratch[*write_pos] = (value_len & 0xFF) as u8;
        scratch[*write_pos + 1] = ((value_len >> 8) & 0xFF) as u8;
        *write_pos += 2;

        // Read value data
        unsafe {
            bpf_probe_read_user_buf(
                value_buf as *const u8,
                &mut scratch[*write_pos..*write_pos + value_len],
            )
            .map_err(|e| e as i64)?;
        }
        *write_pos += value_len;

        Ok(())
    }

    // Bounded loop - verifier can prove this terminates after MAX_LABELS iterations
    for i in 0..MAX_LABELS {
        if i < count {
            read_label(storage_ptr, i, scratch, &mut write_pos)?;
        }
    }

    let end_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Emit the packed label data
    emit_event(
        ctx,
        tid,
        1,
        &scratch[..write_pos],
        labelset_ptr,
        start_time,
        end_time,
    )?;

    Ok(())
}

/// Read V2 format labels and emit to ringbuf.
///
/// Uses a two-stage read approach:
/// 1. Read the fixed 28-byte header to get validity and attrs_data_size
/// 2. If valid and attrs_data_size > 0, read the attribute bytes
#[inline(always)]
fn read_and_emit_v2(
    ctx: &PerfEventContext,
    tid: u32,
    thread_pointer: u64,
    config: &TlsConfig,
    arch: Architecture,
) -> Result<(), i64> {
    debug!(ctx, "read_and_emit_v2: tid={}", tid);

    let start_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let tls_addr = compute_tls_address(thread_pointer, config, arch)?;

    // Read pointer to v2 record
    let record_ptr: u64 =
        unsafe { bpf_probe_read_user(tls_addr as *const u64).map_err(|e| e as i64)? };

    if record_ptr == 0 {
        return Ok(()); // No record set
    }

    // Get scratch buffer
    let scratch = unsafe { SCRATCH.get_ptr_mut(0).ok_or(-1)? };
    let scratch = unsafe { &mut *scratch };

    // Stage 1: Read the fixed 28-byte header
    unsafe {
        bpf_probe_read_user_buf(
            record_ptr as *const u8,
            &mut scratch[..V2_HEADER_SIZE],
        )
        .map_err(|e| e as i64)?;
    }

    // Check valid flag (byte 24) - skip if not 1
    if scratch[24] != 1 {
        return Ok(());
    }

    // Extract attrs_data_size from header (bytes 26-27, little-endian u16)
    let attrs_data_size = (scratch[26] as usize) | ((scratch[27] as usize) << 8);

    // Total record size = header + attribute data
    let total_size = V2_HEADER_SIZE + attrs_data_size;

    // Bound to scratch buffer capacity
    if total_size > MAX_LABEL_DATA_SIZE {
        return Err(-1);
    }

    // Stage 2: Read attribute data (if any)
    if attrs_data_size > 0 {
        unsafe {
            bpf_probe_read_user_buf(
                (record_ptr + V2_HEADER_SIZE as u64) as *const u8,
                &mut scratch[V2_HEADER_SIZE..total_size],
            )
            .map_err(|e| e as i64)?;
        }
    }

    let end_time = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    emit_event(
        ctx,
        tid,
        2,
        &scratch[..total_size],
        record_ptr,
        start_time,
        end_time,
    )?;

    Ok(())
}

/// Emit a label event to the ring buffer
#[inline(always)]
fn emit_event(
    ctx: &PerfEventContext,
    tid: u32,
    format_version: u8,
    data: &[u8],
    ptr: u64,
    start_time_ns: u64,
    end_time_ns: u64,
) -> Result<(), i64> {
    let mut buf = EVENTS.reserve::<LabelEvent>(0).ok_or(-10)?;

    let event = unsafe { &mut *buf.as_mut_ptr() };
    event.tid = tid;
    event.format_version = format_version;
    event.data_len = data.len() as u16;
    event.ptr = ptr;
    event.start_time_ns = start_time_ns;
    event.end_time_ns = end_time_ns;

    // Copy data (bounded by MAX_LABEL_DATA_SIZE)
    let copy_len = data.len().min(MAX_LABEL_DATA_SIZE);
    event.data[..copy_len].copy_from_slice(&data[..copy_len]);

    buf.submit(0);
    debug!(ctx, "emit_event: tid={} format={}", tid, format_version);

    Ok(())
}

/// Helper to read user memory into a buffer
#[inline(always)]
unsafe fn bpf_probe_read_user_buf(src: *const u8, dst: &mut [u8]) -> Result<(), i64> {
    // BPF verifier needs bounded access, so we read in chunks
    // For simplicity, just read the whole thing if it's small enough
    if dst.len() > MAX_LABEL_DATA_SIZE {
        return Err(-1);
    }

    let result = aya_ebpf::helpers::bpf_probe_read_user_buf(src, dst);
    result.map_err(|e| e as i64)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

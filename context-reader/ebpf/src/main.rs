#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_perf_event_data,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel, bpf_probe_read_user},
    macros::{map, perf_event},
    maps::{HashMap, RingBuf},
    programs::PerfEventContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use context_reader_common::{KernelOffsets, LabelEvent, TlsConfig, MAX_LABEL_DATA_SIZE};

/// Target PID we're monitoring (set by userspace)
#[map]
static TARGET_PID: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

/// V1 TLS configuration (custom_labels_current_set)
#[map]
static V1_TLS_CONFIG: HashMap<u32, TlsConfig> = HashMap::with_max_entries(1, 0);

/// V2 TLS configuration (custom_labels_current_set_v2)
#[map]
static V2_TLS_CONFIG: HashMap<u32, TlsConfig> = HashMap::with_max_entries(1, 0);

/// Kernel structure offsets (calculated from BTF in userspace)
/// This provides portability across kernel versions
#[map]
static KERNEL_OFFSETS: HashMap<u32, KernelOffsets> = HashMap::with_max_entries(1, 0);

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

    // Log that we caught the target process
    info!(ctx, "Caught target PID {} TID {}", pid, tid);

    // Get thread pointer from task_struct
    let thread_pointer = match get_thread_pointer() {
        Ok(tp) => {
            info!(ctx, "PID={} TID={} Thread pointer (fsbase)={}", pid, tid, tp);
            tp
        }
        Err(e) => {
            info!(ctx, "PID={} TID={} Failed to get thread pointer: {}", pid, tid, e);
            return Err(e);
        }
    };

    // Try to read V1 labels
    if let Some(config) = unsafe { V1_TLS_CONFIG.get(&0) } {
        info!(ctx, "About to call read_and_emit_v1");
        match read_and_emit_v1(ctx, tid, thread_pointer, config) {
            Ok(()) => info!(ctx, "V1 event emitted successfully!!!!11"),
            Err(e) => info!(ctx, "V1 failed: error {}", e),
        }
    }

    // Try to read V2 labels
    if let Some(config) = unsafe { V2_TLS_CONFIG.get(&0) } {
        info!(ctx, "About to call read_and_emit_v2");
        match read_and_emit_v2(ctx, tid, thread_pointer, config) {
            Ok(()) => info!(ctx, "V2 event emitted successfully"),
            Err(e) => info!(ctx, "V2 failed: error {}", e),
        }
    } else {
        info!(ctx, "No V2 config found");
    }

    Ok(())
}

/// Get thread pointer using kernel offsets provided by userspace.
/// This approach provides portability - userspace calculates offsets from BTF
/// and passes them to BPF, avoiding hardcoded values.
#[inline(always)]
fn get_thread_pointer() -> Result<u64, i64> {
    // Get kernel offsets from map (calculated by userspace from BTF)
    let offsets = unsafe { KERNEL_OFFSETS.get(&0) };
    let Some(offsets) = offsets else {
        return Err(-2); // Offsets not configured
    };

    if offsets.valid == 0 {
        return Err(-3); // Offsets marked as invalid
    }

    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return Err(-1);
    }

    // Read task_struct->thread.fsbase using offsets from userspace
    // Works on x86_64; other architectures would use different field names
    let thread_offset = offsets.task_struct_thread_offset as usize;
    let fsbase_offset = offsets.thread_struct_fsbase_offset as usize;
    let total_offset = thread_offset + fsbase_offset;

    let fsbase_ptr = unsafe { (task as *const u8).add(total_offset) as *const u64 };
    let fsbase = unsafe { bpf_probe_read_kernel(fsbase_ptr).map_err(|e| e as i64)? };

    Ok(fsbase)
}

/// Compute TLS variable address from thread pointer and config
#[inline(always)]
fn compute_tls_address(thread_pointer: u64, config: &TlsConfig) -> Result<u64, i64> {
    if config.is_main_executable != 0 {
        // Main executable: static offset from thread pointer
        // x86_64 uses TLS variant II: address = thread_pointer - offset
        // aarch64 uses TLS variant I: address = thread_pointer + TCB_SIZE + offset
        // For now, assume x86_64 (variant II)
        Ok(thread_pointer.wrapping_sub(config.offset))
    } else {
        // Shared library: need DTV lookup
        // DTV pointer is at thread_pointer + 0 on both architectures
        let dtv_ptr: u64 = unsafe {
            bpf_probe_read_user(thread_pointer as *const u64).map_err(|e| e as i64)?
        };

        if dtv_ptr == 0 {
            return Err(-1);
        }

        // DTV entry size is 16 bytes on 64-bit
        const DTV_ENTRY_SIZE: u64 = 16;
        let dtv_entry_addr = dtv_ptr + (config.module_id * DTV_ENTRY_SIZE);

        // Read TLS block pointer from DTV entry
        let tls_block: u64 = unsafe {
            bpf_probe_read_user(dtv_entry_addr as *const u64).map_err(|e| e as i64)?
        };

        // Check for unallocated marker (-1)
        if tls_block == u64::MAX || tls_block == 0 {
            return Err(-1);
        }

        Ok(tls_block + config.offset)
    }
}

/// Read V1 format labels and emit to ringbuf
#[inline(always)]
fn read_and_emit_v1(ctx: &PerfEventContext, tid: u32, thread_pointer: u64, config: &TlsConfig) -> Result<(), i64> {
    info!(ctx, "read_and_emit_v1: START");

    let tls_addr = compute_tls_address(thread_pointer, config)?;
    info!(ctx, "read_and_emit_v1: computed tls_addr");

    // Read pointer to labelset
    let labelset_ptr: u64 = unsafe {
        bpf_probe_read_user(tls_addr as *const u64).map_err(|e| e as i64)?
    };
    info!(ctx, "read_and_emit_v1: read labelset_ptr={}", labelset_ptr);

    if labelset_ptr == 0 {
        info!(ctx, "read_and_emit_v1: labelset_ptr is 0, returning");
        return Ok(()); // No labels set
    }

    // V1 labelset structure: { storage: *mut Label, count: usize, capacity: usize }
    // We'll read the raw structure and pass to userspace for parsing

    // Get scratch buffer
    let scratch = unsafe { SCRATCH.get_ptr_mut(0).ok_or(-1)? };
    let scratch = unsafe { &mut *scratch };
    info!(ctx, "read_and_emit_v1: got scratch buffer");

    // Read labelset header (24 bytes on 64-bit)
    const LABELSET_HEADER_SIZE: usize = 24;
    unsafe {
        bpf_probe_read_user_buf(labelset_ptr as *const u8, &mut scratch[..LABELSET_HEADER_SIZE])
            .map_err(|e| e as i64)?;
    }
    info!(ctx, "read_and_emit_v1: read labelset header");

    // Emit event with raw data for userspace to parse
    info!(ctx, "read_and_emit_v1: about to call emit_event");
    emit_event(ctx, tid, 1, &scratch[..LABELSET_HEADER_SIZE], labelset_ptr)?;
    info!(ctx, "read_and_emit_v1: emit_event returned Ok");

    Ok(())
}

/// Read V2 format labels and emit to ringbuf
#[inline(always)]
fn read_and_emit_v2(ctx: &PerfEventContext, tid: u32, thread_pointer: u64, config: &TlsConfig) -> Result<(), i64> {
    info!(ctx, "read_and_emit_v2: START");

    let tls_addr = compute_tls_address(thread_pointer, config)?;
    info!(ctx, "read_and_emit_v2: TP={} offset={} -> tls_addr={}", thread_pointer, config.offset, tls_addr);

    // Read pointer to v2 record - read as byte array to see exact bytes
    let mut ptr_bytes = [0u8; 8];
    unsafe {
        for i in 0..8 {
            ptr_bytes[i] = bpf_probe_read_user((tls_addr + i as u64) as *const u8).map_err(|e| e as i64)?;
        }
    }
    let record_ptr = u64::from_ne_bytes(ptr_bytes);
    info!(ctx, "read_and_emit_v2: read bytes [{} {} {} {} {} {} {} {}] -> ptr={}",
        ptr_bytes[0], ptr_bytes[1], ptr_bytes[2], ptr_bytes[3],
        ptr_bytes[4], ptr_bytes[5], ptr_bytes[6], ptr_bytes[7], record_ptr);

    if record_ptr == 0 {
        info!(ctx, "read_and_emit_v2: record_ptr is 0, returning");
        return Ok(()); // No record set
    }

    // Get scratch buffer
    let scratch = unsafe { SCRATCH.get_ptr_mut(0).ok_or(-1)? };
    let scratch = unsafe { &mut *scratch };
    info!(ctx, "read_and_emit_v2: got scratch buffer");

    // Read V2 record using the actual max_record_size from config
    let read_size = (config.max_record_size as usize).min(MAX_LABEL_DATA_SIZE);
    info!(ctx, "read_and_emit_v2: about to read {} bytes from record_ptr (config.max_record_size={})", read_size, config.max_record_size);
    unsafe {
        bpf_probe_read_user_buf(record_ptr as *const u8, &mut scratch[..read_size])
            .map_err(|e| {
                info!(ctx, "read_and_emit_v2: bpf_probe_read_user_buf FAILED with error {}", e);
                e as i64
            })?;
    }
    info!(ctx, "read_and_emit_v2: read record data");

    // Emit event with raw record data
    info!(ctx, "read_and_emit_v2: about to call emit_event");
    emit_event(ctx, tid, 2, &scratch[..read_size], record_ptr)?;
    info!(ctx, "read_and_emit_v2: emit_event returned Ok");

    Ok(())
}

/// Emit a label event to the ring buffer
#[inline(always)]
fn emit_event(ctx: &PerfEventContext, tid: u32, format_version: u8, data: &[u8], ptr: u64) -> Result<(), i64> {
    info!(ctx, "emit_event: ENTERED tid={} format={} data_len={}", tid, format_version, data.len());

    info!(ctx, "emit_event: calling reserve");
    let mut buf = EVENTS.reserve::<LabelEvent>(0).ok_or(-10)?;
    info!(ctx, "emit_event: reserve succeeded");

    let event = unsafe { &mut *buf.as_mut_ptr() };
    event.tid = tid;
    event.format_version = format_version;
    event.data_len = data.len() as u16;
    event.ptr = ptr;

    // Copy data (bounded by MAX_LABEL_DATA_SIZE)
    let copy_len = data.len().min(MAX_LABEL_DATA_SIZE);
    event.data[..copy_len].copy_from_slice(&data[..copy_len]);
    info!(ctx, "emit_event: data copied, calling submit");

    buf.submit(0);
    info!(ctx, "emit_event: submit completed");

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

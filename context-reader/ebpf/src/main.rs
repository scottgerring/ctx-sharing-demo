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
use aya_log_ebpf::debug;
use context_reader_common::{
    calculate_static_tls_address, Architecture, KernelOffsets, LabelEvent, TlsConfig,
    MAX_LABEL_DATA_SIZE, CURRENT_ARCH,
};

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

    debug!(ctx, "on_cpu_sample: pid={} tid={}", pid, tid);

    // Get thread pointer from task_struct
    let thread_pointer = get_thread_pointer()?;

    // Try to read V1 labels
    if let Some(config) = unsafe { V1_TLS_CONFIG.get(&0) } {
        let _ = read_and_emit_v1(ctx, tid, thread_pointer, config);
    }

    // Try to read V2 labels
    if let Some(config) = unsafe { V2_TLS_CONFIG.get(&0) } {
        let _ = read_and_emit_v2(ctx, tid, thread_pointer, config);
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
        // Main executable: use shared calculation logic
        Ok(calculate_static_tls_address(
            thread_pointer,
            config.offset,
            CURRENT_ARCH,
        ))
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
fn read_and_emit_v1(ctx: &PerfEventContext, tid: u32, thread_pointer: u64, config: &TlsConfig) -> Result<(), i64> {
    debug!(ctx, "read_and_emit_v1: tid={}", tid);

    let tls_addr = compute_tls_address(thread_pointer, config)?;

    // Read pointer to labelset
    let labelset_ptr: u64 = unsafe {
        bpf_probe_read_user(tls_addr as *const u64).map_err(|e| e as i64)?
    };

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
    const MAX_LABELS: usize = 12;

    #[inline(always)]
    fn read_label(
        storage_ptr: u64,
        index: usize,
        scratch: &mut [u8],
        write_pos: &mut usize,
    ) -> Result<(), i64> {
        let label_addr = storage_ptr + (index as u64 * 32);

        // Read label structure: [key_len, key_buf, value_len, value_buf]
        let key_len: u64 = unsafe {
            bpf_probe_read_user(label_addr as *const u64).map_err(|e| e as i64)?
        };
        let key_buf: u64 = unsafe {
            bpf_probe_read_user((label_addr + 8) as *const u64).map_err(|e| e as i64)?
        };
        let value_len: u64 = unsafe {
            bpf_probe_read_user((label_addr + 16) as *const u64).map_err(|e| e as i64)?
        };
        let value_buf: u64 = unsafe {
            bpf_probe_read_user((label_addr + 24) as *const u64).map_err(|e| e as i64)?
        };

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

    // Emit the packed label data
    emit_event(ctx, tid, 1, &scratch[..write_pos], labelset_ptr)?;

    Ok(())
}

/// Read V2 format labels and emit to ringbuf
#[inline(always)]
fn read_and_emit_v2(ctx: &PerfEventContext, tid: u32, thread_pointer: u64, config: &TlsConfig) -> Result<(), i64> {
    debug!(ctx, "read_and_emit_v2: tid={}", tid);

    let tls_addr = compute_tls_address(thread_pointer, config)?;

    // Read pointer to v2 record
    let record_ptr: u64 = unsafe {
        bpf_probe_read_user(tls_addr as *const u64).map_err(|e| e as i64)?
    };

    if record_ptr == 0 {
        return Ok(()); // No record set
    }

    // Get scratch buffer
    let scratch = unsafe { SCRATCH.get_ptr_mut(0).ok_or(-1)? };
    let scratch = unsafe { &mut *scratch };

    // Read V2 record using the actual max_record_size from config
    let read_size = (config.max_record_size as usize).min(MAX_LABEL_DATA_SIZE);
    unsafe {
        bpf_probe_read_user_buf(record_ptr as *const u8, &mut scratch[..read_size])
            .map_err(|e| e as i64)?;
    }

    emit_event(ctx, tid, 2, &scratch[..read_size], record_ptr)?;

    Ok(())
}

/// Emit a label event to the ring buffer
#[inline(always)]
fn emit_event(ctx: &PerfEventContext, tid: u32, format_version: u8, data: &[u8], ptr: u64) -> Result<(), i64> {
    let mut buf = EVENTS.reserve::<LabelEvent>(0).ok_or(-10)?;

    let event = unsafe { &mut *buf.as_mut_ptr() };
    event.tid = tid;
    event.format_version = format_version;
    event.data_len = data.len() as u16;
    event.ptr = ptr;

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

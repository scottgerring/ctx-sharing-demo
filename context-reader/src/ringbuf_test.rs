//! Minimal ringbuf test - polls an existing EVENTS ringbuf
//!
//! Usage: Find the map ID with `sudo bpftool map list | grep EVENTS`
//! Then run: `sudo cargo run --bin ringbuf-test -- <map_id>`

use anyhow::{Context, Result};
use aya::maps::{Map, MapData};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <map_id>", args[0]);
        eprintln!("\nFind map ID with: sudo bpftool map list | grep EVENTS");
        std::process::exit(1);
    }

    let map_id: u32 = args[1].parse().context("Invalid map ID")?;

    println!("Opening ringbuf map with ID: {}", map_id);

    // Open the existing map by ID and create RingBuf
    let mut ring = open_ringbuf_by_id(map_id)?;
    println!("Created RingBuf, starting to poll...\n");

    let mut iteration = 0u64;
    let mut total_events = 0u64;

    loop {
        iteration += 1;

        // Poll the ringbuf
        match ring.next() {
            Some(item) => {
                total_events += 1;
                let data: &[u8] = &*item;  // Deref RingBufItem to &[u8]
                println!("[Event {}] Received {} bytes:", total_events, data.len());
                println!("  First 64 bytes (hex): {:02x?}", &data[..data.len().min(64)]);

                // Try to interpret as LabelEvent if size matches
                if data.len() >= 1040 {
                    let tid = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    let format_version = data[4];
                    let data_len = u16::from_ne_bytes([data[6], data[7]]);
                    println!("  Parsed: tid={}, format_version={}, data_len={}", tid, format_version, data_len);
                }
                println!();
            }
            None => {
                // No data available
            }
        }

        if iteration % 1000 == 0 {
            println!("[Iteration {}] Polled {} times, received {} events", iteration, iteration, total_events);
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Open a RingBuf from an existing map ID
fn open_ringbuf_by_id(map_id: u32) -> Result<aya::maps::ring_buf::RingBuf<MapData>> {
    use aya::maps::ring_buf::RingBuf;
    use std::os::fd::FromRawFd;

    println!("Getting FD for map ID {}...", map_id);

    // Call bpf_map_get_fd_by_id syscall
    let fd = unsafe {
        // BPF syscall number and BPF_MAP_GET_FD_BY_ID command
        #[repr(C)]
        struct bpf_attr {
            map_id: u32,
            next_id: u32,
            flags: u32,
        }

        let mut attr = bpf_attr {
            map_id,
            next_id: 0,
            flags: 0,
        };

        let fd = libc::syscall(
            libc::SYS_bpf,
            14, // BPF_MAP_GET_FD_BY_ID (correct command number)
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<bpf_attr>(),
        );

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("BPF syscall failed: {}", err);
            return Err(err.into());
        }

        std::os::fd::OwnedFd::from_raw_fd(fd as i32)
    };

    println!("Got FD: {:?}", fd);

    // Create MapData from the FD
    let map_data = MapData::from_fd(fd)?;
    println!("Created MapData");

    // Create a Map enum wrapping the MapData
    let map = Map::RingBuf(map_data);
    println!("Created Map");

    // Create RingBuf from the Map
    let ring = RingBuf::try_from(map)?;
    println!("Created RingBuf");

    Ok(ring)
}

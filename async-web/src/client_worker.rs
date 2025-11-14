use crate::http_server::{DoWorkRequest, MergesortRequest, PrimeSieveRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self};
use std::time::Duration;
use tracing::{info, warn};

pub fn background_client_thread(request_count: Arc<AtomicUsize>, shutdown_signal: Arc<AtomicBool>) {
    const NUM_PARALLEL_CLIENTS: usize = 5; // Number of parallel client threads
    const REQUESTS_PER_CLIENT: usize = 1500; // Each client makes 1500 requests

    info!(
        "Background client thread started: {NUM_PARALLEL_CLIENTS} parallel clients, {REQUESTS_PER_CLIENT} reqs per client"
    );

    // Spawn multiple client threads
    let mut handles = vec![];

    for client_id in 0..NUM_PARALLEL_CLIENTS {
        let request_count = Arc::clone(&request_count);
        let shutdown_signal = Arc::clone(&shutdown_signal);

        let handle = thread::spawn(move || {
            // Give the server time to start
            thread::sleep(Duration::from_millis(100));

            info!("Background client #{} starting requests...", client_id);

            // Create a blocking HTTP client
            let client = reqwest::blocking::Client::new();

            for i in 0..REQUESTS_PER_CLIENT {
                if shutdown_signal.load(Ordering::Acquire) {
                    break;
                }

                // Rotate through endpoints based on request number
                let endpoint_choice = i % 3;

                let result = match endpoint_choice {
                    0 => {
                        let request_data = DoWorkRequest { iterations: 100 };
                        client
                            .post("http://127.0.0.1:3000/do_work")
                            .json(&request_data)
                            .send()
                    }
                    1 => {
                        let request_data = MergesortRequest { size: 100_000 };
                        client
                            .post("http://127.0.0.1:3000/mergesort")
                            .json(&request_data)
                            .send()
                    }
                    2 => {
                        let request_data = PrimeSieveRequest { limit: 1_000_000 };
                        client
                            .post("http://127.0.0.1:3000/prime_sieve")
                            .json(&request_data)
                            .send()
                    }
                    _ => unreachable!(),
                };

                match result {
                    Ok(response) => {
                        let total = request_count.fetch_add(1, Ordering::Release) + 1;
                        if total % 10 == 0 {
                            let endpoint_name = match endpoint_choice {
                                0 => "do_work",
                                1 => "mergesort",
                                2 => "prime_sieve",
                                _ => "unknown",
                            };
                            info!(
                                "Client #{} request {}/{} ({}): {}",
                                client_id,
                                i + 1,
                                REQUESTS_PER_CLIENT,
                                endpoint_name,
                                response.status()
                            );
                        }
                    }
                    Err(e) => {
                        let total = request_count.fetch_add(1, Ordering::Release) + 1;
                        if total % 10 == 0 {
                            warn!(
                                "Client #{} request {}/{} failed: {}",
                                client_id,
                                i + 1,
                                REQUESTS_PER_CLIENT,
                                e
                            );
                        }
                    }
                }
            }

            info!(
                "Background client #{} completed {} requests",
                client_id, REQUESTS_PER_CLIENT
            );
        });

        handles.push(handle);
    }

    // Spawn a coordinator thread that waits for all clients to finish
    thread::spawn(move || {
        for handle in handles {
            let _ = handle.join();
        }

        let total = request_count.load(Ordering::Acquire);
        info!(
            "All background clients completed {} total requests, signaling shutdown...",
            total
        );

        shutdown_signal.store(true, Ordering::Release);
    });
}

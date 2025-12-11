use actix_web::dev::Server;
use actix_web::{App, HttpResponse, HttpServer, web};
use opentelemetry::{
    Context, global,
    trace::{TraceContextExt, Tracer, TracerProvider},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Deserialize, Serialize)]
pub struct DoWorkRequest {
    #[serde(default = "default_iterations")]
    pub(crate) iterations: u32,
}

fn default_iterations() -> u32 {
    1000
}

#[derive(Serialize)]
struct DoWorkResponse {
    iterations_completed: u32,
    random_result: f64,
}

#[instrument(skip(request))]
pub async fn do_work_handler(request: web::Json<DoWorkRequest>) -> HttpResponse {
    // Create an OpenTelemetry span and attach it to trigger context label logging
    let tracer = global::tracer_provider().tracer("async-web");
    let span = tracer
        .span_builder("do_work_handler")
        .with_attributes(vec![opentelemetry::KeyValue::new(
            "http.route",
            "/do_work",
        )])
        .start(&tracer);
    let cx = Context::current_with_span(span);
    let _guard = cx.attach();

    // Nested span 1: Initialize random number generator
    let mut random_result = {
        let child_span = tracer
            .span_builder("initialize_rng")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        // Do some initialization work
        let mut rng = rand::thread_rng();
        rng.r#gen::<f64>()
    };

    // Nested span 2: Perform iterations
    {
        let child_span = tracer
            .span_builder("perform_iterations")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        for _ in 1..request.iterations {
            let mut rng = rand::thread_rng();
            random_result += rng.r#gen::<f64>();
        }
    }

    // Nested span 3: Calculate average
    let final_result = {
        let child_span = tracer
            .span_builder("calculate_average")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        random_result / request.iterations as f64
    };

    let response = DoWorkResponse {
        iterations_completed: request.iterations,
        random_result: final_result,
    };

    HttpResponse::Ok().json(response)
}

#[derive(Deserialize, Serialize)]
pub struct MergesortRequest {
    #[serde(default = "default_array_size")]
    pub(crate) size: usize,
}

fn default_array_size() -> usize {
    100_000
}

#[derive(Serialize)]
struct MergesortResponse {
    size: usize,
    first_10: Vec<i32>,
    last_10: Vec<i32>,
    sorted_checksum: i64,
}

#[instrument(skip(request))]
pub async fn mergesort_handler(request: web::Json<MergesortRequest>) -> HttpResponse {
    // Create an OpenTelemetry span and attach it to trigger context label logging
    let tracer = global::tracer_provider().tracer("async-web");
    let span = tracer
        .span_builder("mergesort_handler")
        .with_attributes(vec![opentelemetry::KeyValue::new(
            "http.route",
            "/mergesort",
        )])
        .start(&tracer);
    let cx = Context::current_with_span(span);
    let _guard = cx.attach();

    // Nested span 1: Generate random array
    let mut arr: Vec<i32> = {
        let child_span = tracer
            .span_builder("generate_random_array")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        let mut rng = rand::thread_rng();
        (0..request.size)
            .map(|_| rng.gen_range(0..1_000_000))
            .collect()
    };

    // Nested span 2: Perform mergesort
    {
        let child_span = tracer
            .span_builder("perform_mergesort")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        mergesort(&mut arr);
    }

    // Nested span 3: Calculate statistics
    let (sorted_checksum, first_10, last_10) = {
        let child_span = tracer
            .span_builder("calculate_statistics")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        let checksum: i64 = arr.iter().map(|&x| x as i64).sum();
        let first: Vec<i32> = arr.iter().take(10).copied().collect();
        let last: Vec<i32> = arr.iter().rev().take(10).rev().copied().collect();
        (checksum, first, last)
    };

    let response = MergesortResponse {
        size: request.size,
        first_10,
        last_10,
        sorted_checksum,
    };

    HttpResponse::Ok().json(response)
}

fn mergesort(arr: &mut [i32]) {
    let len = arr.len();
    if len <= 1 {
        return;
    }

    let mid = len / 2;
    mergesort(&mut arr[..mid]);
    mergesort(&mut arr[mid..]);

    // Merge the two sorted halves
    let mut temp = Vec::with_capacity(len);
    let (left, right) = arr.split_at(mid);

    let mut i = 0;
    let mut j = 0;

    while i < left.len() && j < right.len() {
        if left[i] <= right[j] {
            temp.push(left[i]);
            i += 1;
        } else {
            temp.push(right[j]);
            j += 1;
        }
    }

    temp.extend_from_slice(&left[i..]);
    temp.extend_from_slice(&right[j..]);
    arr.copy_from_slice(&temp);
}

#[derive(Deserialize, Serialize)]
pub struct PrimeSieveRequest {
    #[serde(default = "default_limit")]
    pub(crate) limit: usize,
}

fn default_limit() -> usize {
    1_000_000
}

#[derive(Serialize)]
struct PrimeSieveResponse {
    limit: usize,
    prime_count: usize,
    largest_prime: usize,
    first_10_primes: Vec<usize>,
}

#[instrument(skip(request))]
pub async fn prime_sieve_handler(request: web::Json<PrimeSieveRequest>) -> HttpResponse {
    // Create an OpenTelemetry span and attach it to trigger context label logging
    let tracer = global::tracer_provider().tracer("async-web");
    let span = tracer
        .span_builder("prime_sieve_handler")
        .with_attributes(vec![opentelemetry::KeyValue::new(
            "http.route",
            "/prime_sieve",
        )])
        .start(&tracer);
    let cx = Context::current_with_span(span);
    let _guard = cx.attach();

    // Nested span 1: Run sieve algorithm
    let primes = {
        let child_span = tracer
            .span_builder("run_sieve_algorithm")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        sieve_of_eratosthenes(request.limit)
    };

    // Nested span 2: Extract statistics
    let (prime_count, largest_prime, first_10_primes) = {
        let child_span = tracer
            .span_builder("extract_prime_statistics")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        let count = primes.len();
        let largest = *primes.last().unwrap_or(&0);
        let first_10: Vec<usize> = primes.iter().take(10).copied().collect();
        (count, largest, first_10)
    };

    // Nested span 3: Build response
    let response = {
        let child_span = tracer
            .span_builder("build_response")
            .start_with_context(&tracer, &Context::current());
        let child_cx = Context::current_with_span(child_span);
        let _child_guard = child_cx.attach();

        PrimeSieveResponse {
            limit: request.limit,
            prime_count,
            largest_prime,
            first_10_primes,
        }
    };

    HttpResponse::Ok().json(response)
}

fn sieve_of_eratosthenes(limit: usize) -> Vec<usize> {
    if limit < 2 {
        return vec![];
    }

    let mut is_prime = vec![true; limit + 1];
    is_prime[0] = false;
    is_prime[1] = false;

    let sqrt_limit = (limit as f64).sqrt() as usize;
    for i in 2..=sqrt_limit {
        if is_prime[i] {
            let mut j = i * i;
            while j <= limit {
                is_prime[j] = false;
                j += i;
            }
        }
    }

    is_prime
        .iter()
        .enumerate()
        .filter_map(|(num, &prime)| if prime { Some(num) } else { None })
        .collect()
}

pub fn start_http_server() -> Server {
    HttpServer::new(move || {
        App::new()
            .wrap(opentelemetry_instrumentation_actix_web::RequestTracing::new())
            .route("/do_work", web::post().to(do_work_handler))
            .route("/mergesort", web::post().to(mergesort_handler))
            .route("/prime_sieve", web::post().to(prime_sieve_handler))
    })
    .workers(10)
    .bind(("0.0.0.0", 3000))
    .expect("Failed to bind server")
    .run()
}

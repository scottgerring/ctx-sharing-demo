use crate::label_parser::LabelValue;
use crate::tls_reader::ThreadResult;
use tracing::info;

pub fn print_iteration(iteration: u64, results: &[ThreadResult]) {
    let mut found_threads = Vec::new();
    let mut empty_threads = Vec::new();
    let mut not_found_threads = Vec::new();

    for result in results {
        match result {
            ThreadResult::Found { tid, labels } => {
                if labels.is_empty() {
                    empty_threads.push(*tid);
                } else {
                    found_threads.push((*tid, labels));
                }
            }
            ThreadResult::NotFound { tid } => {
                not_found_threads.push(*tid);
            }
            ThreadResult::Error { tid, error: _ } => {
                // Errors? Just record them as not found, for now ...
                not_found_threads.push(*tid);
            }
        }
    }

    // Print threads with labels
    for (tid, labels) in found_threads {
        let label_strs: Vec<String> = labels
            .iter()
            .map(|l| {
                let value_str = match &l.value {
                    LabelValue::Text(s) => s.clone(),
                    LabelValue::Bytes(b) => {
                        // Format bytes as hex string
                        b.iter().map(|byte| format!("{:02x}", byte)).collect()
                    }
                };
                format!("{}={}", l.key, value_str)
            })
            .collect();

        info!(
            "iteration = {}, thread = {}, context_labels = [{}]",
            iteration,
            tid,
            label_strs.join(", ")
        );
    }

    // Print threads with empty labelsets
    for tid in empty_threads {
        info!(
            "iteration = {}, thread = {}, context_labels = []",
            iteration, tid
        );
    }

    // Print not found threads
    if !not_found_threads.is_empty() {
        let tid_strs: Vec<String> = not_found_threads.iter().map(|t| t.to_string()).collect();
        info!(
            "iteration = {}, not_found = threads [{}]",
            iteration,
            tid_strs.join(", ")
        );
    }
}

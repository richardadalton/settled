use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};

lazy_static! {
    /// Total entries durably appended to the log.
    pub static ref ENTRIES_APPENDED: IntCounter = register_int_counter!(
        "settled_entries_appended_total",
        "Total number of entries appended to the log"
    ).unwrap();

    /// Histogram of append durations (seconds). Buckets tuned to the p50 < 100µs target.
    pub static ref APPEND_DURATION: Histogram = register_histogram!(
        "settled_append_duration_seconds",
        "Duration of log append operations in seconds",
        vec![0.000_025, 0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.005, 0.01]
    ).unwrap();

    /// Total Signed Tree Heads produced.
    pub static ref STH_SIGNED: IntCounter = register_int_counter!(
        "settled_sth_signed_total",
        "Total number of Signed Tree Heads produced"
    ).unwrap();

    /// Histogram of STH signing durations (seconds).
    pub static ref STH_SIGN_DURATION: Histogram = register_histogram!(
        "settled_sth_sign_duration_seconds",
        "Duration of STH signing operations in seconds",
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
    ).unwrap();

    /// Current Merkle tree size (number of committed entries under a signed root).
    pub static ref TREE_SIZE: IntGauge = register_int_gauge!(
        "settled_tree_size",
        "Number of entries covered by the latest Signed Tree Head"
    ).unwrap();

    /// Unix timestamp (nanoseconds) of the latest Signed Tree Head.
    /// Compute lag as `time.now_ns - settled_sth_last_timestamp_ns`.
    pub static ref STH_LAST_TIMESTAMP_NS: IntGauge = register_int_gauge!(
        "settled_sth_last_timestamp_ns",
        "Timestamp of the latest Signed Tree Head in nanoseconds since Unix epoch"
    ).unwrap();
}

/// Render all registered metrics in Prometheus text format.
pub fn gather_text() -> Result<String, prometheus::Error> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let families = prometheus::gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf)?;
    Ok(String::from_utf8(buf).expect("prometheus output is always valid UTF-8"))
}

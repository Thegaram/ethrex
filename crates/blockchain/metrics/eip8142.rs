use prometheus::{
    Gauge, Histogram, HistogramVec, IntCounterVec, IntGauge, exponential_buckets, register_gauge,
    register_histogram, register_histogram_vec, register_int_counter_vec, register_int_gauge,
};
use std::sync::LazyLock;

// Metrics defined in this module register into the Prometheus default registry.
// The metrics API exposes them via `gather_default_metrics()`.

pub static METRICS_EIP8142: LazyLock<MetricsEip8142> = LazyLock::new(MetricsEip8142::default);

/// `payload_blob_count` is small (1 .. MAX_BLOBS_PER_BLOCK), so use explicit
/// integer-aligned buckets rather than exponential.
fn payload_blob_count_buckets() -> Vec<f64> {
    vec![
        1.0, 2.0, 3.0, 4.0, 6.0, 9.0, 12.0, 16.0, 24.0, 32.0, 48.0,
    ]
}

#[derive(Debug, Clone)]
pub struct MetricsEip8142 {
    /// 1 while EIP-8142 (block-in-blobs) is active, 0 otherwise.
    pub active: IntGauge,
    /// Distribution of `payload_blob_count` per built block.
    pub payload_blob_count: Histogram,
    /// Cumulative blob count, split by `kind` ("payload" vs "type3").
    pub blobs_total: IntCounterVec,
    /// Payload-blob count of the most recent built block (per-block, not a histogram).
    pub payload_blob_count_last: IntGauge,
    /// Total blobs (payload + type-3) in the most recent built block.
    pub block_blobs: IntGauge,
    /// Effective MAX_BLOBS_PER_BLOCK for the most recent built block.
    pub max_blobs: IntGauge,
    /// Fill fraction (0..1) of the trailing payload blob of the most recent block
    /// — the padding-waste signal (every blob but the last is full).
    pub last_payload_blob_utilization: Gauge,
    /// RLP-encoded block access list bytes packed into payload blobs, most recent
    /// built block.
    pub payload_bal_bytes: IntGauge,
    /// RLP-encoded transactions bytes packed into payload blobs, most recent built
    /// block.
    pub payload_txs_bytes: IntGauge,
    /// Duration of payload-blob KZG work, by `op`: "commit" (native newPayload,
    /// `blob_to_kzg_commitment` MSM, hot path) and "proofs" (zk getPayload,
    /// `compute_payload_kzg_proofs`).
    pub kzg_duration_seconds: HistogramVec,
}

impl Default for MetricsEip8142 {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsEip8142 {
    pub fn new() -> Self {
        MetricsEip8142 {
            active: register_int_gauge!(
                "eip8142_active",
                "1 while EIP-8142 (block-in-blobs) is active, 0 otherwise"
            )
            .expect("Failed to create eip8142_active metric"),
            payload_blob_count: register_histogram!(
                "eip8142_payload_blob_count",
                "Distribution of payload_blob_count per built block",
                payload_blob_count_buckets()
            )
            .expect("Failed to create eip8142_payload_blob_count metric"),
            blobs_total: register_int_counter_vec!(
                "eip8142_blobs_total",
                "Cumulative blob count split by kind (payload vs type3)",
                &["kind"]
            )
            .expect("Failed to create eip8142_blobs_total metric"),
            payload_blob_count_last: register_int_gauge!(
                "eip8142_payload_blob_count_last",
                "Payload-blob count of the most recent built block"
            )
            .expect("Failed to create eip8142_payload_blob_count_last metric"),
            block_blobs: register_int_gauge!(
                "eip8142_block_blobs",
                "Total blobs (payload + type-3) in the most recent built block"
            )
            .expect("Failed to create eip8142_block_blobs metric"),
            max_blobs: register_int_gauge!(
                "eip8142_max_blobs",
                "Effective MAX_BLOBS_PER_BLOCK for the most recent built block"
            )
            .expect("Failed to create eip8142_max_blobs metric"),
            last_payload_blob_utilization: register_gauge!(
                "eip8142_last_payload_blob_utilization",
                "Fill fraction (0..1) of the trailing payload blob of the most recent block"
            )
            .expect("Failed to create eip8142_last_payload_blob_utilization metric"),
            payload_bal_bytes: register_int_gauge!(
                "eip8142_payload_bal_bytes",
                "RLP-encoded block access list bytes packed into payload blobs (most recent built block)"
            )
            .expect("Failed to create eip8142_payload_bal_bytes metric"),
            payload_txs_bytes: register_int_gauge!(
                "eip8142_payload_txs_bytes",
                "RLP-encoded transactions bytes packed into payload blobs (most recent built block)"
            )
            .expect("Failed to create eip8142_payload_txs_bytes metric"),
            kzg_duration_seconds: register_histogram_vec!(
                "eip8142_kzg_duration_seconds",
                "Duration of payload-blob KZG work by op (commit / proofs)",
                &["op"],
                // ~100us .. ~3s, doubling: covers a single MSM up to many blobs.
                exponential_buckets(0.0001, 2.0, 16)
                    .expect("Invalid eip8142 KZG histogram bucket params")
            )
            .expect("Failed to create eip8142_kzg_duration_seconds metric"),
        }
    }
}

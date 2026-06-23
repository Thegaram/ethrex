//! EIP-8142 "block-in-blobs" native end-to-end round-trip tests.
//!
//! No external source of EIP-8142 blocks exists yet (no EELS fixtures, no CL
//! support), so these round-trip against ethrex's own builder: build a payload
//! with a type-3 (blob) tx in the mempool → `engine_getPayloadV7` →
//! `engine_newPayloadV6` → VALID.
//!
//! This target is built **without** the `eip-8025` feature (`required-features =
//! ["c-kzg"]`), so `ethrex-blockchain` compiles with its parallel BAL executor
//! present — the production configuration. The `newPayloadV6` step here imports a
//! BAL-carrying block through `execute_block_pipeline`, which is only correct with
//! that executor compiled in. The `eip-8025` guest flow lives in the separate
//! `eip8142_guest` target; **do not** run the two under one `cargo test` with
//! `--features ...,eip-8025`, or feature unification would compile this target's
//! blockchain crate without the parallel executor. Run them separately:
//!   cargo test -p ethrex-test --test eip8142_native --features c-kzg
//!   cargo test -p ethrex-test --test eip8142_guest  --features c-kzg,eip-8025

#[path = "eip8142_common/mod.rs"]
mod common;

use common::{
    build_bib_payload_fixture, bundle_from_response, get_payload_v7, hex_bytes, hex_u64,
    new_payload_request,
};
use ethrex_common::types::{Transaction, eip8142::execution_payload_to_blobs_from_raw_bal};
use ethrex_rpc::engine::payload::{NewPayloadV5Request, NewPayloadV6Request};
use ethrex_rpc::rpc::RpcHandler;
use ethrex_rpc::utils::RpcErr;
use serde_json::json;

/// Happy path: getPayloadV7 returns `payloadBlobCount` and a payload-first
/// bundle, and the same payload is VALID through newPayloadV6.
#[tokio::test]
async fn engine_get_payload_v7_then_new_payload_v6_round_trip() {
    let fixture = build_bib_payload_fixture().await;
    let response = get_payload_v7(&fixture).await;
    let payload = &response["executionPayload"];

    // Both txs made it into the block.
    assert_eq!(payload["transactions"].as_array().unwrap().len(), 2);

    let payload_blob_count = hex_u64(&payload["payloadBlobCount"]) as usize;
    assert!(payload_blob_count >= 1, "payload must occupy >= 1 blob");

    let bundle = bundle_from_response(&response);
    // Payload blobs first, then the type-3 tx's single user blob.
    assert_eq!(bundle.blobs.len(), payload_blob_count + 1);
    let max_blobs = fixture
        .context
        .storage
        .get_chain_config()
        .get_fork_blob_schedule(hex_u64(&payload["timestamp"]))
        .unwrap()
        .max as usize;
    assert!(bundle.blobs.len() <= max_blobs, "combined MAX_BLOBS bound");

    // The leading blobs re-derive exactly from {blockAccessList, transactions}.
    let raw_bal = hex_bytes(&payload["blockAccessList"]);
    let transactions: Vec<Transaction> = payload["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tx| Transaction::decode_canonical(&hex_bytes(tx)).unwrap())
        .collect();
    let payload_blobs = execution_payload_to_blobs_from_raw_bal(&raw_bal, &transactions);
    assert_eq!(payload_blobs.len(), payload_blob_count);
    assert_eq!(
        payload_blobs.as_slice(),
        &bundle.blobs[..payload_blob_count]
    );

    // The trailing commitment is the blob tx's (user blobs ride behind).
    let versioned_hashes = bundle.generate_versioned_hashes();
    assert_eq!(
        &versioned_hashes[payload_blob_count..],
        fixture.blob_tx_versioned_hashes.as_slice()
    );

    // The native V7 response carries no zk opening proofs.
    assert!(bundle.payload_kzg_proofs.is_empty());

    // newPayloadV6 re-derives the blobs, recomputes commitments and accepts.
    let request = new_payload_request(
        "engine_newPayloadV6",
        &response,
        payload.clone(),
        fixture.beacon_root,
    );
    let status = NewPayloadV6Request::call(&request, fixture.context.clone())
        .await
        .expect("engine_newPayloadV6 should not error");
    assert_eq!(status["status"], "VALID", "got: {status}");
}

/// A tampered `payloadBlobCount` must be rejected before execution.
#[tokio::test]
async fn engine_new_payload_v6_rejects_tampered_payload_blob_count() {
    let fixture = build_bib_payload_fixture().await;
    let response = get_payload_v7(&fixture).await;

    let mut payload = response["executionPayload"].clone();
    let tampered = hex_u64(&payload["payloadBlobCount"]) + 1;
    payload["payloadBlobCount"] = json!(format!("{tampered:#x}"));

    let request = new_payload_request(
        "engine_newPayloadV6",
        &response,
        payload,
        fixture.beacon_root,
    );
    let status = NewPayloadV6Request::call(&request, fixture.context.clone())
        .await
        .expect("engine_newPayloadV6 should not error");
    assert_eq!(status["status"], "INVALID", "got: {status}");
    assert!(
        status["validationError"]
            .as_str()
            .unwrap()
            .contains("payload_blob_count"),
        "got: {status}"
    );
}

/// Mismatched `expected_blob_versioned_hashes` must be rejected. Unlike the
/// tampered-count case (which trips the earlier count check), here the count is
/// left correct so verification reaches the payload↔commitment binding step
/// (`expected == payload_hashes + type3_hashes`).
#[tokio::test]
async fn engine_new_payload_v6_rejects_mismatched_versioned_hashes() {
    let fixture = build_bib_payload_fixture().await;
    let response = get_payload_v7(&fixture).await;

    // Corrupt the first (payload-blob) versioned hash, leaving the payload — and so
    // `payloadBlobCount` and the block hash — untouched.
    let mut versioned_hashes = bundle_from_response(&response).generate_versioned_hashes();
    versioned_hashes[0].0[31] ^= 0x01;

    let mut request = new_payload_request(
        "engine_newPayloadV6",
        &response,
        response["executionPayload"].clone(),
        fixture.beacon_root,
    );
    // `params[1]` is `expected_blob_versioned_hashes`.
    request.params.as_mut().unwrap()[1] = json!(versioned_hashes);

    let status = NewPayloadV6Request::call(&request, fixture.context.clone())
        .await
        .expect("engine_newPayloadV6 should not error");
    assert_eq!(status["status"], "INVALID", "got: {status}");
    assert!(
        status["validationError"]
            .as_str()
            .unwrap()
            .contains("blob_versioned_hashes"),
        "got: {status}"
    );
}

/// An EIP-8142-active payload must use V6: V5 fails with unsupported fork.
#[tokio::test]
async fn engine_new_payload_v5_rejects_eip8142_active_payload() {
    let fixture = build_bib_payload_fixture().await;
    let response = get_payload_v7(&fixture).await;

    let request = new_payload_request(
        "engine_newPayloadV5",
        &response,
        response["executionPayload"].clone(),
        fixture.beacon_root,
    );
    let result = NewPayloadV5Request::call(&request, fixture.context.clone()).await;
    assert!(
        matches!(result, Err(RpcErr::UnsupportedFork(_))),
        "got: {result:?}"
    );
}

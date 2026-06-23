//! EIP-8142 "block-in-blobs" guest-program ("prover") flow.
//!
//! The zk `getPayload` variant plus the witness is everything a prover needs to
//! assemble the spec's `new_payload_zk` input and prove the block — without ever
//! seeing the blobs themselves. We build a payload with ethrex's own builder,
//! assemble a `BibStatelessInput`, run the guest program natively, and assert
//! `valid = true`.
//!
//! Built with `required-features = ["c-kzg", "eip-8025"]`. The setup only uses the
//! payload **build** path and witness generation (`collect_witness = true`) — it
//! never imports a BAL-carrying block through `execute_block_pipeline` — so it is
//! unaffected by whether `ethrex-blockchain`'s parallel executor is compiled in.
//! The native round-trip (which does import) lives in the separate `eip8142_native`
//! target; run the two suites in **separate** `cargo test` invocations (see the
//! header of `eip8142_native.rs`).

#[path = "eip8142_common/mod.rs"]
mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::{build_bib_payload_fixture, bundle_from_response, test_secret_key};
use ethrex_common::types::block_execution_witness::RpcExecutionWitness;
use ethrex_common::types::eip8025_ssz::{
    Bytes20, ExecutionPayloadV5, ExecutionRequests, NewPayloadRequestBib,
};
use ethrex_crypto::NativeCrypto;
use ethrex_guest_program::l1::{
    BibStatelessInput, CanonicalBlobSchedule, CanonicalChainConfig, CanonicalExecutionWitness,
    CanonicalForkActivation, CanonicalForkConfig, EIP8025_VERSION_BIB, ProgramOutput,
    execution_program,
};
use ethrex_rlp::encode::RLPEncode;
use ethrex_rpc::engine::payload::{GetPayloadV7Request, GetPayloadWithKzgProofsV7Request};
use ethrex_rpc::rpc::RpcHandler;
use ethrex_rpc::utils::RpcRequest;
use libssz::SszEncode;

/// Build a block, fetch it through the zk getPayload variant (bundle +
/// `payload_kzg_proofs`), and assemble the `0x02` BiB stateless input the
/// guest program consumes: canonical request + witness + private inputs
/// (public keys, payload-blob commitments and opening proofs).
async fn assemble_bib_stateless_input() -> (BibStatelessInput, Vec<u8>) {
    let fixture = build_bib_payload_fixture().await;

    // zk getPayload: native V7 response + payload_kzg_proofs attached.
    let request: RpcRequest = GetPayloadWithKzgProofsV7Request(GetPayloadV7Request {
        payload_id: fixture.payload_id,
    })
    .into();
    let response = GetPayloadWithKzgProofsV7Request::call(&request, fixture.context.clone())
        .await
        .expect("zk getPayload should succeed");
    let bundle = bundle_from_response(&response);

    // The build is finished now; grab the built block and BAL host-side.
    let build = fixture
        .context
        .blockchain
        .get_payload(fixture.payload_id)
        .await
        .unwrap();
    let block = build.payload;
    let header = &block.header;
    let raw_bal = build.block_access_list.unwrap().encode_to_vec();
    let payload_blob_count = header.payload_blob_count.unwrap() as usize;

    // One opening proof per payload blob, none for the user blob.
    assert_eq!(bundle.payload_kzg_proofs.len(), payload_blob_count);

    // The witness is the same one `engine_newPayloadWithWitness*` serves.
    let witness = fixture
        .context
        .blockchain
        .generate_witness_for_blocks(std::slice::from_ref(&block))
        .await
        .unwrap();
    let rpc_witness = RpcExecutionWitness::try_from(witness).unwrap();
    fn to_ssz_list<const MAX_BYTES: usize, const MAX_ITEMS: usize>(
        items: Vec<Bytes>,
    ) -> libssz_types::SszList<libssz_types::SszList<u8, MAX_BYTES>, MAX_ITEMS> {
        items
            .into_iter()
            .map(|b| b.to_vec().try_into().expect("witness item fits"))
            .collect::<Vec<_>>()
            .try_into()
            .expect("witness list fits")
    }

    let mut base_fee_per_gas = [0u8; 32]; // SSZ uint256, little-endian
    base_fee_per_gas[..8].copy_from_slice(&header.base_fee_per_gas.unwrap().to_le_bytes());
    let execution_payload = ExecutionPayloadV5 {
        parent_hash: header.parent_hash.0,
        fee_recipient: Bytes20(header.coinbase.0),
        state_root: header.state_root.0,
        receipts_root: header.receipts_root.0,
        logs_bloom: header.logs_bloom.0.to_vec().try_into().unwrap(),
        prev_randao: header.prev_randao.0,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header.extra_data.to_vec().try_into().unwrap(),
        base_fee_per_gas,
        block_hash: block.hash().0,
        transactions: block
            .body
            .transactions
            .iter()
            .map(|tx| tx.encode_canonical_to_vec().try_into().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        withdrawals: vec![].try_into().unwrap(),
        blob_gas_used: header.blob_gas_used.unwrap(),
        excess_blob_gas: header.excess_blob_gas.unwrap(),
        block_access_list: raw_bal.try_into().unwrap(),
        slot_number: header.slot_number.unwrap(),
        payload_blob_count: header.payload_blob_count.unwrap(),
    };

    // Per-tx uncompressed secp256k1 keys (every tx is from the test signer).
    let public_key = test_secret_key()
        .public_key(secp256k1::SECP256K1)
        .serialize_uncompressed();
    let public_keys = block
        .body
        .transactions
        .iter()
        .map(|_| public_key.to_vec().try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let chain_config = fixture.context.storage.get_chain_config();
    let blob_schedule = chain_config
        .get_fork_blob_schedule(header.timestamp)
        .unwrap();

    let stateless_input = BibStatelessInput {
        new_payload_request: NewPayloadRequestBib {
            execution_payload,
            versioned_hashes: bundle
                .generate_versioned_hashes()
                .into_iter()
                .map(|hash| hash.0)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            parent_beacon_block_root: fixture.beacon_root.0,
            execution_requests: ExecutionRequests {
                deposits: vec![].try_into().unwrap(),
                withdrawals: vec![].try_into().unwrap(),
                consolidations: vec![].try_into().unwrap(),
            },
        },
        witness: CanonicalExecutionWitness {
            state: to_ssz_list(rpc_witness.state),
            codes: to_ssz_list(rpc_witness.codes),
            headers: to_ssz_list(rpc_witness.headers),
        },
        chain_config: CanonicalChainConfig {
            chain_id: chain_config.chain_id,
            active_fork: CanonicalForkConfig {
                fork: 0,
                activation: CanonicalForkActivation {
                    block_number: vec![].try_into().unwrap(),
                    timestamp: vec![].try_into().unwrap(),
                },
                blob_schedule: vec![CanonicalBlobSchedule {
                    target: u64::from(blob_schedule.target),
                    max: u64::from(blob_schedule.max),
                    base_fee_update_fraction: blob_schedule.base_fee_update_fraction,
                }]
                .try_into()
                .unwrap(),
            },
        },
        public_keys,
        payload_kzg_commitments: bundle.commitments[..payload_blob_count]
            .to_vec()
            .try_into()
            .unwrap(),
        payload_kzg_proofs: bundle.payload_kzg_proofs.clone().try_into().unwrap(),
    };

    let chain_config_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&chain_config)
        .unwrap()
        .to_vec();
    (stateless_input, chain_config_bytes)
}

/// Encode the `0x02` wire framing and run the guest program entry point.
fn run_guest(stateless_input: &BibStatelessInput, chain_config_bytes: &[u8]) -> ProgramOutput {
    let ssz_bytes = stateless_input.to_ssz();
    let mut wire = vec![EIP8025_VERSION_BIB];
    wire.extend((ssz_bytes.len() as u32).to_le_bytes());
    wire.extend_from_slice(&ssz_bytes);
    wire.extend((chain_config_bytes.len() as u32).to_le_bytes());
    wire.extend_from_slice(chain_config_bytes);

    execution_program(&wire, Arc::new(NativeCrypto)).expect("guest program should run")
}

/// `new_payload_zk` happy path: the guest verifies the payload blobs as
/// KZG openings and re-executes the block statelessly.
#[tokio::test]
async fn guest_program_proves_built_block() {
    let (stateless_input, chain_config_bytes) = assemble_bib_stateless_input().await;
    let output = run_guest(&stateless_input, &chain_config_bytes);

    assert!(output.valid, "guest must prove the built block valid");
    assert_eq!(output.chain_id, stateless_input.chain_config.chain_id);
    assert_ne!(output.new_payload_request_root, [0u8; 32]);
}

/// Corrupting any private input flips `valid` to false. A corrupted
/// opening proof must not change the committed request root: proofs are
/// private inputs outside the hash-tree-rooted `NewPayloadRequest`.
#[tokio::test]
async fn guest_program_rejects_corrupted_inputs() {
    let (stateless_input, chain_config_bytes) = assemble_bib_stateless_input().await;
    let honest = run_guest(&stateless_input, &chain_config_bytes);
    assert!(honest.valid);

    // Corrupted opening proof: KZG batch verification fails.
    let mut corrupted = stateless_input.clone();
    let mut proofs: Vec<[u8; 48]> = corrupted.payload_kzg_proofs.iter().copied().collect();
    proofs[0][47] ^= 0x01;
    corrupted.payload_kzg_proofs = proofs.try_into().unwrap();
    let output = run_guest(&corrupted, &chain_config_bytes);
    assert!(!output.valid, "corrupted proof must invalidate");
    assert_eq!(
        output.new_payload_request_root, honest.new_payload_request_root,
        "proofs are private inputs and must not affect the request root"
    );

    // Corrupted commitment: versioned-hash check fails.
    let mut corrupted = stateless_input.clone();
    let mut commitments: Vec<[u8; 48]> =
        corrupted.payload_kzg_commitments.iter().copied().collect();
    commitments[0][0] ^= 0x01;
    corrupted.payload_kzg_commitments = commitments.try_into().unwrap();
    assert!(!run_guest(&corrupted, &chain_config_bytes).valid);

    // Tampered payload_blob_count: block reconstruction hash check fails.
    let mut corrupted = stateless_input.clone();
    corrupted
        .new_payload_request
        .execution_payload
        .payload_blob_count += 1;
    assert!(!run_guest(&corrupted, &chain_config_bytes).valid);

    // Tampered payload data (BAL byte): re-derived blobs and the header's
    // BAL hash no longer match the committed block.
    let mut corrupted = stateless_input;
    let mut raw_bal: Vec<u8> = corrupted
        .new_payload_request
        .execution_payload
        .block_access_list
        .iter()
        .copied()
        .collect();
    *raw_bal.last_mut().unwrap() ^= 0x01;
    corrupted
        .new_payload_request
        .execution_payload
        .block_access_list = raw_bal.try_into().unwrap();
    assert!(!run_guest(&corrupted, &chain_config_bytes).valid);
}

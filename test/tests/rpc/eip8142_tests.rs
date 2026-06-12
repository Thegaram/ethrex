//! EIP-8142 "block-in-blobs" end-to-end round-trip tests.
//!
//! No external source of EIP-8142 blocks exists yet (no EELS fixtures, no CL
//! support), so these tests round-trip against ethrex's own builder. The two
//! sides are independent: the builder encodes payload blobs, the native
//! `engine_newPayloadV6` re-derives them and recomputes commitments (MSM),
//! and the guest program verifies KZG openings over a raw-BAL re-encoding.
//!
//! - Native flow: build a payload with a type-3 (blob) tx in the mempool →
//!   `engine_getPayloadV7` → `engine_newPayloadV6` → VALID.
//! - Guest flow (`eip-8025` feature): the zk `getPayload` variant →
//!   assemble a `BibStatelessInput` (the spec's `new_payload_zk` inputs) →
//!   run the guest program natively → `valid = true`.

use std::{fs::File, io::BufReader, path::PathBuf};

use bytes::Bytes;
use ethrex_blockchain::payload::{BuildPayloadArgs, create_payload};
use ethrex_common::{
    Address, H256, U256,
    types::{
        BlobsBundle, DEFAULT_BUILDER_GAS_CEIL, EIP1559Transaction, EIP4844Transaction,
        ELASTICITY_MULTIPLIER, Genesis, GenesisAccount, Transaction, TxKind, blob_from_bytes,
        eip8142::execution_payload_to_blobs_from_raw_bal,
    },
};
use ethrex_l2_rpc::signer::{LocalSigner, Signable, Signer};
use ethrex_rpc::engine::payload::{GetPayloadV7Request, NewPayloadV5Request, NewPayloadV6Request};
use ethrex_rpc::rpc::{RpcApiContext, RpcHandler};
use ethrex_rpc::test_utils::default_context_with_storage;
use ethrex_rpc::utils::{RpcErr, RpcRequest};
use ethrex_storage::{EngineType, Store};
use secp256k1::SecretKey;
use serde_json::{Value, json};

/// Test private key from fixtures/keys/private_keys_tests.txt.
const TEST_PRIVATE_KEY: &str = "850643a0224065ecce3882673c21f56bcf6eef86274cc21cadff15930b59fc8c";
/// Comfortably high max fee — well above any genesis base fee.
const TEST_MAX_FEE_PER_GAS: u64 = 10_000_000_000;
const TEST_GAS_LIMIT: u64 = 100_000;

fn test_secret_key() -> SecretKey {
    SecretKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Load the Amsterdam (BAL) genesis, activate EIP-8142 at genesis, and fund
/// the test sender.
async fn bib_store(sender: Address) -> Store {
    let file = File::open(workspace_root().join("fixtures/genesis/l1-bal.json"))
        .expect("Failed to open genesis file");
    let reader = BufReader::new(file);
    let mut genesis: Genesis =
        serde_json::from_reader(reader).expect("Failed to deserialize genesis file");

    genesis.config.eip8142_time = Some(0);
    genesis.alloc.insert(
        sender,
        GenesisAccount {
            balance: U256::from(10).pow(U256::from(20)), // 100 ETH
            code: Bytes::new(),
            storage: Default::default(),
            nonce: 0,
        },
    );

    let mut store =
        Store::new("store.db", EngineType::InMemory).expect("Failed to build DB for testing");
    store
        .add_initial_state(genesis)
        .await
        .expect("Failed to add genesis state");
    store
}

/// A payload built by ethrex's own builder on a BiB-active chain, holding a
/// regular tx and a type-3 (blob) tx, retrievable through `engine_getPayload`.
struct BibPayloadFixture {
    context: RpcApiContext,
    payload_id: u64,
    beacon_root: H256,
    /// Versioned hashes of the type-3 transaction's (user) blobs.
    blob_tx_versioned_hashes: Vec<H256>,
}

async fn build_bib_payload_fixture() -> BibPayloadFixture {
    let sk = test_secret_key();
    let signer: Signer = LocalSigner::new(sk).into();
    let sender = LocalSigner::new(sk).address;

    let store = bib_store(sender).await;
    let chain_id = store.get_chain_config().chain_id;
    let context = default_context_with_storage(store.clone()).await;
    let blockchain = context.blockchain.clone();

    // A regular tx, so payload blobs carry actual transaction data.
    let mut tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: TEST_MAX_FEE_PER_GAS,
        gas_limit: TEST_GAS_LIMIT,
        to: TxKind::Call(Address::from_low_u64_be(0xAA)),
        value: U256::one(),
        data: Bytes::new(),
        ..Default::default()
    });
    tx.sign_inplace(&signer).await.unwrap();
    blockchain.add_transaction_to_pool(tx).await.unwrap();

    // A type-3 tx with one user blob, to prove user blobs ride *behind* the
    // payload blobs (payload-first ordering) under the combined MAX_BLOBS cap.
    let user_blob = blob_from_bytes(Bytes::from_static(b"EIP-8142 user blob")).unwrap();
    let bundle = BlobsBundle::create_from_blobs(&vec![user_blob], Some(1)).unwrap();
    let blob_tx_versioned_hashes = bundle.generate_versioned_hashes();
    let mut blob_tx = Transaction::EIP4844Transaction(EIP4844Transaction {
        chain_id,
        nonce: 1,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: TEST_MAX_FEE_PER_GAS,
        gas: TEST_GAS_LIMIT,
        to: Address::from_low_u64_be(0xBB),
        value: U256::zero(),
        data: Bytes::new(),
        max_fee_per_blob_gas: U256::from(1_000_000_000u64),
        blob_versioned_hashes: blob_tx_versioned_hashes.clone(),
        ..Default::default()
    });
    blob_tx.sign_inplace(&signer).await.unwrap();
    let Transaction::EIP4844Transaction(blob_tx) = blob_tx else {
        unreachable!()
    };
    blockchain
        .add_blob_transaction_to_pool(blob_tx, bundle)
        .await
        .unwrap();

    // Start a payload build like engine_forkchoiceUpdated with payload
    // attributes does (fork_choice.rs `build_payload_v4`).
    let genesis_header = store.get_block_header(0).unwrap().unwrap();
    let beacon_root = H256::zero();
    let args = BuildPayloadArgs {
        parent: genesis_header.hash(),
        timestamp: genesis_header.timestamp + 12,
        fee_recipient: Address::zero(),
        random: H256::zero(),
        withdrawals: Some(Vec::new()),
        beacon_root: Some(beacon_root),
        slot_number: Some(1),
        version: 4,
        elasticity_multiplier: ELASTICITY_MULTIPLIER,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
    };
    let payload_id = args.id().unwrap();
    let payload = create_payload(&args, &store, Bytes::new()).unwrap();
    blockchain.initiate_payload_build(payload, payload_id).await;

    BibPayloadFixture {
        context,
        payload_id,
        beacon_root,
        blob_tx_versioned_hashes,
    }
}

async fn get_payload_v7(fixture: &BibPayloadFixture) -> Value {
    let request: RpcRequest = GetPayloadV7Request {
        payload_id: fixture.payload_id,
    }
    .into();
    GetPayloadV7Request::call(&request, fixture.context.clone())
        .await
        .expect("engine_getPayloadV7 should succeed")
}

fn new_payload_request(
    method: &str,
    response: &Value,
    payload: Value,
    beacon_root: H256,
) -> RpcRequest {
    let bundle: BlobsBundle = serde_json::from_value(response["blobsBundle"].clone()).unwrap();
    RpcRequest {
        method: method.to_string(),
        params: Some(vec![
            payload,
            json!(bundle.generate_versioned_hashes()),
            json!(beacon_root),
            response["executionRequests"].clone(),
        ]),
        ..Default::default()
    }
}

fn hex_u64(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

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

    let bundle: BlobsBundle = serde_json::from_value(response["blobsBundle"].clone()).unwrap();
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

/// Guest-program ("prover") flow: the zk getPayload variant plus the witness
/// is everything a prover needs to assemble the spec's `new_payload_zk` input
/// and prove the block — without ever seeing the blobs themselves.
#[cfg(feature = "eip-8025")]
mod guest_program {
    use super::*;

    use std::sync::Arc;

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
    use ethrex_rpc::engine::payload::GetPayloadWithKzgProofsV7Request;
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
        let bundle: BlobsBundle = serde_json::from_value(response["blobsBundle"].clone()).unwrap();

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
}

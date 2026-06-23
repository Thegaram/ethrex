//! Shared fixtures for the EIP-8142 "block-in-blobs" test targets.
//!
//! Split across two `[[test]]` targets so that the native flow and the
//! `eip-8025` guest flow are built with **disjoint** features (see the docs in
//! `eip8142_native.rs` / `eip8142_guest.rs`). Each target uses a subset of these
//! helpers, hence the crate-level `dead_code` allowance.
#![allow(dead_code)]

use std::{fs::File, io::BufReader, path::PathBuf};

use bytes::Bytes;
use ethrex_blockchain::payload::{BuildPayloadArgs, create_payload};
use ethrex_common::{
    Address, H256, U256,
    types::{
        BlobsBundle, DEFAULT_BUILDER_GAS_CEIL, EIP1559Transaction, EIP4844Transaction,
        ELASTICITY_MULTIPLIER, Genesis, GenesisAccount, Transaction, TxKind, blob_from_bytes,
    },
};
use ethrex_l2_rpc::signer::{LocalSigner, Signable, Signer};
use ethrex_rpc::engine::payload::GetPayloadV7Request;
use ethrex_rpc::rpc::{RpcApiContext, RpcHandler};
use ethrex_rpc::test_utils::default_context_with_storage;
use ethrex_rpc::utils::RpcRequest;
use ethrex_storage::{EngineType, Store};
use secp256k1::SecretKey;
use serde_json::{Value, json};

/// Test private key from fixtures/keys/private_keys_tests.txt.
pub const TEST_PRIVATE_KEY: &str =
    "850643a0224065ecce3882673c21f56bcf6eef86274cc21cadff15930b59fc8c";
/// Comfortably high max fee — well above any genesis base fee.
pub const TEST_MAX_FEE_PER_GAS: u64 = 10_000_000_000;
pub const TEST_GAS_LIMIT: u64 = 100_000;

pub fn test_secret_key() -> SecretKey {
    SecretKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap()
}

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Load the Amsterdam (BAL) genesis, activate EIP-8142 at genesis, and fund
/// the test sender.
pub async fn bib_store(sender: Address) -> Store {
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
pub struct BibPayloadFixture {
    pub context: RpcApiContext,
    pub payload_id: u64,
    pub beacon_root: H256,
    /// Versioned hashes of the type-3 transaction's (user) blobs.
    pub blob_tx_versioned_hashes: Vec<H256>,
}

pub async fn build_bib_payload_fixture() -> BibPayloadFixture {
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

pub async fn get_payload_v7(fixture: &BibPayloadFixture) -> Value {
    let request: RpcRequest = GetPayloadV7Request {
        payload_id: fixture.payload_id,
    }
    .into();
    GetPayloadV7Request::call(&request, fixture.context.clone())
        .await
        .expect("engine_getPayloadV7 should succeed")
}

/// Deserialize the `blobsBundle` field of a getPayload response.
pub fn bundle_from_response(response: &Value) -> BlobsBundle {
    serde_json::from_value(response["blobsBundle"].clone()).unwrap()
}

pub fn new_payload_request(
    method: &str,
    response: &Value,
    payload: Value,
    beacon_root: H256,
) -> RpcRequest {
    let bundle = bundle_from_response(response);
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

pub fn hex_u64(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

pub fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

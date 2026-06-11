use std::sync::Arc;

#[cfg(feature = "eip-8025")]
use ethrex_common::Address;
#[cfg(feature = "eip-8025")]
use ethrex_common::utils::keccak;
use ethrex_crypto::Crypto;

use crate::common::ExecutionError;
use crate::common::execute_blocks;
use crate::l1::input::ProgramInput;
#[cfg(feature = "eip-8025")]
use crate::l1::input::{
    BibStatelessInput, CanonicalExecutionWitness, CanonicalStatelessInput, DecodedEip8025,
    PublicKeysList,
};
use crate::l1::output::ProgramOutput;

use ethrex_common::types::ELASTICITY_MULTIPLIER;
use ethrex_vm::Evm;

#[cfg(feature = "eip-8025")]
use libssz_merkle::Sha256Hasher;

#[cfg(not(feature = "eip-8025"))]
use crate::common::BatchExecutionResult;

/// Execute the L1 stateless validation program.
///
/// This validates and executes a batch of L1 blocks, verifying state transitions
/// without access to the full blockchain state.
#[cfg(not(feature = "eip-8025"))]
pub fn execution_program(
    input: ProgramInput,
    crypto: Arc<dyn Crypto>,
) -> Result<ProgramOutput, ExecutionError> {
    let ProgramInput {
        blocks,
        execution_witness,
    } = input;

    let BatchExecutionResult {
        receipts: _,
        initial_state_hash,
        final_state_hash,
        last_block_hash,
        non_privileged_count,
        chain_id,
    } = execute_blocks(
        &blocks,
        execution_witness,
        ELASTICITY_MULTIPLIER,
        |db, _| {
            // L1 VM factory - simple creation without fee configs
            Ok(Evm::new_for_l1(db.clone(), crypto.clone()))
        },
        crypto.clone(),
    )?;

    Ok(ProgramOutput {
        initial_state_hash,
        final_state_hash,
        last_block_hash,
        chain_id: chain_id.into(),
        transaction_count: non_privileged_count,
    })
}

/// Wrapper to bridge `ethrex_crypto::Crypto` to `libssz_merkle::Sha256Hasher`,
/// so `hash_tree_root` is computed via crypto precompiles in the zkVM.
/// Required because the orphan rule prevents a direct impl on `Arc<dyn Crypto>`.
#[cfg(feature = "eip-8025")]
struct CryptoWrapper(Arc<dyn Crypto>);

#[cfg(feature = "eip-8025")]
impl Sha256Hasher for CryptoWrapper {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        self.0.sha256(data)
    }
}

/// Decode and execute the L1 stateless validation program from EIP-8025 wire
/// bytes.
///
/// The wire format is version-prefixed; see [`super::decode_eip8025`] for the
/// per-version layout. Legacy and canonical-input payloads both commit to the
/// decoded `NewPayloadRequest` root and report execution validity as a boolean.
#[cfg(feature = "eip-8025")]
pub fn execution_program(
    bytes: &[u8],
    crypto: Arc<dyn Crypto>,
) -> Result<ProgramOutput, ExecutionError> {
    let decoded = super::decode_eip8025(bytes).map_err(|err| {
        ExecutionError::Internal(format!("failed to decode EIP-8025 input: {err}"))
    })?;

    execute_decoded(ProgramInput::Wire(decoded), crypto)
}

/// Execute an already-built [`ProgramInput`].
///
/// The `Direct` arm has no `NewPayloadRequest`, so it returns a sentinel
/// `ProgramOutput` with zero request_root and `valid = true`. `ExecBackend`
/// promotes `valid = false` to `Err` for result-only callers.
#[cfg(feature = "eip-8025")]
pub fn execute_decoded(
    input: ProgramInput,
    crypto: Arc<dyn Crypto>,
) -> Result<ProgramOutput, ExecutionError> {
    use libssz_merkle::HashTreeRoot;

    match input {
        ProgramInput::Direct {
            blocks,
            execution_witness,
        } => {
            let chain_id = execution_witness.chain_config.chain_id;
            execute_blocks(
                &blocks,
                execution_witness,
                ELASTICITY_MULTIPLIER,
                |db, _| Ok(Evm::new_for_l1(db.clone(), crypto.clone())),
                crypto.clone(),
            )?;
            Ok(ProgramOutput {
                new_payload_request_root: [0u8; 32],
                valid: true,
                chain_id,
            })
        }
        ProgramInput::Wire(DecodedEip8025::Legacy {
            new_payload_request,
            execution_witness,
        }) => {
            let request_root = new_payload_request.hash_tree_root(&CryptoWrapper(crypto.clone()));
            let chain_id = execution_witness.chain_config.chain_id;
            let valid =
                validate_eip8025_execution(&new_payload_request, execution_witness, crypto).is_ok();

            Ok(ProgramOutput {
                new_payload_request_root: request_root,
                valid,
                chain_id,
            })
        }
        ProgramInput::Wire(DecodedEip8025::Canonical {
            stateless_input,
            chain_config,
        }) => Ok(execute_canonical_stateless_input_decoded(
            stateless_input,
            chain_config,
            crypto,
        )),
        ProgramInput::Wire(DecodedEip8025::Bib {
            stateless_input,
            chain_config,
        }) => Ok(execute_bib_stateless_input_decoded(
            stateless_input,
            chain_config,
            crypto,
        )),
    }
}

#[cfg(feature = "eip-8025")]
fn execute_canonical_stateless_input_decoded(
    stateless_input: CanonicalStatelessInput,
    chain_config: ethrex_common::types::ChainConfig,
    crypto: Arc<dyn Crypto>,
) -> ProgramOutput {
    use libssz_merkle::HashTreeRoot;

    let request_root = stateless_input
        .new_payload_request
        .hash_tree_root(&CryptoWrapper(crypto.clone()));
    let chain_id = stateless_input.chain_config.chain_id;
    let valid = validate_eip8025_canonical_execution(stateless_input, chain_config, crypto).is_ok();

    ProgramOutput {
        new_payload_request_root: request_root,
        valid,
        chain_id,
    }
}

#[cfg(feature = "eip-8025")]
fn execute_bib_stateless_input_decoded(
    stateless_input: BibStatelessInput,
    chain_config: ethrex_common::types::ChainConfig,
    crypto: Arc<dyn Crypto>,
) -> ProgramOutput {
    use libssz_merkle::HashTreeRoot;

    let request_root = stateless_input
        .new_payload_request
        .hash_tree_root(&CryptoWrapper(crypto.clone()));
    let chain_id = stateless_input.chain_config.chain_id;
    let valid = validate_eip8025_bib_execution(stateless_input, chain_config, crypto).is_ok();

    ProgramOutput {
        new_payload_request_root: request_root,
        valid,
        chain_id,
    }
}

#[cfg(feature = "eip-8025")]
fn decode_payload_transactions<const MAX_TXS: usize, const MAX_BYTES_PER_TX: usize>(
    transactions: &libssz_types::SszList<libssz_types::SszList<u8, MAX_BYTES_PER_TX>, MAX_TXS>,
) -> Result<Vec<ethrex_common::types::Transaction>, String> {
    transactions
        .iter()
        .map(|tx_bytes| {
            ethrex_common::types::Transaction::decode_canonical(tx_bytes)
                .map_err(|e| format!("tx decode: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(feature = "eip-8025")]
fn decode_payload_withdrawals<const MAX_WITHDRAWALS: usize>(
    withdrawals: &libssz_types::SszList<
        ethrex_common::types::eip8025_ssz::Withdrawal,
        MAX_WITHDRAWALS,
    >,
) -> Vec<ethrex_common::types::Withdrawal> {
    use ethrex_common::Address;

    withdrawals
        .iter()
        .map(|w| ethrex_common::types::Withdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: Address::from_slice(&w.address.0),
            amount: w.amount,
        })
        .collect()
}

#[cfg(feature = "eip-8025")]
fn base_fee_per_gas_from_le_bytes(bytes: &[u8; 32]) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| "base_fee_per_gas conversion")?,
    ))
}

#[cfg(feature = "eip-8025")]
fn validate_reconstructed_block_hash(
    block: &ethrex_common::types::Block,
    expected_hash: &[u8; 32],
    crypto: &dyn Crypto,
) -> Result<(), String> {
    let computed_hash = block.header.compute_block_hash(crypto);
    let expected_hash = ethrex_common::H256::from_slice(expected_hash);
    if computed_hash != expected_hash {
        return Err(format!(
            "block_hash mismatch: expected {expected_hash:?}, got {computed_hash:?}"
        ));
    }

    Ok(())
}

/// Transform an SSZ `NewPayloadRequest` into a `Block`.
#[cfg(feature = "eip-8025")]
fn new_payload_request_to_block(
    req: &ethrex_common::types::eip8025_ssz::NewPayloadRequest,
    crypto: &dyn Crypto,
) -> Result<ethrex_common::types::Block, String> {
    use bytes::Bytes;
    use ethrex_common::constants::DEFAULT_OMMERS_HASH;
    use ethrex_common::types::requests::compute_requests_hash;
    use ethrex_common::types::{
        Block, BlockBody, BlockHeader, compute_transactions_root, compute_withdrawals_root,
    };
    use ethrex_common::{Address, Bloom, H256};

    let payload = &req.execution_payload;

    let transactions = decode_payload_transactions(&payload.transactions)?;

    let withdrawals = decode_payload_withdrawals(&payload.withdrawals);

    // Build execution_requests from the SSZ typed ExecutionRequests field
    let execution_requests = req.execution_requests.to_encoded_requests();
    let requests_hash = compute_requests_hash(&execution_requests);

    let base_fee_per_gas = base_fee_per_gas_from_le_bytes(&payload.base_fee_per_gas)?;
    let logs_bloom = Bloom::from_slice(&payload.logs_bloom);

    let transactions_root = compute_transactions_root(&transactions, crypto);
    let withdrawals_root = compute_withdrawals_root(&withdrawals, crypto);

    let body = BlockBody {
        transactions,
        ommers: vec![],
        withdrawals: Some(withdrawals),
    };

    let header = BlockHeader {
        parent_hash: H256::from_slice(&payload.parent_hash),
        ommers_hash: *DEFAULT_OMMERS_HASH,
        coinbase: Address::from_slice(&payload.fee_recipient.0),
        state_root: H256::from_slice(&payload.state_root),
        transactions_root,
        receipts_root: H256::from_slice(&payload.receipts_root),
        logs_bloom,
        difficulty: 0.into(),
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::copy_from_slice(&payload.extra_data),
        prev_randao: H256::from_slice(&payload.prev_randao),
        nonce: 0,
        base_fee_per_gas: Some(base_fee_per_gas),
        withdrawals_root: Some(withdrawals_root),
        blob_gas_used: Some(payload.blob_gas_used),
        excess_blob_gas: Some(payload.excess_blob_gas),
        parent_beacon_block_root: Some(H256::from_slice(&req.parent_beacon_block_root)),
        requests_hash: Some(requests_hash),
        ..Default::default()
    };

    Ok(Block::new(header, body))
}

/// Transform an Amsterdam SSZ `NewPayloadRequest` into a `Block`.
#[cfg(feature = "eip-8025")]
fn new_payload_request_amsterdam_to_block(
    req: &ethrex_common::types::eip8025_ssz::NewPayloadRequestAmsterdam,
    crypto: &dyn Crypto,
) -> Result<ethrex_common::types::Block, String> {
    use bytes::Bytes;
    use ethrex_common::constants::DEFAULT_OMMERS_HASH;
    use ethrex_common::types::block_access_list::BlockAccessList;
    use ethrex_common::types::requests::compute_requests_hash;
    use ethrex_common::types::{
        Block, BlockBody, BlockHeader, compute_transactions_root, compute_withdrawals_root,
    };
    use ethrex_common::{Address, Bloom, H256};
    use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};

    let payload = &req.execution_payload;

    let transactions = decode_payload_transactions(&payload.transactions)?;
    let withdrawals = decode_payload_withdrawals(&payload.withdrawals);

    let block_access_list = BlockAccessList::decode(&payload.block_access_list)
        .map_err(|e| format!("block access list decode: {e}"))?;
    block_access_list
        .validate_ordering()
        .map_err(|e| format!("block access list ordering: {e}"))?;
    if block_access_list.encode_to_vec().as_slice() != &payload.block_access_list[..] {
        return Err("block access list is not canonically encoded".to_string());
    }

    let execution_requests = req.execution_requests.to_encoded_requests();
    let requests_hash = compute_requests_hash(&execution_requests);
    let base_fee_per_gas = base_fee_per_gas_from_le_bytes(&payload.base_fee_per_gas)?;
    let logs_bloom = Bloom::from_slice(&payload.logs_bloom);

    let transactions_root = compute_transactions_root(&transactions, crypto);
    let withdrawals_root = compute_withdrawals_root(&withdrawals, crypto);

    let body = BlockBody {
        transactions,
        ommers: vec![],
        withdrawals: Some(withdrawals),
    };

    let header = BlockHeader {
        parent_hash: H256::from_slice(&payload.parent_hash),
        ommers_hash: *DEFAULT_OMMERS_HASH,
        coinbase: Address::from_slice(&payload.fee_recipient.0),
        state_root: H256::from_slice(&payload.state_root),
        transactions_root,
        receipts_root: H256::from_slice(&payload.receipts_root),
        logs_bloom,
        difficulty: 0.into(),
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::copy_from_slice(&payload.extra_data),
        prev_randao: H256::from_slice(&payload.prev_randao),
        nonce: 0,
        base_fee_per_gas: Some(base_fee_per_gas),
        withdrawals_root: Some(withdrawals_root),
        blob_gas_used: Some(payload.blob_gas_used),
        excess_blob_gas: Some(payload.excess_blob_gas),
        parent_beacon_block_root: Some(H256::from_slice(&req.parent_beacon_block_root)),
        requests_hash: Some(requests_hash),
        block_access_list_hash: Some(block_access_list.compute_hash()),
        slot_number: Some(payload.slot_number),
        ..Default::default()
    };

    let block = Block::new(header, body);
    validate_reconstructed_block_hash(&block, &payload.block_hash, crypto)?;
    Ok(block)
}

/// Transform an EIP-8142 "block-in-blobs" SSZ `NewPayloadRequest` into a `Block`.
#[cfg(feature = "eip-8025")]
fn new_payload_request_bib_to_block(
    req: &ethrex_common::types::eip8025_ssz::NewPayloadRequestBib,
    crypto: &dyn Crypto,
) -> Result<ethrex_common::types::Block, String> {
    use bytes::Bytes;
    use ethrex_common::constants::DEFAULT_OMMERS_HASH;
    use ethrex_common::types::block_access_list::BlockAccessList;
    use ethrex_common::types::requests::compute_requests_hash;
    use ethrex_common::types::{
        Block, BlockBody, BlockHeader, compute_transactions_root, compute_withdrawals_root,
    };
    use ethrex_common::{Address, Bloom, H256};
    use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};

    let payload = &req.execution_payload;

    let transactions = decode_payload_transactions(&payload.transactions)?;
    let withdrawals = decode_payload_withdrawals(&payload.withdrawals);

    let block_access_list = BlockAccessList::decode(&payload.block_access_list)
        .map_err(|e| format!("block access list decode: {e}"))?;
    block_access_list
        .validate_ordering()
        .map_err(|e| format!("block access list ordering: {e}"))?;
    let encoded_block_access_list = block_access_list.encode_to_vec();
    if encoded_block_access_list.as_slice() != &payload.block_access_list[..] {
        return Err("block access list is not canonically encoded".to_string());
    }
    // Equivalent to `BlockAccessList::compute_hash` (keccak of the canonical
    // encoding), reusing the encoding bound for the canonicity check above.
    let block_access_list_hash = keccak(&encoded_block_access_list);

    let execution_requests = req.execution_requests.to_encoded_requests();
    let requests_hash = compute_requests_hash(&execution_requests);
    let base_fee_per_gas = base_fee_per_gas_from_le_bytes(&payload.base_fee_per_gas)?;
    let logs_bloom = Bloom::from_slice(&payload.logs_bloom);

    let transactions_root = compute_transactions_root(&transactions, crypto);
    let withdrawals_root = compute_withdrawals_root(&withdrawals, crypto);

    let body = BlockBody {
        transactions,
        ommers: vec![],
        withdrawals: Some(withdrawals),
    };

    let header = BlockHeader {
        parent_hash: H256::from_slice(&payload.parent_hash),
        ommers_hash: *DEFAULT_OMMERS_HASH,
        coinbase: Address::from_slice(&payload.fee_recipient.0),
        state_root: H256::from_slice(&payload.state_root),
        transactions_root,
        receipts_root: H256::from_slice(&payload.receipts_root),
        logs_bloom,
        difficulty: 0.into(),
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::copy_from_slice(&payload.extra_data),
        prev_randao: H256::from_slice(&payload.prev_randao),
        nonce: 0,
        base_fee_per_gas: Some(base_fee_per_gas),
        withdrawals_root: Some(withdrawals_root),
        blob_gas_used: Some(payload.blob_gas_used),
        excess_blob_gas: Some(payload.excess_blob_gas),
        parent_beacon_block_root: Some(H256::from_slice(&req.parent_beacon_block_root)),
        requests_hash: Some(requests_hash),
        block_access_list_hash: Some(block_access_list_hash),
        slot_number: Some(payload.slot_number),
        // New in EIP-8142
        payload_blob_count: Some(payload.payload_blob_count),
        ..Default::default()
    };

    let block = Block::new(header, body);
    validate_reconstructed_block_hash(&block, &payload.block_hash, crypto)?;
    Ok(block)
}

/// Validate that the blob versioned hashes in the `NewPayloadRequest` match
/// the EIP-8142 payload-blob hashes followed by the versioned hashes of the
/// blob transactions.
#[cfg(feature = "eip-8025")]
fn validate_versioned_hashes<'a>(
    transactions: &[ethrex_common::types::Transaction],
    payload_versioned_hashes: &[ethrex_common::H256],
    expected_blob_versioned_hashes: impl IntoIterator<Item = &'a [u8; 32]>,
) -> Result<(), ExecutionError> {
    use ethrex_common::H256;

    // All versioned hashes from blob transactions, in order
    let tx_hashes = transactions
        .iter()
        .flat_map(|tx| tx.blob_versioned_hashes());

    // Payload blobs first, then blob transactions in order
    let all_hashes = payload_versioned_hashes.iter().copied().chain(tx_hashes);

    let req_hashes = expected_blob_versioned_hashes
        .into_iter()
        .map(|h| H256::from_slice(h));

    if !all_hashes.eq(req_hashes) {
        return Err(ExecutionError::Internal(
            "versioned hashes mismatch between NewPayloadRequest and transactions".to_string(),
        ));
    }

    Ok(())
}

#[cfg(feature = "eip-8025")]
fn canonical_execution_witness_to_rpc(
    witness: CanonicalExecutionWitness,
) -> ethrex_common::types::block_execution_witness::RpcExecutionWitness {
    use bytes::Bytes;

    fn copy_ssz_bytes<const MAX_BYTES: usize>(
        bytes: &libssz_types::SszList<u8, MAX_BYTES>,
    ) -> Bytes {
        Bytes::copy_from_slice(bytes)
    }

    ethrex_common::types::block_execution_witness::RpcExecutionWitness {
        state: witness.state.iter().map(copy_ssz_bytes).collect(),
        // The specs do not have a `keys` field in the witness. This field
        // is inherited from a legacy debug_executionWitness design.
        // A `keys` field is not currently planned to be included in
        // the specs. It might if there is rough consensus it is valuable
        // for execution witness validation performance.
        keys: Vec::new(),
        codes: witness.codes.iter().map(copy_ssz_bytes).collect(),
        headers: witness.headers.iter().map(copy_ssz_bytes).collect(),
    }
}

/// Convert the canonical SSZ witness into an `ExecutionWitness`, validating
/// header-chain linkage on the way. Shared by the canonical and BiB paths.
#[cfg(feature = "eip-8025")]
fn canonical_witness_into_execution_witness(
    witness: CanonicalExecutionWitness,
    chain_config: ethrex_common::types::ChainConfig,
    block_number: u64,
    crypto: &dyn Crypto,
) -> Result<ethrex_common::types::block_execution_witness::ExecutionWitness, ExecutionError> {
    let rpc_witness = canonical_execution_witness_to_rpc(witness);

    // Decode headers once; reused by the chain-linkage check and `into_execution_witness`.
    let decoded_headers = ethrex_common::types::block_execution_witness::decode_witness_headers(
        &rpc_witness.headers,
    )?;

    // EELS `test_validation_headers_non_contiguous_chain`: check chain linkage
    // in input order, before any sort/dedup.
    ethrex_common::types::block_execution_witness::validate_witness_headers_chain(
        &decoded_headers,
        crypto,
    )?;

    Ok(rpc_witness.into_execution_witness(chain_config, block_number, &decoded_headers)?)
}

#[cfg(feature = "eip-8025")]
fn validate_eip8025_canonical_execution(
    stateless_input: CanonicalStatelessInput,
    chain_config: ethrex_common::types::ChainConfig,
    crypto: Arc<dyn Crypto>,
) -> Result<(), ExecutionError> {
    let block_timestamp = stateless_input
        .new_payload_request
        .execution_payload
        .timestamp;

    validate_canonical_chain_config(
        &stateless_input.chain_config,
        &chain_config,
        block_timestamp,
    )?;

    let block_number = stateless_input
        .new_payload_request
        .execution_payload
        .block_number;

    let execution_witness = canonical_witness_into_execution_witness(
        stateless_input.witness,
        chain_config,
        block_number,
        crypto.as_ref(),
    )?;

    validate_eip8025_amsterdam_execution(
        &stateless_input.new_payload_request,
        execution_witness,
        crypto,
        stateless_input.public_keys,
    )
}

/// Validate the EIP-8142 "block-in-blobs stateless input.
/// Corresponds to `new_payload_zk` of the spec.
#[cfg(feature = "eip-8025")]
fn validate_eip8025_bib_execution(
    stateless_input: BibStatelessInput,
    chain_config: ethrex_common::types::ChainConfig,
    crypto: Arc<dyn Crypto>,
) -> Result<(), ExecutionError> {
    let BibStatelessInput {
        new_payload_request,
        witness,
        chain_config: canonical_chain_config,
        public_keys,
        payload_kzg_commitments,
        payload_kzg_proofs,
    } = stateless_input;

    let block_timestamp = new_payload_request.execution_payload.timestamp;

    validate_canonical_chain_config(&canonical_chain_config, &chain_config, block_timestamp)?;

    // A BiB input is only meaningful once EIP-8142 is active.
    if !chain_config.is_eip8142_activated(block_timestamp) {
        return Err(ExecutionError::Internal(
            "Block-in-blobs stateless input for a block before EIP-8142 activation".to_string(),
        ));
    }

    let block = new_payload_request_bib_to_block(&new_payload_request, crypto.as_ref())
        .map_err(|e| ExecutionError::Internal(format!("payload conversion: {e}")))?;

    verify_payload_blobs(
        &block.body.transactions,
        &new_payload_request.execution_payload.block_access_list,
        new_payload_request.execution_payload.payload_blob_count,
        new_payload_request.versioned_hashes.iter(),
        &payload_kzg_commitments,
        &payload_kzg_proofs,
        crypto.as_ref(),
    )?;

    validate_transaction_public_keys(&block, &public_keys, crypto.as_ref())?;

    let execution_witness = canonical_witness_into_execution_witness(
        witness,
        chain_config,
        new_payload_request.execution_payload.block_number,
        crypto.as_ref(),
    )?;

    let _result = execute_blocks(
        &[block],
        execution_witness,
        ELASTICITY_MULTIPLIER,
        |db, _| Ok(Evm::new_for_l1(db.clone(), crypto.clone())),
        crypto.clone(),
    )?;

    Ok(())
}

/// Validate `chain_id` and `active_fork.blob_schedule` from the prover's
/// `CanonicalChainConfig` against the verifier's `ChainConfig`.
#[cfg(feature = "eip-8025")]
fn validate_canonical_chain_config(
    canonical: &crate::l1::input::CanonicalChainConfig,
    expected: &ethrex_common::types::ChainConfig,
    block_timestamp: u64,
) -> Result<(), ExecutionError> {
    if canonical.chain_id != expected.chain_id {
        return Err(ExecutionError::Internal(format!(
            "chain_id mismatch between canonical input ({}) and chain config ({})",
            canonical.chain_id, expected.chain_id
        )));
    }

    // TODO: `fork` and `activation` are not compared. EELS and ethrex number
    // forks differently, and the spec stores activation values for canonical-root
    // determinism rather than verifier cross-checking. The blob-schedule check
    // below is a partial proxy and misses forks with identical blob parameters.

    // Single-entry check is sound because `MAX_BLOB_SCHEDULES_PER_FORK = 1`.
    let canonical_schedule = canonical.active_fork.blob_schedule.iter().next();
    let expected_schedule = expected.get_fork_blob_schedule(block_timestamp);
    match (canonical_schedule, expected_schedule) {
        (Some(c), Some(e)) => {
            if c.target != e.target as u64
                || c.max != e.max as u64
                || c.base_fee_update_fraction != e.base_fee_update_fraction
            {
                return Err(ExecutionError::Internal(format!(
                    "blob_schedule mismatch: canonical \
                     (target={}, max={}, base_fee_update_fraction={}) \
                     vs chain config (target={}, max={}, base_fee_update_fraction={})",
                    c.target,
                    c.max,
                    c.base_fee_update_fraction,
                    e.target,
                    e.max,
                    e.base_fee_update_fraction
                )));
            }
        }
        (Some(_), None) => {
            return Err(ExecutionError::Internal(
                "blob_schedule mismatch: canonical input includes a schedule but \
                 chain config has none at the block's timestamp"
                    .to_string(),
            ));
        }
        (None, Some(_)) => {
            return Err(ExecutionError::Internal(
                "blob_schedule mismatch: canonical input omits the schedule but \
                 chain config has one at the block's timestamp"
                    .to_string(),
            ));
        }
        (None, None) => {}
    }

    Ok(())
}

#[cfg(feature = "eip-8025")]
fn validate_eip8025_execution(
    new_payload_request: &ethrex_common::types::eip8025_ssz::NewPayloadRequest,
    execution_witness: ethrex_common::types::block_execution_witness::ExecutionWitness,
    crypto: Arc<dyn Crypto>,
) -> Result<(), ExecutionError> {
    // Transform SSZ NewPayloadRequest → Block
    let block = new_payload_request_to_block(new_payload_request, crypto.as_ref())
        .map_err(|e| ExecutionError::Internal(format!("payload conversion: {e}")))?;

    validate_reconstructed_block_hash(
        &block,
        &new_payload_request.execution_payload.block_hash,
        crypto.as_ref(),
    )
    .map_err(|e| ExecutionError::Internal(format!("payload conversion: {e}")))?;

    // Validate blob versioned hashes
    validate_versioned_hashes(
        &block.body.transactions,
        &[], // no payload blobs before EIP-8142
        new_payload_request.versioned_hashes.iter(),
    )?;

    // Execute statelessly — reuse the common `execute_blocks` infrastructure
    let _result = execute_blocks(
        &[block],
        execution_witness,
        ELASTICITY_MULTIPLIER,
        |db, _| Ok(Evm::new_for_l1(db.clone(), crypto.clone())),
        crypto.clone(),
    )?;

    Ok(())
}

/// Check the stateless input's per-transaction public keys against each
/// transaction's recovered sender.
#[cfg(feature = "eip-8025")]
fn validate_transaction_public_keys(
    block: &ethrex_common::types::Block,
    public_keys: &PublicKeysList,
    crypto: &dyn Crypto,
) -> Result<(), ExecutionError> {
    if public_keys.len() != block.body.transactions.len() {
        return Err(ExecutionError::Internal(format!(
            "Found {} public keys in the stateless input, but there are {} transactions",
            public_keys.len(),
            block.body.transactions.len()
        )));
    }
    for (public_key, tx) in public_keys.iter().zip(block.body.transactions.iter()) {
        // SSZ decode fixes the length at 65; uncompressed secp256k1 is 0x04 || X || Y.
        let pk_bytes: &[u8] = public_key;
        if pk_bytes[0] != 0x04 {
            return Err(ExecutionError::Internal(
                "Stateless input public key is not a 65-byte uncompressed secp256k1 key"
                    .to_string(),
            ));
        }
        let derived = Address::from_slice(&keccak(&pk_bytes[1..])[12..]);
        let recovered = tx.sender(crypto).map_err(|e| {
            ExecutionError::Internal(format!("failed to recover transaction sender: {e}"))
        })?;
        if recovered != derived {
            return Err(ExecutionError::Internal(
                "Stateless input public key does not match recovered transaction sender"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(feature = "eip-8025")]
fn validate_eip8025_amsterdam_execution(
    new_payload_request: &ethrex_common::types::eip8025_ssz::NewPayloadRequestAmsterdam,
    execution_witness: ethrex_common::types::block_execution_witness::ExecutionWitness,
    crypto: Arc<dyn Crypto>,
    public_keys: PublicKeysList,
) -> Result<(), ExecutionError> {
    let block = new_payload_request_amsterdam_to_block(new_payload_request, crypto.as_ref())
        .map_err(|e| ExecutionError::Internal(format!("payload conversion: {e}")))?;

    // Validate blob versioned hashes
    validate_versioned_hashes(
        &block.body.transactions,
        &[], // no payload blobs before EIP-8142
        new_payload_request.versioned_hashes.iter(),
    )?;

    validate_transaction_public_keys(&block, &public_keys, crypto.as_ref())?;

    // Execute statelessly — reuse the common `execute_blocks` infrastructure
    let _result = execute_blocks(
        &[block],
        execution_witness,
        ELASTICITY_MULTIPLIER,
        |db, _| Ok(Evm::new_for_l1(db.clone(), crypto.clone())),
        crypto.clone(),
    )?;

    Ok(())
}

/// EIP-8142 `new_payload_zk`, steps 1–6 (everything except the EL STF)
#[cfg(feature = "eip-8025")]
fn verify_payload_blobs<'a>(
    transactions: &Vec<ethrex_common::types::Transaction>,
    raw_block_access_list: &[u8],
    payload_blob_count: u64,
    expected_blob_versioned_hashes: impl IntoIterator<Item = &'a [u8; 32]>,
    payload_kzg_commitments: &[[u8; 48]],
    payload_kzg_proofs: &[[u8; 48]],
    crypto: &dyn Crypto,
) -> Result<(), ExecutionError> {
    use ethrex_common::types::eip8142::execution_payload_to_blobs_from_raw_bal;
    use ethrex_common::types::kzg_commitment_to_versioned_hash;

    // 1. Declared payload blob count from the header
    let n: usize = payload_blob_count
        .try_into()
        .map_err(|_| ExecutionError::Internal("payload_blob_count overflows usize".to_string()))?;

    if payload_kzg_commitments.len() != n || payload_kzg_proofs.len() != n {
        return Err(ExecutionError::Internal(format!(
            "payload blob private inputs mismatch: header declares {n} payload blobs but \
             got {} commitments and {} proofs",
            payload_kzg_commitments.len(),
            payload_kzg_proofs.len(),
        )));
    }

    // 2. Derive payload blobs and versioned hashes
    let payload_blobs =
        execution_payload_to_blobs_from_raw_bal(raw_block_access_list, transactions);

    let payload_versioned_hashes: Vec<ethrex_common::H256> = payload_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    // 3. Verify payload blob count matches header
    if payload_blobs.len() != n {
        return Err(ExecutionError::Internal(format!(
            "payload_blob_count mismatch: header declares {n} but the execution-payload \
             data encodes into {} blobs",
            payload_blobs.len(),
        )));
    }

    // 4–5. Verify versioned hashes: payload blobs first, then type-3
    validate_versioned_hashes(
        transactions,
        &payload_versioned_hashes,
        expected_blob_versioned_hashes,
    )?;

    // 6. Verify blob–commitment consistency using batch KZG proof verification
    let valid = crypto
        .verify_blob_kzg_proof_batch(&payload_blobs, payload_kzg_commitments, payload_kzg_proofs)
        .map_err(|e| ExecutionError::Internal(format!("payload blob KZG verification: {e}")))?;

    if !valid {
        return Err(ExecutionError::Internal(
            "payload blobs do not match their KZG commitments".to_string(),
        ));
    }

    Ok(())
}

#[cfg(all(test, feature = "eip-8025"))]
mod tests {
    use std::sync::Arc;

    use crate::{common::ExecutionError, crypto::NativeCrypto, l1::execution_program};
    use ethrex_common::types::block_access_list::BlockAccessList;
    use ethrex_common::types::kzg_commitment_to_versioned_hash;
    use ethrex_crypto::{Crypto, CryptoError};

    #[test]
    fn execution_program_rejects_invalid_eip8025_wire_bytes() {
        let err = match execution_program(&[], Arc::new(NativeCrypto)) {
            Ok(_) => panic!("expected invalid EIP-8025 input to fail decoding"),
            Err(err) => err,
        };

        match err {
            ExecutionError::Internal(msg) => {
                assert_eq!(msg, "failed to decode EIP-8025 input: input too short");
            }
            other => panic!("expected internal decode error, got {other:?}"),
        }
    }

    /// Crypto stub with a fixed blob-proof verdict, so payload-blob wiring
    /// (counts, ordering, hashes) is testable without real KZG inputs.
    #[derive(Debug)]
    struct StubKzgCrypto {
        blob_proofs_valid: bool,
    }

    impl Crypto for StubKzgCrypto {
        // Override the batch method `verify_payload_blobs` calls directly, so the
        // stub takes effect regardless of which cfg arm provides the trait default
        // (the c-kzg default delegates to c-kzg instead of the single-blob verify).
        fn verify_blob_kzg_proof_batch(
            &self,
            _blobs: &[[u8; ethrex_crypto::kzg::BYTES_PER_BLOB]],
            _commitments: &[[u8; 48]],
            _proofs: &[[u8; 48]],
        ) -> Result<bool, CryptoError> {
            Ok(self.blob_proofs_valid)
        }
    }

    fn raw_bal() -> Vec<u8> {
        use ethrex_rlp::encode::RLPEncode;
        BlockAccessList::default().encode_to_vec()
    }

    #[test]
    fn verify_payload_blobs_accepts_matching_inputs() {
        let transactions = Vec::new();
        let bal = raw_bal();
        // Empty BAL + no txs packs into a single blob (just the 8-byte header).
        let count = 1;

        let commitments = [[0xAA_u8; 48]];
        let proofs = [[0xBB_u8; 48]];
        // The request's expected hashes must lead with the payload-blob hash
        // derived from the commitment (no type-3 transactions here).
        let expected_hash: [u8; 32] = kzg_commitment_to_versioned_hash(&commitments[0]).0;
        super::verify_payload_blobs(
            &transactions,
            &bal,
            count,
            [&expected_hash],
            &commitments,
            &proofs,
            &StubKzgCrypto {
                blob_proofs_valid: true,
            },
        )
        .expect("payload blobs should verify");

        // A request whose hashes don't lead with the payload-blob hash fails
        // (spec steps 4-5).
        let wrong_hash = [0x99_u8; 32];
        let err = super::verify_payload_blobs(
            &transactions,
            &bal,
            count,
            [&wrong_hash],
            &commitments,
            &proofs,
            &StubKzgCrypto {
                blob_proofs_valid: true,
            },
        )
        .expect_err("hash mismatch must fail");
        assert!(
            matches!(err, ExecutionError::Internal(msg) if msg.contains("versioned hashes mismatch"))
        );
    }

    #[test]
    fn verify_payload_blobs_rejects_count_mismatch() {
        // Header declares 2 payload blobs but the payload data encodes into 1.
        let no_hashes: [&[u8; 32]; 0] = [];
        let err = super::verify_payload_blobs(
            &Vec::new(),
            &raw_bal(),
            2,
            no_hashes,
            &[[0xAA_u8; 48]; 2],
            &[[0xBB_u8; 48]; 2],
            &StubKzgCrypto {
                blob_proofs_valid: true,
            },
        )
        .expect_err("count mismatch must fail");
        assert!(
            matches!(err, ExecutionError::Internal(msg) if msg.contains("payload_blob_count mismatch"))
        );
    }

    #[test]
    fn verify_payload_blobs_rejects_private_input_length_mismatch() {
        let no_hashes: [&[u8; 32]; 0] = [];
        let err = super::verify_payload_blobs(
            &Vec::new(),
            &raw_bal(),
            1,
            no_hashes,
            &[],
            &[[0xBB_u8; 48]],
            &StubKzgCrypto {
                blob_proofs_valid: true,
            },
        )
        .expect_err("missing commitments must fail");
        assert!(
            matches!(err, ExecutionError::Internal(msg) if msg.contains("private inputs mismatch"))
        );
    }

    #[test]
    fn verify_payload_blobs_rejects_invalid_proof() {
        let commitments = [[0xAA_u8; 48]];
        let expected_hash: [u8; 32] = kzg_commitment_to_versioned_hash(&commitments[0]).0;
        let err = super::verify_payload_blobs(
            &Vec::new(),
            &raw_bal(),
            1,
            [&expected_hash],
            &commitments,
            &[[0xBB_u8; 48]],
            &StubKzgCrypto {
                blob_proofs_valid: false,
            },
        )
        .expect_err("invalid blob proof must fail");
        assert!(
            matches!(err, ExecutionError::Internal(msg) if msg.contains("do not match their KZG commitments"))
        );
    }

    /// A BiB stateless input for a block before EIP-8142 activation must be
    /// rejected (a prover must not be able to prove pre-fork blocks as BiB).
    #[test]
    fn bib_execution_rejects_inactive_fork() {
        use ethrex_common::types::ChainConfig;

        let stateless_input = crate::l1::input::sample_bib_stateless_input();
        // chain_id matches the fixture so the config cross-check passes and the
        // activation gate is what fires (eip8142_time unset).
        let chain_config = ChainConfig {
            chain_id: 1,
            ..Default::default()
        };
        let err = super::validate_eip8025_bib_execution(
            stateless_input,
            chain_config,
            Arc::new(NativeCrypto),
        )
        .expect_err("pre-activation BiB input must be rejected");
        assert!(
            matches!(err, ExecutionError::Internal(msg) if msg.contains("before EIP-8142 activation"))
        );
    }

    #[test]
    fn versioned_hashes_must_lead_with_payload_blob_hashes() {
        let payload_hash = kzg_commitment_to_versioned_hash(&[0xAA_u8; 48]);
        let payload_hash_bytes: [u8; 32] = payload_hash.0;

        // Request hashes == payload hashes (no blob txs): ok.
        super::validate_versioned_hashes(&[], &[payload_hash], [&payload_hash_bytes])
            .expect("matching prefix should validate");

        // Missing the payload prefix: must fail.
        let no_hashes: [&[u8; 32]; 0] = [];
        assert!(super::validate_versioned_hashes(&[], &[payload_hash], no_hashes).is_err());
    }
}

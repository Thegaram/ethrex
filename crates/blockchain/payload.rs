use std::{
    cmp::{Ordering, max},
    ops::Div,
    sync::Arc,
    time::{Duration, Instant},
};

use rustc_hash::FxHashMap;

use ethrex_common::{
    Address, Bloom, Bytes, H256, U256,
    constants::{
        DEFAULT_OMMERS_HASH, DEFAULT_REQUESTS_HASH, GAS_PER_BLOB, MAX_RLP_BLOCK_SIZE,
        TX_MAX_GAS_LIMIT_AMSTERDAM,
    },
    types::{
        AccountUpdate, BlobsBundle, Block, BlockBody, BlockHash, BlockHeader, BlockNumber,
        ChainConfig, Fork, MempoolTransaction, Receipt, Transaction, TxKind, TxType, Withdrawal,
        block_access_list::BlockAccessList,
        bloom_from_logs, calc_excess_blob_gas, calculate_base_fee_per_blob_gas,
        calculate_base_fee_per_gas, compute_receipts_root, compute_transactions_root,
        compute_withdrawals_root,
        requests::{EncodedRequests, compute_requests_hash},
    },
};

use ethrex_common::types::eip8142::{HEADER_SIZE, payload_blob_count_for_byte_len};

#[cfg(feature = "c-kzg")]
use ethrex_common::types::{
    PayloadBlobsBundle, eip8142::execution_payload_data_to_blobs_with_lens,
};

use ethrex_crypto::NativeCrypto;
use ethrex_crypto::keccak::Keccak256;
use ethrex_vm::{Evm, EvmError, check_2d_gas_allowance};

use ethrex_rlp::encode::RLPEncode;
use ethrex_storage::{Store, error::StoreError};

use ethrex_metrics::metrics;

#[cfg(feature = "metrics")]
use ethrex_metrics::blocks::METRICS_BLOCKS;
#[cfg(feature = "metrics")]
use ethrex_metrics::transactions::{METRICS_TX, MetricsTxType};
use tokio_util::sync::CancellationToken;

use crate::{
    Blockchain, BlockchainType, MAX_PAYLOADS,
    constants::{GAS_LIMIT_BOUND_DIVISOR, MIN_GAS_LIMIT, TX_GAS_COST},
    error::{ChainError, InvalidBlockError},
    mempool::PendingTxFilter,
    new_evm,
    vm::StoreVmDatabase,
};

use thiserror::Error;
use tracing::{debug, warn};

// EIP-8142 "block-in-blobs": Keeping the combined blob count within MAX_BLOBS_PER_BLOCK.
//
// The payload blobs (BAL + transactions, encoded into blobs) and type-3 user blobs must
// fit within the blob count limit. The payload-blob count isn't known until the BAL is
// final. During tx selection we estimate it with a cheap running upper bound on the BAL
// size (`estimated_encoded_len`) plus the tx bytes, and skip candidates that would overflow.
// We then do a strict check at seal time (`add_eip8142_payload_blobs`).

/// Headroom for BAL growth after tx selection (withdrawal credits + request system-calls);
/// bounded, so a small fixed reservation keeps the projection sound.
const EIP8142_POST_TRANSACTIONS_BUFFER_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub struct PayloadBuildTask {
    task: tokio::task::JoinHandle<Result<PayloadBuildResult, ChainError>>,
    cancel: CancellationToken,
}

#[derive(Debug)]
pub enum PayloadOrTask {
    Payload(Box<PayloadBuildResult>),
    Task(PayloadBuildTask),
}

impl PayloadBuildTask {
    /// Finishes the current payload build process and returns its result
    pub async fn finish(self) -> Result<PayloadBuildResult, ChainError> {
        self.cancel.cancel();
        self.task
            .await
            .map_err(|_| ChainError::Custom("Failed to join task".to_string()))?
    }
}

impl PayloadOrTask {
    /// Converts self into a `PayloadOrTask::Payload` by finishing the current build task
    /// If self is already a `PayloadOrTask::Payload` this is a NoOp
    pub async fn to_payload(self) -> Result<Self, ChainError> {
        Ok(match self {
            PayloadOrTask::Payload(_) => self,
            PayloadOrTask::Task(task) => PayloadOrTask::Payload(Box::new(task.finish().await?)),
        })
    }
}

pub struct BuildPayloadArgs {
    pub parent: BlockHash,
    pub timestamp: u64,
    pub fee_recipient: Address,
    pub random: H256,
    pub withdrawals: Option<Vec<Withdrawal>>,
    pub beacon_root: Option<H256>,
    pub slot_number: Option<u64>,
    pub version: u8,
    pub elasticity_multiplier: u64,
    pub gas_ceil: u64,
}

#[derive(Debug, Error)]
pub enum BuildPayloadArgsError {
    #[error("Payload hashed has wrong size")]
    FailedToConvertPayload,
}

impl BuildPayloadArgs {
    /// Computes an 8-byte identifier by hashing the components of the payload arguments.
    pub fn id(&self) -> Result<u64, BuildPayloadArgsError> {
        let mut hasher = Keccak256::new();
        hasher.update(self.parent);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.random);
        hasher.update(self.fee_recipient);
        if let Some(withdrawals) = &self.withdrawals {
            hasher.update(withdrawals.encode_to_vec());
        }
        if let Some(beacon_root) = self.beacon_root {
            hasher.update(beacon_root);
        }
        let res = &mut hasher.finalize()[..8];
        res[0] = self.version;
        Ok(u64::from_be_bytes(res.try_into().map_err(|_| {
            BuildPayloadArgsError::FailedToConvertPayload
        })?))
    }
}

/// Creates a new payload based on the payload arguments
// Basic payload block building, can and should be improved
pub fn create_payload(
    args: &BuildPayloadArgs,
    storage: &Store,
    extra_data: Bytes,
) -> Result<Block, ChainError> {
    let parent_block = storage
        .get_block_header_by_hash(args.parent)?
        .ok_or_else(|| ChainError::ParentNotFound)?;
    let chain_config = storage.get_chain_config();
    let fork = chain_config.fork(args.timestamp);
    let gas_limit = calc_gas_limit(parent_block.gas_limit, args.gas_ceil);
    let excess_blob_gas = chain_config
        .get_fork_blob_schedule(args.timestamp)
        .map(|schedule| calc_excess_blob_gas(&parent_block, schedule, fork));

    let header = BlockHeader {
        parent_hash: args.parent,
        ommers_hash: *DEFAULT_OMMERS_HASH,
        coinbase: args.fee_recipient,
        state_root: parent_block.state_root,
        transactions_root: compute_transactions_root(&[], &NativeCrypto),
        receipts_root: compute_receipts_root(&[], &NativeCrypto),
        logs_bloom: Bloom::default(),
        difficulty: U256::zero(),
        number: parent_block.number.saturating_add(1),
        gas_limit,
        gas_used: 0,
        timestamp: args.timestamp,
        extra_data,
        prev_randao: args.random,
        nonce: 0,
        base_fee_per_gas: calculate_base_fee_per_gas(
            gas_limit,
            parent_block.gas_limit,
            parent_block.gas_used,
            parent_block.base_fee_per_gas.unwrap_or_default(),
            args.elasticity_multiplier,
        ),
        withdrawals_root: chain_config
            .is_shanghai_activated(args.timestamp)
            .then_some(compute_withdrawals_root(
                args.withdrawals.as_ref().unwrap_or(&Vec::new()),
                &NativeCrypto,
            )),
        blob_gas_used: chain_config
            .is_cancun_activated(args.timestamp)
            .then_some(0),
        excess_blob_gas,
        parent_beacon_block_root: args.beacon_root,
        requests_hash: chain_config
            .is_prague_activated(args.timestamp)
            .then_some(*DEFAULT_REQUESTS_HASH),
        slot_number: args.slot_number,
        ..Default::default()
    };

    let body = BlockBody {
        transactions: Vec::new(),
        ommers: Vec::new(),
        withdrawals: args.withdrawals.clone(),
    };

    // Delay applying withdrawals until the payload is requested and built
    Ok(Block::new(header, body))
}

pub fn calc_gas_limit(parent_gas_limit: u64, builder_gas_ceil: u64) -> u64 {
    // TODO: check where we should get builder values from
    let delta = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR - 1;
    let mut limit = parent_gas_limit;
    let desired_limit = max(builder_gas_ceil, MIN_GAS_LIMIT);
    if limit < desired_limit {
        limit = parent_gas_limit + delta;
        if limit > desired_limit {
            limit = desired_limit
        }
        return limit;
    }
    if limit > desired_limit {
        limit = parent_gas_limit - delta;
        if limit < desired_limit {
            limit = desired_limit
        }
    }
    limit
}

#[derive(Clone)]
pub struct PayloadBuildContext {
    pub payload: Block,
    pub remaining_gas: u64,
    /// Cumulative gas spent (post-refund) for receipt tracking.
    /// Per EIP-7778 this differs from `remaining_gas` which tracks pre-refund gas.
    pub cumulative_gas_spent: u64,
    /// EIP-8037 (Amsterdam+): cumulative regular (non-state) gas used.
    pub block_regular_gas_used: u64,
    /// EIP-8037 (Amsterdam+): cumulative state gas used.
    pub block_state_gas_used: u64,
    /// Whether Amsterdam fork is active for this block.
    pub is_amsterdam: bool,
    pub receipts: Vec<Receipt>,
    pub requests: Option<Vec<EncodedRequests>>,
    pub block_value: U256,
    base_fee_per_blob_gas: U256,
    pub blobs_bundle: BlobsBundle,
    pub store: Store,
    pub vm: Evm,
    pub account_updates: Vec<AccountUpdate>,
    pub payload_size: u64,
    /// Block Access List for EIP-7928
    pub block_access_list: Option<BlockAccessList>,
    /// Whether EIP-8142 "block-in-blobs" is active for this block.
    pub eip8142_active: bool,
}

impl PayloadBuildContext {
    pub fn new(
        payload: Block,
        storage: &Store,
        blockchain_type: &BlockchainType,
    ) -> Result<Self, EvmError> {
        let config = storage.get_chain_config();
        let base_fee_per_blob_gas = calculate_base_fee_per_blob_gas(
            payload.header.excess_blob_gas.unwrap_or_default(),
            config
                .get_fork_blob_schedule(payload.header.timestamp)
                .map(|schedule| schedule.base_fee_update_fraction)
                .unwrap_or_default(),
        );

        let parent_header = storage
            .get_block_header_by_hash(payload.header.parent_hash)
            .map_err(|e| EvmError::DB(e.to_string()))?
            .ok_or_else(|| EvmError::DB("parent header not found".to_string()))?;
        let vm_db = StoreVmDatabase::new(storage.clone(), parent_header)?;
        let mut vm = new_evm(blockchain_type, vm_db)?;

        // Enable BAL recording for Amsterdam and later forks (EIP-7928)
        if config.is_amsterdam_activated(payload.header.timestamp) {
            vm.enable_bal_recording();
            // Set index 0 for pre-execution phase (system contracts)
            vm.set_bal_index(0);
        }

        let is_amsterdam = config.is_amsterdam_activated(payload.header.timestamp);
        let eip8142_active = config.is_eip8142_activated(payload.header.timestamp);
        let payload_size = payload.length() as u64;
        Ok(PayloadBuildContext {
            remaining_gas: payload.header.gas_limit,
            cumulative_gas_spent: 0,
            block_regular_gas_used: 0,
            block_state_gas_used: 0,
            is_amsterdam,
            receipts: vec![],
            requests: config
                .is_prague_activated(payload.header.timestamp)
                .then_some(Vec::new()),
            block_value: U256::zero(),
            base_fee_per_blob_gas,
            payload,
            blobs_bundle: BlobsBundle::default(),
            store: storage.clone(),
            vm,
            account_updates: Vec::new(),
            payload_size,
            block_access_list: None,
            eip8142_active,
        })
    }

    pub fn gas_used(&self) -> u64 {
        if self.is_amsterdam {
            // EIP-8037: block gas = max(sum_regular, sum_state)
            self.block_regular_gas_used.max(self.block_state_gas_used)
        } else {
            self.payload.header.gas_limit - self.remaining_gas
        }
    }
}

impl PayloadBuildContext {
    fn parent_hash(&self) -> BlockHash {
        self.payload.header.parent_hash
    }

    pub fn block_number(&self) -> BlockNumber {
        self.payload.header.number
    }

    fn chain_config(&self) -> ChainConfig {
        self.store.get_chain_config()
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.payload.header.base_fee_per_gas
    }

    /// Protocol `MAX_BLOBS_PER_BLOCK` for this block, used for the EIP-8142 combined (payload + type-3) limit.
    /// Unlike `effective_max_blobs`, this ignores the builder's optional blob cap, since payload blobs are mandatory.
    fn protocol_max_blobs(&self) -> usize {
        self.chain_config()
            .get_fork_blob_schedule(self.payload.header.timestamp)
            .map(|schedule| schedule.max as usize)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct PayloadBuildResult {
    pub blobs_bundle: BlobsBundle,
    pub block_value: U256,
    pub receipts: Vec<Receipt>,
    pub requests: Vec<EncodedRequests>,
    pub account_updates: Vec<AccountUpdate>,
    pub payload: Block,
    /// Block Access List for EIP-7928
    pub block_access_list: Option<BlockAccessList>,
}

impl From<PayloadBuildContext> for PayloadBuildResult {
    fn from(value: PayloadBuildContext) -> Self {
        let PayloadBuildContext {
            blobs_bundle,
            block_value,
            requests,
            receipts,
            account_updates,
            payload,
            block_access_list,
            ..
        } = value;

        Self {
            blobs_bundle,
            block_value,
            requests: requests.unwrap_or_default(),
            receipts,
            account_updates,
            payload,
            block_access_list,
        }
    }
}

impl Blockchain {
    /// Attempts to fetch a payload given it's id. If the payload is still being built, it will be finished.
    /// Fails if there is no payload or active payload build task for the given id.
    pub async fn get_payload(&self, payload_id: u64) -> Result<PayloadBuildResult, ChainError> {
        let mut payloads = self.payloads.lock().await;
        // Find the given payload and finish the active build process if needed
        let idx = payloads
            .iter()
            .position(|(id, _)| id == &payload_id)
            .ok_or(ChainError::UnknownPayload)?;
        let finished_payload = (payload_id, payloads.remove(idx).1.to_payload().await?);
        payloads.insert(idx, finished_payload);
        // Return the held payload
        match &payloads[idx].1 {
            PayloadOrTask::Payload(payload) => Ok(*payload.clone()),
            _ => unreachable!("we already converted the payload into a finished version"),
        }
    }

    /// Starts a payload build process. The built payload can be retrieved by calling `get_payload`.
    /// The build process will run for the full block building timeslot or until `get_payload` is called
    pub async fn initiate_payload_build(self: Arc<Blockchain>, payload: Block, payload_id: u64) {
        let self_clone = self.clone();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let payload_build_task = tokio::task::spawn(async move {
            self_clone
                .build_payload_loop(payload, cancel_token_clone)
                .await
        });
        let mut payloads = self.payloads.lock().await;
        if payloads.len() >= MAX_PAYLOADS {
            // Remove oldest unclaimed payload
            payloads.remove(0);
        }
        payloads.push((
            payload_id,
            PayloadOrTask::Task(PayloadBuildTask {
                task: payload_build_task,
                cancel: cancel_token,
            }),
        ));
    }

    /// Build the given payload and keep on rebuilding it until either the time slot
    /// given by `SECONDS_PER_SLOT` is up or the `cancel_token` is cancelled
    pub async fn build_payload_loop(
        self: Arc<Blockchain>,
        payload: Block,
        cancel_token: CancellationToken,
    ) -> Result<PayloadBuildResult, ChainError> {
        let start = Instant::now();
        const SECONDS_PER_SLOT: Duration = Duration::from_secs(12);
        // Attempt to rebuild the payload as many times within the given timeframe to maximize fee revenue
        // TODO(#4997): start with an empty block
        // Snapshot the mempool sequence *before* the build so any tx that lands
        // during the build is seen as newer than the current `res`.
        let mut last_built_seq = self.mempool.tx_seq();
        let mut res = self.build_payload(payload.clone())?;
        while start.elapsed() < SECONDS_PER_SLOT && !cancel_token.is_cancelled() {
            // Wait for new transactions, cancellation, or slot deadline before rebuilding
            let remaining = SECONDS_PER_SLOT.saturating_sub(start.elapsed());
            let notified = self.mempool.tx_added().notified();
            tokio::select! {
                _ = notified => {}
                _ = cancel_token.cancelled() => break,
                _ = tokio::time::sleep(remaining) => break,
            }
            let payload = payload.clone();
            let self_clone = self.clone();
            let seq_before = self.mempool.tx_seq();
            let building_task =
                tokio::task::spawn_blocking(move || self_clone.build_payload(payload));
            // Cancel the current build process and return the previous payload if it is requested earlier
            // TODO(#5011): this doesn't stop the building task, but only keeps it running in the background,
            //   which wastes CPU resources.
            match cancel_token.run_until_cancelled(building_task).await {
                Some(Ok(current_res)) => {
                    res = current_res?;
                    last_built_seq = seq_before;
                }
                Some(Err(err)) => {
                    warn!(%err, "Payload-building task panicked");
                }
                None => {}
            }
        }

        // If a tx landed after the snapshot that produced `res`, do one final
        // build before returning. Covers both races: (a) cancellation dropping
        // an in-progress rebuild via `run_until_cancelled`, and (b) the slot-
        // timeout `select!` arm winning over a simultaneous `tx_added`
        // notification near the slot boundary.
        if self.mempool.tx_seq() > last_built_seq {
            let blockchain = self.clone();
            match tokio::task::spawn_blocking(move || blockchain.build_payload(payload)).await {
                Ok(Ok(final_res)) => res = final_res,
                Ok(Err(err)) => {
                    warn!(%err, "Final payload rebuild failed; returning previous result")
                }
                Err(err) => warn!(%err, "Final payload rebuild task panicked"),
            }
        }

        Ok(res)
    }

    /// Completes the payload building process, return the block value
    pub fn build_payload(&self, payload: Block) -> Result<PayloadBuildResult, ChainError> {
        let since = Instant::now();

        debug!("Building payload");
        let base_fee = payload.header.base_fee_per_gas.unwrap_or_default();
        let mut context = PayloadBuildContext::new(payload, &self.storage, &self.options.r#type)?;

        if let BlockchainType::L1 = self.options.r#type {
            self.apply_system_operations(&mut context)?;
        }
        // build phase 1/3: EVM execution + tx selection (see `build_phase_seconds`).
        {
            #[cfg(feature = "metrics")]
            let _timer = ethrex_metrics::eip8142::METRICS_EIP8142
                .build_phase_seconds
                .with_label_values(&["fill_transactions"])
                .start_timer();

            self.fill_transactions(&mut context)?;
        }
        // EIP-7928: Post-tx phase uses index n+1 for both requests and withdrawals.
        // Order must match geth: requests (system calls) BEFORE withdrawals.
        if context
            .chain_config()
            .is_amsterdam_activated(context.payload.header.timestamp)
        {
            let post_tx_index =
                u32::try_from(context.payload.body.transactions.len() + 1).unwrap_or(u32::MAX);
            context.vm.set_bal_index(post_tx_index);
            // Record withdrawal recipients as touched addresses per EIP-7928
            if let Some(recorder) = context.vm.db.bal_recorder_mut()
                && let Some(withdrawals) = &context.payload.body.withdrawals
            {
                recorder.extend_touched_addresses(withdrawals.iter().map(|w| w.address));
            }
        }
        self.extract_requests(&mut context)?;
        self.apply_withdrawals(&mut context)?;
        self.finalize_payload(&mut context)?;

        let interval = Instant::now().duration_since(since).as_millis();

        tracing::debug!(
            "[METRIC] BUILDING PAYLOAD TOOK: {interval} ms, base fee {}",
            base_fee
        );
        metrics!(METRICS_BLOCKS.set_block_building_ms(interval as i64));
        metrics!(METRICS_BLOCKS.set_block_building_base_fee(base_fee as i64));
        let gas_used = context.gas_used();
        if gas_used > 0 {
            let as_gigas = (gas_used as f64).div(10_f64.powf(9_f64));

            if interval != 0 {
                let throughput = (as_gigas) / (interval as f64) * 1000_f64;
                metrics!(METRICS_BLOCKS.set_latest_gigagas_block_building(throughput));

                tracing::debug!(
                    "[METRIC] BLOCK BUILDING THROUGHPUT: {throughput} Gigagas/s TIME SPENT: {interval} msecs"
                );
            }
        }

        Ok(context.into())
    }

    pub fn apply_withdrawals(&self, context: &mut PayloadBuildContext) -> Result<(), EvmError> {
        let binding = Vec::new();
        let withdrawals = context
            .payload
            .body
            .withdrawals
            .as_ref()
            .unwrap_or(&binding);
        context.vm.process_withdrawals(withdrawals)
    }

    // This function applies system level operations:
    // - Call beacon root contract, and obtain the new state root
    // - Call block hash process contract, and store parent block hash
    pub fn apply_system_operations(
        &self,
        context: &mut PayloadBuildContext,
    ) -> Result<(), EvmError> {
        context.vm.apply_system_calls(&context.payload.header)
    }

    /// Fetches suitable transactions from the mempool
    /// Returns two transaction queues, one for plain and one for blob txs
    pub fn fetch_mempool_transactions(
        &self,
        context: &mut PayloadBuildContext,
    ) -> Result<(TransactionQueue, TransactionQueue), ChainError> {
        let blob_fee: u64 = context.base_fee_per_blob_gas.try_into().map_err(|_| {
            ChainError::Custom("base_fee_per_blob_gas does not fit in u64".to_owned())
        })?;
        let tx_filter = PendingTxFilter {
            /*TODO(https://github.com/lambdaclass/ethrex/issues/680): add tip filter */
            base_fee: context.base_fee_per_gas(),
            blob_fee: Some(blob_fee),
            ..Default::default()
        };
        let plain_tx_filter = PendingTxFilter {
            only_plain_txs: true,
            ..tx_filter
        };
        let blob_tx_filter = PendingTxFilter {
            only_blob_txs: true,
            ..tx_filter
        };
        Ok((
            // Plain txs
            TransactionQueue::new(
                self.mempool.filter_transactions(&plain_tx_filter)?,
                context.base_fee_per_gas(),
            )?,
            // Blob txs
            TransactionQueue::new(
                self.mempool.filter_transactions(&blob_tx_filter)?,
                context.base_fee_per_gas(),
            )?,
        ))
    }

    /// EIP-7872: Computes effective max blobs per block.
    /// Returns min(protocol_max, user_configured_max).
    fn effective_max_blobs(&self, context: &PayloadBuildContext) -> usize {
        let protocol_max = context
            .chain_config()
            .get_fork_blob_schedule(context.payload.header.timestamp)
            .map(|schedule| schedule.max)
            .unwrap_or_default();
        match self.options.max_blobs_per_block {
            Some(user_max) => protocol_max.min(user_max) as usize,
            None => protocol_max as usize,
        }
    }

    /// Fills the payload with transactions taken from the mempool
    /// Returns the block value
    pub fn fill_transactions(&self, context: &mut PayloadBuildContext) -> Result<(), ChainError> {
        let chain_config = context.chain_config();
        let max_blob_number_per_block = self.effective_max_blobs(context);

        debug!("Fetching transactions from mempool");
        // Fetch mempool transactions
        let (mut plain_txs, mut blob_txs) = self.fetch_mempool_transactions(context)?;
        // Execute and add transactions to payload (if suitable)
        loop {
            // Check if we have enough gas to run more transactions
            if context.remaining_gas < TX_GAS_COST {
                debug!("No more gas to run transactions");
                break;
            };
            if !blob_txs.is_empty() && context.blobs_bundle.blobs.len() >= max_blob_number_per_block
            {
                debug!("No more blob gas to run blob transactions");
                blob_txs.clear();
            }
            // Fetch the next transactions
            let (head_tx, is_blob) = match (plain_txs.peek(), blob_txs.peek()) {
                (None, None) => break,
                (None, Some(tx)) => (tx, true),
                (Some(tx), None) => (tx, false),
                (Some(a), Some(b)) if b < a => (b, true),
                (Some(tx), _) => (tx, false),
            };

            let txs = if is_blob {
                &mut blob_txs
            } else {
                &mut plain_txs
            };

            // Check if we have enough gas to run the transaction.
            // EIP-7825/EIP-8037: for Amsterdam, cap at TX_MAX_GAS_LIMIT since
            // remaining_gas tracks regular gas only.
            let tx_gas_reservation = if context.is_amsterdam {
                head_tx.tx.gas_limit().min(TX_MAX_GAS_LIMIT_AMSTERDAM)
            } else {
                head_tx.tx.gas_limit()
            };
            if context.remaining_gas < tx_gas_reservation {
                debug!("Skipping transaction: {}, no gas left", head_tx.tx.hash());
                // We don't have enough gas left for the transaction, so we skip all txs from this account
                txs.pop();
                continue;
            }

            // Check adding a transaction wouldn't exceed the Osaka block size limit of 10 MiB
            // if inclusion of the transaction puts the block size over the size limit
            // we don't add any more txs to the payload.
            let candidate_rlp_size = head_tx.encode_canonical_len() as u64;
            let potential_rlp_block_size = context.payload_size + candidate_rlp_size;
            if context
                .chain_config()
                .is_osaka_activated(context.payload.header.timestamp)
                && potential_rlp_block_size > MAX_RLP_BLOCK_SIZE
            {
                break;
            }
            // Include the candidate's bytes now (the EIP-8142 gate reads payload_size);
            // rolled back below on every path that doesn't keep the tx.
            context.payload_size = potential_rlp_block_size;

            // TODO: maybe fetch hash too when filtering mempool so we don't have to compute it here (we can do this in the same refactor as adding timestamp)
            let tx_hash = head_tx.tx.hash();

            // Check whether the tx is replay-protected
            if head_tx.tx.protected() && !chain_config.is_eip155_activated(context.block_number()) {
                // Ignore replay protected tx & all txs from the sender
                // Pull transaction from the mempool
                debug!("Ignoring replay-protected transaction: {}", tx_hash);
                context.payload_size = context.payload_size.saturating_sub(candidate_rlp_size);
                txs.pop();
                self.remove_transaction_from_pool(&tx_hash)?;
                continue;
            }

            // EIP-8142 pre-execution fast-reject: skip candidates that already overflow the
            // combined blob cap on committed state alone, sparing the EVM run + O(BAL) checkpoint.
            // It's a lower bound (the candidate's BAL growth isn't measured yet), so the exact
            // post-exec gate in `apply_tx_to_payload` still catches the marginal case.
            if eip8142_projected_blob_overflow(&head_tx, context).is_some() {
                debug!("Skipping transaction: {tx_hash}, EIP-8142 combined blob cap reached");
                context.payload_size = context.payload_size.saturating_sub(candidate_rlp_size);
                txs.pop();
                continue;
            }

            match self.apply_tx_to_payload(head_tx, context) {
                Ok(()) => txs.shift()?,
                Err(_) => {
                    context.payload_size = context.payload_size.saturating_sub(candidate_rlp_size);
                    txs.pop();
                }
            }
        }
        Ok(())
    }

    /// Apply a single transaction to the in-progress payload.
    ///
    /// Runs the full per-tx pipeline: EIP-8037 2D inclusion check, EIP-7928
    /// BAL index/checkpoint setup, sender/recipient recording, dispatch to
    /// blob/plain execution, and on failure rolls the BAL recorder back so
    /// rejected txs leave no trace. On success the tx is appended to the
    /// payload body and the receipt to `context.receipts`.
    ///
    /// Caller is responsible for mempool bookkeeping (advancing or dropping
    /// the sender's queue) — this function only mutates the payload context.
    pub fn apply_tx_to_payload(
        &self,
        head: HeadTransaction,
        context: &mut PayloadBuildContext,
    ) -> Result<(), ChainError> {
        let tx_hash = head.tx.hash();

        // EIP-8037 (Amsterdam+, PR #2703): per-tx 2D inclusion check against
        // running block totals. Run BEFORE we touch the BAL recorder so a
        // rejected tx doesn't even produce a sender/recipient touch.
        if context.is_amsterdam
            && let Err(e) = check_2d_gas_allowance(
                &head.tx,
                Fork::Amsterdam,
                context.block_regular_gas_used,
                context.block_state_gas_used,
                context.payload.header.gas_limit,
            )
        {
            debug!("Skipping tx {tx_hash:x}: fails 2D inclusion check: {e}");
            return Err(e.into());
        }

        // Set BAL index for this transaction (1-indexed per EIP-7928).
        // Must happen BEFORE tx_checkpoint: set_bal_index flushes net-zero
        // filters for the previous (committed) tx, which may insert reads.
        let tx_index =
            u32::try_from(context.payload.body.transactions.len() + 1).unwrap_or(u32::MAX);
        context.vm.set_bal_index(tx_index);

        // EIP-7928: lightweight tx-level checkpoint before trying the tx.
        // If the tx is rejected, restore so only included txs affect the BAL.
        // Taken after set_bal_index (which flushes previous tx) but before
        // this tx's touches, so rejected txs leave no trace.
        let bal_checkpoint = context
            .vm
            .db
            .bal_recorder
            .as_ref()
            .map(|r| r.tx_checkpoint());

        if let Some(recorder) = context.vm.db.bal_recorder_mut() {
            recorder.record_touched_address(head.tx.sender());
            if let TxKind::Call(to) = head.to() {
                recorder.record_touched_address(to);
            }
        }

        let receipt = match self.apply_transaction(&head, context) {
            Ok(receipt) => {
                metrics!(METRICS_TX.inc_tx_with_type(MetricsTxType(head.tx_type())));
                receipt
            }
            Err(e) => {
                debug!("Failed to execute transaction: {tx_hash:x}, {e}");
                metrics!(METRICS_TX.inc_tx_errors(e.to_metric()));
                if let (Some(recorder), Some(checkpoint)) =
                    (context.vm.db.bal_recorder_mut(), bal_checkpoint)
                {
                    recorder.tx_restore(checkpoint);
                }
                return Err(e);
            }
        };

        debug!("Adding transaction: {} to payload", tx_hash);
        context.payload.body.transactions.push(head.into());
        context.receipts.push(receipt);
        Ok(())
    }

    /// Executes the transaction, updates gas-related context values & return the receipt
    /// The payload build context should have enough remaining gas to cover the transaction's gas_limit
    fn apply_transaction(
        &self,
        head: &HeadTransaction,
        context: &mut PayloadBuildContext,
    ) -> Result<Receipt, ChainError> {
        match **head {
            Transaction::EIP4844Transaction(_) => self.apply_blob_transaction(head, context),
            _ => apply_plain_transaction(head, context),
        }
    }

    /// Runs a blob transaction, updates the gas count & blob data and returns the receipt
    fn apply_blob_transaction(
        &self,
        head: &HeadTransaction,
        context: &mut PayloadBuildContext,
    ) -> Result<Receipt, ChainError> {
        // Fetch blobs bundle
        let tx_hash = head.tx.hash();
        let max_blob_number_per_block = self.effective_max_blobs(context);
        let Some(blobs_bundle) = self.mempool.get_blobs_bundle(tx_hash)? else {
            // No blob tx should enter the mempool without its blobs bundle so this is an internal error
            return Err(
                StoreError::Custom(format!("No blobs bundle found for blob tx {tx_hash}")).into(),
            );
        };
        if context.blobs_bundle.blobs.len() + blobs_bundle.blobs.len() > max_blob_number_per_block {
            // This error will only be used for debug tracing
            return Err(EvmError::Custom("max data blobs reached".to_string()).into());
        };
        // Apply transaction
        let receipt = apply_plain_transaction(head, context)?;
        // Update context with blob data
        let prev_blob_gas = context.payload.header.blob_gas_used.unwrap_or_default();
        context.payload.header.blob_gas_used =
            Some(prev_blob_gas + (blobs_bundle.blobs.len() * GAS_PER_BLOB as usize) as u64);
        context.blobs_bundle += blobs_bundle;
        Ok(receipt)
    }

    pub fn extract_requests(&self, context: &mut PayloadBuildContext) -> Result<(), EvmError> {
        if !context
            .chain_config()
            .is_prague_activated(context.payload.header.timestamp)
        {
            return Ok(());
        };

        let requests = context
            .vm
            .extract_requests(&context.receipts, &context.payload.header)?;

        context.requests = Some(requests.iter().map(|r| r.encode()).collect());

        Ok(())
    }

    // EIP-8142 "block-in-blobs": producing payload blobs needs a KZG backend.
    #[cfg(not(feature = "c-kzg"))]
    fn add_eip8142_payload_blobs(
        &self,
        _context: &mut PayloadBuildContext,
    ) -> Result<(), ChainError> {
        Err(ChainError::Custom(
            "EIP-8142 is active but ethrex was built without the c-kzg feature, so payload \
             blobs cannot be produced (rebuild with c-kzg or unset eip8142_time)"
                .to_string(),
        ))
    }

    // EIP-8142 "block-in-blobs": construct and prepend the payload blobs.
    #[cfg(feature = "c-kzg")]
    fn add_eip8142_payload_blobs(
        &self,
        context: &mut PayloadBuildContext,
    ) -> Result<(), ChainError> {
        // EIP-8142 ⇒ Amsterdam, so the BAL must be present.
        let block_access_list = context.block_access_list.as_ref().ok_or_else(|| {
            ChainError::Custom(
                "EIP-8142 is active but the block access list is missing \
                 (configure eip8142_time >= amsterdam_time)"
                    .to_string(),
            )
        })?;

        // Encode the BAL + txs into payload blobs.
        let (payload_blobs, bal_len, txs_len) = {
            #[cfg(feature = "metrics")]
            let _timer = ethrex_metrics::eip8142::METRICS_EIP8142
                .build_phase_seconds
                .with_label_values(&["encode"])
                .start_timer();

            execution_payload_data_to_blobs_with_lens(
                block_access_list,
                &context.payload.body.transactions,
            )
        };

        // Suppress unused variable errors.
        #[cfg(not(feature = "metrics"))]
        let _ = (bal_len, txs_len);

        let payload_bundle = {
            // Measure latency added by KZG commitments + cell proofs.
            #[cfg(feature = "metrics")]
            let _timer = ethrex_metrics::eip8142::METRICS_EIP8142
                .build_phase_seconds
                .with_label_values(&["build_bundle"])
                .start_timer();

            // Encode payload blobs.
            // Hardcode wrapper version 1 (EIP-7594 cell proofs).
            PayloadBlobsBundle::create_from_blobs(&payload_blobs, Some(1))?
        };

        // Prepend payload blobs to existing blob bundle.
        context.blobs_bundle =
            BlobsBundle::from_sections(payload_bundle, std::mem::take(&mut context.blobs_bundle))?;

        // Set the new EIP-8142 header field
        context.payload.header.payload_blob_count = Some(payload_blobs.len() as u64);

        // EIP-8142: payload blobs consume blob gas like type-3 blobs, so add them to
        // blob_gas_used (which also feeds the next block's excess_blob_gas / base fee).
        let payload_blob_gas = payload_blobs.len() as u64 * u64::from(GAS_PER_BLOB);
        context.payload.header.blob_gas_used =
            Some(context.payload.header.blob_gas_used.unwrap_or(0) + payload_blob_gas);

        // Hard guarantee against the protocol MAX_BLOBS_PER_BLOCK.
        // Fail here rather than build an invalid block.
        let max_blobs = context.protocol_max_blobs();
        let total_blobs = context.blobs_bundle.blobs.len();
        if total_blobs > max_blobs {
            return Err(ChainError::Custom(format!(
                "EIP-8142: built block has {total_blobs} blobs ({} payload + {} type-3), \
                 exceeding MAX_BLOBS_PER_BLOCK ({max_blobs})",
                payload_blobs.len(),
                total_blobs.saturating_sub(payload_blobs.len()),
            )));
        }

        metrics!({
            record_eip8142_build_metrics(bal_len, txs_len, payload_blobs.len());
        });

        Ok(())
    }

    pub fn finalize_payload(&self, context: &mut PayloadBuildContext) -> Result<(), ChainError> {
        // EIP-8142: record the BAL-size estimate before `take_bal` consumes the recorder;
        // paired with the exact `bal_actual_size_bytes` it gives the gate's estimate↔exact gap.
        metrics!({
            use ethrex_metrics::eip8142::METRICS_EIP8142;
            if context.eip8142_active
                && let Some(recorder) = context.vm.db.bal_recorder.as_ref()
            {
                METRICS_EIP8142
                    .bal_estimated_size_bytes
                    .set(recorder.estimated_encoded_len() as i64);
            }
        });

        // Take BAL from VM before getting state transitions (which clears state)
        let block_access_list = context.vm.take_bal();

        let account_updates = context.vm.get_state_transitions()?;

        let ret_acount_updates_list = self
            .storage
            .apply_account_updates_batch(context.parent_hash(), &account_updates)?
            .ok_or(ChainError::ParentStateNotFound)?;

        let state_root = ret_acount_updates_list.state_trie_hash;

        context.payload.header.state_root = state_root;
        context.payload.header.transactions_root =
            compute_transactions_root(&context.payload.body.transactions, &NativeCrypto);
        context.payload.header.receipts_root =
            compute_receipts_root(&context.receipts, &NativeCrypto);
        context.payload.header.requests_hash = context
            .requests
            .as_ref()
            .map(|requests| compute_requests_hash(requests));
        let gas_used = context.gas_used();
        if context.is_amsterdam {
            debug!(
                "EIP-8037 block finalize: gas_used={gas_used} regular={} state={} txs={}",
                context.block_regular_gas_used,
                context.block_state_gas_used,
                context.payload.body.transactions.len(),
            );
        }
        context.payload.header.gas_used = gas_used;
        context.account_updates = account_updates;

        // Set BAL hash in block header (EIP-7928)
        context.payload.header.block_access_list_hash =
            block_access_list.as_ref().map(|bal| bal.compute_hash());
        context.block_access_list = block_access_list;

        // Add payload blobs (EIP-8142)
        if context.eip8142_active {
            self.add_eip8142_payload_blobs(context)?;
        }

        metrics!({
            use ethrex_metrics::eip8142::METRICS_EIP8142;
            METRICS_EIP8142
                .max_blobs
                .set(self.effective_max_blobs(context) as i64);
            METRICS_EIP8142
                .block_blobs
                .set(context.blobs_bundle.blobs.len() as i64);
            METRICS_EIP8142
                .payload_blob_count_last
                .set(context.payload.header.payload_blob_count.unwrap_or(0) as i64);
        });

        let mut logs = vec![];
        for receipt in context.receipts.iter().cloned() {
            for log in receipt.logs {
                logs.push(log);
            }
        }

        context.payload.header.logs_bloom = bloom_from_logs(&logs, &NativeCrypto);
        Ok(())
    }
}

#[cfg(feature = "metrics")]
#[cfg_attr(not(feature = "c-kzg"), allow(dead_code))]
fn record_eip8142_build_metrics(bal_len: usize, txs_len: usize, payload_blob_count: usize) {
    use ethrex_common::types::eip8142::last_blob_utilization;
    use ethrex_metrics::eip8142::METRICS_EIP8142;
    METRICS_EIP8142.active.set(1);
    METRICS_EIP8142.payload_bal_bytes.set(bal_len as i64);
    METRICS_EIP8142.payload_txs_bytes.set(txs_len as i64);
    METRICS_EIP8142.bal_actual_size_bytes.set(bal_len as i64);
    METRICS_EIP8142
        .last_payload_blob_utilization
        .set(last_blob_utilization(
            HEADER_SIZE + bal_len + txs_len,
            payload_blob_count,
        ));
}

/// Projected blob counts that would exceed the limit, for the rejection message.
struct BlobLimitOverflow {
    payload_blobs: usize,
    type3_blobs: usize,
    max_blobs: usize,
}

/// Would keeping `head` push the block's combined blob count (payload + type-3) over the protocol
/// `MAX_BLOBS_PER_BLOCK`? Returns the projected counts on overflow, else `None`.
///
/// Uses the recorder's O(1) running upper bound for the BAL size. Called *after* a tx executes
/// it's exact; called *before* (the fast-reject) it's a lower bound. Either way a fit guarantees
/// the `add_eip8142_payload_blobs` seal check can't trip, at the cost of a slightly early seal.
fn eip8142_projected_blob_overflow(
    head: &HeadTransaction,
    context: &PayloadBuildContext,
) -> Option<BlobLimitOverflow> {
    if !context.eip8142_active {
        return None;
    }

    // 8142 ⇒ Amsterdam ⇒ BAL recording is on, so the recorder is present; if not, skip the gate
    // and let the missing-BAL check in `add_eip8142_payload_blobs` fail the build.
    let recorder = context.vm.db.bal_recorder.as_ref()?;

    let payload_blobs = payload_blob_count_for_byte_len(
        HEADER_SIZE
            + recorder.estimated_encoded_len()
            + EIP8142_POST_TRANSACTIONS_BUFFER_BYTES
            + context.payload_size as usize,
    );
    let type3_blobs = context.blobs_bundle.blobs.len() + head.blob_versioned_hashes_len();
    let max_blobs = context.protocol_max_blobs();

    (payload_blobs + type3_blobs > max_blobs).then_some(BlobLimitOverflow {
        payload_blobs,
        type3_blobs,
        max_blobs,
    })
}

/// Runs a plain (non blob) transaction, updates the gas count and returns the receipt
pub fn apply_plain_transaction(
    head: &HeadTransaction,
    context: &mut PayloadBuildContext,
) -> Result<Receipt, ChainError> {
    let (receipt, report) = context.vm.execute_tx(
        &head.tx,
        &context.payload.header,
        &mut context.cumulative_gas_spent,
        head.tx.sender(),
    )?;

    // EIP-8037 (Amsterdam+): track regular and state gas separately
    let tx_state_gas = report.state_gas_used;
    let tx_regular_gas = report.gas_used.saturating_sub(tx_state_gas);

    // Compute new totals before committing them
    let new_regular = context
        .block_regular_gas_used
        .saturating_add(tx_regular_gas);
    let new_state = context.block_state_gas_used.saturating_add(tx_state_gas);

    // EIP-8037 (Amsterdam+): post-execution block gas overflow check
    // Reject the transaction if adding it would cause max(regular, state) to exceed the gas limit
    // and also check the EIP-8142 "block-in-blobs" combined blob-limit
    let gas_overflow =
        context.is_amsterdam && new_regular.max(new_state) > context.payload.header.gas_limit;
    let blob_overflow = eip8142_projected_blob_overflow(head, context);
    if gas_overflow || blob_overflow.is_some() {
        // Rollback transaction state before returning error:
        // 1. Undo DB mutations (nonce, balance, storage, etc.)
        // 2. Revert cumulative gas counter inflation
        // This ensures the next transaction executes against clean state.
        // The BAL recorder is rolled back separately by the caller.
        context.vm.undo_last_tx()?;
        // `cumulative_gas_spent` was bumped inside `execute_tx` above; revert it
        // now that the tx is being rejected. Use `saturating_sub` as a defensive
        // guard — cumulative must always dominate this tx's contribution unless
        // some upstream bug leaks a stale value, in which case we'd rather clamp
        // to 0 than underflow the counter.
        debug_assert!(
            context.cumulative_gas_spent >= report.gas_spent,
            "cumulative_gas_spent underflow on tx rollback"
        );
        context.cumulative_gas_spent = context
            .cumulative_gas_spent
            .saturating_sub(report.gas_spent);

        if let Some(BlobLimitOverflow {
            payload_blobs,
            type3_blobs,
            max_blobs,
        }) = blob_overflow
        {
            return Err(EvmError::Custom(format!(
                "EIP-8142: including transaction would exceed the combined blob limit: \
                 {payload_blobs} payload + {type3_blobs} type-3 = {} > MAX_BLOBS_PER_BLOCK {max_blobs}",
                payload_blobs + type3_blobs,
            ))
        .into());
        };

        return Err(EvmError::Custom(format!(
            "block gas limit exceeded (state gas overflow): \
             max({new_regular}, {new_state}) = {} > gas_limit {}",
            new_regular.max(new_state),
            context.payload.header.gas_limit
        ))
        .into());
    }

    // Commit the new totals
    context.block_regular_gas_used = new_regular;
    context.block_state_gas_used = new_state;

    if context.is_amsterdam {
        debug!(
            "EIP-8037 tx gas: regular={tx_regular_gas} state={tx_state_gas} gas_used={} gas_spent={} block_regular={} block_state={} block_max={}",
            report.gas_used,
            report.gas_spent,
            context.block_regular_gas_used,
            context.block_state_gas_used,
            context
                .block_regular_gas_used
                .max(context.block_state_gas_used),
        );
    }

    // Update remaining_gas for block gas limit checks.
    // EIP-8037 (Amsterdam+): remaining_gas reflects both regular and state gas dimensions.
    // For pre-tx heuristic checks, this ensures we reject txs when either dimension is full.
    if context.is_amsterdam {
        context.remaining_gas = context
            .payload
            .header
            .gas_limit
            .saturating_sub(new_regular.max(new_state));
    } else {
        context.remaining_gas = context.remaining_gas.saturating_sub(report.gas_used);
    }

    // Block value uses gas_spent (what the user actually pays) for tip calculation
    context.block_value += U256::from(report.gas_spent) * head.tip;
    Ok(receipt)
}

/// A struct representing suitable mempool transactions waiting to be included in a block
// TODO: Consider using VecDequeue instead of Vec
pub struct TransactionQueue {
    // The first transaction for each account along with its tip, sorted by highest tip
    heads: Vec<HeadTransaction>,
    // The remaining txs grouped by account and sorted by nonce
    txs: FxHashMap<Address, Vec<MempoolTransaction>>,
    // Base Fee stored for tip calculations
    base_fee: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadTransaction {
    pub tx: MempoolTransaction,
    pub tip: U256,
}

impl std::ops::Deref for HeadTransaction {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl From<HeadTransaction> for Transaction {
    fn from(val: HeadTransaction) -> Self {
        val.tx.transaction().clone()
    }
}

impl TransactionQueue {
    /// Creates a new TransactionQueue from a set of transactions grouped by sender and sorted by nonce
    fn new(
        mut txs: FxHashMap<Address, Vec<MempoolTransaction>>,
        base_fee: Option<u64>,
    ) -> Result<Self, ChainError> {
        let mut heads = Vec::with_capacity(100);
        for (_, txs) in txs.iter_mut() {
            // Pull the first tx from each list and add it to the heads list
            // This should be a newly filtered tx list so we are guaranteed to have a first element
            let head_tx = txs.remove(0);
            heads.push(HeadTransaction {
                // We already ran this method when filtering the transactions from the mempool so it shouldn't fail
                tip: head_tx
                    .effective_gas_tip(base_fee)
                    .ok_or(ChainError::InvalidBlock(
                        InvalidBlockError::InvalidTransaction("Attempted to add an invalid transaction to the block. The transaction filter must have failed.".to_owned()),
                    ))?,
                tx: head_tx,
            });
        }
        // Sort heads by higest tip (and lowest timestamp if tip is equal)
        heads.sort();
        Ok(TransactionQueue {
            heads,
            txs,
            base_fee,
        })
    }

    /// Remove all transactions from the queue
    pub fn clear(&mut self) {
        self.heads.clear();
        self.txs.clear();
    }

    /// Returns true if there are no more transactions in the queue
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }

    /// Returns the head transaction with the highest tip
    /// If there is more than one transaction with the highest tip, return the one with the lowest timestamp
    pub fn peek(&self) -> Option<HeadTransaction> {
        self.heads.first().cloned()
    }

    /// Removes current head transaction and all transactions from the given sender
    pub fn pop(&mut self) {
        if !self.is_empty() {
            let sender = self.heads.remove(0).tx.sender();
            self.txs.remove(&sender);
        }
    }

    /// Remove the top transaction
    /// Add a tx from the same sender to the head transactions
    pub fn shift(&mut self) -> Result<(), ChainError> {
        let tx = self.heads.remove(0);
        if let Some(txs) = self.txs.get_mut(&tx.tx.sender()) {
            // Fetch next head
            if !txs.is_empty() {
                let head_tx = txs.remove(0);
                let head = HeadTransaction {
                    // We already ran this method when filtering the transactions from the mempool so it shouldn't fail
                    tip: head_tx.effective_gas_tip(self.base_fee).ok_or(
                        ChainError::InvalidBlock(
                            InvalidBlockError::InvalidTransaction("Attempted to add an invalid transaction to the block. The transaction filter must have failed.".to_owned()),
                        ),
                    )?,
                    tx: head_tx,
                };
                // Insert head into heads list while maintaing order
                let index = match self.heads.binary_search(&head) {
                    Ok(index) => index, // Same ordering shouldn't be possible when adding timestamps
                    Err(index) => index,
                };
                self.heads.insert(index, head);
            }
        }
        Ok(())
    }
}

// Orders transactions by highest tip, if tip is equal, orders by lowest timestamp
impl Ord for HeadTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.tx_type(), other.tx_type()) {
            (TxType::Privileged, TxType::Privileged) => return self.nonce().cmp(&other.nonce()),
            (TxType::Privileged, _) => return Ordering::Less,
            (_, TxType::Privileged) => return Ordering::Greater,
            _ => (),
        };
        match other.tip.cmp(&self.tip) {
            Ordering::Equal => self.tx.time().cmp(&other.tx.time()),
            ordering => ordering,
        }
    }
}

impl PartialOrd for HeadTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

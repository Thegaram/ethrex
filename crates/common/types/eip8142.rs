//! EIP-8142 "block-in-blobs" helpers.
//!
//! Encode and decode the subset of an execution payload that is published via
//! blobs (the EIP-7928 block access list and the block's transactions) to and
//! from the blob field-element layout.
//!
//! Spec: <https://eips.ethereum.org/EIPS/eip-8142>

use crate::types::{
    BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT, Blob, FIELD_ELEMENTS_PER_BLOB, SAFE_BYTES_PER_BLOB,
    Transaction, block_access_list::BlockAccessList,
};
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode, error::RLPDecodeError};
use thiserror::Error;

/// Usable bytes per field element, index 0 (MSB in big-endian) is left zero.
const USABLE_BYTES_PER_FIELD_ELEMENT: usize = 31;
/// Total usable bytes per blob: FIELD_ELEMENTS_PER_BLOB * 31.
const USABLE_BYTES_PER_BLOB: usize = SAFE_BYTES_PER_BLOB;
/// Width of each big-endian `u32` length prefix in the packed payload header.
const LENGTH_PREFIX_SIZE: usize = 4;
/// Packed payload header: BAL length + transactions length.
pub const HEADER_SIZE: usize = 2 * LENGTH_PREFIX_SIZE;

/// The subset of an execution payload published via blobs under EIP-8142.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExecutionPayloadData {
    /// The block access list (EIP-7928).
    pub block_access_list: BlockAccessList,
    /// The block's transactions.
    pub transactions: Vec<Transaction>,
}

/// Payload blob decoding errors.
#[derive(Debug, Error)]
pub enum BibError {
    #[error("blob field element {0} has a non-zero most-significant byte")]
    NonZeroPadding(usize),
    #[error(
        "packed payload is incomplete: header declares {declared} bytes but only {available} are available"
    )]
    Incomplete { declared: usize, available: usize },
    #[error("blob has non-zero trailing data after the declared payload")]
    TrailingData,
    #[error("failed to RLP-decode packed payload: {0}")]
    Rlp(#[from] RLPDecodeError),
}

/// Packs the already-encoded block access list and transactions bytes into blobs,
/// prefixed with an 8-byte header holding their big-endian `u32` lengths.
fn payload_parts_to_blobs(bal_bytes: &[u8], txs_bytes: &[u8]) -> Vec<Blob> {
    debug_assert!(bal_bytes.len() <= u32::MAX as usize);
    debug_assert!(txs_bytes.len() <= u32::MAX as usize);

    let mut payload = Vec::with_capacity(HEADER_SIZE + bal_bytes.len() + txs_bytes.len());
    payload.extend_from_slice(&(bal_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&(txs_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(bal_bytes);
    payload.extend_from_slice(txs_bytes);

    bytes_to_blobs(&payload)
}

/// Encodes the block access list and transactions of an execution payload into
/// blobs, prefixed with an 8-byte header holding their big-endian `u32` lengths.
///
/// The fields of the spec's `ExecutionPayloadData` are taken by reference, so
/// callers (the builder) don't have to clone them into an owning struct.
pub fn execution_payload_data_to_blobs(
    block_access_list: &BlockAccessList,
    transactions: &Vec<Transaction>,
) -> Vec<Blob> {
    execution_payload_data_to_blobs_with_lens(block_access_list, transactions).0
}

/// Like [`execution_payload_data_to_blobs`], but also returns the RLP-encoded byte
/// lengths of the two packed sections, `(blobs, bal_len, txs_len)`. The builder
/// uses the lengths for size metrics without re-encoding the (potentially multi-MiB)
/// block access list and transactions a second time.
pub fn execution_payload_data_to_blobs_with_lens(
    block_access_list: &BlockAccessList,
    transactions: &Vec<Transaction>,
) -> (Vec<Blob>, usize, usize) {
    let bal_bytes = block_access_list.encode_to_vec();
    let txs_bytes = transactions.encode_to_vec();
    let (bal_len, txs_len) = (bal_bytes.len(), txs_bytes.len());
    (
        payload_parts_to_blobs(&bal_bytes, &txs_bytes),
        bal_len,
        txs_len,
    )
}

/// Like [`execution_payload_data_to_blobs`], but takes the block access list as the
/// raw RLP bytes received in the payload. Per the EIP-8142 spec, `blockAccessList`
/// is opaque bytes, so using them verbatim avoids a decode→re-encode round-trip.
pub fn execution_payload_to_blobs_from_raw_bal(
    bal_bytes: &[u8],
    transactions: &Vec<Transaction>,
) -> Vec<Blob> {
    payload_parts_to_blobs(bal_bytes, &transactions.encode_to_vec())
}

/// Number of payload blobs the EIP-8142 codec emits for a packed payload-data
/// section of `data_len` bytes (the 8-byte length header + RLP block access list
/// + RLP transactions): `ceil(data_len / USABLE_BYTES_PER_BLOB)`.
///
/// Used by the block builder to project the payload-blob count *before* the BAL
/// is finalized, so transaction selection can keep the combined
/// `payload_blob_count + type-3 blobs` count within `MAX_BLOBS_PER_BLOCK`.
pub fn payload_blob_count_for_byte_len(data_len: usize) -> usize {
    data_len.div_ceil(USABLE_BYTES_PER_BLOB)
}

/// Fill fraction (in `(0.0, 1.0]`) of the *trailing* payload blob. Every payload
/// blob but the last is full by construction (the encoder chunks at
/// `USABLE_BYTES_PER_BLOB`), so the last blob's fill is the padding-waste signal:
/// `(1.0 - utilization) * USABLE_BYTES_PER_BLOB` is the wasted bytes. `data_len`
/// is the packed payload length; `blob_count` the number of payload blobs.
pub fn last_blob_utilization(data_len: usize, blob_count: usize) -> f64 {
    if blob_count == 0 {
        return 0.0;
    }
    let leading_capacity = blob_count.saturating_sub(1) * USABLE_BYTES_PER_BLOB;
    let last_blob_bytes = data_len
        .saturating_sub(leading_capacity)
        .min(USABLE_BYTES_PER_BLOB);
    last_blob_bytes as f64 / USABLE_BYTES_PER_BLOB as f64
}

/// Decodes blobs produced by [`execution_payload_data_to_blobs`] back into the
/// block access list and transactions based on the 8-byte length header.
pub fn blobs_to_execution_payload_data(blobs: &[Blob]) -> Result<ExecutionPayloadData, BibError> {
    let raw = blobs_to_bytes(blobs)?;

    let incomplete = |declared: usize| BibError::Incomplete {
        declared,
        available: raw.len(),
    };

    // Decode header
    let Some((bal_length_bytes, rest)) = raw.split_first_chunk::<LENGTH_PREFIX_SIZE>() else {
        return Err(incomplete(HEADER_SIZE));
    };
    let bal_length = u32::from_be_bytes(*bal_length_bytes) as usize;

    let Some((txs_length_bytes, rest)) = rest.split_first_chunk::<LENGTH_PREFIX_SIZE>() else {
        return Err(incomplete(HEADER_SIZE));
    };
    let txs_length = u32::from_be_bytes(*txs_length_bytes) as usize;

    let declared_total = HEADER_SIZE
        .saturating_add(bal_length)
        .saturating_add(txs_length);

    // Decode BAL
    let Some((bal_bytes, rest)) = rest.split_at_checked(bal_length) else {
        return Err(incomplete(declared_total));
    };
    let block_access_list = BlockAccessList::decode(bal_bytes)?;

    // Decode transactions
    let Some((txs_bytes, padding)) = rest.split_at_checked(txs_length) else {
        return Err(incomplete(declared_total));
    };
    let transactions = Vec::<Transaction>::decode(txs_bytes)?;

    // Everything after the declared payload must be zero padding.
    if padding.iter().any(|&b| b != 0) {
        return Err(BibError::TrailingData);
    }

    Ok(ExecutionPayloadData {
        block_access_list,
        transactions,
    })
}

/// Packs arbitrary bytes into one or more blobs, zero-padding the final blob.
fn bytes_to_blobs(data: &[u8]) -> Vec<Blob> {
    data.chunks(USABLE_BYTES_PER_BLOB)
        .map(chunk_to_blob)
        .collect()
}

/// Packs up to [`USABLE_BYTES_PER_BLOB`] bytes into a single blob.
/// Each 31-byte chunk lands in bytes `[1..32]` of a field element, leaving the
/// most-significant byte (index 0) zero so the big-endian element is canonical.
fn chunk_to_blob(data: &[u8]) -> Blob {
    debug_assert!(data.len() <= USABLE_BYTES_PER_BLOB);
    let mut blob = [0u8; BYTES_PER_BLOB];
    for (i, chunk) in data.chunks(USABLE_BYTES_PER_FIELD_ELEMENT).enumerate() {
        let fe_start = i * BYTES_PER_FIELD_ELEMENT;
        let data_start = fe_start + 1; // skip index 0
        blob[data_start..data_start + chunk.len()].copy_from_slice(chunk); // copy <=31 bytes
    }
    blob
}

/// Unpacks blobs back into bytes, concatenating the usable bytes of each.
fn blobs_to_bytes(blobs: &[Blob]) -> Result<Vec<u8>, BibError> {
    let mut data = vec![0u8; blobs.len() * USABLE_BYTES_PER_BLOB];
    let (chunks, rest) = data.as_chunks_mut::<USABLE_BYTES_PER_BLOB>();
    debug_assert!(rest.is_empty());
    for (blob, chunk) in blobs.iter().zip(chunks) {
        blob_to_chunk(blob, chunk)?;
    }
    Ok(data)
}

/// Fills `out` with the 31 usable bytes (`[1..32]`) of every field element of
/// `blob`, validating that each field element's MSB (index 0) is zero.
fn blob_to_chunk(blob: &Blob, out: &mut [u8; USABLE_BYTES_PER_BLOB]) -> Result<(), BibError> {
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        let fe_start = i * BYTES_PER_FIELD_ELEMENT;
        if blob[fe_start] != 0 {
            return Err(BibError::NonZeroPadding(i));
        }
        let usable_bytes = &blob[fe_start + 1..fe_start + BYTES_PER_FIELD_ELEMENT];
        // copy 31 bytes
        let data_start = i * USABLE_BYTES_PER_FIELD_ELEMENT;
        out[data_start..data_start + USABLE_BYTES_PER_FIELD_ELEMENT].copy_from_slice(usable_bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_blobs_round_trip_across_blob_boundary() {
        // A payload larger than one blob exercises the multi-blob path.
        let data: Vec<u8> = (0..USABLE_BYTES_PER_BLOB + 1234).map(|i| i as u8).collect();

        let blobs = bytes_to_blobs(&data);
        assert_eq!(blobs.len(), 2);

        let raw = blobs_to_bytes(&blobs).unwrap();
        // Decoding yields the data zero-padded to a whole number of blobs.
        assert_eq!(&raw[..data.len()], &data[..]);
        assert!(raw[data.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn payload_blob_count_for_byte_len_cases() {
        let cap = USABLE_BYTES_PER_BLOB;
        // Empty data needs zero blobs; any data up to one blob's capacity needs one.
        assert_eq!(payload_blob_count_for_byte_len(0), 0);
        assert_eq!(payload_blob_count_for_byte_len(1), 1);
        assert_eq!(payload_blob_count_for_byte_len(cap), 1);
        // One byte over a boundary rolls into the next blob.
        assert_eq!(payload_blob_count_for_byte_len(cap + 1), 2);
        assert_eq!(payload_blob_count_for_byte_len(3 * cap), 3);
        // Agrees with the actual encoder for a multi-blob payload.
        let data = vec![0u8; 2 * cap + 1234];
        assert_eq!(
            payload_blob_count_for_byte_len(data.len()),
            bytes_to_blobs(&data).len()
        );
    }

    #[test]
    fn last_blob_utilization_cases() {
        let cap = USABLE_BYTES_PER_BLOB;
        // Empty payload = 8-byte header only -> 1 blob, barely used.
        assert_eq!(last_blob_utilization(8, 1), 8.0 / cap as f64);
        // Exact multiple -> trailing blob is full.
        assert_eq!(last_blob_utilization(2 * cap, 2), 1.0);
        // 3 blobs, 100 bytes spill into the last -> low utilization.
        assert_eq!(last_blob_utilization(2 * cap + 100, 3), 100.0 / cap as f64);
        // Defensive: zero count never divides by zero or panics.
        assert_eq!(last_blob_utilization(0, 0), 0.0);
    }

    #[test]
    fn chunk_to_blob_leaves_msb_zero() {
        let data = vec![0xffu8; USABLE_BYTES_PER_FIELD_ELEMENT * 3];
        let blob = chunk_to_blob(&data);
        for i in 0..3 {
            let start = i * BYTES_PER_FIELD_ELEMENT;
            // The most-significant byte (index 0) is the forced-zero byte...
            assert_eq!(blob[start], 0);
            // ...and the following 31 bytes carry the data.
            assert!(
                blob[start + 1..start + BYTES_PER_FIELD_ELEMENT]
                    .iter()
                    .all(|&b| b == 0xff)
            );
        }
    }

    #[test]
    fn blob_to_chunk_rejects_non_zero_msb() {
        let mut blob = [0u8; BYTES_PER_BLOB];
        blob[0] = 1; // most-significant byte of the first field element
        let mut out = [0u8; USABLE_BYTES_PER_BLOB];
        assert!(matches!(
            blob_to_chunk(&blob, &mut out),
            Err(BibError::NonZeroPadding(0))
        ));
    }

    #[test]
    fn execution_payload_data_round_trip() {
        let data = ExecutionPayloadData {
            block_access_list: BlockAccessList::default(),
            transactions: Vec::new(),
        };

        let blobs = execution_payload_data_to_blobs(&data.block_access_list, &data.transactions);
        let decoded = blobs_to_execution_payload_data(&blobs).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn blobs_to_execution_payload_data_rejects_short_header() {
        let blobs: Vec<Blob> = Vec::new();
        assert!(matches!(
            blobs_to_execution_payload_data(&blobs),
            Err(BibError::Incomplete { .. })
        ));
    }

    #[test]
    fn blobs_to_execution_payload_data_rejects_trailing_data() {
        let data = ExecutionPayloadData::default();
        let mut blobs =
            execution_payload_data_to_blobs(&data.block_access_list, &data.transactions);
        // Corrupt a usable data byte far past the declared payload. The blob's
        // last byte is a data byte (not an MSB), so it bypasses the per-element
        // check and lands in the trailing padding region.
        let last = blobs[0].len() - 1;
        blobs[0][last] = 1;
        assert!(matches!(
            blobs_to_execution_payload_data(&blobs),
            Err(BibError::TrailingData)
        ));
    }

    #[test]
    fn raw_bal_encoding_matches_typed_encoding() {
        // The builder encodes from the typed BAL, the verifier from the raw RLP
        // bytes received in the payload; both must produce identical blobs.
        let bal = BlockAccessList::default();
        let txs = Vec::new();
        assert_eq!(
            execution_payload_to_blobs_from_raw_bal(&bal.encode_to_vec(), &txs),
            execution_payload_data_to_blobs(&bal, &txs),
        );
    }

    #[test]
    fn decode_rejects_adversarial_declared_lengths() {
        // A header declaring u32::MAX-length sections must be rejected cleanly
        // (no panic / no usize overflow — guests are 32-bit).
        let mut blob = [0u8; BYTES_PER_BLOB];
        // Field-element layout: data lives in bytes [1..32]; the 8-byte length
        // header occupies the first 8 usable bytes.
        blob[1..5].copy_from_slice(&u32::MAX.to_be_bytes()); // bal_length
        blob[5..9].copy_from_slice(&u32::MAX.to_be_bytes()); // txs_length
        assert!(matches!(
            blobs_to_execution_payload_data(&[blob]),
            Err(BibError::Incomplete { .. })
        ));
    }

    #[test]
    fn decode_rejects_garbage_block_access_list() {
        // Sections that fit but don't RLP-decode surface as `Rlp`, not a panic.
        let mut blob = [0u8; BYTES_PER_BLOB];
        blob[1..5].copy_from_slice(&1u32.to_be_bytes()); // bal_length = 1
        // txs_length = 0; bal byte = 0x81 (truncated RLP string header)
        blob[9] = 0x81;
        assert!(matches!(
            blobs_to_execution_payload_data(&[blob]),
            Err(BibError::Rlp(_))
        ));
    }
}

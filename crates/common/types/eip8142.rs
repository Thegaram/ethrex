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

/// Usable bytes per field element: 31 bytes carry data while the
/// most-significant byte (index 0, big-endian) is left zero so every field
/// element stays below the BLS modulus (is canonical).
const USABLE_BYTES_PER_FIELD_ELEMENT: usize = 31;
/// Usable bytes across all the field elements of a single blob.
const USABLE_BYTES_PER_BLOB: usize = SAFE_BYTES_PER_BLOB; // FIELD_ELEMENTS_PER_BLOB * 31

/// Width of each big-endian `u32` length prefix in the packed payload header.
const LENGTH_PREFIX_SIZE: usize = 4;
/// Packed payload header: a length prefix for the BAL followed by one for the
/// transactions.
const HEADER_SIZE: usize = 2 * LENGTH_PREFIX_SIZE;

/// The subset of an execution payload published via blobs under EIP-8142.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExecutionPayloadData {
    /// The block access list (EIP-7928).
    pub block_access_list: BlockAccessList,
    /// The block's transactions.
    pub transactions: Vec<Transaction>,
}

/// Errors returned when decoding blobs back into execution-payload data.
#[derive(Debug, Error)]
pub enum BibError {
    #[error("blob field element {0} has a non-zero most-significant byte")]
    NonZeroPadding(usize),
    #[error(
        "packed payload is truncated: header declares {declared} bytes but only {available} are present"
    )]
    Truncated { declared: usize, available: usize },
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
pub fn execution_payload_data_to_blobs(data: &ExecutionPayloadData) -> Vec<Blob> {
    payload_parts_to_blobs(
        &data.block_access_list.encode_to_vec(),
        &data.transactions.encode_to_vec(),
    )
}

/// Like [`execution_payload_data_to_blobs`], but takes the block access list as the
/// raw RLP bytes received in the payload. Per the EIP-8142 spec, `blockAccessList`
/// is opaque bytes, so using them verbatim avoids a decode→re-encode round-trip
/// (and the non-canonical mismatch it could introduce). Transactions are still
/// RLP-encoded as a list. Used by `engine_newPayload` verification.
pub fn execution_payload_to_blobs_from_raw_bal(
    bal_bytes: &[u8],
    transactions: &Vec<Transaction>,
) -> Vec<Blob> {
    payload_parts_to_blobs(bal_bytes, &transactions.encode_to_vec())
}

/// Number of blobs the execution-payload data (block access list + transactions)
/// packs into, computed from the RLP-encoded lengths without materializing the
/// blobs. Equal to `execution_payload_data_to_blobs(..).len()`.
pub fn payload_blob_count(
    block_access_list: &BlockAccessList,
    transactions: &Vec<Transaction>,
) -> u64 {
    let len = HEADER_SIZE + block_access_list.length() + transactions.length();
    len.div_ceil(USABLE_BYTES_PER_BLOB) as u64
}

/// Decodes blobs produced by [`execution_payload_data_to_blobs`] back into the
/// block access list and transactions by reading the 8-byte length header.
///
/// Rejects non-canonical encodings: a header whose declared lengths exceed the
/// unpacked bytes, or non-zero trailing data after the declared payload.
pub fn blobs_to_execution_payload_data(blobs: &[Blob]) -> Result<ExecutionPayloadData, BibError> {
    let raw = blobs_to_bytes(blobs)?;

    let truncated = |declared: usize| BibError::Truncated {
        declared,
        available: raw.len(),
    };
    let Some((bal_length_bytes, rest)) = raw.split_first_chunk::<LENGTH_PREFIX_SIZE>() else {
        return Err(truncated(HEADER_SIZE));
    };
    let bal_length = u32::from_be_bytes(*bal_length_bytes) as usize;

    let Some((txs_length_bytes, rest)) = rest.split_first_chunk::<LENGTH_PREFIX_SIZE>() else {
        return Err(truncated(HEADER_SIZE));
    };
    let txs_length = u32::from_be_bytes(*txs_length_bytes) as usize;

    // The declared size can overflow `usize` on 32-bit (zkVM) targets for
    // adversarial headers. Saturating here is for the error message only.
    let declared_total = HEADER_SIZE
        .saturating_add(bal_length)
        .saturating_add(txs_length);

    let Some((bal_bytes, rest)) = rest.split_at_checked(bal_length) else {
        return Err(truncated(declared_total));
    };
    let block_access_list = BlockAccessList::decode(bal_bytes)?;

    let Some((txs_bytes, padding)) = rest.split_at_checked(txs_length) else {
        return Err(truncated(declared_total));
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

/// Packs up to [`USABLE_BYTES_PER_BLOB`] bytes into a single blob. Each 31-byte
/// chunk lands in bytes `[1..32]` of a field element, leaving the
/// most-significant byte (index 0) zero so the big-endian element is canonical.
fn chunk_to_blob(data: &[u8]) -> Blob {
    debug_assert!(data.len() <= USABLE_BYTES_PER_BLOB);
    let mut blob = [0u8; BYTES_PER_BLOB];
    for (i, chunk) in data.chunks(USABLE_BYTES_PER_FIELD_ELEMENT).enumerate() {
        let field_element_start = i * BYTES_PER_FIELD_ELEMENT;
        let data_start = field_element_start + 1;
        blob[data_start..data_start + chunk.len()].copy_from_slice(chunk);
    }
    blob
}

/// Unpacks blobs back into bytes, concatenating the usable bytes of each.
fn blobs_to_bytes(blobs: &[Blob]) -> Result<Vec<u8>, BibError> {
    let mut raw = Vec::with_capacity(blobs.len() * USABLE_BYTES_PER_BLOB);
    for blob in blobs {
        blob_to_chunk(blob, &mut raw)?;
    }
    Ok(raw)
}

/// Appends the 31 usable bytes (`[1..32]`) of every field element of `blob` to
/// `out`, validating that each field element's most-significant byte (index 0)
/// is zero.
fn blob_to_chunk(blob: &Blob, out: &mut Vec<u8>) -> Result<(), BibError> {
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        let field_element_start = i * BYTES_PER_FIELD_ELEMENT;
        if blob[field_element_start] != 0 {
            return Err(BibError::NonZeroPadding(i));
        }
        out.extend_from_slice(
            &blob[field_element_start + 1..field_element_start + BYTES_PER_FIELD_ELEMENT],
        );
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
        let mut out = Vec::new();
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

        let blobs = execution_payload_data_to_blobs(&data);
        let decoded = blobs_to_execution_payload_data(&blobs).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn payload_blob_count_matches_encoding() {
        let data = ExecutionPayloadData::default();
        assert_eq!(
            payload_blob_count(&data.block_access_list, &data.transactions),
            execution_payload_data_to_blobs(&data).len() as u64
        );
    }

    #[test]
    fn blobs_to_execution_payload_data_rejects_short_header() {
        let blobs: Vec<Blob> = Vec::new();
        assert!(matches!(
            blobs_to_execution_payload_data(&blobs),
            Err(BibError::Truncated { .. })
        ));
    }

    #[test]
    fn blobs_to_execution_payload_data_rejects_trailing_data() {
        let mut blobs = execution_payload_data_to_blobs(&ExecutionPayloadData::default());
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
}

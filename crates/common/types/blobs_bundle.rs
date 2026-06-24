use std::ops::AddAssign;

use crate::serde_utils;
#[cfg(feature = "c-kzg")]
use crate::types::Fork;
use crate::types::constants::VERSIONED_HASH_VERSION_KZG;
use crate::{Bytes, H256};

use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use serde::{Deserialize, Serialize};

use super::{BYTES_PER_BLOB, CELLS_PER_EXT_BLOB, SAFE_BYTES_PER_BLOB};

pub type Bytes48 = [u8; 48];
pub type Blob = [u8; BYTES_PER_BLOB];
pub type Commitment = Bytes48;
pub type Proof = Bytes48;
pub type BlobTuple = (Box<Blob>, Commitment, Vec<Proof>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
/// Struct containing all the blobs for a blob transaction, along with the corresponding commitments and proofs
pub struct BlobsBundle {
    #[serde(with = "serde_utils::blob::vec")]
    pub blobs: Vec<Blob>,
    #[serde(with = "serde_utils::bytes48::vec")]
    pub commitments: Vec<Commitment>,
    #[serde(with = "serde_utils::bytes48::vec")]
    pub proofs: Vec<Proof>,
    /// EIP-8142 "block-in-blobs": Add random-point KZG opening proofs for the payload blobs.
    /// These will be passed as private input to the prover guest program and batch-verified.
    /// This field is omitted in normal engine API responses.
    /// Note: `proofs` are cell proofs, while `payload_kzg_proofs` are random-point KZG opening proofs.
    #[serde(
        with = "serde_utils::bytes48::vec",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub payload_kzg_proofs: Vec<Proof>,
    #[serde(skip, default)]
    pub version: u8,
}

pub fn blob_from_bytes(bytes: Bytes) -> Result<Blob, BlobsBundleError> {
    // This functions moved from `l2/utils/eth_client/transaction.rs`
    // We set the first byte of every 32-bytes chunk to 0x00
    // so it's always under the field module.
    if bytes.len() > SAFE_BYTES_PER_BLOB {
        return Err(BlobsBundleError::BlobDataInvalidBytesLength);
    }

    let mut buf = [0u8; BYTES_PER_BLOB];
    buf[..(bytes.len() * 32).div_ceil(31)].copy_from_slice(
        &bytes
            .chunks(31)
            .map(|x| [&[0x00], x].concat())
            .collect::<Vec<_>>()
            .concat(),
    );

    Ok(buf)
}

pub fn bytes_from_blob(blob: Bytes) -> [u8; SAFE_BYTES_PER_BLOB] {
    let mut buf = [0u8; SAFE_BYTES_PER_BLOB];
    buf.copy_from_slice(
        &blob
            .chunks(32)
            .map(|x| x[1..].to_vec())
            .collect::<Vec<_>>()
            .concat(),
    );

    buf
}

pub fn kzg_commitment_to_versioned_hash(data: &Commitment) -> H256 {
    use sha2::{Digest, Sha256};
    let mut versioned_hash: [u8; 32] = Sha256::digest(data).into();
    versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
    versioned_hash.into()
}

impl BlobsBundle {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty() && self.commitments.is_empty() && self.proofs.is_empty()
    }

    /// Builder path: blob cell-proofs are independent and dominate engine_getPayload latency
    /// under EIP-8142 where the EL node must compute proofs for payload blobs, so parallelize.
    #[cfg(all(feature = "c-kzg", feature = "rayon", not(feature = "eip-8025")))]
    pub fn create_from_blobs(
        blobs: &Vec<Blob>,
        wrapper_version: Option<u8>,
    ) -> Result<Self, BlobsBundleError> {
        use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
        let version = wrapper_version.unwrap_or(0);
        let per_blob = blobs
            .par_iter()
            .map(|blob| Self::blob_commitment_and_proofs(blob, version))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::blobs_to_bundle(blobs, version, per_blob))
    }

    /// Guest/zkVM (`eip-8025`) or no `rayon`: deterministic serial form.
    #[cfg(all(feature = "c-kzg", any(feature = "eip-8025", not(feature = "rayon"))))]
    pub fn create_from_blobs(
        blobs: &Vec<Blob>,
        wrapper_version: Option<u8>,
    ) -> Result<Self, BlobsBundleError> {
        let version = wrapper_version.unwrap_or(0);
        let per_blob = blobs
            .iter()
            .map(|blob| Self::blob_commitment_and_proofs(blob, version))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::blobs_to_bundle(blobs, version, per_blob))
    }

    #[cfg(feature = "c-kzg")]
    fn blob_commitment_and_proofs(
        blob: &Blob,
        version: u8,
    ) -> Result<(Commitment, Vec<Proof>), BlobsBundleError> {
        use ethrex_crypto::kzg::{
            blob_to_commitment_and_cell_proofs, blob_to_kzg_commitment_and_proof,
        };
        if version == 0 {
            let (commitment, proof) = blob_to_kzg_commitment_and_proof(blob)?;
            Ok((commitment, vec![proof]))
        } else {
            let (commitment, cell_proofs) = blob_to_commitment_and_cell_proofs(blob)?;
            Ok((commitment, cell_proofs))
        }
    }

    /// Assemble a bundle, flattening per-blob proofs in blob order so commitments
    /// stay 1:1 with blobs and proofs remain aligned for downstream slicing.
    #[cfg(feature = "c-kzg")]
    fn blobs_to_bundle(
        blobs: &[Blob],
        version: u8,
        per_blob: Vec<(Commitment, Vec<Proof>)>,
    ) -> Self {
        let mut commitments = Vec::with_capacity(per_blob.len());
        let mut proofs = Vec::new();
        for (commitment, blob_proofs) in per_blob {
            commitments.push(commitment);
            proofs.extend(blob_proofs);
        }
        Self {
            blobs: blobs.to_vec(),
            commitments,
            proofs,
            payload_kzg_proofs: Vec::new(),
            version,
        }
    }

    pub fn generate_versioned_hashes(&self) -> Vec<H256> {
        self.commitments
            .iter()
            .map(kzg_commitment_to_versioned_hash)
            .collect()
    }

    /// EIP-8142 "block-in-blobs": compute random-point KZG opening proofs for payload blobs.
    /// These are included in the zkVM prover witness.
    #[cfg(feature = "c-kzg")]
    pub fn compute_payload_kzg_proofs(
        &self,
        payload_blob_count: usize,
    ) -> Result<Vec<Proof>, BlobsBundleError> {
        use ethrex_crypto::kzg::compute_blob_kzg_proof;

        if self.blobs.len() < payload_blob_count || self.commitments.len() < payload_blob_count {
            return Err(BlobsBundleError::BlobsBundleWrongLen);
        }

        let blobs = &self.blobs[..payload_blob_count];
        let commitments = &self.commitments[..payload_blob_count];

        let compute = |(blob, commitment): (&Blob, &Commitment)| {
            compute_blob_kzg_proof(blob, commitment).map_err(BlobsBundleError::from)
        };

        #[cfg(all(feature = "rayon", not(feature = "eip-8025")))]
        {
            use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
            blobs.par_iter().zip(commitments).map(compute).collect()
        }
        #[cfg(any(feature = "eip-8025", not(feature = "rayon")))]
        {
            blobs.iter().zip(commitments).map(compute).collect()
        }
    }

    /// EIP-8142 "block-in-blobs": Combine payload blobs with user (type-3) blobs into a single blob bundle.
    pub fn from_sections(
        payload: PayloadBlobsBundle,
        user: BlobsBundle,
    ) -> Result<Self, BlobsBundleError> {
        if !user.payload_kzg_proofs.is_empty() {
            return Err(BlobsBundleError::UserBundleHasPayloadProofs);
        }
        // ignore version mismatch, just like +=
        let mut bundle = payload.0;
        bundle += user;
        Ok(bundle)
    }

    /// Given an index returns all or nothing `BlobTuple` if either of the commitment, proof or
    /// blob is not found then it will return None instead of Partial data.
    pub fn get_blob_tuple_by_index(&self, index: usize) -> Option<BlobTuple> {
        let blob = Box::new(*self.blobs.get(index)?);
        let commitment = *self.commitments.get(index)?;
        let proofs = if self.version == 0 {
            vec![*self.proofs.get(index)?]
        } else {
            self.proofs.chunks(CELLS_PER_EXT_BLOB).nth(index)?.to_vec()
        };
        Some((blob, commitment, proofs))
    }

    /// Full blob bundle validation: structural checks + KZG cryptographic proof verification.
    #[cfg(feature = "c-kzg")]
    pub fn validate(
        &self,
        tx: &super::EIP4844Transaction,
        fork: super::Fork,
    ) -> Result<(), BlobsBundleError> {
        self.validate_cheap(tx, fork)?;
        self.verify_kzg_proofs()
    }

    /// Verifies KZG cryptographic proofs against the blobs and commitments.
    /// Dispatches to cell-proof or standard verification based on bundle version.
    #[cfg(feature = "c-kzg")]
    fn verify_kzg_proofs(&self) -> Result<(), BlobsBundleError> {
        let valid = if self.version != 0 {
            ethrex_crypto::kzg::verify_cell_kzg_proof_batch(
                &self.blobs,
                &self.commitments,
                &self.proofs,
            )?
        } else {
            ethrex_crypto::kzg::verify_kzg_proof_batch(
                &self.blobs,
                &self.commitments,
                &self.proofs,
            )?
        };
        if !valid {
            return Err(BlobsBundleError::BlobToCommitmentAndProofError);
        }
        Ok(())
    }

    /// Validates blob bundle structure without expensive KZG cryptographic verification.
    /// Used in P2P validation where full KZG is deferred to mempool insertion
    /// (after dedup check), avoiding redundant proof verification for the same
    /// blob tx received from multiple peers.
    #[cfg(feature = "c-kzg")]
    pub fn validate_cheap(
        &self,
        tx: &super::EIP4844Transaction,
        fork: super::Fork,
    ) -> Result<(), BlobsBundleError> {
        use super::CELLS_PER_EXT_BLOB;

        let max_blobs = max_blobs_per_block(fork);
        let blob_count = self.blobs.len();

        if blob_count > max_blobs {
            return Err(BlobsBundleError::MaxBlobsExceeded);
        }

        // EIP-7594: a single transaction may carry at most MAX_BLOB_COUNT (6) blobs,
        // independent of the higher per-block limit.
        if fork >= Fork::Osaka && blob_count > MAX_BLOB_COUNT {
            return Err(BlobsBundleError::MaxBlobsExceeded);
        }

        if blob_count == 0 {
            return Err(BlobsBundleError::BlobBundleEmptyError);
        }

        // The wrapper version is fork-specific: 0 (blob proofs) before Osaka, 1 (cell
        // proofs, EIP-7594) on Osaka+. Any other value is invalid.
        let expected_version = if fork >= Fork::Osaka { 1 } else { 0 };
        if self.version != expected_version {
            return Err(BlobsBundleError::InvalidBlobVersionForFork);
        }

        if blob_count != self.commitments.len()
            || (self.version == 0 && blob_count != self.proofs.len())
            || (self.version != 0 && blob_count * CELLS_PER_EXT_BLOB != self.proofs.len())
            || blob_count != tx.blob_versioned_hashes.len()
        {
            return Err(BlobsBundleError::BlobsBundleWrongLen);
        };

        self.validate_blob_commitment_hashes(&tx.blob_versioned_hashes)?;

        Ok(())
    }

    pub fn validate_blob_commitment_hashes(
        &self,
        blob_versioned_hashes: &[H256],
    ) -> Result<(), BlobsBundleError> {
        if self.commitments.len() != blob_versioned_hashes.len() {
            return Err(BlobsBundleError::BlobVersionedHashesError);
        }
        for (commitment, blob_versioned_hash) in
            self.commitments.iter().zip(blob_versioned_hashes.iter())
        {
            if *blob_versioned_hash != kzg_commitment_to_versioned_hash(commitment) {
                return Err(BlobsBundleError::BlobVersionedHashesError);
            }
        }
        Ok(())
    }
}

impl RLPEncode for BlobsBundle {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        let encoder = Encoder::new(buf);
        encoder
            .encode_field(&self.blobs)
            .encode_field(&self.commitments)
            .encode_field(&self.proofs)
            .encode_optional_field(&(self.version != 0).then_some(self.version))
            .finish();
    }
}

impl RLPDecode for BlobsBundle {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (blobs, decoder) = decoder.decode_field("blobs")?;
        let (commitments, decoder) = decoder.decode_field("commitments")?;
        let (proofs, decoder) = decoder.decode_field("proofs")?;
        let (version, decoder) = decoder.decode_optional_field();
        Ok((
            Self {
                blobs,
                commitments,
                proofs,
                // `payload_kzg_proofs` are used in the engine/prover path only,
                // excluded from normal Engine API responses
                payload_kzg_proofs: Vec::new(),
                version: version.unwrap_or_default(),
            },
            decoder.finish()?,
        ))
    }
}

/// EIP-8142 "block-in-blobs": a bundle holding only payload blobs. This type
/// enforces the ordering guarantee that payload blobs come before user blobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadBlobsBundle(BlobsBundle);

impl PayloadBlobsBundle {
    #[cfg(feature = "c-kzg")]
    pub fn create_from_blobs(
        blobs: &Vec<Blob>,
        wrapper_version: Option<u8>,
    ) -> Result<Self, BlobsBundleError> {
        BlobsBundle::create_from_blobs(blobs, wrapper_version).map(Self)
    }
}

impl AddAssign for BlobsBundle {
    fn add_assign(&mut self, rhs: Self) {
        self.blobs.extend_from_slice(&rhs.blobs);
        self.commitments.extend_from_slice(&rhs.commitments);
        self.proofs.extend_from_slice(&rhs.proofs);
    }
}

#[cfg(feature = "c-kzg")]
const MAX_BLOB_COUNT: usize = 6;
#[cfg(feature = "c-kzg")]
const MAX_BLOB_COUNT_ELECTRA: usize = 9;

#[cfg(feature = "c-kzg")]
fn max_blobs_per_block(fork: crate::types::Fork) -> usize {
    if fork >= crate::types::Fork::Prague {
        MAX_BLOB_COUNT_ELECTRA
    } else {
        MAX_BLOB_COUNT
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlobsBundleError {
    #[error("Blob data has an invalid length")]
    BlobDataInvalidBytesLength,
    #[error("Blob bundle is empty")]
    BlobBundleEmptyError,
    #[error("Blob versioned hashes and blobs bundle content length mismatch")]
    BlobsBundleWrongLen,
    #[error("Blob versioned hashes are incorrect")]
    BlobVersionedHashesError,
    #[error("Blob to commitment and proof generation error")]
    BlobToCommitmentAndProofError,
    #[error("Max blobs per block exceeded")]
    MaxBlobsExceeded,
    #[error("Invalid blob version for the current fork")]
    InvalidBlobVersionForFork,
    #[error("user blob bundle unexpectedly carries payload KZG proofs")]
    UserBundleHasPayloadProofs,
    #[cfg(feature = "c-kzg")]
    #[error("KZG related error: {0}")]
    Kzg(#[from] ethrex_crypto::kzg::KzgError),
}

#[cfg(test)]
mod tests {
    mod shared {
        #[cfg(feature = "c-kzg")]
        pub fn convert_str_to_bytes48(s: &str) -> [u8; 48] {
            let bytes = hex::decode(s).expect("Invalid hex string");
            let mut array = [0u8; 48];
            array.copy_from_slice(&bytes[..48]);
            array
        }
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_valid_blobs_should_pass() {
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, None)
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Ok(())
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_valid_blobs_should_pass_on_osaka() {
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, Some(1))
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Osaka),
            Ok(())
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_invalid_fork_should_fail() {
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, Some(1))
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(!matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Ok(())
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_invalid_proofs_should_fail() {
        // blob data taken from: https://etherscan.io/tx/0x02a623925c05c540a7633ffa4eb78474df826497faa81035c4168695656801a2#blobs, but with 0 size blobs
        let blobs_bundle = crate::types::BlobsBundle {
            blobs: vec![[0; crate::types::BYTES_PER_BLOB], [0; crate::types::BYTES_PER_BLOB]],
            commitments: vec!["b90289aabe0fcfb8db20a76b863ba90912d1d4d040cb7a156427d1c8cd5825b4d95eaeb221124782cc216960a3d01ec5",
                              "91189a03ce1fe1225fc5de41d502c3911c2b19596f9011ea5fca4bf311424e5f853c9c46fe026038036c766197af96a0"]
                              .into_iter()
                              .map(|s| {
                                  shared::convert_str_to_bytes48(s)
                              })
                              .collect(),
            proofs: vec!["b502263fc5e75b3587f4fb418e61c5d0f0c18980b4e00179326a65d082539a50c063507a0b028e2db10c55814acbe4e9",
                         "a29c43f6d05b7f15ab6f3e5004bd5f6b190165dc17e3d51fd06179b1e42c7aef50c145750d7c1cd1cd28357593bc7658"]
                            .into_iter()
                            .map(|s| {
                                shared::convert_str_to_bytes48(s)
                            })
                            .collect(),
            payload_kzg_proofs: Vec::new(),
            version: 0,
        };

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes: vec![
                "01ec8054d05bfec80f49231c6e90528bbb826ccd1464c255f38004099c8918d9",
                "0180cb2dee9e6e016fabb5da4fb208555f5145c32895ccd13b26266d558cd77d",
            ]
            .into_iter()
            .map(|b| {
                let bytes = hex::decode(b).expect("Invalid hex string");
                crate::H256::from_slice(&bytes)
            })
            .collect::<Vec<crate::H256>>(),
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Err(crate::types::BlobsBundleError::BlobToCommitmentAndProofError)
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_incorrect_blobs_should_fail() {
        // blob data taken from: https://etherscan.io/tx/0x02a623925c05c540a7633ffa4eb78474df826497faa81035c4168695656801a2#blobs
        let blobs_bundle = crate::types::BlobsBundle {
            blobs: vec![[0; crate::types::BYTES_PER_BLOB], [0; crate::types::BYTES_PER_BLOB]],
            commitments: vec!["dead89aabe0fcfb8db20a76b863ba90912d1d4d040cb7a156427d1c8cd5825b4d95eaeb221124782cc216960a3d01ec5",
                              "91189a03ce1fe1225fc5de41d502c3911c2b19596f9011ea5fca4bf311424e5f853c9c46fe026038036c766197af96a0"]
                              .into_iter()
                              .map(|s| {
                                shared::convert_str_to_bytes48(s)
                              })
                              .collect(),
            proofs: vec!["b502263fc5e75b3587f4fb418e61c5d0f0c18980b4e00179326a65d082539a50c063507a0b028e2db10c55814acbe4e9",
                         "a29c43f6d05b7f15ab6f3e5004bd5f6b190165dc17e3d51fd06179b1e42c7aef50c145750d7c1cd1cd28357593bc7658"]
                         .into_iter()
                              .map(|s| {
                                shared::convert_str_to_bytes48(s)
                              })
                              .collect(),
            payload_kzg_proofs: Vec::new(),
            version: 0,
        };

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes: vec![
                "01ec8054d05bfec80f49231c6e90528bbb826ccd1464c255f38004099c8918d9",
                "0180cb2dee9e6e016fabb5da4fb208555f5145c32895ccd13b26266d558cd77d",
            ]
            .into_iter()
            .map(|b| {
                let bytes = hex::decode(b).expect("Invalid hex string");
                crate::H256::from_slice(&bytes)
            })
            .collect::<Vec<crate::H256>>(),
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Err(crate::types::BlobsBundleError::BlobVersionedHashesError)
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_too_many_blobs_should_fail() {
        let blob = crate::types::blobs_bundle::blob_from_bytes("Im a Blob".as_bytes().into())
            .expect("Failed to create blob");
        let blobs =
            std::iter::repeat_n(blob, super::MAX_BLOB_COUNT_ELECTRA + 1).collect::<Vec<_>>();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, None)
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Err(crate::types::BlobsBundleError::MaxBlobsExceeded)
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_version_0_blobs_should_fail_on_amsterdam() {
        // Version 0 blobs should be invalid on Amsterdam fork (which comes after Osaka)
        // The validation requires version 0 only on Osaka; Amsterdam >= Osaka so version 0 is rejected
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, None)
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Amsterdam),
            Err(crate::types::BlobsBundleError::InvalidBlobVersionForFork)
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn compute_payload_kzg_proofs_produces_verifiable_proofs() {
        use ethrex_crypto::{Crypto, NativeCrypto};

        // Three blobs; the first two stand in for payload blobs, the third for a
        // type-3 transaction blob.
        let blobs = vec![
            "payload blob a".as_bytes(),
            "payload blob b".as_bytes(),
            "type-3 blob".as_bytes(),
        ]
        .into_iter()
        .map(|data| {
            crate::types::blobs_bundle::blob_from_bytes(data.into()).expect("Failed to create blob")
        })
        .collect();
        let bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, Some(1))
            .expect("Failed to create blobs bundle");

        let payload_blob_count = 2;
        let proofs = bundle
            .compute_payload_kzg_proofs(payload_blob_count)
            .expect("Failed to compute payload kzg proofs");

        // One proof per payload blob — only the leading `payload_blob_count` blobs.
        assert_eq!(proofs.len(), payload_blob_count);
        // These proofs are exactly what the zkVM `new_payload` checks in one batch
        // call (spec step 6), so verify them through the same entry point.
        assert!(
            NativeCrypto
                .verify_blob_kzg_proof_batch(
                    &bundle.blobs[..payload_blob_count],
                    &bundle.commitments[..payload_blob_count],
                    &proofs,
                )
                .expect("verification errored")
        );

        // Proof-to-blob alignment matters: the same proofs in the wrong order
        // must not verify.
        let swapped: Vec<_> = proofs.iter().rev().copied().collect();
        assert!(
            !NativeCrypto
                .verify_blob_kzg_proof_batch(
                    &bundle.blobs[..payload_blob_count],
                    &bundle.commitments[..payload_blob_count],
                    &swapped,
                )
                .expect("verification errored")
        );

        // A count past the available blobs is rejected.
        assert!(matches!(
            bundle.compute_payload_kzg_proofs(bundle.blobs.len() + 1),
            Err(crate::types::BlobsBundleError::BlobsBundleWrongLen)
        ));
    }

    #[test]
    fn payload_blobs_bundle_orders_payload_first_and_keeps_section_metadata() {
        use crate::types::{BYTES_PER_BLOB, BlobsBundle, BlobsBundleError};

        // The tuple constructor is private to this module: sections are only
        // built through `create_from_blobs` in production.
        let payload_section = super::PayloadBlobsBundle(BlobsBundle {
            blobs: vec![[1u8; BYTES_PER_BLOB], [2u8; BYTES_PER_BLOB]],
            commitments: vec![[1u8; 48], [2u8; 48]],
            proofs: vec![[1u8; 48], [2u8; 48]],
            payload_kzg_proofs: vec![[0xAAu8; 48], [0xBBu8; 48]],
            version: 1,
        });
        let user = BlobsBundle {
            blobs: vec![[3u8; BYTES_PER_BLOB]],
            commitments: vec![[3u8; 48]],
            proofs: vec![[3u8; 48]],
            payload_kzg_proofs: Vec::new(),
            // Accumulated bundles carry a stale `version` label (`+=` keeps the
            // lhs's, starting from `default()`); `from_sections` ignores it, so
            // the realistic stale `0` composes fine with a version-1 section.
            version: 0,
        };

        let combined = BlobsBundle::from_sections(payload_section.clone(), user.clone())
            .expect("composition should succeed");
        // Payload blobs strictly first, then the user blobs.
        assert_eq!(combined.blobs[0][0], 1);
        assert_eq!(combined.blobs[2][0], 3);
        assert_eq!(combined.commitments, vec![[1u8; 48], [2u8; 48], [3u8; 48]]);
        // The payload section's version and (prefix-aligned) payload proofs stay.
        assert_eq!(combined.version, 1);
        assert_eq!(combined.payload_kzg_proofs.len(), 2);

        // A user bundle carrying payload proofs would be misaligned: rejected.
        let mut bad_user = user;
        bad_user.payload_kzg_proofs = vec![[0xCCu8; 48]];
        assert!(matches!(
            BlobsBundle::from_sections(payload_section, bad_user),
            Err(BlobsBundleError::UserBundleHasPayloadProofs)
        ));
    }
}

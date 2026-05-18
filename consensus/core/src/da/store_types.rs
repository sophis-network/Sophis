//! Types persisted by the Phase 6 DA store. Lives in `consensus-core` so
//! both the consensus crate (which owns the RocksDB stores) and the host
//! RPC crate (which serves them) can depend on a single source of truth.
//!
//! Serialization: bincode via serde, matching the rest of the consensus
//! database. The 48-byte SHA3-384 identifier is wrapped in `PayloadIdHash`
//! because raw `[u8; 48]` does not implement `serde::Serialize`/`Deserialize`
//! out-of-the-box.

use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;
use sophis_utils::mem_size::MemSizeEstimator;

use super::CARRIER_PAYLOAD_HASH_LEN;

/// 48-byte SHA3-384 identifier (`payload_id` or `bundle_id`) wrapped in a
/// newtype so it can implement `serde::{Serialize, Deserialize}` (raw
/// `[u8; 48]` does not — serde stops deriving past `[u8; 32]`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct PayloadIdHash(pub [u8; CARRIER_PAYLOAD_HASH_LEN]);

impl PayloadIdHash {
    pub const ZERO: Self = Self([0u8; CARRIER_PAYLOAD_HASH_LEN]);

    pub const fn new(bytes: [u8; CARRIER_PAYLOAD_HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_array(&self) -> &[u8; CARRIER_PAYLOAD_HASH_LEN] {
        &self.0
    }

    pub const fn into_array(self) -> [u8; CARRIER_PAYLOAD_HASH_LEN] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for PayloadIdHash {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; CARRIER_PAYLOAD_HASH_LEN]> for PayloadIdHash {
    fn from(value: [u8; CARRIER_PAYLOAD_HASH_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for PayloadIdHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PayloadIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print as hex (first 8 bytes + ".." + last 4) for readability
        write!(
            f,
            "PayloadIdHash({:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}{:02x})",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7],
            self.0[44],
            self.0[45],
            self.0[46],
            self.0[47]
        )
    }
}

impl fmt::Display for PayloadIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for PayloadIdHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(CARRIER_PAYLOAD_HASH_LEN)?;
        for byte in &self.0 {
            t.serialize_element(byte)?;
        }
        t.end()
    }
}

impl<'de> Deserialize<'de> for PayloadIdHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = PayloadIdHash;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("48-byte SHA3-384 hash as tuple")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; CARRIER_PAYLOAD_HASH_LEN];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(PayloadIdHash(arr))
            }
        }
        d.deserialize_tuple(CARRIER_PAYLOAD_HASH_LEN, V)
    }
}

/// Type alias kept for codec callers that want raw bytes. Newtype wrapper
/// `PayloadIdHash` is the storage form; `PayloadId` is the codec form.
pub type PayloadId = [u8; CARRIER_PAYLOAD_HASH_LEN];

/// Persistent record for one V5 carrier output. Keyed by `payload_id` in
/// the `DaCarrierPayloads` column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadEntry {
    /// Raw bytes of `script_public_key.script()` — the framed carrier.
    pub script: Vec<u8>,
    /// Hash of the chain block whose virtual-state commit indexed this fragment.
    pub accepting_block_hash: Hash,
    /// Blue score of the accepting block (for `min_confirmations` math).
    pub blue_score: u64,
    /// `fragment_index` field copied from the header for fast lookups.
    pub fragment_index: u8,
    /// `fragment_count` field copied from the header.
    pub fragment_count: u8,
    /// `bundle_id` copied from the header — links this fragment to the bundle.
    pub bundle_id: PayloadIdHash,
    /// Single domain byte (`CARRIER_FLAG_DOMAIN_*` set, or 0 for unclassified).
    pub domain_byte: u8,
}

impl MemSizeEstimator for PayloadEntry {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.script.len()
    }
}

/// F-26 Fix B — metadata half of a `PayloadEntry`, persisted in
/// `DaCarrierPayloads` (196). Kept to `pruning_depth`. The `script`/body
/// is split out to `PayloadBody`/`DaCarrierBodies` (209) so it can be
/// dropped on a much shorter retention horizon. Consensus reads only
/// these metadata fields (H1), never the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadMeta {
    pub accepting_block_hash: Hash,
    pub blue_score: u64,
    pub fragment_index: u8,
    pub fragment_count: u8,
    pub bundle_id: PayloadIdHash,
    pub domain_byte: u8,
}

impl MemSizeEstimator for PayloadMeta {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

/// F-26 Fix B — body half of a `PayloadEntry`, persisted in
/// `DaCarrierBodies` (209). Droppable on a short retention horizon
/// independently of the metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadBody(pub Vec<u8>);

impl MemSizeEstimator for PayloadBody {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.0.len()
    }
}

/// F-26 Fix B (M3.2) — single-value watermark: the selected-chain index up
/// to which carrier bodies have already been dropped by the short body
/// retention horizon. Stored under `DaBodyGcWatermark` (one fixed key).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BodyGcWatermark(pub u64);

impl MemSizeEstimator for BodyGcWatermark {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

impl PayloadEntry {
    /// Split into the two persisted halves (F-26 Fix B).
    pub fn into_meta_and_body(self) -> (PayloadMeta, PayloadBody) {
        (
            PayloadMeta {
                accepting_block_hash: self.accepting_block_hash,
                blue_score: self.blue_score,
                fragment_index: self.fragment_index,
                fragment_count: self.fragment_count,
                bundle_id: self.bundle_id,
                domain_byte: self.domain_byte,
            },
            PayloadBody(self.script),
        )
    }

    /// Reassemble from the metadata store + the (possibly already-pruned)
    /// body. `body` is empty when the short body horizon dropped it while
    /// the metadata is still retained — consensus never reads it (H1).
    pub fn reassemble(meta: PayloadMeta, body: Vec<u8>) -> Self {
        Self {
            script: body,
            accepting_block_hash: meta.accepting_block_hash,
            blue_score: meta.blue_score,
            fragment_index: meta.fragment_index,
            fragment_count: meta.fragment_count,
            bundle_id: meta.bundle_id,
            domain_byte: meta.domain_byte,
        }
    }
}

/// All `payload_id`s that share a `bundle_id`, sorted by `fragment_index`
/// ascending. Stored in `DaCarrierBundles` keyed by `bundle_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleIndex {
    /// Total fragments expected — copied from any one fragment's header.
    /// Reassembly is "complete" iff `payload_ids.len() == fragment_count`.
    pub fragment_count: u8,
    /// Sorted by fragment_index. May be partial during ingestion (a later
    /// fragment may extend the vector).
    pub payload_ids: Vec<PayloadIdHash>,
}

impl MemSizeEstimator for BundleIndex {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.payload_ids.len() * size_of::<PayloadIdHash>()
    }
}

/// `payload_id`s accepted by a single block. Stored in `DaCarrierByBlock`
/// keyed by block hash. Insertion order; consumers don't need to sort.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockCarriers {
    pub payload_ids: Vec<PayloadIdHash>,
}

impl MemSizeEstimator for BlockCarriers {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.payload_ids.len() * size_of::<PayloadIdHash>()
    }
}

/// `payload_id`s in a (domain_byte, blue_score_bucket) cell. Stored in
/// `DaCarrierByDomain`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainBucket {
    pub payload_ids: Vec<PayloadIdHash>,
}

impl MemSizeEstimator for DomainBucket {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.payload_ids.len() * size_of::<PayloadIdHash>()
    }
}

/// Bucket size in blue-score units for the `by_domain` index. ~100s at 10 BPS.
pub const DOMAIN_BUCKET_SIZE: u64 = 1000;

/// Computes the 9-byte composite key for `DaCarrierByDomain`:
/// `[domain_byte, bucket_le_8_bytes]` where `bucket = blue_score / DOMAIN_BUCKET_SIZE`.
pub fn domain_bucket_key_bytes(domain_byte: u8, blue_score: u64) -> [u8; 9] {
    let bucket = blue_score / DOMAIN_BUCKET_SIZE;
    let mut out = [0u8; 9];
    out[0] = domain_byte;
    out[1..].copy_from_slice(&bucket.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_id_hash_roundtrip_bincode() {
        let original = PayloadIdHash([0xAB; 48]);
        let bytes = bincode::serialize(&original).unwrap();
        let decoded: PayloadIdHash = bincode::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn payload_id_hash_roundtrip_borsh() {
        let original = PayloadIdHash([0xCD; 48]);
        let bytes = borsh::to_vec(&original).unwrap();
        let decoded: PayloadIdHash = borsh::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn payload_id_hash_default_is_zero() {
        let h: PayloadIdHash = Default::default();
        assert_eq!(h.0, [0u8; 48]);
        assert_eq!(h, PayloadIdHash::ZERO);
    }

    #[test]
    fn payload_id_hash_debug_is_truncated() {
        let h = PayloadIdHash([0xAB; 48]);
        let s = format!("{h:?}");
        assert!(s.starts_with("PayloadIdHash(abababab"));
        assert!(s.contains(".."));
    }

    #[test]
    fn domain_bucket_key_layout() {
        let k = domain_bucket_key_bytes(0x10, 0);
        assert_eq!(k, [0x10, 0, 0, 0, 0, 0, 0, 0, 0]);

        let k = domain_bucket_key_bytes(0x20, 999);
        assert_eq!(k, [0x20, 0, 0, 0, 0, 0, 0, 0, 0]);

        let k = domain_bucket_key_bytes(0x20, 1000);
        // bucket = 1
        assert_eq!(k[0], 0x20);
        assert_eq!(u64::from_le_bytes(k[1..].try_into().unwrap()), 1);

        let k = domain_bucket_key_bytes(0x40, 12_345);
        // bucket = 12
        assert_eq!(k[0], 0x40);
        assert_eq!(u64::from_le_bytes(k[1..].try_into().unwrap()), 12);
    }

    #[test]
    fn payload_entry_roundtrip_bincode() {
        let entry = PayloadEntry {
            script: vec![1, 2, 3, 4],
            accepting_block_hash: Hash::from_slice(&[7u8; 32]),
            blue_score: 42,
            fragment_index: 0,
            fragment_count: 1,
            bundle_id: PayloadIdHash([9u8; 48]),
            domain_byte: 0x10,
        };
        let encoded = bincode::serialize(&entry).unwrap();
        let decoded: PayloadEntry = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.script, entry.script);
        assert_eq!(decoded.accepting_block_hash, entry.accepting_block_hash);
        assert_eq!(decoded.blue_score, entry.blue_score);
        assert_eq!(decoded.bundle_id, entry.bundle_id);
        assert_eq!(decoded.domain_byte, entry.domain_byte);
    }

    #[test]
    fn bundle_index_roundtrip_bincode() {
        let bi = BundleIndex {
            fragment_count: 3,
            payload_ids: vec![PayloadIdHash([1u8; 48]), PayloadIdHash([2u8; 48]), PayloadIdHash([3u8; 48])],
        };
        let encoded = bincode::serialize(&bi).unwrap();
        let decoded: BundleIndex = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.fragment_count, 3);
        assert_eq!(decoded.payload_ids.len(), 3);
        assert_eq!(decoded.payload_ids, bi.payload_ids);
    }
}

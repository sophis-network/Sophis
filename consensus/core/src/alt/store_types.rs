//! Types persisted by the L1 ALT store. Lives in `consensus-core` so both
//! the consensus crate (which owns the RocksDB stores) and the host RPC
//! crate (which serves them) can depend on a single source of truth.
//!
//! Serialization: borsh + serde, matching the rest of the consensus
//! database. The 6-byte handle is wrapped in `AltHandleHash` for type
//! safety; the underlying `[u8; 6]` does serialize natively (serde drops
//! its blanket impl past `[u8; 32]`, but `[u8; 6]` is well below that
//! cutoff so no custom adapter is needed).

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;
use sophis_utils::mem_size::MemSizeEstimator;

use super::ALT_HANDLE_LEN;

// ---------------------------------------------------------------------------
// AltHandleHash — 6-byte handle newtype
// ---------------------------------------------------------------------------

/// Type-safe wrapper around the 6-byte ALT handle. Two handles compare equal
/// if and only if their underlying bytes are byte-wise identical.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AltHandleHash(pub [u8; ALT_HANDLE_LEN]);

impl AltHandleHash {
    pub const ZERO: Self = Self([0u8; ALT_HANDLE_LEN]);

    pub const fn new(bytes: [u8; ALT_HANDLE_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_array(&self) -> &[u8; ALT_HANDLE_LEN] {
        &self.0
    }

    pub const fn into_array(self) -> [u8; ALT_HANDLE_LEN] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for AltHandleHash {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; ALT_HANDLE_LEN]> for AltHandleHash {
    fn from(value: [u8; ALT_HANDLE_LEN]) -> Self {
        Self(value)
    }
}

impl From<AltHandleHash> for [u8; ALT_HANDLE_LEN] {
    fn from(value: AltHandleHash) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for AltHandleHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for AltHandleHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AltHandleHash(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Display for AltHandleHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl MemSizeEstimator for AltHandleHash {}

// ---------------------------------------------------------------------------
// AltEntryRecord — one entry inside an AltEntry record (separated from the
// wire-side `AltEntryView` to allow owned bytes for store persistence).
// ---------------------------------------------------------------------------

/// Owned form of an entry in an `AltEntry`. Mirrors the wire format
/// produced by `iter_alt_entries`.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AltEntryRecord {
    pub spk_version: u16,
    pub spk_script: Vec<u8>,
}

impl MemSizeEstimator for AltEntryRecord {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.spk_script.capacity()
    }
}

// ---------------------------------------------------------------------------
// AltEntry — full record stored under prefix 200
// ---------------------------------------------------------------------------

/// Canonical persisted form of an ALT. Contains everything a validator or
/// RPC caller needs: the handle that identifies it, every entry's
/// `(spk_version, spk_script)` pair, and the `(block, DAA score)` pair of
/// the block that first accepted it.
///
/// The `entries` vector is bounded by `MAX_ALT_ENTRIES = 256` and each
/// `spk_script` by `MAX_ALT_ENTRY_SCRIPT_BYTES = 4096`. The validator that
/// constructs this record (L1.3) MUST have called `parse_alt_creation_header`
/// successfully on the originating output script first; therefore every
/// `AltEntry` in the store is well-formed by construction.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AltEntry {
    pub handle: AltHandleHash,
    pub entries: Vec<AltEntryRecord>,
    pub creating_block_hash: Hash,
    pub creating_daa_score: u64,
}

impl AltEntry {
    /// Total bytes consumed by the `entries` field on the wire, useful for
    /// callers that want to compute storage cost without re-serializing.
    pub fn payload_len(&self) -> usize {
        self.entries.iter().map(|e| 4 + e.spk_script.len()).sum()
    }

    /// Number of entries; convenience to avoid a `.len()` call on a
    /// `Vec<AltEntryRecord>` field.
    pub fn entry_count(&self) -> u16 {
        self.entries.len() as u16
    }
}

impl MemSizeEstimator for AltEntry {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.entries.iter().map(|e| e.estimate_mem_bytes()).sum::<usize>()
    }
}

// ---------------------------------------------------------------------------
// AltBlockHandles — per-block index stored under prefix 201
// ---------------------------------------------------------------------------

/// Handles of every ALT created inside a single block, in tx-index order.
/// Used by pruning logic and by `listAltsCreatedInBlock` RPC.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AltBlockHandles {
    pub handles: Vec<AltHandleHash>,
}

impl MemSizeEstimator for AltBlockHandles {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.handles.len() * size_of::<AltHandleHash>()
    }
}

// ---------------------------------------------------------------------------
// AltResolution — lightweight metadata stored under prefix 202
// ---------------------------------------------------------------------------

/// Lightweight (block, DAA-score) pair that lets a caller answer "where /
/// when was this ALT created?" without paying to load the full entries
/// payload (which can reach ~1 MB for a saturated 256-entry × 4096-byte
/// ALT).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AltResolution {
    pub creating_block_hash: Hash,
    pub creating_daa_score: u64,
}

impl MemSizeEstimator for AltResolution {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_handle_hash_round_trips_borsh() {
        let h = AltHandleHash([1, 2, 3, 4, 5, 6]);
        let bytes = borsh::to_vec(&h).unwrap();
        let decoded: AltHandleHash = borsh::from_slice(&bytes).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn alt_handle_hash_display_is_lowercase_hex() {
        let h = AltHandleHash([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        assert_eq!(format!("{h}"), "deadbeefcafe");
    }

    #[test]
    fn alt_entry_round_trips_borsh() {
        let record = AltEntry {
            handle: AltHandleHash([7u8; ALT_HANDLE_LEN]),
            entries: vec![
                AltEntryRecord { spk_version: 0, spk_script: vec![0xAA, 0xBB, 0xCC] },
                AltEntryRecord { spk_version: 1, spk_script: vec![1, 2, 3, 4, 5] },
            ],
            creating_block_hash: Hash::from_slice(&[9u8; 32]),
            creating_daa_score: 42_000,
        };
        let bytes = borsh::to_vec(&record).unwrap();
        let decoded: AltEntry = borsh::from_slice(&bytes).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn alt_entry_payload_len_matches_wire_format_sum() {
        let record = AltEntry {
            handle: AltHandleHash::ZERO,
            entries: vec![
                AltEntryRecord { spk_version: 0, spk_script: vec![0u8; 36] },
                AltEntryRecord { spk_version: 1, spk_script: vec![0u8; 100] },
            ],
            creating_block_hash: Hash::default(),
            creating_daa_score: 0,
        };
        // 2 entries × 4-byte prefix + 36 + 100 = 144 bytes
        assert_eq!(record.payload_len(), 144);
        assert_eq!(record.entry_count(), 2);
    }

    #[test]
    fn alt_block_handles_round_trips_borsh() {
        let v = AltBlockHandles { handles: vec![AltHandleHash([1u8; 6]), AltHandleHash([2u8; 6]), AltHandleHash([3u8; 6])] };
        let bytes = borsh::to_vec(&v).unwrap();
        let decoded: AltBlockHandles = borsh::from_slice(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn alt_resolution_round_trips_borsh() {
        let r = AltResolution { creating_block_hash: Hash::from_slice(&[5u8; 32]), creating_daa_score: 12345 };
        let bytes = borsh::to_vec(&r).unwrap();
        let decoded: AltResolution = borsh::from_slice(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn mem_size_estimator_includes_payload() {
        let record = AltEntry {
            handle: AltHandleHash::ZERO,
            entries: vec![AltEntryRecord { spk_version: 0, spk_script: vec![0u8; 1024] }],
            creating_block_hash: Hash::default(),
            creating_daa_score: 0,
        };
        // Should at least include the 1024-byte spk_script bytes.
        assert!(record.estimate_mem_bytes() >= 1024);
    }
}

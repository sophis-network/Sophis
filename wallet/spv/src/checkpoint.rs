//! J5 — Sync checkpoint.
//!
//! Per design §4.2, the minimum tuple a wallet caches between sync
//! sessions to bootstrap incremental sync. Ship-with-binary
//! checkpoints are signed by the founder release process; runtime
//! checkpoints are cached by the wallet itself after each successful
//! sync forward.

use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;

/// Sync checkpoint. The four fields together let a light client skip
/// re-validating the entire header / filter chain on every restart.
///
/// `filter_header` is the K2 `filter_header` of `block_hash` — i.e.
/// the running 32-byte commitment to all per-block filters up to and
/// including this block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    pub block_hash: Hash,
    pub blue_score: u64,
    pub daa_score: u64,
    pub filter_header: [u8; 32],
}

impl SyncCheckpoint {
    /// Genesis-parent checkpoint (cold-start sentinel). Wallets that
    /// have never synced use this to bootstrap from genesis.
    pub fn genesis_parent(genesis_hash: Hash) -> Self {
        Self { block_hash: genesis_hash, blue_score: 0, daa_score: 0, filter_header: [0u8; 32] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_parent_has_zero_filter_header() {
        let c = SyncCheckpoint::genesis_parent(Hash::from_slice(&[0xABu8; 32]));
        assert_eq!(c.filter_header, [0u8; 32]);
        assert_eq!(c.blue_score, 0);
        assert_eq!(c.daa_score, 0);
    }

    #[test]
    fn checkpoint_serde_round_trips() {
        let c = SyncCheckpoint {
            block_hash: Hash::from_slice(&[1u8; 32]),
            blue_score: 12345,
            daa_score: 67890,
            filter_header: [0xCDu8; 32],
        };
        let s = serde_json::to_string(&c).unwrap();
        let d: SyncCheckpoint = serde_json::from_str(&s).unwrap();
        assert_eq!(c, d);
    }
}

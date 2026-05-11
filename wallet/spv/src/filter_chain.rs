//! J5 — Filter chain verification.
//!
//! Walks the K2 filter header chain forward from a trusted starting
//! point, verifying each entry against the previous. Divergence
//! detection per design §3.3: a node that serves a `filter_header`
//! whose `prev_header` doesn't match what the wallet last cached
//! signals either a real reorg or a malicious node — both demand
//! rollback.

use sophis_compact_filters::build_filter_header;
use sophis_hashes::Hash;
use thiserror::Error;

/// One entry in the filter header chain, as fetched from a full node
/// via `getBlockFilterHeader` and verified locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterChainEntry {
    pub block_hash: Hash,
    pub prev_header: [u8; 32],
    pub filter_hash: [u8; 32],
    pub filter_header: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FilterChainError {
    /// Server-supplied `prev_header` doesn't match the previously-
    /// trusted `filter_header`. Indicates either a reorg or a
    /// malicious / divergent node. Per design §3.3 the wallet should
    /// roll back to the deepest `Confirmed` checkpoint and re-sync.
    #[error("filter chain divergence at block {block_hash:?}: expected prev={expected:?}, got prev={got:?}")]
    Divergence { block_hash: Hash, expected: [u8; 32], got: [u8; 32] },

    /// Server-supplied `filter_header` doesn't equal the locally
    /// recomputed `SHA3-384(prev_header || filter_hash)[..32]`.
    /// Indicates a malicious / buggy server.
    #[error("filter header recomputation mismatch at block {block_hash:?}")]
    HeaderRecomputeMismatch { block_hash: Hash },
}

/// Stateful filter chain walker. Starts from a trusted
/// `prev_filter_header` (the cached checkpoint's `filter_header`)
/// and accepts entries one at a time, advancing the trust frontier
/// or returning `Err` on divergence.
pub struct FilterChain {
    /// The most recently trusted `filter_header`. New entries must
    /// link via `prev_header == self.prev_filter_header`.
    prev_filter_header: [u8; 32],
}

impl FilterChain {
    /// Constructs a walker starting from a trusted starting point
    /// (typically `SyncCheckpoint.filter_header`).
    pub fn from_checkpoint(prev_filter_header: [u8; 32]) -> Self {
        Self { prev_filter_header }
    }

    /// Returns the current trust frontier — the last accepted entry's
    /// `filter_header`.
    pub fn current(&self) -> [u8; 32] {
        self.prev_filter_header
    }

    /// Verifies and accepts one chain entry. On success the trust
    /// frontier advances to `entry.filter_header`. On error the
    /// frontier stays at the previous value; caller decides whether
    /// to retry, switch nodes, or roll back to a deeper checkpoint.
    ///
    /// Two checks per entry:
    /// 1. `entry.prev_header == self.prev_filter_header` (chain link)
    /// 2. `entry.filter_header == SHA3-384(entry.prev_header || entry.filter_hash)[..32]`
    ///    (recomputation; the server cannot lie about the header
    ///    derivation).
    pub fn accept(&mut self, entry: &FilterChainEntry) -> Result<(), FilterChainError> {
        if entry.prev_header != self.prev_filter_header {
            return Err(FilterChainError::Divergence {
                block_hash: entry.block_hash,
                expected: self.prev_filter_header,
                got: entry.prev_header,
            });
        }
        let recomputed = build_filter_header(&entry.prev_header, &entry.filter_hash);
        if recomputed != entry.filter_header {
            return Err(FilterChainError::HeaderRecomputeMismatch { block_hash: entry.block_hash });
        }
        self.prev_filter_header = entry.filter_header;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_compact_filters::{build_basic_filter, filter_hash};

    fn h(byte: u8) -> Hash {
        Hash::from_slice(&[byte; 32])
    }

    /// Builds a coherent (block, filter_bytes) sequence, returns
    /// `Vec<FilterChainEntry>` chained correctly from `start_prev`.
    fn make_chain(start_prev: [u8; 32], blocks: &[Hash]) -> Vec<FilterChainEntry> {
        let mut prev = start_prev;
        let mut out = Vec::new();
        for (i, &block) in blocks.iter().enumerate() {
            let bytes = build_basic_filter(&block, &[&[i as u8]]);
            let fh = filter_hash(&bytes);
            let header = build_filter_header(&prev, &fh);
            out.push(FilterChainEntry { block_hash: block, prev_header: prev, filter_hash: fh, filter_header: header });
            prev = header;
        }
        out
    }

    #[test]
    fn happy_path_accepts_chained_entries() {
        let entries = make_chain([0u8; 32], &[h(1), h(2), h(3)]);
        let mut chain = FilterChain::from_checkpoint([0u8; 32]);
        for e in &entries {
            chain.accept(e).unwrap();
        }
        assert_eq!(chain.current(), entries.last().unwrap().filter_header);
    }

    #[test]
    fn divergence_detected_on_wrong_prev() {
        let entries = make_chain([0u8; 32], &[h(1), h(2)]);
        let mut chain = FilterChain::from_checkpoint([0xAAu8; 32]); // wrong start
        let err = chain.accept(&entries[0]).unwrap_err();
        assert!(matches!(err, FilterChainError::Divergence { .. }));
        // Frontier did NOT advance.
        assert_eq!(chain.current(), [0xAAu8; 32]);
    }

    #[test]
    fn header_recompute_mismatch_rejected() {
        let mut entries = make_chain([0u8; 32], &[h(1)]);
        // Tamper with filter_header (server lying).
        entries[0].filter_header = [0xDEu8; 32];
        let mut chain = FilterChain::from_checkpoint([0u8; 32]);
        let err = chain.accept(&entries[0]).unwrap_err();
        assert!(matches!(err, FilterChainError::HeaderRecomputeMismatch { .. }));
    }

    #[test]
    fn frontier_does_not_advance_on_error() {
        let entries = make_chain([0u8; 32], &[h(1), h(2)]);
        let mut chain = FilterChain::from_checkpoint([0u8; 32]);
        chain.accept(&entries[0]).unwrap();
        let frontier_after_first = chain.current();

        // Try to accept entry 2 with tampered prev — should fail
        let mut bad = entries[1].clone();
        bad.prev_header = [0xFFu8; 32];
        let _ = chain.accept(&bad).unwrap_err();
        assert_eq!(chain.current(), frontier_after_first, "frontier must not move on error");
    }

    #[test]
    fn out_of_order_acceptance_rejected() {
        let entries = make_chain([0u8; 32], &[h(1), h(2), h(3)]);
        let mut chain = FilterChain::from_checkpoint([0u8; 32]);
        // Try to skip entry 0 and accept entry 1 directly.
        let err = chain.accept(&entries[1]).unwrap_err();
        assert!(matches!(err, FilterChainError::Divergence { .. }));
    }
}

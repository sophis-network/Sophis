//! Phase 5 — Oracle sVM contract (skeleton).
//!
//! Sub-phase 5.0 ships only the type surface. Sub-phase 5.3 will:
//!   - declare contract entrypoints with `sophis-sdk-macros`
//!   - call `sophis_oracle_verifier::verify(proof, &journal)` (which
//!     internally uses the new `Capability::VerifyPlonky3Proof`)
//!   - verify the relayer's Dilithium signature over the journal
//!   - reject if `journal.sequence <= state.last_sequence` (replay)
//!   - reject if journal bounds are wider than the contract's policy
//!   - write `state.feeds[feed] = (price, exponent, publish_time)`
//!
//! Until then, this crate exists so the workspace builds end-to-end and
//! downstream code (`oracle/relayer`, integration tests) can take it as a
//! dependency.

use sophis_oracle_core::{FeedId, OracleJournal, PublisherKey};

/// What the contract persists per feed (latest accepted update).
#[derive(Debug, Clone)]
pub struct FeedState {
    pub price: i64,
    pub exponent: i32,
    pub publish_time: u64,
    pub last_sequence: u64,
    pub publisher: PublisherKey,
}

/// Policy the contract enforces against an incoming `OracleJournal` before
/// trusting the verified price. Stricter than what the circuit enforces:
/// the circuit proves the relayer used some bounds; this contract checks
/// the bounds were sane.
#[derive(Debug, Clone)]
pub struct FeedPolicy {
    pub feed: FeedId,
    pub publisher: PublisherKey,
    pub min_price: i64,
    pub max_price: i64,
    pub max_age_secs: u64,
}

impl FeedPolicy {
    /// Returns true if the journal is consistent with this policy.
    pub fn accepts(&self, j: &OracleJournal) -> bool {
        j.feed == self.feed
            && j.publisher == self.publisher
            && j.min_price >= self.min_price
            && j.max_price <= self.max_price
            && j.max_age_secs <= self.max_age_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol() -> FeedPolicy {
        FeedPolicy {
            feed: FeedId(*b"BTC/USD\0"),
            publisher: PublisherKey([1u8; 32]),
            min_price: 1_000_00,
            max_price: 1_000_000_00,
            max_age_secs: 60,
        }
    }

    fn journal_for(p: &FeedPolicy) -> OracleJournal {
        OracleJournal {
            sequence: 1,
            feed: p.feed,
            publisher: p.publisher,
            price: 65_000_00,
            exponent: -8,
            publish_time: 1_700_000_000,
            min_price: p.min_price,
            max_price: p.max_price,
            max_age_secs: p.max_age_secs,
            payload_hash: [0u8; 32],
        }
    }

    #[test]
    fn policy_accepts_matching_journal() {
        let p = pol();
        assert!(p.accepts(&journal_for(&p)));
    }

    #[test]
    fn policy_rejects_wider_bounds_from_relayer() {
        let p = pol();
        let mut j = journal_for(&p);
        j.min_price = 0; // relayer used a wider window than policy allows
        assert!(!p.accepts(&j));
    }

    #[test]
    fn policy_rejects_publisher_mismatch() {
        let p = pol();
        let mut j = journal_for(&p);
        j.publisher = PublisherKey([9u8; 32]);
        assert!(!p.accepts(&j));
    }

    #[test]
    fn policy_rejects_stale_max_age() {
        let p = pol();
        let mut j = journal_for(&p);
        j.max_age_secs = 600; // relayer accepted older data than policy allows
        assert!(!p.accepts(&j));
    }
}

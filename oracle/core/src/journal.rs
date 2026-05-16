use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256};

use crate::price::{FeedId, PriceUpdate, PublisherKey};

/// Public output committed by the Plonky3 STARK after verifying one Pyth
/// price update. Everything in this struct is what the on-chain sVM
/// contract gets to see and act on. Anything *not* in this struct must
/// be re-derivable from it (or accepted on faith — which we do not).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OracleJournal {
    /// Monotonic sequence number assigned by the relayer; the contract
    /// rejects updates with `sequence <= last_sequence` to prevent replay.
    pub sequence: u64,

    pub feed: FeedId,
    pub publisher: PublisherKey,

    /// Verified price (already passed `[min_price, max_price]` check inside the circuit).
    pub price: i64,
    pub exponent: i32,
    pub publish_time: u64,

    /// Bounds the circuit enforced. Recorded in the journal so the contract
    /// can audit them against its own configured policy and reject if the
    /// relayer passed an absurdly wide window.
    pub min_price: i64,
    pub max_price: i64,
    pub max_age_secs: u64,

    /// SHA3-256 of the underlying `PriceUpdate`. Recorded so the contract
    /// can correlate the journal with the raw payload it stores off-chain
    /// for transparency dashboards.
    pub payload_hash: [u8; 32],
}

/// SHA3-256 over a domain-separated borsh encoding of the `PriceUpdate`.
/// The Plonky3 circuit recomputes this exact hash and feeds it into the
/// ed25519 signature verification chip, so any drift between what the
/// publisher signed and what the journal commits would be caught.
pub fn hash_oracle_payload(update: &PriceUpdate) -> [u8; 32] {
    let bytes = borsh::to_vec(update).unwrap_or_default();
    let mut h = Sha3_256::new();
    h.update(b"sophis-oracle-payload-v1:");
    h.update(&bytes);
    h.finalize().into()
}

// Audit category-D coverage closure, item 7 (Session 16, 2026-05-16):
// closes journal.rs (was 88.89%) — `hash_oracle_payload` determinism /
// domain separation and the `OracleJournal` borsh round-trip.
#[cfg(test)]
mod tests {
    use super::*;

    fn upd(price: i64) -> PriceUpdate {
        PriceUpdate {
            feed: FeedId(*b"BTC/USD\0"),
            publisher: PublisherKey([1u8; 32]),
            price,
            conf: 1,
            exponent: -8,
            publish_time: 100,
        }
    }

    #[test]
    fn hash_oracle_payload_is_deterministic_and_sensitive() {
        let a = hash_oracle_payload(&upd(100));
        assert_eq!(a, hash_oracle_payload(&upd(100)), "deterministic");
        assert_ne!(a, hash_oracle_payload(&upd(101)), "sensitive to the payload");
        assert_eq!(a.len(), 32);
        // Domain separation: the prefix means the digest is not a bare
        // SHA3 of the borsh bytes.
        let bare = {
            let mut h = Sha3_256::new();
            h.update(borsh::to_vec(&upd(100)).unwrap());
            <[u8; 32]>::from(h.finalize())
        };
        assert_ne!(a, bare, "domain-separated, not a bare hash");
    }

    #[test]
    fn oracle_journal_borsh_roundtrip() {
        let j = OracleJournal {
            sequence: 7,
            feed: FeedId(*b"ETH/USD\0"),
            publisher: PublisherKey([2u8; 32]),
            price: 1234,
            exponent: -6,
            publish_time: 200,
            min_price: 0,
            max_price: 9999,
            max_age_secs: 60,
            payload_hash: [3u8; 32],
        };
        let back: OracleJournal = borsh::from_slice(&borsh::to_vec(&j).unwrap()).unwrap();
        assert_eq!(j, back);
    }
}

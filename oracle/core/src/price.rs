use borsh::{BorshDeserialize, BorshSerialize};

/// Fixed-width feed identifier, e.g. `b"BTC/USD\0"`.
/// 8 bytes is enough for typical Pyth feed symbols and keeps the journal
/// fixed-size for cheap on-chain comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct FeedId(pub [u8; 8]);

/// Pythnet publisher's ed25519 public key (32 bytes).
/// In the Sophis singleton design exactly one publisher per feed is trusted at a time.
/// Rotation happens via a contract config update (no hard fork).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct PublisherKey(pub [u8; 32]);

impl core::fmt::Display for PublisherKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// One Pyth price observation as it is signed by a publisher.
/// `price * 10^exponent` is the human-readable price (Pyth convention).
/// `conf` is the 1-sigma confidence interval in the same scale (kept for diagnostics
/// — the singleton variant does not enforce a confidence bound in v0).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PriceUpdate {
    pub feed: FeedId,
    pub publisher: PublisherKey,
    pub price: i64,
    pub conf: u64,
    pub exponent: i32,
    pub publish_time: u64,
}

/// Wire format pulled from Pythnet by the relayer: one update plus the
/// publisher's ed25519 signature over `hash_oracle_payload(update)`.
///
/// In the Pythnet pull architecture (sub-phase 5.1) the publisher's actual
/// ed25519 signature is over the full Solana transaction message, **not**
/// over our `hash_oracle_payload`. The relayer therefore wraps the raw
/// Pythnet submission in a `PythnetSubmission`; the Plonky3 circuit
/// (sub-phase 5.2) is what bridges between the on-Solana signature scope
/// and our journal commitment. This struct stays as the contract-facing
/// "decoded" view.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SignedPriceUpdate {
    pub update: PriceUpdate,
    pub signature: Box<[u8; 64]>,
}

/// Raw Pythnet submission as fetched by `oracle/feeds` (sub-phase 5.1).
///
/// The `tx_message` field is the exact byte sequence the publisher signed
/// (Solana transaction message — NOT the price payload itself). The Plonky3
/// circuit will:
///   1. Verify `ed25519(publisher, sha512(tx_message), signature)` is valid.
///   2. Re-derive `price`, `conf`, `publish_time` from inside `tx_message`
///      (Pyth's instruction encoding is fixed and parseable in AIR).
///   3. Bind those derived values to the `OracleJournal` it commits to.
///
/// Stored as `Vec<u8>` because Solana tx messages are variable-length.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PythnetSubmission {
    /// Already-decoded view of the price (parsed by the relayer from
    /// Pythnet's `PriceAccountV2`). Treat as a hint — the circuit must
    /// re-derive these from `tx_message` to be sound.
    pub update: PriceUpdate,
    /// Raw Solana tx message the publisher signed.
    pub tx_message: Vec<u8>,
    /// ed25519 signature on `sha512(tx_message)`.
    pub signature: Box<[u8; 64]>,
    /// Solana slot at which the submission was confirmed (diagnostic).
    pub slot: u64,
}

// Audit category-D coverage closure, item 7 (Session 16, 2026-05-16):
// `price.rs` was at 0% coverage. These are pure data types — borsh
// round-trips, the manual `PublisherKey` hex `Display`, and the derived
// equality/hash. (Item 7 = the deprecated Phase-5 crates; this is a
// bounded high-ROI pure-code pass — the network `feeds/rpc.rs` and the
// heavy STARK `oracle/host` AIR files are documented residual-by-
// deprecation: code scheduled for deletion at SIP-11 D11.)
#[cfg(test)]
mod tests {
    use super::*;

    fn upd() -> PriceUpdate {
        PriceUpdate {
            feed: FeedId(*b"BTC/USD\0"),
            publisher: PublisherKey([0xab; 32]),
            price: -12345,
            conf: 42,
            exponent: -8,
            publish_time: 1_700_000_000,
        }
    }

    #[test]
    fn publisher_key_display_is_lowercase_hex() {
        let mut k = [0u8; 32];
        k[0] = 0x0f;
        k[1] = 0xa0;
        let s = PublisherKey(k).to_string();
        assert!(s.starts_with("0fa0"));
        assert!(s.ends_with("00"));
        assert_eq!(s.len(), 64); // 32 bytes * 2 hex chars
    }

    #[test]
    fn feed_id_and_keys_eq_clone_hash() {
        use std::collections::HashSet;
        let a = FeedId(*b"ETH/USD\0");
        assert_eq!(a, a);
        assert_eq!(a, a); // Copy
        let mut set = HashSet::new();
        set.insert(PublisherKey([1u8; 32]));
        assert!(set.contains(&PublisherKey([1u8; 32])));
        assert!(!set.contains(&PublisherKey([2u8; 32])));
    }

    #[test]
    fn price_update_borsh_roundtrip() {
        let u = upd();
        let bytes = borsh::to_vec(&u).unwrap();
        let back: PriceUpdate = borsh::from_slice(&bytes).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn signed_and_pythnet_submission_borsh_roundtrip() {
        let s = SignedPriceUpdate { update: upd(), signature: Box::new([7u8; 64]) };
        let sb = borsh::to_vec(&s).unwrap();
        let sback: SignedPriceUpdate = borsh::from_slice(&sb).unwrap();
        assert_eq!(sback.update, s.update);
        assert_eq!(*sback.signature, [7u8; 64]);

        let p = PythnetSubmission { update: upd(), tx_message: vec![1, 2, 3], signature: Box::new([9u8; 64]), slot: 555 };
        let pb = borsh::to_vec(&p).unwrap();
        let pback: PythnetSubmission = borsh::from_slice(&pb).unwrap();
        assert_eq!(pback.update, p.update);
        assert_eq!(pback.tx_message, vec![1, 2, 3]);
        assert_eq!(pback.slot, 555);
        assert!(!format!("{pback:?}").is_empty());
    }
}

//! Phase 5 — ZK-Oracle Aggregator: shared types.
//!
//! Architecture (decision 2026-05-05):
//! - Source: Pyth (Pythnet pull) — single publisher (no Wormhole, no multisig).
//! - Proof: Plonky3 STARK over `(ed25519_sig_valid, freshness, bounds, payload_hash)`.
//! - Operator: Sophis-controlled relayer signs the aggregated batch with
//!   Dilithium ML-DSA-44 (PQC-resistant on the Sophis-controlled boundary).
//! - On-chain: a sVM contract verifies the STARK via
//!   `Capability::VerifyPlonky3Proof` (added in parallel to the Phase 3
//!   `VerifyRisc0Proof`; the two coexist) plus the relayer's Dilithium
//!   signature, then writes the price into oracle state.
//!
//! This crate intentionally has no Plonky3, Pythnet, or Dilithium dependencies
//! — those live in the downstream crates (`oracle/feeds`, `oracle/host`,
//! `oracle/verifier`, `oracle/relayer`, `oracle/contract`).

pub mod error;
pub mod journal;
pub mod price;

pub use error::OracleError;
pub use journal::{OracleJournal, hash_oracle_payload};
pub use price::{FeedId, PriceUpdate, PublisherKey, PythnetSubmission, SignedPriceUpdate};

/// Script-public-key version used by the relayer (sub-fase 5.4.e) to mark
/// a transaction output as carrying an oracle invocation payload (the
/// borsh-serialized `RelayerBundle` wire format from `sign::SignedBundle::encode_wire`).
///
/// Picked so it does not collide with existing Sophis SPK versions:
///   0..2 → standard wallet scripts (ECDSA / Schnorr / P2SH; max=2)
///   3    → BRIDGE_VAULT (deposit; legacy, kept for in-tree rollup)
///   4    → BRIDGE_CLAIM (withdrawal; legacy, kept for in-tree rollup)
///   5    → ROLLUP_STATE
///   6    → ROLLUP_SUBMISSION
///   7    → ORACLE_INVOKE  ← *this constant*
///
/// Changing this is a hard fork of the relayer↔contract protocol — every
/// running contract pinned against version 7 would silently stop accepting
/// updates. Do not bump without a coordinated rollout.
pub const ORACLE_INVOKE_VERSION: u16 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_publisher() -> PublisherKey {
        PublisherKey([3u8; 32])
    }

    fn dummy_feed() -> FeedId {
        FeedId(*b"BTC/USD\0")
    }

    fn make_update(price: i64, exponent: i32, ts: u64) -> SignedPriceUpdate {
        SignedPriceUpdate {
            update: PriceUpdate {
                feed: dummy_feed(),
                publisher: dummy_publisher(),
                price,
                conf: 0,
                exponent,
                publish_time: ts,
            },
            // ed25519 signature is 64 bytes
            signature: Box::new([0u8; 64]),
        }
    }

    #[test]
    fn pythnet_submission_borsh_roundtrip() {
        let sub = PythnetSubmission {
            update: PriceUpdate {
                feed: dummy_feed(),
                publisher: dummy_publisher(),
                price: 65_000_00,
                conf: 50,
                exponent: -8,
                publish_time: 1_700_000_000,
            },
            tx_message: vec![0x01, 0x02, 0x03, 0x04],
            signature: Box::new([7u8; 64]),
            slot: 250_000_000,
        };
        let bytes = borsh::to_vec(&sub).unwrap();
        let decoded: PythnetSubmission = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded.tx_message, sub.tx_message);
        assert_eq!(decoded.slot, sub.slot);
        assert_eq!(decoded.update.price, sub.update.price);
    }

    #[test]
    fn signed_update_borsh_roundtrip() {
        let u = make_update(100_000_00, -8, 1_700_000_000);
        let bytes = borsh::to_vec(&u).unwrap();
        let decoded: SignedPriceUpdate = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded.update.price, 100_000_00);
        assert_eq!(decoded.update.publish_time, 1_700_000_000);
    }

    #[test]
    fn journal_borsh_roundtrip() {
        let j = OracleJournal {
            sequence: 42,
            feed: dummy_feed(),
            publisher: dummy_publisher(),
            price: 65_000_00,
            exponent: -8,
            publish_time: 1_700_000_000,
            min_price: 1_000_00,
            max_price: 1_000_000_00,
            max_age_secs: 60,
            payload_hash: [9u8; 32],
        };
        let bytes = borsh::to_vec(&j).unwrap();
        let decoded: OracleJournal = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.price, 65_000_00);
        assert_eq!(decoded.payload_hash, [9u8; 32]);
    }

    #[test]
    fn payload_hash_is_deterministic() {
        let u = make_update(50_000_00, -8, 1_700_000_000);
        let h1 = hash_oracle_payload(&u.update);
        let h2 = hash_oracle_payload(&u.update);
        assert_eq!(h1, h2);
    }

    #[test]
    fn payload_hash_depends_on_price() {
        let a = make_update(50_000_00, -8, 1_700_000_000);
        let b = make_update(60_000_00, -8, 1_700_000_000);
        assert_ne!(hash_oracle_payload(&a.update), hash_oracle_payload(&b.update));
    }

    #[test]
    fn feed_id_pads_short_symbols() {
        let f = FeedId(*b"ETH\0\0\0\0\0");
        // first three bytes are the symbol; the rest are NUL padding
        assert_eq!(&f.0[..3], b"ETH");
        assert_eq!(f.0[3], 0);
    }
}

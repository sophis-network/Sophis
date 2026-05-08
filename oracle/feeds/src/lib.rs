//! Phase 5 — Pythnet pull adapter (sub-phase 5.1).
//!
//! Real implementation of the singleton Pyth feed:
//!
//! 1. `account` decodes Pyth's `PriceAccountV2` binary layout (well-defined,
//!    fixed-offset C struct) — used to find the publisher's most-recent slot
//!    and parsed `(price, conf, exponent, publish_time)`.
//! 2. `rpc` is a thin Solana JSON-RPC v2 wrapper (just the four methods we
//!    need: `getAccountInfo`, `getSignaturesForAddress`, `getTransaction`,
//!    `getSlot`).
//! 3. `pythnet` is the high-level adapter that ties them together: given a
//!    `(feed price account, publisher pubkey)` it returns a
//!    `PythnetSubmission` containing the publisher's latest signed
//!    transaction message + ed25519 signature + the parsed price view.
//!
//! No signature verification happens here — that's the Plonky3 circuit's
//! job in sub-phase 5.2. The relayer can optionally verify off-chain as a
//! sanity check before invoking the prover.

pub mod account;
pub mod pythnet;
pub mod rpc;

use async_trait::async_trait;
use sophis_oracle_core::{FeedId, PublisherKey, PythnetSubmission, SignedPriceUpdate};

#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON-RPC error: {message} (code {code})")]
    Rpc { code: i64, message: String },

    #[error("malformed RPC response: {0}")]
    BadResponse(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Pyth account decode error: {0}")]
    Account(#[from] account::DecodeError),

    #[error("publisher {publisher} has no recent submissions in the last {window} signatures")]
    NoPublisherSubmission { publisher: String, window: usize },

    #[error("publisher submission tx had no signatures (malformed)")]
    NoSignaturesInTx,

    #[error("not implemented yet (sub-phase 5.x)")]
    NotImplemented,
}

/// Pulls the latest signed price update for a single feed from a single
/// publisher. The caller is responsible for verifying signature/freshness/bounds
/// downstream — this trait is purely transport.
#[async_trait]
pub trait PriceFeed: Send + Sync {
    /// Fetch the latest Pythnet submission for `(feed, publisher)`. Returns
    /// the raw transaction message + ed25519 signature so a downstream ZK
    /// circuit can verify it.
    async fn latest_submission(&self, feed: FeedId, publisher: PublisherKey) -> Result<PythnetSubmission, FeedError>;

    /// Convenience: drop the raw tx bytes and return only the
    /// `SignedPriceUpdate` view. The signature is *not* over the simplified
    /// view — only over the full Solana tx message stripped here. Use only
    /// for diagnostics / mocked tests, never for the actual prover input.
    async fn latest(&self, feed: FeedId, publisher: PublisherKey) -> Result<SignedPriceUpdate, FeedError> {
        let s = self.latest_submission(feed, publisher).await?;
        Ok(SignedPriceUpdate { update: s.update, signature: s.signature })
    }
}

pub use pythnet::{PythnetClient, PythnetConfig};

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: the public surface compiles and the trait can be implemented
    /// by a hand-rolled stub (matters for the relayer + integration tests
    /// in sub-phase 5.4 which will swap in a fixture).
    struct StubFeed;

    #[async_trait]
    impl PriceFeed for StubFeed {
        async fn latest_submission(&self, _f: FeedId, _p: PublisherKey) -> Result<PythnetSubmission, FeedError> {
            Err(FeedError::NotImplemented)
        }
    }

    #[tokio::test]
    async fn stub_implements_trait() {
        let s = StubFeed;
        let r = s.latest_submission(FeedId([0; 8]), PublisherKey([0; 32])).await;
        assert!(matches!(r, Err(FeedError::NotImplemented)));
    }
}

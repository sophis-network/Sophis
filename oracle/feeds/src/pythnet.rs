//! High-level Pythnet adapter (sub-phase 5.1).
//!
//! Given a configured Pythnet RPC endpoint and a `(price account pubkey,
//! publisher pubkey)` pair, returns the publisher's most-recent on-Pythnet
//! submission as a `PythnetSubmission`.
//!
//! Algorithm:
//!   1. Fetch the Pyth `PriceAccountV2` to discover the publisher's most
//!      recent `pub_slot` and the parsed `(price, conf, exponent)`.
//!   2. List the publisher's recent confirmed signatures via
//!      `getSignaturesForAddress`.
//!   3. Walk that list newest-first, fetching transactions until we find one
//!      that landed in `pub_slot` (the slot the Pyth account attributes to
//!      this publisher).
//!   4. Return the tx's message bytes + signature[0] (the publisher's
//!      ed25519 signature on `sha512(message)`).
//!
//! The Plonky3 circuit (sub-phase 5.2) takes `(message, signature, publisher_pubkey)`
//! and proves: ed25519 valid + parsed-price-from-message matches the
//! committed `OracleJournal` price.

use async_trait::async_trait;
use sophis_oracle_core::{FeedId, PriceUpdate, PublisherKey, PythnetSubmission};

use crate::account::PriceAccountV2;
use crate::rpc::SolanaRpc;
use crate::{FeedError, PriceFeed};

/// How many recent publisher signatures we will scan looking for the one
/// matching the Price account's attributed slot before giving up.
const PUBLISHER_SIGNATURE_SCAN_WINDOW: usize = 25;

#[derive(Debug, Clone)]
pub struct PythnetConfig {
    /// JSON-RPC endpoint, e.g. `https://pythnet.rpcpool.com`.
    pub rpc_endpoint: String,
    /// Base58-encoded pubkey of the Pyth `PriceAccountV2` for the singleton feed.
    /// Each `FeedId` maps to one of these — the operator hard-codes the mapping.
    pub price_account_b58: String,
    /// Base58-encoded publisher pubkey we trust as the singleton source.
    pub publisher_b58: String,
}

/// Real Pythnet client. Holds an `SolanaRpc` and the static config telling
/// it which feed/publisher to fetch.
pub struct PythnetClient {
    pub rpc: SolanaRpc,
    pub config: PythnetConfig,
}

impl PythnetClient {
    pub fn new(config: PythnetConfig) -> Self {
        let rpc = SolanaRpc::new(config.rpc_endpoint.clone());
        Self { rpc, config }
    }

    /// Decode a base58 pubkey string into the 32-byte raw form Pyth stores
    /// in its `PriceComp.publisher` field. We don't depend on the `bs58`
    /// crate here — base58 decoding is small enough to inline (and we already
    /// validate format upstream when the operator sets the config).
    fn decode_b58_pubkey(s: &str) -> Result<[u8; 32], FeedError> {
        let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut num = vec![0u8; 0];
        for c in s.bytes() {
            let v =
                alphabet.iter().position(|&x| x == c).ok_or_else(|| FeedError::BadResponse(format!("invalid base58 char: {c:?}")))?;
            let mut carry = v;
            for byte in num.iter_mut() {
                carry += (*byte as usize) * 58;
                *byte = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                num.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        // Leading '1's in base58 represent leading zero bytes
        for c in s.bytes() {
            if c == b'1' {
                num.push(0);
            } else {
                break;
            }
        }
        num.reverse();
        if num.len() != 32 {
            return Err(FeedError::BadResponse(format!("expected 32-byte pubkey, decoded {} bytes", num.len())));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&num);
        Ok(out)
    }
}

#[async_trait]
impl PriceFeed for PythnetClient {
    async fn latest_submission(&self, _feed: FeedId, publisher: PublisherKey) -> Result<PythnetSubmission, FeedError> {
        // 1. Sanity: the publisher we're querying must match the one we're
        //    configured for. Distinct args caught via assertion is friendlier
        //    than silently using the config one.
        let configured = Self::decode_b58_pubkey(&self.config.publisher_b58)?;
        if publisher.0 != configured {
            return Err(FeedError::BadResponse(format!(
                "publisher arg does not match configured publisher (configured prefix {:02x}{:02x}.., arg prefix {:02x}{:02x}..)",
                configured[0], configured[1], publisher.0[0], publisher.0[1]
            )));
        }

        // 2. Fetch + decode the Pyth Price account.
        let acc_bytes = self.rpc.get_account_data(&self.config.price_account_b58).await?;
        let acc = PriceAccountV2::decode(&acc_bytes)?;
        let comp = acc
            .find_publisher(&publisher.0)
            .ok_or_else(|| FeedError::NoPublisherSubmission { publisher: hex_short(&publisher.0), window: 0 })?;
        let target_slot = comp.latest_pub_slot;

        // 3. Walk the publisher's recent submission txs until we find the one
        //    that landed at `target_slot`.
        let sigs = self.rpc.get_signatures_for_address(&self.config.publisher_b58, PUBLISHER_SIGNATURE_SCAN_WINDOW).await?;
        let mut matched: Option<(Vec<u8>, [u8; 64], u64)> = None;
        for sig in sigs {
            let tx = self.rpc.get_transaction(&sig).await?;
            if tx.slot == target_slot {
                let pub_sig = *tx.signatures.first().ok_or(FeedError::NoSignaturesInTx)?;
                matched = Some((tx.message, pub_sig, tx.slot));
                break;
            }
        }
        let (message, signature, slot) = matched
            .ok_or(FeedError::NoPublisherSubmission { publisher: hex_short(&publisher.0), window: PUBLISHER_SIGNATURE_SCAN_WINDOW })?;

        // 4. Build the parsed view (`update`). `publish_time` here is taken
        //    from the *aggregated* account timestamp — Pyth's per-publisher
        //    contribution does not carry a Unix timestamp, only a slot number.
        //    The relayer treats this as a hint; the circuit uses the slot
        //    derived from inside the message bytes for the freshness check.
        let update = PriceUpdate {
            feed: _feed,
            publisher,
            price: comp.latest_price,
            conf: comp.latest_conf,
            exponent: acc.exponent,
            publish_time: acc.timestamp.max(0) as u64,
        };

        Ok(PythnetSubmission { update, tx_message: message, signature: Box::new(signature), slot })
    }
}

fn hex_short(k: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}..", k[0], k[1], k[2], k[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_b58_pubkey() {
        // System program ID (all-zero pubkey) base58-encodes to "11111111111111111111111111111111"
        let zero = PythnetClient::decode_b58_pubkey("11111111111111111111111111111111").unwrap();
        assert_eq!(zero, [0u8; 32]);
    }

    #[test]
    fn rejects_invalid_base58_char() {
        let r = PythnetClient::decode_b58_pubkey("0OIl"); // contains forbidden chars
        assert!(matches!(r, Err(FeedError::BadResponse(_))));
    }
}

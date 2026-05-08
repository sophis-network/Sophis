//! Minimal Solana JSON-RPC v2 client. Only the four methods we need:
//!
//!   - `getSlot`                 — current slot (diagnostic)
//!   - `getAccountInfo`          — fetch Pyth Price account binary data
//!   - `getSignaturesForAddress` — list publisher's recent tx signatures
//!   - `getTransaction`          — fetch the full tx bytes for a signature
//!
//! We avoid `solana-client` to keep the dependency footprint tiny — that
//! crate transitively pulls ~30 other Solana crates we do not need.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::FeedError;

#[derive(Debug, Clone)]
pub struct SolanaRpc {
    pub endpoint: String,
    pub client: Client,
}

impl SolanaRpc {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into(), client: Client::new() }
    }

    pub fn with_client(endpoint: impl Into<String>, client: Client) -> Self {
        Self { endpoint: endpoint.into(), client }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, FeedError> {
        let req = JsonRpcRequest { jsonrpc: "2.0", id: 1, method, params };
        let resp: JsonRpcResponse = self.client.post(&self.endpoint).json(&req).send().await?.json().await?;
        if let Some(err) = resp.error {
            return Err(FeedError::Rpc { code: err.code, message: err.message });
        }
        resp.result.ok_or_else(|| FeedError::BadResponse("missing 'result'".into()))
    }

    pub async fn get_slot(&self) -> Result<u64, FeedError> {
        let v = self.call("getSlot", json!([])).await?;
        v.as_u64().ok_or_else(|| FeedError::BadResponse("getSlot: result not u64".into()))
    }

    /// Fetches an account's raw data, returning the bytes (base64-decoded).
    pub async fn get_account_data(&self, pubkey_b58: &str) -> Result<Vec<u8>, FeedError> {
        let v = self.call("getAccountInfo", json!([pubkey_b58, { "encoding": "base64" }])).await?;
        let arr = v
            .get("value")
            .and_then(|x| x.get("data"))
            .and_then(|x| x.as_array())
            .ok_or_else(|| FeedError::BadResponse("getAccountInfo: no value.data array".into()))?;
        let b64_str = arr
            .first()
            .and_then(|s| s.as_str())
            .ok_or_else(|| FeedError::BadResponse("getAccountInfo: missing base64 payload".into()))?;
        Ok(B64.decode(b64_str)?)
    }

    /// Returns up to `limit` recent confirmed signatures for the given address,
    /// newest first.
    pub async fn get_signatures_for_address(&self, pubkey_b58: &str, limit: usize) -> Result<Vec<String>, FeedError> {
        let v = self.call("getSignaturesForAddress", json!([pubkey_b58, { "limit": limit }])).await?;
        let arr = v.as_array().ok_or_else(|| FeedError::BadResponse("getSignaturesForAddress: not array".into()))?;
        Ok(arr.iter().filter_map(|x| x.get("signature").and_then(|s| s.as_str()).map(String::from)).collect())
    }

    /// Fetches a confirmed transaction. Returns `(slot, message_bytes, signatures)`
    /// where `signatures` are 64-byte ed25519 signatures in transaction order
    /// (signatures[0] always corresponds to the fee payer / first signer).
    pub async fn get_transaction(&self, signature_b58: &str) -> Result<TxFetched, FeedError> {
        let v = self
            .call(
                "getTransaction",
                json!([
                    signature_b58,
                    { "encoding": "base64", "maxSupportedTransactionVersion": 0 }
                ]),
            )
            .await?;
        let slot = v.get("slot").and_then(|s| s.as_u64()).ok_or_else(|| FeedError::BadResponse("getTransaction: missing slot".into()))?;
        let tx_arr = v
            .get("transaction")
            .and_then(|x| x.as_array())
            .ok_or_else(|| FeedError::BadResponse("getTransaction: transaction not array".into()))?;
        let b64_str = tx_arr
            .first()
            .and_then(|s| s.as_str())
            .ok_or_else(|| FeedError::BadResponse("getTransaction: missing base64 payload".into()))?;
        let tx_bytes = B64.decode(b64_str)?;
        let (signatures, message) = split_tx(&tx_bytes)?;
        Ok(TxFetched { slot, message, signatures })
    }
}

#[derive(Debug, Clone)]
pub struct TxFetched {
    pub slot: u64,
    /// The serialized transaction message — exactly the bytes each signer
    /// signed (after sha512 / ed25519 internal hashing).
    pub message: Vec<u8>,
    /// All signatures attached to the tx, in order. signatures[0] is the
    /// fee payer / first required signer.
    pub signatures: Vec<[u8; 64]>,
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// Solana wire format for a transaction:
///     [u8 num_signatures][ed25519 sig × num_signatures][message bytes...]
/// where `num_signatures` is a compact-u16 varint. We support the common case
/// where the signature count fits in a single byte (≤127), which is true for
/// every real-world Pyth publisher submission.
fn split_tx(tx_bytes: &[u8]) -> Result<(Vec<[u8; 64]>, Vec<u8>), FeedError> {
    if tx_bytes.is_empty() {
        return Err(FeedError::BadResponse("split_tx: empty tx bytes".into()));
    }
    let first = tx_bytes[0];
    if first & 0x80 != 0 {
        return Err(FeedError::BadResponse("split_tx: multi-byte signature count not supported".into()));
    }
    let n = first as usize;
    let header_end = 1 + n * 64;
    if tx_bytes.len() < header_end {
        return Err(FeedError::BadResponse("split_tx: tx truncated before message".into()));
    }
    let mut sigs = Vec::with_capacity(n);
    for i in 0..n {
        let mut s = [0u8; 64];
        s.copy_from_slice(&tx_bytes[1 + i * 64..1 + (i + 1) * 64]);
        sigs.push(s);
    }
    let message = tx_bytes[header_end..].to_vec();
    Ok((sigs, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tx_single_signature() {
        let mut tx = vec![1u8]; // 1 signature
        tx.extend_from_slice(&[7u8; 64]); // signature
        tx.extend_from_slice(b"the-message"); // message
        let (sigs, msg) = split_tx(&tx).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0], [7u8; 64]);
        assert_eq!(msg, b"the-message");
    }

    #[test]
    fn split_tx_two_signatures() {
        let mut tx = vec![2u8];
        tx.extend_from_slice(&[1u8; 64]);
        tx.extend_from_slice(&[2u8; 64]);
        tx.extend_from_slice(b"abc");
        let (sigs, msg) = split_tx(&tx).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0][0], 1);
        assert_eq!(sigs[1][0], 2);
        assert_eq!(msg, b"abc");
    }

    #[test]
    fn split_tx_rejects_truncated() {
        let tx = vec![1u8, 0u8, 0u8]; // claims 1 sig but only has 2 bytes after
        assert!(matches!(split_tx(&tx), Err(FeedError::BadResponse(_))));
    }

    #[test]
    fn split_tx_rejects_multi_byte_count() {
        let tx = vec![0x80u8, 0x01u8]; // compact-u16 with continuation
        assert!(matches!(split_tx(&tx), Err(FeedError::BadResponse(_))));
    }
}

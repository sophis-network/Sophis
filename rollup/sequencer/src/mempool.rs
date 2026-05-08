use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use libcrux_ml_dsa::ml_dsa_44::{self, MLDSA44Signature, MLDSA44VerificationKey};
use sophis_rollup_core::L2Tx;

const MAX_MEMPOOL: usize = 10_000;

#[derive(Debug, Clone, thiserror::Error)]
pub enum MempoolError {
    #[error("duplicate transaction: {0:?}")]
    Duplicate([u8; 32]),
    #[error("mempool full ({MAX_MEMPOOL} txs)")]
    Full,
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("invalid verification key on input {0}")]
    BadVerKey(usize),
    #[error("invalid signature on input {0}")]
    BadSignature(usize),
    #[error("output amount overflow")]
    Overflow,
}

pub struct Mempool {
    inner: Arc<Mutex<MempoolInner>>,
}

struct MempoolInner {
    queue: VecDeque<L2Tx>,
    seen: HashMap<[u8; 32], ()>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(MempoolInner { queue: VecDeque::new(), seen: HashMap::new() })) }
    }

    /// Validate and enqueue an L2 tx. Returns Err if invalid or duplicate.
    pub fn push(&self, tx: L2Tx) -> Result<(), MempoolError> {
        validate_tx(&tx)?;

        let txid = tx.txid();
        let mut inner = self.inner.lock().unwrap();

        if inner.seen.contains_key(&txid) {
            return Err(MempoolError::Duplicate(txid));
        }
        if inner.queue.len() >= MAX_MEMPOOL {
            return Err(MempoolError::Full);
        }

        inner.seen.insert(txid, ());
        inner.queue.push_back(tx);
        Ok(())
    }

    /// Drain up to `max` txs for batch assembly.
    pub fn drain(&self, max: usize) -> Vec<L2Tx> {
        let mut inner = self.inner.lock().unwrap();
        let n = max.min(inner.queue.len());
        let txs: Vec<L2Tx> = inner.queue.drain(..n).collect();
        for tx in &txs {
            inner.seen.remove(&tx.txid());
        }
        txs
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Validate an L2 tx: structure + Dilithium signatures.
/// The UTXO set existence check is deferred to the guest (full state not available here).
fn validate_tx(tx: &L2Tx) -> Result<(), MempoolError> {
    if tx.inputs.is_empty() {
        return Err(MempoolError::NoInputs);
    }
    if tx.body.outputs.is_empty() {
        return Err(MempoolError::NoOutputs);
    }

    let sig_hash = tx.sig_hash();

    for (idx, input) in tx.inputs.iter().enumerate() {
        // Verify the verkey and signature
        let vk = MLDSA44VerificationKey::new(*input.verification_key);
        let sig = MLDSA44Signature::new(*input.signature);
        ml_dsa_44::verify(&vk, &sig_hash, b"", &sig).map_err(|_| MempoolError::BadSignature(idx))?;
    }

    // Overflow check on outputs
    let mut total: u64 = tx.body.fee;
    for out in &tx.body.outputs {
        total = total.checked_add(out.amount).ok_or(MempoolError::Overflow)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::{
        KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE,
        ml_dsa_44::{self, MLDSA44SigningKey},
    };
    use rand::{TryRngCore, rngs::OsRng};
    use sophis_rollup_core::{L2Address, L2TxBody, L2TxInput, L2TxOutput, L2UtxoId};

    fn make_signed_tx(amount: u64) -> L2Tx {
        let mut seed = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        OsRng.try_fill_bytes(&mut seed).expect("os entropy");
        let keypair = ml_dsa_44::generate_key_pair(seed);
        let vk_bytes: [u8; 1312] = *keypair.verification_key.as_ref();
        let sk_bytes: [u8; 2560] = *keypair.signing_key.as_ref();

        let addr = L2Address::from_verkey(&vk_bytes);
        let utxo_id = L2UtxoId { txid: [1u8; 32], index: 0 };

        let body = L2TxBody { input_utxo_ids: vec![utxo_id.clone()], outputs: vec![L2TxOutput { address: addr, amount }], fee: 0 };
        let tx_no_sig = L2Tx { body: body.clone(), inputs: vec![] };
        let sig_hash = tx_no_sig.sig_hash();

        let sk = MLDSA44SigningKey::new(sk_bytes);
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        OsRng.try_fill_bytes(&mut randomness).expect("os entropy");
        let sig: [u8; 2420] = *ml_dsa_44::sign(&sk, &sig_hash, b"", randomness).unwrap().as_ref();

        L2Tx { body, inputs: vec![L2TxInput { utxo_id, verification_key: Box::new(vk_bytes), signature: Box::new(sig) }] }
    }

    #[test]
    fn valid_tx_accepted() {
        let pool = Mempool::new();
        let tx = make_signed_tx(1_000);
        assert!(pool.push(tx).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn duplicate_rejected() {
        let pool = Mempool::new();
        let tx = make_signed_tx(1_000);
        pool.push(tx.clone()).unwrap();
        let err = pool.push(tx).unwrap_err();
        assert!(matches!(err, MempoolError::Duplicate(_)));
    }

    #[test]
    fn drain_returns_requested_count() {
        let pool = Mempool::new();
        pool.push(make_signed_tx(100)).unwrap();
        pool.push(make_signed_tx(200)).unwrap();
        pool.push(make_signed_tx(300)).unwrap();

        let batch = pool.drain(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn drain_removes_from_seen_allowing_resubmission() {
        let pool = Mempool::new();
        let tx = make_signed_tx(500);
        pool.push(tx.clone()).unwrap();
        pool.drain(1);
        // After drain, txid is removed from `seen` → same tx can be re-submitted
        assert!(pool.push(tx).is_ok());
    }

    #[test]
    fn bad_signature_rejected() {
        let pool = Mempool::new();
        let mut tx = make_signed_tx(1_000);
        // Corrupt the signature
        tx.inputs[0].signature[0] ^= 0xFF;
        let err = pool.push(tx).unwrap_err();
        assert!(matches!(err, MempoolError::BadSignature(0)));
    }

    #[test]
    fn no_inputs_rejected() {
        let pool = Mempool::new();
        let tx = L2Tx {
            body: L2TxBody {
                input_utxo_ids: vec![],
                outputs: vec![L2TxOutput { address: L2Address([0u8; 48]), amount: 100 }],
                fee: 0,
            },
            inputs: vec![],
        };
        assert!(matches!(pool.push(tx), Err(MempoolError::NoInputs)));
    }

    #[test]
    fn no_outputs_rejected() {
        // Can't easily make a signed tx with no outputs through the normal path,
        // so verify the rule directly via validate_tx
        let body = L2TxBody { input_utxo_ids: vec![], outputs: vec![], fee: 0 };
        let tx = L2Tx {
            body,
            inputs: vec![L2TxInput {
                utxo_id: L2UtxoId { txid: [0u8; 32], index: 0 },
                verification_key: Box::new([0u8; 1312]),
                signature: Box::new([0u8; 2420]),
            }],
        };
        assert!(matches!(validate_tx(&tx), Err(MempoolError::NoOutputs)));
    }
}

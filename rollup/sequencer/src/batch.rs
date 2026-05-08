use std::time::{Duration, Instant};

use libcrux_ml_dsa::{
    SIGNING_RANDOMNESS_SIZE,
    ml_dsa_44::{self, MLDSA44SigningKey},
};
use rand::{TryRngCore, rngs::OsRng};
use sha3::{Digest, Sha3_384};

use sophis_rollup_core::{Batch, BatchJournal, L2Utxo, L2UtxoId, StateRoot, hash_withdrawals, sort_utxos};
use sophis_rollup_verifier::RollupSubmission;

use crate::error::SequencerError;

// ---------------------------------------------------------------------------
// Trigger
// ---------------------------------------------------------------------------

/// Decides when to flush pending txs into a batch.
/// Trigger: `pending >= max_txs` OR `elapsed >= timeout`.
pub struct BatchTrigger {
    pub max_txs: usize,
    pub timeout: Duration,
    last_flush: Instant,
}

impl BatchTrigger {
    pub fn new(max_txs: usize, timeout_secs: u64) -> Self {
        Self { max_txs, timeout: Duration::from_secs(timeout_secs), last_flush: Instant::now() }
    }

    pub fn should_flush(&self, pending: usize) -> bool {
        pending >= self.max_txs || self.last_flush.elapsed() >= self.timeout
    }

    pub fn mark_flushed(&mut self) {
        self.last_flush = Instant::now();
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.last_flush.elapsed().as_secs()
    }
}

// ---------------------------------------------------------------------------
// State transition (native — mirrors guest logic, without ZK proof)
// ---------------------------------------------------------------------------

/// Apply a batch's deposits + transactions to a UTXO set and return the new set.
/// This is the same logic as the Risc0 guest but runs natively so the sequencer
/// can compute the new state root before signing.
pub fn apply_batch(batch: &Batch, mut utxos: Vec<L2Utxo>) -> Result<Vec<L2Utxo>, SequencerError> {
    sort_utxos(&mut utxos);

    let mut map: std::collections::HashMap<L2UtxoId, L2Utxo> = utxos.into_iter().map(|u| (u.id.clone(), u)).collect();

    // Apply deposits
    for dep in &batch.deposits {
        let id = L2UtxoId { txid: dep.l1_tx_id, index: dep.l1_output_index };
        map.insert(id.clone(), L2Utxo { id, address: dep.l2_address.clone(), amount: dep.amount });
    }

    // Apply txs (no signature re-verification — already verified at mempool push)
    let mut spent = std::collections::HashSet::new();
    for tx in &batch.txs {
        let mut in_total: u64 = 0;
        for input in &tx.inputs {
            if spent.contains(&input.utxo_id) {
                return Err(SequencerError::DoubleSpend(input.utxo_id.txid));
            }
            let utxo = map.get(&input.utxo_id).ok_or(SequencerError::UtxoNotFound(input.utxo_id.txid))?;
            in_total = in_total.checked_add(utxo.amount).ok_or(SequencerError::Overflow)?;
            spent.insert(input.utxo_id.clone());
        }
        let mut out_total = tx.body.fee;
        for out in &tx.body.outputs {
            out_total = out_total.checked_add(out.amount).ok_or(SequencerError::Overflow)?;
        }
        if in_total != out_total {
            return Err(SequencerError::AmountMismatch { inputs: in_total, outputs_fee: out_total });
        }
        for input in &tx.inputs {
            map.remove(&input.utxo_id);
        }
        let txid = tx.txid();
        for (i, out) in tx.body.outputs.iter().enumerate() {
            let id = L2UtxoId { txid, index: i as u32 };
            map.insert(id.clone(), L2Utxo { id, address: out.address.clone(), amount: out.amount });
        }
    }

    let mut result: Vec<L2Utxo> = map.into_values().collect();
    sort_utxos(&mut result);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Phase 6 — DA calldata helpers
// ---------------------------------------------------------------------------

/// Encodes a batch as DA calldata. Phase 6 stores the borsh-serialized
/// `Batch` inside the V5 carrier outputs of `T_carrier`. The calldata is
/// what the rollup verifier (or any third-party replay) needs in order to
/// reproduce the state transition off-chain. Mirrors what the Risc0 guest
/// receives as private input.
pub fn batch_calldata(batch: &Batch) -> Result<Vec<u8>, SequencerError> {
    borsh::to_vec(batch).map_err(|e| SequencerError::Serialization(e.to_string()))
}

/// `bundle_id = SHA3-384(borsh(batch))` — used both as the BatchJournal's
/// `da_bundle_id` field and as the bundle_id of the V5 carrier outputs
/// in `T_carrier`. The guest computes the same value so the journal
/// produced inside the zkVM matches what the sequencer signed.
pub fn compute_da_bundle_id(calldata: &[u8]) -> [u8; 48] {
    let mut h = Sha3_384::new();
    h.update(calldata);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Journal building + signing
// ---------------------------------------------------------------------------

/// Build a BatchJournal and sign it with the sequencer's Dilithium key.
/// Phase 3: no STARK proof — sequencer attests with Dilithium signature.
///
/// Phase 6: `da_bundle_id` binds this journal to the calldata bytes the
/// sequencer publishes in a companion `T_carrier` transaction. It must
/// equal `SHA3-384(borsh::to_vec(batch))` — see `compute_da_bundle_id`.
/// Pass `[0u8; 48]` only for legacy / test paths that do not publish DA.
pub fn build_and_sign_submission(
    batch: &Batch,
    new_state_root: StateRoot,
    da_bundle_id: [u8; 48],
    signing_key: &[u8; 2560],
) -> Result<RollupSubmission, SequencerError> {
    let journal = BatchJournal {
        sequence: batch.sequence,
        prev_state_root: batch.prev_state_root.clone(),
        new_state_root,
        batch_hash: batch.hash(),
        deposit_count: batch.deposits.len() as u32,
        withdrawal_count: batch.withdrawals.len() as u32,
        withdrawals_hash: hash_withdrawals(&batch.withdrawals),
        l1_anchor_block: batch.l1_anchor_block,
        da_bundle_id,
    };

    let journal_bytes = borsh::to_vec(&journal).map_err(|e| SequencerError::Serialization(e.to_string()))?;

    // msg = SHA3-384(journal_bytes) — mirrors verifier contract's sha3_384 host call
    let msg: [u8; 48] = {
        let mut h = Sha3_384::new();
        h.update(&journal_bytes);
        h.finalize().into()
    };

    let sk = MLDSA44SigningKey::new(*signing_key);
    let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
    OsRng.try_fill_bytes(&mut randomness).expect("os entropy");
    let sig_raw = ml_dsa_44::sign(&sk, &msg, b"", randomness).map_err(|_| SequencerError::SigningFailed)?;
    let sig: [u8; 2420] = *sig_raw.as_ref();

    Ok(RollupSubmission { journal_bytes, sequencer_sig: sig })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::{
        KEY_GENERATION_RANDOMNESS_SIZE,
        ml_dsa_44::{self, MLDSA44Signature, MLDSA44VerificationKey},
    };
    use rand::TryRngCore;
    use sophis_rollup_core::{Deposit, L2Address};
    fn zero_state_root() -> StateRoot {
        StateRoot([0u8; 48])
    }

    fn empty_batch(seq: u64, prev: StateRoot) -> Batch {
        Batch { sequence: seq, l1_anchor_block: 100, prev_state_root: prev, txs: vec![], deposits: vec![], withdrawals: vec![] }
    }

    fn gen_keypair() -> ([u8; 2560], [u8; 1312]) {
        let mut seed = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        rand::rngs::OsRng.try_fill_bytes(&mut seed).expect("os entropy");
        let kp = ml_dsa_44::generate_key_pair(seed);
        let sk: [u8; 2560] = *kp.signing_key.as_ref();
        let vk: [u8; 1312] = *kp.verification_key.as_ref();
        (sk, vk)
    }

    // --- BatchTrigger ---

    #[test]
    fn trigger_fires_at_tx_count() {
        let trigger = BatchTrigger::new(3, 60);
        assert!(!trigger.should_flush(2));
        assert!(trigger.should_flush(3));
        assert!(trigger.should_flush(4));
    }

    #[test]
    fn trigger_fires_at_zero_pending_after_timeout() {
        // Use a 0-second timeout so it fires immediately
        let trigger = BatchTrigger { max_txs: 100, timeout: Duration::ZERO, last_flush: Instant::now() };
        assert!(trigger.should_flush(0));
    }

    #[test]
    fn trigger_does_not_fire_below_count_and_within_timeout() {
        let trigger = BatchTrigger::new(100, 3600);
        assert!(!trigger.should_flush(0));
        assert!(!trigger.should_flush(99));
    }

    // --- apply_batch ---

    #[test]
    fn empty_batch_returns_same_utxo_set() {
        let utxos = vec![L2Utxo { id: L2UtxoId { txid: [1u8; 32], index: 0 }, address: L2Address([2u8; 48]), amount: 1_000 }];
        let batch = empty_batch(1, zero_state_root());
        let result = apply_batch(&batch, utxos.clone()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, 1_000);
    }

    #[test]
    fn deposit_adds_utxo() {
        let batch = Batch {
            deposits: vec![Deposit { l1_tx_id: [5u8; 32], l1_output_index: 0, l2_address: L2Address([7u8; 48]), amount: 5_000 }],
            ..empty_batch(1, zero_state_root())
        };
        let result = apply_batch(&batch, vec![]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, 5_000);
    }

    // --- build_and_sign_submission ---

    #[test]
    fn submission_signature_is_verifiable() {
        let (sk, vk) = gen_keypair();
        let batch = empty_batch(1, zero_state_root());
        let new_root = StateRoot([9u8; 48]);
        let calldata = batch_calldata(&batch).unwrap();
        let bundle_id = compute_da_bundle_id(&calldata);

        let submission = build_and_sign_submission(&batch, new_root, bundle_id, &sk).unwrap();

        // Reconstruct the msg
        let msg: [u8; 48] = {
            let mut h = Sha3_384::new();
            h.update(&submission.journal_bytes);
            h.finalize().into()
        };

        let vk_obj = MLDSA44VerificationKey::new(vk);
        let sig_obj = MLDSA44Signature::new(submission.sequencer_sig);
        assert!(ml_dsa_44::verify(&vk_obj, &msg, b"", &sig_obj).is_ok(), "signature did not verify");
    }

    #[test]
    fn submission_journal_contains_correct_sequence() {
        let (sk, _) = gen_keypair();
        let batch = empty_batch(42, zero_state_root());
        let submission = build_and_sign_submission(&batch, StateRoot([1u8; 48]), [0u8; 48], &sk).unwrap();

        let journal: BatchJournal = borsh::from_slice(&submission.journal_bytes).unwrap();
        assert_eq!(journal.sequence, 42);
    }

    // --- Phase 6 — DA calldata + bundle_id ---

    #[test]
    fn da_bundle_id_is_sha3_384_of_calldata() {
        let batch = empty_batch(1, zero_state_root());
        let calldata = batch_calldata(&batch).unwrap();
        let bundle_id = compute_da_bundle_id(&calldata);

        // Reproduce the hash by hand
        let mut h = Sha3_384::new();
        h.update(&calldata);
        let expected: [u8; 48] = h.finalize().into();
        assert_eq!(bundle_id, expected);
    }

    #[test]
    fn da_bundle_id_matches_codec_bundle_id_of() {
        // Sanity: the sequencer's `compute_da_bundle_id` produces the same
        // 48 bytes as `consensus_core::da::bundle_id_of` for the same input.
        let batch = empty_batch(1, zero_state_root());
        let calldata = batch_calldata(&batch).unwrap();
        let from_sequencer = compute_da_bundle_id(&calldata);
        let from_consensus_core = sophis_consensus_core::da::bundle_id_of(&calldata);
        assert_eq!(from_sequencer, from_consensus_core);
    }

    #[test]
    fn submission_journal_carries_da_bundle_id() {
        let (sk, _) = gen_keypair();
        let batch = empty_batch(99, zero_state_root());
        let calldata = batch_calldata(&batch).unwrap();
        let bundle_id = compute_da_bundle_id(&calldata);

        let submission = build_and_sign_submission(&batch, StateRoot([0u8; 48]), bundle_id, &sk).unwrap();
        let journal: BatchJournal = borsh::from_slice(&submission.journal_bytes).unwrap();
        assert_eq!(journal.da_bundle_id, bundle_id);
        assert_ne!(journal.da_bundle_id, [0u8; 48], "non-empty batch must produce non-zero bundle_id");
    }
}

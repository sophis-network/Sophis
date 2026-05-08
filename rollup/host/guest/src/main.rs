//! Risc0 guest — L2 state transition function.
//!
//! Runs inside the zkVM. Receives private inputs (batch + UTXO set),
//! verifies every Dilithium signature, applies the state transition,
//! and commits the public BatchJournal for on-chain verification.

#![no_main]

use std::collections::{HashMap, HashSet};

use libcrux_ml_dsa::ml_dsa_44;
use risc0_zkvm::guest::env;
use sha3::{Digest, Sha3_384};
use sophis_rollup_core::{
    compute_state_root, hash_withdrawals, sort_utxos,
    types::{Batch, BatchJournal, L2Utxo, L2UtxoId},
    RollupError,
};

risc0_zkvm::guest::entry!(main);

fn main() {
    // Inputs are borsh-encoded on the host side and wrapped in Vec<u8> for
    // risc0's serde-based transport.
    let batch: Batch =
        borsh::from_slice(&env::read::<Vec<u8>>()).expect("batch deserialization failed");
    let mut utxos: Vec<L2Utxo> =
        borsh::from_slice(&env::read::<Vec<u8>>()).expect("utxo deserialization failed");

    // Sort for deterministic Merkle root
    sort_utxos(&mut utxos);

    let journal = process_batch(batch, utxos).expect("state transition failed");
    // Commit using borsh — avoids serde array-size limitations
    let journal_bytes = borsh::to_vec(&journal).expect("journal serialization failed");
    env::commit_slice(&journal_bytes);
}

fn process_batch(batch: Batch, utxos: Vec<L2Utxo>) -> Result<BatchJournal, RollupError> {
    // --- 1. Verify prev state root ---
    let computed_prev = compute_state_root(&utxos);
    if computed_prev != batch.prev_state_root {
        return Err(RollupError::StateRootMismatch {
            expected: batch.prev_state_root.0,
            got: computed_prev.0,
        });
    }

    // --- 2. Build UTXO index ---
    let mut utxo_map: HashMap<L2UtxoId, L2Utxo> =
        utxos.into_iter().map(|u| (u.id.clone(), u)).collect();

    // --- 3. Apply deposits (L1 → L2): mint UTXOs, no signature needed ---
    for deposit in &batch.deposits {
        let id = L2UtxoId {
            txid: deposit.l1_tx_id,
            index: deposit.l1_output_index,
        };
        utxo_map.insert(
            id.clone(),
            L2Utxo { id, address: deposit.l2_address.clone(), amount: deposit.amount },
        );
    }

    // --- 4. Process L2 transactions ---
    let mut spent: HashSet<L2UtxoId> = HashSet::new();

    for tx in &batch.txs {
        let sig_hash = tx.sig_hash();

        let mut input_total: u64 = 0;

        for (inp_idx, input) in tx.inputs.iter().enumerate() {
            // Double-spend guard
            if spent.contains(&input.utxo_id) {
                return Err(RollupError::DoubleSpend(input.utxo_id.txid));
            }

            // UTXO must exist
            let utxo = utxo_map
                .get(&input.utxo_id)
                .ok_or_else(|| RollupError::UtxoNotFound(input.utxo_id.txid))?;

            // Address must match verkey (ownership proof)
            let vk_hash: [u8; 48] = {
                let mut h = Sha3_384::new();
                h.update(input.verification_key.as_ref());
                h.finalize().into()
            };
            if vk_hash != utxo.address.0 {
                return Err(RollupError::AddressMismatch(inp_idx));
            }

            // Dilithium ML-DSA-44 signature verification.
            // MLDSA44VerificationKey::new / MLDSA44Signature::new just wrap
            // the raw bytes without fallible parsing; verify() does the crypto check.
            let vk = ml_dsa_44::MLDSA44VerificationKey::new(*input.verification_key);
            let sig = ml_dsa_44::MLDSA44Signature::new(*input.signature);
            ml_dsa_44::verify(&vk, &sig_hash, b"", &sig)
                .map_err(|_| RollupError::InvalidSignature(inp_idx))?;

            input_total = input_total
                .checked_add(utxo.amount)
                .ok_or(RollupError::Overflow)?;

            spent.insert(input.utxo_id.clone());
        }

        // Conservation: inputs == outputs + fee
        let mut output_total: u64 = tx.body.fee;
        for out in &tx.body.outputs {
            output_total = output_total
                .checked_add(out.amount)
                .ok_or(RollupError::Overflow)?;
        }
        if input_total != output_total {
            return Err(RollupError::AmountMismatch {
                inputs: input_total,
                outputs_plus_fee: output_total,
            });
        }

        // Remove spent, create new outputs
        for input in &tx.inputs {
            utxo_map.remove(&input.utxo_id);
        }
        let txid = tx.txid();
        for (out_idx, out) in tx.body.outputs.iter().enumerate() {
            let id = L2UtxoId { txid, index: out_idx as u32 };
            utxo_map.insert(
                id.clone(),
                L2Utxo { id, address: out.address.clone(), amount: out.amount },
            );
        }
    }

    // --- 5. Apply withdrawals: burn L2 UTXOs (they were spent in step 4 via bridge tx) ---
    // Withdrawal commitments are carried in the journal; the L1 bridge contract
    // releases SPHS when it sees them in a verified BatchJournal.

    // --- 6. Compute new state root ---
    let mut new_utxos: Vec<L2Utxo> = utxo_map.into_values().collect();
    sort_utxos(&mut new_utxos);
    let new_state_root = compute_state_root(&new_utxos);

    let batch_hash = batch.hash();

    // Phase 6 — `da_bundle_id = SHA3-384(borsh(batch))`. The sequencer
    // publishes the same bytes as V5 carriers in T_carrier, and any L1
    // verifier can call `Capability::VerifyDataAvailability(bundle_id)`
    // to confirm the calldata behind this proof is on-chain.
    let calldata = borsh::to_vec(&batch).map_err(|e| RollupError::Serialization(e.to_string()))?;
    let da_bundle_id: [u8; 48] = {
        let mut h = Sha3_384::new();
        h.update(&calldata);
        h.finalize().into()
    };

    Ok(BatchJournal {
        sequence: batch.sequence,
        prev_state_root: batch.prev_state_root,
        new_state_root,
        batch_hash,
        deposit_count: batch.deposits.len() as u32,
        withdrawal_count: batch.withdrawals.len() as u32,
        withdrawals_hash: hash_withdrawals(&batch.withdrawals),
        l1_anchor_block: batch.l1_anchor_block,
        da_bundle_id,
    })
}

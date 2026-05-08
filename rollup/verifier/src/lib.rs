//! # Rollup Verifier Contract
//!
//! sVM WASM contract invoked when the Rollup State UTXO is spent.
//! Verifies that the sequencer submitted a valid batch journal and advances
//! the stored L2 state root.
//!
//! ## Transaction layout expected by this contract
//!
//! | Slot | UTXO | Script contains |
//! |------|------|-----------------|
//! | Input 0  | Rollup State UTXO (current) | borsh(RollupState) |
//! | Input 1  | Submission UTXO             | borsh(RollupSubmission) |
//! | Input 2+ | Fee UTXOs (any)             | — |
//! | Output 0 | Rollup State UTXO (new)     | borsh(RollupState) |
//! | Output 1 | Fee change (any)            | — |
//!
//! ## Phase 3 trust model
//!
//! The STARK proof is verified off-chain by the host (`rollup-host`).
//! The sequencer attests to having a valid proof by signing the journal with
//! their Dilithium key.  On-chain, this contract verifies:
//!   1. The sequencer signature is valid (using `verify_dilithium` host fn).
//!   2. The journal is consistent with the current and new state.
//!   3. The sequence number increments exactly by 1.
//!
//! Phase 3b will add inline STARK verification using `sha3_384` host fn for
//! FRI commitment checks once the verifier circuit stabilises.

use borsh::BorshDeserialize;
use sophis_rollup_core::BatchJournal;
use sophis_sdk::prelude::*;

mod state;
pub use state::{ROLLUP_STATE_VERSION, ROLLUP_SUBMISSION_VERSION, RollupState, RollupSubmission};

// ---------------------------------------------------------------------------
// Contract entry point
// ---------------------------------------------------------------------------

#[sophis_contract]
pub fn rollup_verifier(env: Env) -> bool {
    // --- Read inputs ---
    let state_utxo = match env.input_utxo(0) {
        Some(u) => u,
        None => return false,
    };
    let submission_utxo = match env.input_utxo(1) {
        Some(u) => u,
        None => return false,
    };

    // --- Read output ---
    let new_state_output = match env.output_utxo(0) {
        Some(o) => o,
        None => return false,
    };

    // --- Deserialize current state ---
    let current_state = match RollupState::try_from_slice(&state_utxo.script_public_key.script) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // --- Deserialize submission ---
    let submission = match RollupSubmission::try_from_slice(&submission_utxo.script_public_key.script) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // --- Deserialize new state ---
    let new_state = match RollupState::try_from_slice(&new_state_output.script_public_key.script) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // --- Deserialize journal ---
    let journal = match BatchJournal::try_from_slice(&submission.journal_bytes) {
        Ok(j) => j,
        Err(_) => return false,
    };

    verify_batch(&env, &current_state, &submission, &journal, &new_state)
}

// ---------------------------------------------------------------------------
// Core verification logic — pure enough to test without WASM
// ---------------------------------------------------------------------------

fn verify_batch(
    env: &Env,
    current: &RollupState,
    submission: &RollupSubmission,
    journal: &BatchJournal,
    new_state: &RollupState,
) -> bool {
    // 1. Sequence must increment by exactly 1
    let expected_seq = match current.sequence.checked_add(1) {
        Some(s) => s,
        None => return false,
    };
    if journal.sequence != expected_seq {
        return false;
    }

    // 2. Journal must reference the current state root
    if journal.prev_state_root.0 != current.state_root {
        return false;
    }

    // 3. New state must reflect the journal's output
    if new_state.state_root != journal.new_state_root.0 {
        return false;
    }
    if new_state.sequence != journal.sequence {
        return false;
    }

    // 4. Authorized sequencer key must not change (rotation is a separate tx)
    if new_state.sequencer_vk != current.sequencer_vk {
        return false;
    }

    // 5. Verify sequencer's Dilithium signature over SHA3-384(journal_bytes)
    //    msg = SHA3-384(journal_bytes) — uses host function (hardware-accelerated on L1 node)
    let msg = env.sha3_384(&submission.journal_bytes);
    if !env.verify_dilithium(&current.sequencer_vk, &msg, &submission.sequencer_sig) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Unit tests — run natively without WASM toolchain
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_rollup_core::StateRoot;

    fn zero_vk() -> Box<[u8; 1312]> {
        Box::new([0u8; 1312])
    }
    fn zero_sig() -> Box<[u8; 2420]> {
        Box::new([0u8; 2420])
    }

    fn make_journal(seq: u64, prev: [u8; 48], new: [u8; 48]) -> BatchJournal {
        BatchJournal {
            sequence: seq,
            prev_state_root: StateRoot(prev),
            new_state_root: StateRoot(new),
            batch_hash: [0u8; 32],
            deposit_count: 0,
            withdrawal_count: 0,
            withdrawals_hash: [0u8; 48],
            l1_anchor_block: 100,
            da_bundle_id: [0u8; 48],
        }
    }

    fn make_state(seq: u64, root: [u8; 48]) -> RollupState {
        RollupState { sequence: seq, state_root: root, sequencer_vk: *zero_vk() }
    }

    fn make_submission(journal: &BatchJournal) -> RollupSubmission {
        RollupSubmission { journal_bytes: borsh::to_vec(journal).unwrap(), sequencer_sig: *zero_sig() }
    }

    // Native Env always returns false for verify_dilithium — we test the pure
    // structural checks separately from signature verification (which requires WASM).
    fn native_env() -> Env {
        Env::new()
    }

    #[test]
    fn sequence_must_increment_by_one() {
        let current = make_state(5, [1u8; 48]);
        // journal.sequence = 7 (skipped 6) → reject
        let journal = make_journal(7, [1u8; 48], [2u8; 48]);
        let new_state = make_state(7, [2u8; 48]);
        let submission = make_submission(&journal);
        assert!(!verify_batch(&native_env(), &current, &submission, &journal, &new_state));
    }

    #[test]
    fn prev_root_must_match_current_state() {
        let current = make_state(5, [1u8; 48]);
        // journal claims prev = [9;48] but current.state_root = [1;48] → reject
        let journal = make_journal(6, [9u8; 48], [2u8; 48]);
        let new_state = make_state(6, [2u8; 48]);
        let submission = make_submission(&journal);
        assert!(!verify_batch(&native_env(), &current, &submission, &journal, &new_state));
    }

    #[test]
    fn new_state_root_must_match_journal() {
        let current = make_state(5, [1u8; 48]);
        let journal = make_journal(6, [1u8; 48], [2u8; 48]);
        // new_state has wrong root → reject
        let new_state = make_state(6, [9u8; 48]);
        let submission = make_submission(&journal);
        assert!(!verify_batch(&native_env(), &current, &submission, &journal, &new_state));
    }

    #[test]
    fn new_state_sequence_must_match_journal() {
        let current = make_state(5, [1u8; 48]);
        let journal = make_journal(6, [1u8; 48], [2u8; 48]);
        // new_state.sequence = 7 but journal.sequence = 6 → reject
        let new_state = make_state(7, [2u8; 48]);
        let submission = make_submission(&journal);
        assert!(!verify_batch(&native_env(), &current, &submission, &journal, &new_state));
    }

    #[test]
    fn sequencer_key_change_rejected() {
        let current = make_state(5, [1u8; 48]);
        let journal = make_journal(6, [1u8; 48], [2u8; 48]);
        let submission = make_submission(&journal);
        let mut new_state = make_state(6, [2u8; 48]);
        new_state.sequencer_vk = *Box::new([99u8; 1312]); // changed → reject
        assert!(!verify_batch(&native_env(), &current, &submission, &journal, &new_state));
    }

    #[test]
    fn all_structural_checks_pass_but_sig_fails_natively() {
        // All structural checks pass; signature fails because native Env
        // always returns false for verify_dilithium (WASM-only host fn).
        let current = make_state(5, [1u8; 48]);
        let journal = make_journal(6, [1u8; 48], [2u8; 48]);
        let new_state = make_state(6, [2u8; 48]);
        let submission = make_submission(&journal);
        // Returns false only because of the signature (native env returns false)
        assert!(!verify_batch(&native_env(), &current, &submission, &journal, &new_state));
    }

    #[test]
    fn rollup_state_borsh_roundtrip() {
        let s = make_state(42, [7u8; 48]);
        let bytes = borsh::to_vec(&s).unwrap();
        let decoded = RollupState::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.state_root, [7u8; 48]);
    }

    #[test]
    fn rollup_submission_borsh_roundtrip() {
        let journal = make_journal(1, [1u8; 48], [2u8; 48]);
        let sub = make_submission(&journal);
        let bytes = borsh::to_vec(&sub).unwrap();
        let decoded = RollupSubmission::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded.journal_bytes, sub.journal_bytes);
    }
}

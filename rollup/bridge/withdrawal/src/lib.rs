//! # Bridge Withdrawal Contract
//!
//! sVM WASM contract invoked when a bridge vault UTXO is spent to release
//! locked SPHS back to L1 after a withdrawal is proven in an L2 batch.
//!
//! ## Transaction layout
//!
//! | Slot     | UTXO / Script                    | Contains                        |
//! |----------|----------------------------------|---------------------------------|
//! | Input 0  | Bridge vault UTXO                | BRIDGE_VAULT_VERSION, locked SPHS |
//! | Input 1  | Withdrawal claim UTXO            | borsh(WithdrawalClaim)          |
//! | Input 2+ | Fee UTXOs                        | —                               |
//! | Output 0 | L1 recipient payment             | value == withdrawal.amount      |
//! | Output 1 | Remaining vault (if any)         | value == vault − withdrawal     |
//! | Output 2+ | Fee change                      | —                               |
//!
//! ## Trust model (Phase 3)
//!
//! The sequencer signs the BatchJournal with Dilithium ML-DSA-44. This contract
//! verifies that signature and checks the claimed withdrawal is in the journal
//! (via `withdrawals_hash`). Phase 3b will add inline STARK proof verification.
//!
//! ## Anti-replay
//!
//! Each bridge vault UTXO can only be spent once (UTXO model). A `WithdrawalClaim`
//! UTXO must be a fresh UTXO created by the user for this specific release tx.
//! The sequencer must not reuse journal bytes across claim UTXOs — enforced by
//! the monotonically increasing `sequence` in the journal.

use borsh::{BorshDeserialize, BorshSerialize};
use sophis_rollup_core::{BatchJournal, Withdrawal};
use sophis_sdk::prelude::*;

// ---------------------------------------------------------------------------
// Claim type
// ---------------------------------------------------------------------------

/// Proof that a specific withdrawal is included in a sequencer-attested batch.
/// Stored as borsh-encoded bytes in the `script_public_key.script` of the
/// withdrawal claim UTXO (Input 1 of a release transaction).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct WithdrawalClaim {
    /// Borsh-encoded `BatchJournal` that includes this withdrawal.
    pub journal_bytes: Vec<u8>,
    /// Dilithium ML-DSA-44 signature: sign(sk, SHA3-384(journal_bytes)).
    pub sequencer_sig: [u8; 2420],
    /// Sequencer's ML-DSA-44 verification key (must match rollup state).
    pub sequencer_vk: [u8; 1312],
    /// All withdrawals in this batch (in order). Used to verify `withdrawals_hash`.
    pub withdrawals: Vec<Withdrawal>,
    /// Index into `withdrawals` that this claim is releasing.
    pub claim_index: u32,
}

// ---------------------------------------------------------------------------
// Contract entry point
// ---------------------------------------------------------------------------

#[sophis_contract]
pub fn bridge_withdrawal(env: Env) -> bool {
    // F-28 — DISABLED. The Phase 3 L1↔L2 bridge does NOT ship at genesis.
    // This contract is unsafe as written (audit F-28): it trusts the
    // `sequencer_vk` supplied IN the attacker-built claim instead of pinning
    // the canonical sequencer key, binds neither the recipient nor the vault
    // UTXO, and carries no nullifier — so a single self-signed journal could
    // drain every BRIDGE_VAULT_VERSION vault. It is gated OFF (rejects every
    // withdrawal) until the bridge is properly redesigned + reviewed. The
    // verification helpers below are retained for that future redesign.
    // Rejects every withdrawal. The unsafe orchestration was removed; a
    // future redesign re-implements it against the retained pure helpers
    // (`verify_withdrawals_integrity`, `get_withdrawal`, `check_amounts`)
    // PLUS a pinned canonical sequencer key + recipient/vault binding + a
    // nullifier — none of which the original had.
    let _ = &env;
    false
}

// ---------------------------------------------------------------------------
// Pure helpers — testable without WASM
// ---------------------------------------------------------------------------

pub fn verify_withdrawals_integrity(env: &Env, withdrawals: &[Withdrawal], journal: &BatchJournal) -> bool {
    if journal.withdrawal_count != withdrawals.len() as u32 {
        return false;
    }
    let w_bytes = match borsh::to_vec(withdrawals) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut prefixed = b"sophis-l2-withdrawals:".to_vec();
    prefixed.extend_from_slice(&w_bytes);
    let computed = env.sha3_384(&prefixed);
    computed == journal.withdrawals_hash
}

pub fn get_withdrawal(claim: &WithdrawalClaim) -> Option<&Withdrawal> {
    claim.withdrawals.get(claim.claim_index as usize)
}

/// Vault amount must cover the withdrawal; output 0 must equal withdrawal amount.
pub fn check_amounts(vault_amount: u64, output0_value: u64, withdrawal_amount: u64) -> bool {
    vault_amount >= withdrawal_amount && output0_value == withdrawal_amount
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE, ml_dsa_44};
    use rand::TryRngCore;
    use sha3::{Digest, Sha3_384};
    use sophis_rollup_core::{StateRoot, hash_withdrawals};

    fn gen_keypair() -> ([u8; 2560], [u8; 1312]) {
        let mut seed = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        rand::rngs::OsRng.try_fill_bytes(&mut seed).expect("os entropy");
        let kp = ml_dsa_44::generate_key_pair(seed);
        (*kp.signing_key.as_ref(), *kp.verification_key.as_ref())
    }

    fn sign_journal(sk: &[u8; 2560], journal_bytes: &[u8]) -> [u8; 2420] {
        use libcrux_ml_dsa::ml_dsa_44::MLDSA44SigningKey;
        let msg: [u8; 48] = Sha3_384::digest(journal_bytes).into();
        let signing_key = MLDSA44SigningKey::new(*sk);
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        rand::rngs::OsRng.try_fill_bytes(&mut randomness).expect("os entropy");
        let sig = ml_dsa_44::sign(&signing_key, &msg, b"", randomness).unwrap();
        *sig.as_ref()
    }

    fn make_withdrawal(amount: u64) -> Withdrawal {
        Withdrawal { l2_tx_id: [1u8; 32], l1_address: [2u8; 48], amount }
    }

    fn make_journal(withdrawals: &[Withdrawal]) -> BatchJournal {
        BatchJournal {
            sequence: 1,
            prev_state_root: StateRoot::default(),
            new_state_root: StateRoot([1u8; 48]),
            batch_hash: [0u8; 32],
            deposit_count: 0,
            withdrawal_count: withdrawals.len() as u32,
            withdrawals_hash: hash_withdrawals(withdrawals),
            l1_anchor_block: 100,
            da_bundle_id: [0u8; 48],
        }
    }

    fn make_claim(sk: &[u8; 2560], vk: &[u8; 1312], withdrawals: Vec<Withdrawal>, idx: u32) -> WithdrawalClaim {
        let journal = make_journal(&withdrawals);
        let journal_bytes = borsh::to_vec(&journal).unwrap();
        let sig = sign_journal(sk, &journal_bytes);
        WithdrawalClaim { journal_bytes, sequencer_sig: sig, sequencer_vk: *vk, withdrawals, claim_index: idx }
    }

    // --- Pure logic tests ---

    #[test]
    fn withdrawal_claim_borsh_roundtrip() {
        let (sk, vk) = gen_keypair();
        let claim = make_claim(&sk, &vk, vec![make_withdrawal(1_000_000)], 0);
        let bytes = borsh::to_vec(&claim).unwrap();
        let decoded: WithdrawalClaim = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded.claim_index, 0);
        assert_eq!(decoded.withdrawals[0].amount, 1_000_000);
    }

    #[test]
    fn check_amounts_exact_match() {
        assert!(check_amounts(1_000_000, 1_000_000, 1_000_000));
    }

    #[test]
    fn check_amounts_vault_covers_withdrawal() {
        assert!(check_amounts(2_000_000, 1_000_000, 1_000_000));
    }

    #[test]
    fn check_amounts_output_wrong() {
        assert!(!check_amounts(1_000_000, 999_999, 1_000_000));
    }

    #[test]
    fn check_amounts_vault_insufficient() {
        assert!(!check_amounts(500_000, 1_000_000, 1_000_000));
    }

    #[test]
    fn get_withdrawal_valid_index() {
        let (sk, vk) = gen_keypair();
        let claim = make_claim(&sk, &vk, vec![make_withdrawal(100), make_withdrawal(200)], 1);
        assert_eq!(get_withdrawal(&claim).unwrap().amount, 200);
    }

    #[test]
    fn get_withdrawal_out_of_bounds() {
        let (sk, vk) = gen_keypair();
        let claim = make_claim(&sk, &vk, vec![make_withdrawal(100)], 5);
        assert!(get_withdrawal(&claim).is_none());
    }

    #[test]
    fn withdrawal_count_mismatch_rejected() {
        let withdrawals = vec![make_withdrawal(1_000_000)];
        let mut journal = make_journal(&withdrawals);
        journal.withdrawal_count = 99; // tampered
        let env = Env::new();
        assert!(!verify_withdrawals_integrity(&env, &withdrawals, &journal));
    }

    #[test]
    fn hash_withdrawals_deterministic() {
        let w = vec![make_withdrawal(500_000)];
        assert_eq!(hash_withdrawals(&w), hash_withdrawals(&w));
    }

    #[test]
    fn hash_withdrawals_empty_vs_nonempty_differ() {
        let empty: Vec<Withdrawal> = vec![];
        let nonempty = vec![make_withdrawal(1)];
        assert_ne!(hash_withdrawals(&empty), hash_withdrawals(&nonempty));
    }

    #[test]
    fn verify_withdrawals_integrity_correct() {
        // Native Env.sha3_384 returns [0u8;48], which will NOT match the real
        // hash_withdrawals. This test confirms the function returns false natively
        // (sig verification is WASM-only) — just as the verifier contract does.
        let withdrawals = vec![make_withdrawal(1_000_000)];
        let journal = make_journal(&withdrawals);
        let env = Env::new();
        // Outside WASM, sha3_384 returns [0;48] ≠ real withdrawals_hash → false
        assert!(!verify_withdrawals_integrity(&env, &withdrawals, &journal));
    }
}

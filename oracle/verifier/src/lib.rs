//! Phase 5 — Plonky3 verifier (host-side; the sVM contract delegates to it
//! via the new `Capability::VerifyPlonky3Proof`, added in parallel to the
//! Phase 3 `VerifyRisc0Proof`).
//!
//! Sub-phase 5.0 ships only the surface. Sub-phase 5.3 will implement the
//! verifier and add the corresponding sVM capability.

use sophis_oracle_core::OracleJournal;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("not implemented yet (sub-phase 5.3)")]
    NotImplemented,
    #[error("proof did not verify against the supplied journal")]
    ProofRejected,
}

/// Verifies that `proof_bytes` is a valid Plonky3 STARK whose public output
/// is the borsh encoding of `journal`. The contract is then free to apply
/// its own policy (publisher allow-list, sequence monotonicity, bounds sanity).
pub fn verify(_proof_bytes: &[u8], _journal: &OracleJournal) -> Result<(), VerifyError> {
    Err(VerifyError::NotImplemented)
}

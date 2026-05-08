use borsh::{BorshDeserialize, BorshSerialize};

/// Script version for Rollup State UTXOs (sVM dispatches to rollup_verifier when spent).
pub const ROLLUP_STATE_VERSION: u16 = 5;

/// Script version for Submission UTXOs (ephemeral, created per batch by sequencer).
pub const ROLLUP_SUBMISSION_VERSION: u16 = 6;

/// L1-side rollup state — stored in the `script_public_key.script` of the
/// Rollup State UTXO.  Updated every time a valid batch journal is accepted.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RollupState {
    /// Monotonically increasing batch counter. Starts at 0 (genesis state).
    pub sequence: u64,
    /// SHA3-384 Merkle root of the current L2 UTXO set.
    pub state_root: [u8; 48],
    /// Dilithium ML-DSA-44 verification key of the currently authorized sequencer.
    /// Updated via a separate sequencer-rotation transaction (Phase 3b+).
    pub sequencer_vk: [u8; 1312],
}

/// Data submitted by the sequencer alongside the batch journal.
/// Stored in the `script_public_key.script` of the Submission UTXO (Input 1).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RollupSubmission {
    /// Borsh-encoded `BatchJournal` (public output from the Risc0 guest).
    pub journal_bytes: Vec<u8>,
    /// Dilithium ML-DSA-44 signature over SHA3-384(journal_bytes).
    /// Signed by the authorized sequencer's L2 key (path m/44'/111111'/0'/1/0).
    pub sequencer_sig: [u8; 2420],
}

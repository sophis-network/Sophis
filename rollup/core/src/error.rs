use thiserror::Error;

#[derive(Debug, Error)]
pub enum RollupError {
    #[error("invalid dilithium signature on input {0}")]
    InvalidSignature(usize),

    #[error("invalid verification key on input {0}")]
    InvalidVerificationKey(usize),

    #[error("utxo not found: {0:?}")]
    UtxoNotFound([u8; 32]),

    #[error("double spend detected: {0:?}")]
    DoubleSpend([u8; 32]),

    #[error("output amount overflow")]
    Overflow,

    #[error("inputs ({inputs}) != outputs + fee ({outputs_plus_fee})")]
    AmountMismatch { inputs: u64, outputs_plus_fee: u64 },

    #[error("state root mismatch: expected {expected:?}, got {got:?}")]
    StateRootMismatch { expected: [u8; 48], got: [u8; 48] },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("address mismatch on input {0}: verification key does not match UTXO address")]
    AddressMismatch(usize),
}

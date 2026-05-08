use thiserror::Error;

#[derive(Debug, Error)]
pub enum SequencerError {
    #[error("utxo not found: {0:?}")]
    UtxoNotFound([u8; 32]),
    #[error("double spend: {0:?}")]
    DoubleSpend([u8; 32]),
    #[error("amount mismatch: inputs={inputs} outputs+fee={outputs_fee}")]
    AmountMismatch { inputs: u64, outputs_fee: u64 },
    #[error("amount overflow")]
    Overflow,
    #[error("invalid signing key")]
    InvalidSigningKey,
    #[error("signing failed")]
    SigningFailed,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("l1 client error: {0}")]
    L1Client(String),
    #[error("not authorized sequencer for current state")]
    NotAuthorized,
}

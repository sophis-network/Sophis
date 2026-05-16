//! Error types for the PSKT crate.

use sophis_txscript_errors::TxScriptError;

use crate::input::InputBuilderError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Custom(String),
    #[error(transparent)]
    ConstructorError(#[from] ConstructorError),
    #[error("OutputNotModifiable")]
    OutOfBounds,
    #[error("Missing UTXO entry")]
    MissingUtxoEntry,
    #[error("Missing redeem script")]
    MissingRedeemScript,
    #[error(transparent)]
    InputBuilder(#[from] crate::input::InputBuilderError),
    #[error(transparent)]
    OutputBuilder(#[from] crate::output::OutputBuilderError),
    #[error("Serialization error: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
    #[error("Json deserialize error: {0}")]
    JsonDeserializeError(#[from] serde_json::Error),
    #[error("Serialize error")]
    PskbSerializeError(String),
    #[error("Unlock utxo error")]
    MultipleUnlockUtxoError(Vec<Error>),
    #[error("Unlock fees exceed available amount")]
    ExcessUnlockFeeError,
    #[error("Transaction output to output conversion error")]
    TxToInnerConversionError(#[source] Box<Error>),
    #[error("Transaction input building error in conversion")]
    TxToInnerConversionInputBuildingError(#[source] InputBuilderError),
    #[error("P2SH extraction error")]
    P2SHExtractError(#[source] TxScriptError),
    #[error("PSKB hex serialization error: {0}")]
    PskbSerializeToHexError(String),
    #[error("PSKB serialization requires 'PSKB' prefix")]
    PskbPrefixError,
    #[error("PSKT serialization requires 'PSKT' prefix")]
    PsktPrefixError,
    #[error("Cannot set payload on PSKT version {0}, payload requires version 1 or higher")]
    PayloadRequiresVersion1(crate::pskt::Version),
}
#[derive(thiserror::Error, Debug)]
pub enum ConstructorError {
    #[error("InputNotModifiable")]
    InputNotModifiable,
    #[error("OutputNotModifiable")]
    OutputNotModifiable,
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self::Custom(err)
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::Custom(err.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Invalid output conversion")]
    InvalidOutput,
}

// Audit category-D coverage closure (Session 16, 2026-05-16):
// `error.rs` was at 0% coverage. The `From<String>`/`From<&str>`
// conversions and the `Display` of representative variants are pure.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_and_str_map_to_custom() {
        assert!(matches!(Error::from("boom".to_string()), Error::Custom(s) if s == "boom"));
        assert!(matches!(Error::from("bang"), Error::Custom(s) if s == "bang"));
    }

    #[test]
    fn display_messages() {
        assert_eq!(Error::MissingUtxoEntry.to_string(), "Missing UTXO entry");
        assert_eq!(Error::MissingRedeemScript.to_string(), "Missing redeem script");
        assert_eq!(Error::PskbPrefixError.to_string(), "PSKB serialization requires 'PSKB' prefix");
        assert_eq!(ConstructorError::InputNotModifiable.to_string(), "InputNotModifiable");
        assert_eq!(ConversionError::InvalidOutput.to_string(), "Invalid output conversion");
        // `#[error(transparent)]` delegates to the inner error.
        let e: Error = ConstructorError::OutputNotModifiable.into();
        assert_eq!(e.to_string(), "OutputNotModifiable");
    }
}

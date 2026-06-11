use crate::script_builder::{ScriptBuilder, ScriptBuilderError};
use std::borrow::Borrow;
use thiserror::Error;

#[derive(Error, PartialEq, Eq, Debug, Clone)]
pub enum Error {
    // ErrTooManyRequiredSigs is returned from multisig_script when the
    // specified number of required signatures is larger than the number of
    // provided public keys.
    #[error("too many required signatures")]
    ErrTooManyRequiredSigs,
    #[error(transparent)]
    ScriptBuilderError(#[from] ScriptBuilderError),
    #[error("provided public keys should not be empty")]
    EmptyKeys,
    #[error(
        "OP_CHECKMULTISIG is disabled in Sophis (PQC-only); a multisig redeem script would be unspendable — build multisig at the Dilithium contract layer"
    )]
    OpcodeDisabled,
}
pub fn multisig_redeem_script(pub_keys: impl Iterator<Item = impl Borrow<[u8; 32]>>, required: usize) -> Result<Vec<u8>, Error> {
    if pub_keys.size_hint().1.is_some_and(|upper| upper < required) {
        return Err(Error::ErrTooManyRequiredSigs);
    }
    let mut builder = ScriptBuilder::new();
    builder.add_i64(required as i64)?;

    let mut count = 0i64;
    for pub_key in pub_keys {
        count += 1;
        builder.add_data(pub_key.borrow().as_slice())?;
    }

    if (count as usize) < required {
        return Err(Error::ErrTooManyRequiredSigs);
    }
    if count == 0 {
        return Err(Error::EmptyKeys);
    }

    // F-37 — refuse to emit the script. `OP_CHECKMULTISIG` is unconditionally
    // disabled by the Sophis script engine (PQC-only: see `op_check_multisig_disabled`),
    // so any P2SH output built from this redeem script would be permanently
    // UNSPENDABLE — a silent fund-loss footgun. Multisig must be built at the
    // Dilithium contract layer instead. The arity validations above are kept so
    // callers still get the precise input error before this.
    let _ = count;
    Err(Error::OpcodeDisabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    #[test]
    fn test_too_many_required_sigs() {
        let result = multisig_redeem_script(iter::once([0u8; 32]), 2);
        assert_eq!(result, Err(Error::ErrTooManyRequiredSigs));
    }

    #[test]
    fn test_empty_keys() {
        let result = multisig_redeem_script(std::iter::empty::<[u8; 32]>(), 0);
        assert_eq!(result, Err(Error::EmptyKeys));
    }

    #[test]
    fn test_valid_input_refused_as_disabled() {
        // F-37 — a well-formed request that would previously have produced an
        // OP_CHECKMULTISIG (unspendable) redeem script must now be refused.
        let result = multisig_redeem_script(iter::once([7u8; 32]), 1);
        assert_eq!(result, Err(Error::OpcodeDisabled));
    }
}

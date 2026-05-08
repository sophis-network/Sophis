use crate::opcodes::codes::OpCheckMultiSig;
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

    builder.add_i64(count)?;
    builder.add_op(OpCheckMultiSig)?;

    Ok(builder.drain())
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
}

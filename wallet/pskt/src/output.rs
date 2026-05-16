//! PSKT output structure.

use crate::utils::combine_if_no_conflicts;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use sophis_consensus_core::tx::ScriptPublicKey;
use std::{collections::BTreeMap, ops::Add};

#[derive(Builder, Default, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[builder(default)]
pub struct Output {
    /// The output's amount (serialized as sompi).
    pub amount: u64,
    /// The script for this output, also known as the scriptPubKey.
    pub script_public_key: ScriptPublicKey,
    #[builder(setter(strip_option))]
    #[serde(with = "sophis_utils::serde_bytes_optional")]
    /// The redeem script for this output.
    pub redeem_script: Option<Vec<u8>>,
    /// Proprietary key-value pairs for this output.
    pub proprietaries: BTreeMap<String, serde_value::Value>,
    #[serde(flatten)]
    /// Unknown key-value pairs for this output.
    pub unknowns: BTreeMap<String, serde_value::Value>,
}

impl Add for Output {
    type Output = Result<Self, CombineError>;

    fn add(mut self, rhs: Self) -> Self::Output {
        if self.amount != rhs.amount {
            return Err(CombineError::AmountMismatch { this: self.amount, that: rhs.amount });
        }
        if self.script_public_key != rhs.script_public_key {
            return Err(CombineError::ScriptPubkeyMismatch { this: self.script_public_key, that: rhs.script_public_key });
        }
        self.redeem_script = match (self.redeem_script.take(), rhs.redeem_script) {
            (None, None) => None,
            (Some(script), None) | (None, Some(script)) => Some(script),
            (Some(script_left), Some(script_right)) if script_left == script_right => Some(script_left),
            (Some(script_left), Some(script_right)) => {
                return Err(CombineError::NotCompatibleRedeemScripts { this: script_left, that: script_right });
            }
        };
        self.proprietaries =
            combine_if_no_conflicts(self.proprietaries, rhs.proprietaries).map_err(CombineError::NotCompatibleProprietary)?;
        self.unknowns = combine_if_no_conflicts(self.unknowns, rhs.unknowns).map_err(CombineError::NotCompatibleUnknownField)?;

        Ok(self)
    }
}

/// Error combining two output maps.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum CombineError {
    #[error("The amounts are not the same")]
    AmountMismatch {
        /// Attempted to combine a PSKT with `this` previous txid.
        this: u64,
        /// Into a PSKT with `that` previous txid.
        that: u64,
    },
    #[error("The script_pubkeys are not the same")]
    ScriptPubkeyMismatch {
        /// Attempted to combine a PSKT with `this` script_pubkey.
        this: ScriptPublicKey,
        /// Into a PSKT with `that` script_pubkey.
        that: ScriptPublicKey,
    },
    #[error("Two different redeem scripts detected")]
    NotCompatibleRedeemScripts { this: Vec<u8>, that: Vec<u8> },

    #[error("Two different unknown field values")]
    NotCompatibleUnknownField(crate::utils::Error<String, serde_value::Value>),
    #[error("Two different proprietary values")]
    NotCompatibleProprietary(crate::utils::Error<String, serde_value::Value>),
}

// Audit category-D coverage closure (Session 16, 2026-05-16):
// `output.rs` was at 0% line coverage. `Output::add` is the PSKT
// "combine" merge — pure, every branch (amount/spk mismatch, all four
// redeem-script combinations, proprietary conflict) is exercised here.
#[cfg(test)]
mod tests {
    use super::*;
    use sophis_consensus_core::tx::{ScriptPublicKey, ScriptVec};

    fn spk(b: u8) -> ScriptPublicKey {
        ScriptPublicKey::new(0, ScriptVec::from_slice(&[b]))
    }

    fn out(amount: u64, spk_byte: u8) -> Output {
        OutputBuilder::default().amount(amount).script_public_key(spk(spk_byte)).build().unwrap()
    }

    #[test]
    fn identical_outputs_combine() {
        let r = (out(100, 1) + out(100, 1)).unwrap();
        assert_eq!(r.amount, 100);
        assert_eq!(r.script_public_key, spk(1));
    }

    #[test]
    fn amount_mismatch_errors() {
        assert!(matches!(out(100, 1) + out(200, 1), Err(CombineError::AmountMismatch { this: 100, that: 200 })));
    }

    #[test]
    fn script_pubkey_mismatch_errors() {
        let e = out(100, 1) + out(100, 2);
        assert!(matches!(e, Err(CombineError::ScriptPubkeyMismatch { .. })));
    }

    #[test]
    fn redeem_script_all_combinations() {
        let with = |rs: Option<&[u8]>| {
            let mut b = OutputBuilder::default();
            b.amount(100).script_public_key(spk(1));
            if let Some(r) = rs {
                b.redeem_script(r.to_vec());
            }
            b.build().unwrap()
        };
        // (None, None) → None
        assert_eq!((with(None) + with(None)).unwrap().redeem_script, None);
        // (Some, None) and (None, Some) → Some
        assert_eq!((with(Some(&[1])) + with(None)).unwrap().redeem_script, Some(vec![1]));
        assert_eq!((with(None) + with(Some(&[2]))).unwrap().redeem_script, Some(vec![2]));
        // (Some(a), Some(a)) → Some(a)
        assert_eq!((with(Some(&[9])) + with(Some(&[9]))).unwrap().redeem_script, Some(vec![9]));
        // (Some(a), Some(b)) → NotCompatibleRedeemScripts
        assert!(matches!(with(Some(&[1])) + with(Some(&[2])), Err(CombineError::NotCompatibleRedeemScripts { .. })));
    }

    #[test]
    fn conflicting_proprietary_errors() {
        let mut a = out(100, 1);
        let mut b = out(100, 1);
        a.proprietaries.insert("k".into(), serde_value::Value::U32(1));
        b.proprietaries.insert("k".into(), serde_value::Value::U32(2));
        assert!(matches!(a + b, Err(CombineError::NotCompatibleProprietary(_))));
    }
}

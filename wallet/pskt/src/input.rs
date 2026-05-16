//! PSKT input structure.

use crate::pskt::PartialSigs;
use crate::utils::{Error as CombineMapErr, combine_if_no_conflicts};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use sophis_consensus_core::{
    hashing::sighash_type::{SIG_HASH_ALL, SigHashType},
    tx::{TransactionId, TransactionOutpoint, UtxoEntry},
};
use std::{collections::BTreeMap, marker::PhantomData, ops::Add};

// todo add unknown field? combine them by deduplicating, if there are different values - return error?
#[derive(Builder, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[builder(default)]
#[builder(setter(skip))]
pub struct Input {
    #[builder(setter(strip_option))]
    pub utxo_entry: Option<UtxoEntry>,
    #[builder(setter)]
    pub previous_outpoint: TransactionOutpoint,
    /// The sequence number of this input.
    ///
    /// If omitted, assumed to be the final sequence number
    pub sequence: Option<u64>,
    #[builder(setter)]
    /// The minimum Unix timestamp that this input requires to be set as the transaction's lock time.
    pub min_time: Option<u64>,
    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig.
    pub partial_sigs: PartialSigs,
    #[builder(setter)]
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: SigHashType,
    #[serde(with = "sophis_utils::serde_bytes_optional")]
    #[builder(setter(strip_option))]
    /// The redeem script for this input.
    pub redeem_script: Option<Vec<u8>>,
    #[builder(setter(strip_option))]
    pub sig_op_count: Option<u8>,
    #[serde(with = "sophis_utils::serde_bytes_optional")]
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<Vec<u8>>,
    #[serde(skip_serializing, default)]
    pub(crate) hidden: PhantomData<()>, // prevents manual filling of fields
    #[builder(setter)]
    /// Proprietary key-value pairs for this output.
    pub proprietaries: BTreeMap<String, serde_value::Value>,
    #[serde(flatten)]
    #[builder(setter)]
    /// Unknown key-value pairs for this output.
    pub unknowns: BTreeMap<String, serde_value::Value>,
}

impl Default for Input {
    fn default() -> Self {
        Self {
            utxo_entry: Default::default(),
            previous_outpoint: Default::default(),
            sequence: Default::default(),
            min_time: Default::default(),
            partial_sigs: Default::default(),
            sighash_type: SIG_HASH_ALL,
            redeem_script: Default::default(),
            sig_op_count: Default::default(),
            final_script_sig: Default::default(),
            hidden: Default::default(),
            proprietaries: Default::default(),
            unknowns: Default::default(),
        }
    }
}

impl Add for Input {
    type Output = Result<Self, CombineError>;

    fn add(mut self, rhs: Self) -> Self::Output {
        if self.previous_outpoint.transaction_id != rhs.previous_outpoint.transaction_id {
            return Err(CombineError::PreviousTxidMismatch {
                this: self.previous_outpoint.transaction_id,
                that: rhs.previous_outpoint.transaction_id,
            });
        }

        if self.previous_outpoint.index != rhs.previous_outpoint.index {
            return Err(CombineError::SpentOutputIndexMismatch {
                this: self.previous_outpoint.index,
                that: rhs.previous_outpoint.index,
            });
        }
        self.utxo_entry = match (self.utxo_entry.take(), rhs.utxo_entry) {
            (None, None) => None,
            (Some(utxo), None) | (None, Some(utxo)) => Some(utxo),
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(left), Some(right)) => return Err(CombineError::NotCompatibleUtxos { this: left, that: right }),
        };

        // todo discuss merging. if sequence is equal - combine, otherwise use input which has bigger sequence number as is
        self.sequence = self.sequence.max(rhs.sequence);
        self.min_time = self.min_time.max(rhs.min_time);
        // Merge partial_sigs deduplicating by pubkey: BTreeMap semantics on a Vec.
        // First sig wins on conflict (lhs is authoritative); see PSBS DESIGN §5.4.
        for (pubkey, signature) in rhs.partial_sigs {
            if !self.partial_sigs.iter().any(|(existing_pk, _)| existing_pk == &pubkey) {
                self.partial_sigs.push((pubkey, signature));
            }
        }
        // todo combine sighash? or always use sighash all since all signatures must be passed after completion of construction step
        // self.sighash_type

        self.redeem_script = match (self.redeem_script.take(), rhs.redeem_script) {
            (None, None) => None,
            (Some(script), None) | (None, Some(script)) => Some(script),
            (Some(script_left), Some(script_right)) if script_left == script_right => Some(script_left),
            (Some(script_left), Some(script_right)) => {
                return Err(CombineError::NotCompatibleRedeemScripts { this: script_left, that: script_right });
            }
        };

        // todo Does Combiner allowed to change final script sig??
        self.final_script_sig = match (self.final_script_sig.take(), rhs.final_script_sig) {
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

/// Error combining two input maps.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum CombineError {
    #[error("The previous txids are not the same")]
    PreviousTxidMismatch {
        /// Attempted to combine a PSKT with `this` previous txid.
        this: TransactionId,
        /// Into a PSKT with `that` previous txid.
        that: TransactionId,
    },
    #[error("The spent output indexes are not the same")]
    SpentOutputIndexMismatch {
        /// Attempted to combine a PSKT with `this` spent output index.
        this: u32,
        /// Into a PSKT with `that` spent output index.
        that: u32,
    },
    #[error("Two different redeem scripts detected")]
    NotCompatibleRedeemScripts { this: Vec<u8>, that: Vec<u8> },
    #[error("Two different utxos detected")]
    NotCompatibleUtxos { this: UtxoEntry, that: UtxoEntry },

    #[error("Two different unknown field values")]
    NotCompatibleUnknownField(CombineMapErr<String, serde_value::Value>),
    #[error("Two different proprietary values")]
    NotCompatibleProprietary(CombineMapErr<String, serde_value::Value>),
}

// Audit category-D coverage closure (Session 16, 2026-05-16):
// `Input::add` is the PSKT combine merge for inputs (was 62.5% line
// coverage). It is pure; every branch — outpoint txid / index mismatch,
// the four utxo / redeem-script / final-script-sig combinations,
// sequence & min_time max-merge, partial-sigs dedup (first wins), and
// proprietary / unknown conflicts — is exercised here.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DILITHIUM44_SIG_SIZE, DILITHIUM44_VK_SIZE, DilithiumPubKey, Signature};
    use sophis_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionId, UtxoEntry};

    fn op(txid_byte: u8, index: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(TransactionId::from_slice(&[txid_byte; 32]), index)
    }

    fn base(txid_byte: u8, index: u32) -> Input {
        Input { previous_outpoint: op(txid_byte, index), ..Default::default() }
    }

    fn utxo(amount: u64) -> UtxoEntry {
        UtxoEntry::new(amount, ScriptPublicKey::new(0, ScriptVec::from_slice(&[1])), 0, false)
    }

    fn pk(b: u8) -> DilithiumPubKey {
        DilithiumPubKey::from_bytes([b; DILITHIUM44_VK_SIZE])
    }
    fn sig(b: u8) -> Signature {
        Signature::dilithium_ml44_from_bytes([b; DILITHIUM44_SIG_SIZE])
    }

    #[test]
    fn outpoint_txid_and_index_mismatch() {
        assert!(matches!(base(1, 0) + base(2, 0), Err(CombineError::PreviousTxidMismatch { .. })));
        assert!(matches!(base(1, 0) + base(1, 1), Err(CombineError::SpentOutputIndexMismatch { .. })));
    }

    #[test]
    fn utxo_entry_all_combinations() {
        // (None, None) → None
        assert_eq!((base(1, 0) + base(1, 0)).unwrap().utxo_entry, None);
        // (Some, None) / (None, Some) → Some
        let mut a = base(1, 0);
        a.utxo_entry = Some(utxo(50));
        assert_eq!((a.clone() + base(1, 0)).unwrap().utxo_entry, Some(utxo(50)));
        assert_eq!((base(1, 0) + a.clone()).unwrap().utxo_entry, Some(utxo(50)));
        // (Some==Some) → Some
        assert_eq!((a.clone() + a.clone()).unwrap().utxo_entry, Some(utxo(50)));
        // (Some!=Some) → NotCompatibleUtxos
        let mut b = base(1, 0);
        b.utxo_entry = Some(utxo(99));
        assert!(matches!(a + b, Err(CombineError::NotCompatibleUtxos { .. })));
    }

    #[test]
    fn sequence_and_min_time_take_max() {
        let mut a = base(1, 0);
        a.sequence = Some(5);
        a.min_time = Some(100);
        let mut b = base(1, 0);
        b.sequence = Some(9);
        b.min_time = Some(50);
        let r = (a + b).unwrap();
        assert_eq!(r.sequence, Some(9));
        assert_eq!(r.min_time, Some(100));
    }

    #[test]
    fn partial_sigs_dedup_first_wins() {
        let mut a = base(1, 0);
        a.partial_sigs = vec![(pk(1), sig(10))];
        let mut b = base(1, 0);
        // Duplicate pubkey (different sig — lhs must win) + a new pubkey.
        b.partial_sigs = vec![(pk(1), sig(99)), (pk(2), sig(20))];
        let r = (a + b).unwrap();
        assert_eq!(r.partial_sigs.len(), 2);
        let a_sig = &r.partial_sigs.iter().find(|(k, _)| *k == pk(1)).unwrap().1;
        assert_eq!(a_sig, &sig(10), "lhs signature is authoritative on pubkey conflict");
        assert!(r.partial_sigs.iter().any(|(k, _)| *k == pk(2)));
    }

    #[test]
    fn redeem_and_final_script_sig_combinations() {
        let with = |rs: Option<&[u8]>, fss: Option<&[u8]>| {
            let mut i = base(1, 0);
            i.redeem_script = rs.map(|s| s.to_vec());
            i.final_script_sig = fss.map(|s| s.to_vec());
            i
        };
        assert_eq!((with(None, None) + with(None, None)).unwrap().redeem_script, None);
        assert_eq!((with(Some(&[1]), None) + with(None, None)).unwrap().redeem_script, Some(vec![1]));
        assert_eq!((with(Some(&[7]), None) + with(Some(&[7]), None)).unwrap().redeem_script, Some(vec![7]));
        assert!(matches!(with(Some(&[1]), None) + with(Some(&[2]), None), Err(CombineError::NotCompatibleRedeemScripts { .. })));
        // final_script_sig mismatch reuses NotCompatibleRedeemScripts by design.
        assert!(matches!(with(None, Some(&[1])) + with(None, Some(&[2])), Err(CombineError::NotCompatibleRedeemScripts { .. })));
        assert_eq!((with(None, Some(&[3])) + with(None, None)).unwrap().final_script_sig, Some(vec![3]));
    }

    #[test]
    fn proprietary_and_unknown_conflicts() {
        let mut a = base(1, 0);
        let mut b = base(1, 0);
        a.proprietaries.insert("k".into(), serde_value::Value::U32(1));
        b.proprietaries.insert("k".into(), serde_value::Value::U32(2));
        assert!(matches!(a.clone() + b, Err(CombineError::NotCompatibleProprietary(_))));

        let mut c = base(1, 0);
        let mut d = base(1, 0);
        c.unknowns.insert("u".into(), serde_value::Value::U32(1));
        d.unknowns.insert("u".into(), serde_value::Value::U32(2));
        assert!(matches!(c + d, Err(CombineError::NotCompatibleUnknownField(_))));
    }
}

//! Global PSKT data.

use crate::pskt::Version;
use crate::utils::combine_if_no_conflicts;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use sophis_consensus_core::tx::TransactionId;
use std::{collections::BTreeMap, ops::Add};

#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[builder(default)]
pub struct Global {
    /// The version number of this PSKT.
    pub version: Version,
    /// The version number of the transaction being built.
    pub tx_version: u16,
    #[builder(setter(strip_option))]
    /// The transaction locktime to use if no inputs specify a required locktime.
    pub fallback_lock_time: Option<u64>,

    pub inputs_modifiable: bool,
    pub outputs_modifiable: bool,

    /// The number of inputs in this PSKT.
    pub input_count: usize,
    /// The number of outputs in this PSKT.
    pub output_count: usize,
    pub id: Option<TransactionId>,
    /// Proprietary key-value pairs for this output.
    pub proprietaries: BTreeMap<String, serde_value::Value>,
    /// Unknown key-value pairs for this output.
    #[serde(flatten)]
    pub unknowns: BTreeMap<String, serde_value::Value>,
    #[serde(with = "sophis_utils::serde_bytes_optional")]
    pub payload: Option<Vec<u8>>,
}

impl Add for Global {
    type Output = Result<Self, CombineError>;

    fn add(mut self, rhs: Self) -> Self::Output {
        if self.version != rhs.version {
            return Err(CombineError::VersionMismatch { this: self.version, that: rhs.version });
        }
        if self.tx_version != rhs.tx_version {
            return Err(CombineError::TxVersionMismatch { this: self.tx_version, that: rhs.tx_version });
        }
        self.fallback_lock_time = match (self.fallback_lock_time, rhs.fallback_lock_time) {
            (Some(lhs), Some(rhs)) if lhs != rhs => return Err(CombineError::LockTimeMismatch { this: lhs, that: rhs }),
            (Some(v), _) | (_, Some(v)) => Some(v),
            _ => None,
        };
        // todo discussable, maybe throw error
        self.inputs_modifiable &= rhs.inputs_modifiable;
        self.outputs_modifiable &= rhs.outputs_modifiable;
        self.input_count = self.input_count.max(rhs.input_count);
        self.output_count = self.output_count.max(rhs.output_count);
        self.id = match (self.id, rhs.id) {
            (Some(lhs), Some(rhs)) if lhs != rhs => return Err(CombineError::TransactionIdMismatch { this: lhs, that: rhs }),
            (Some(v), _) | (_, Some(v)) => Some(v),
            _ => None,
        };

        self.proprietaries =
            combine_if_no_conflicts(self.proprietaries, rhs.proprietaries).map_err(CombineError::NotCompatibleProprietary)?;
        self.unknowns = combine_if_no_conflicts(self.unknowns, rhs.unknowns).map_err(CombineError::NotCompatibleUnknownField)?;

        // Combine payloads according to the rules:
        // - Both None -> None
        // - One has payload -> use that payload
        // - Both have same payload -> use that payload
        // - Different payloads -> error
        // Payload requires version >= 1
        if (self.payload.is_some() || rhs.payload.is_some()) && self.version < Version::One {
            return Err(CombineError::PayloadRequiresHigherVersion { version: self.version });
        }
        self.payload = match (self.payload.take(), rhs.payload) {
            (None, None) => None,
            (Some(p), None) | (None, Some(p)) => Some(p),
            (Some(lhs), Some(rhs)) if lhs == rhs => Some(lhs),
            (Some(lhs), Some(rhs)) => return Err(CombineError::PayloadMismatch { this: Some(lhs), that: Some(rhs) }),
        };

        Ok(self)
    }
}

impl Default for Global {
    fn default() -> Self {
        Global {
            version: Version::Zero,
            tx_version: sophis_consensus_core::constants::TX_VERSION,
            fallback_lock_time: None,
            inputs_modifiable: false,
            outputs_modifiable: false,
            input_count: 0,
            output_count: 0,
            id: None,
            proprietaries: Default::default(),
            unknowns: Default::default(),
            payload: None,
        }
    }
}

/// Error combining two global maps.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum CombineError {
    #[error("The version numbers are not the same")]
    /// The version numbers are not the same.
    VersionMismatch {
        /// Attempted to combine a PSKT with `this` version.
        this: Version,
        /// Into a PSKT with `that` version.
        that: Version,
    },
    #[error("The transaction version numbers are not the same")]
    TxVersionMismatch {
        /// Attempted to combine a PSKT with `this` tx version.
        this: u16,
        /// Into a PSKT with `that` tx version.
        that: u16,
    },
    #[error("The transaction lock times are not the same")]
    LockTimeMismatch {
        /// Attempted to combine a PSKT with `this` lock times.
        this: u64,
        /// Into a PSKT with `that` lock times.
        that: u64,
    },
    #[error("The transaction ids are not the same")]
    TransactionIdMismatch {
        /// Attempted to combine a PSKT with `this` tx id.
        this: TransactionId,
        /// Into a PSKT with `that` tx id.
        that: TransactionId,
    },

    #[error("Two different unknown field values")]
    NotCompatibleUnknownField(crate::utils::Error<String, serde_value::Value>),
    #[error("Two different proprietary values")]
    NotCompatibleProprietary(crate::utils::Error<String, serde_value::Value>),
    #[error("The transaction payloads are not compatible")]
    PayloadMismatch {
        /// lhs
        this: Option<Vec<u8>>,
        /// rhs
        that: Option<Vec<u8>>,
    },
    #[error("Payload requires PSKT version 1 or higher, but current version is {version}")]
    PayloadRequiresHigherVersion {
        /// Current PSKT version
        version: Version,
    },
}

// Audit category-D coverage closure (Session 16, 2026-05-16):
// `global.rs` was at 8.86% line coverage. `Global::add` is the PSKT
// combine merge for global data — pure; every branch (version /
// tx_version / lock-time / tx-id mismatch, the modifiable AND-merge,
// count max, proprietary & unknown conflicts, the payload version gate,
// and all payload combinations) is exercised here.
#[cfg(test)]
mod tests {
    use super::*;

    fn g() -> Global {
        Global::default()
    }

    #[test]
    fn version_and_tx_version_mismatch() {
        let mut a = g();
        a.version = Version::One;
        assert!(matches!(a + g(), Err(CombineError::VersionMismatch { .. })));

        let mut b = g();
        b.tx_version = 99;
        assert!(matches!(b + g(), Err(CombineError::TxVersionMismatch { .. })));
    }

    #[test]
    fn fallback_lock_time_all_combinations() {
        let with = |lt: Option<u64>| {
            let mut x = g();
            x.fallback_lock_time = lt;
            x
        };
        assert_eq!((with(None) + with(None)).unwrap().fallback_lock_time, None);
        assert_eq!((with(Some(5)) + with(None)).unwrap().fallback_lock_time, Some(5));
        assert_eq!((with(None) + with(Some(7))).unwrap().fallback_lock_time, Some(7));
        assert_eq!((with(Some(9)) + with(Some(9))).unwrap().fallback_lock_time, Some(9));
        assert!(matches!(with(Some(1)) + with(Some(2)), Err(CombineError::LockTimeMismatch { .. })));
    }

    #[test]
    fn modifiable_and_counts_merge() {
        let mut a = g();
        a.inputs_modifiable = true;
        a.outputs_modifiable = true;
        a.input_count = 2;
        a.output_count = 5;
        let mut b = g();
        b.inputs_modifiable = true;
        b.outputs_modifiable = false; // AND → false
        b.input_count = 7;
        b.output_count = 3;
        let r = (a + b).unwrap();
        assert!(r.inputs_modifiable); // true & true
        assert!(!r.outputs_modifiable); // true & false
        assert_eq!(r.input_count, 7); // max
        assert_eq!(r.output_count, 5); // max
    }

    #[test]
    fn transaction_id_combinations() {
        use sophis_consensus_core::tx::TransactionId;
        let id = |b: u8| TransactionId::from_slice(&[b; 32]);
        let with = |i: Option<TransactionId>| {
            let mut x = g();
            x.id = i;
            x
        };
        assert_eq!((with(None) + with(None)).unwrap().id, None);
        assert_eq!((with(Some(id(1))) + with(None)).unwrap().id, Some(id(1)));
        assert_eq!((with(Some(id(2))) + with(Some(id(2)))).unwrap().id, Some(id(2)));
        assert!(matches!(with(Some(id(1))) + with(Some(id(2))), Err(CombineError::TransactionIdMismatch { .. })));
    }

    #[test]
    fn proprietary_and_unknown_conflicts() {
        let mut a = g();
        let mut b = g();
        a.proprietaries.insert("k".into(), serde_value::Value::U32(1));
        b.proprietaries.insert("k".into(), serde_value::Value::U32(2));
        assert!(matches!(a + b, Err(CombineError::NotCompatibleProprietary(_))));

        let mut c = g();
        let mut d = g();
        c.unknowns.insert("u".into(), serde_value::Value::U32(1));
        d.unknowns.insert("u".into(), serde_value::Value::U32(2));
        assert!(matches!(c + d, Err(CombineError::NotCompatibleUnknownField(_))));
    }

    #[test]
    fn payload_version_gate_and_combinations() {
        // version Zero (< One) + a payload → rejected.
        let mut z = g();
        z.payload = Some(vec![1]);
        assert!(matches!(z + g(), Err(CombineError::PayloadRequiresHigherVersion { .. })));

        // version One: all payload combinations.
        let v1 = |p: Option<Vec<u8>>| {
            let mut x = g();
            x.version = Version::One;
            x.payload = p;
            x
        };
        assert_eq!((v1(None) + v1(None)).unwrap().payload, None);
        assert_eq!((v1(Some(vec![1])) + v1(None)).unwrap().payload, Some(vec![1]));
        assert_eq!((v1(None) + v1(Some(vec![2]))).unwrap().payload, Some(vec![2]));
        assert_eq!((v1(Some(vec![9])) + v1(Some(vec![9]))).unwrap().payload, Some(vec![9]));
        assert!(matches!(v1(Some(vec![1])) + v1(Some(vec![2])), Err(CombineError::PayloadMismatch { .. })));
    }
}

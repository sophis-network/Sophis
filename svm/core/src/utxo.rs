use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;

use crate::manifest::ContractManifest;

/// Identifies a deployed contract by the blake2b hash of its WASM bytecode.
pub type ContractId = Hash;

/// Arbitrary serialized state carried by a Contract UTXO.
/// Consumed and re-produced on every contract execution (UTXO Puro model).
#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Datum(pub Vec<u8>);

impl Datum {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Extra data attached to a TransactionOutput that makes it a Contract UTXO.
/// Normal (P2PK) outputs carry only ScriptPublicKey + value.
/// Contract outputs additionally carry this structure.
///
/// Dispatch at validation (B3 model):
///   Normal UTXO  → txscript (Dilithium)
///   Contract UTXO → svm/runtime (Wasmtime)
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ContractUtxoData {
    /// Identifies the contract whose WASM validates spending this UTXO.
    pub contract_id: ContractId,
    /// State consumed/produced by each execution.
    pub datum: Datum,
    /// Capabilities, upgrade policy, script hash — declared immutably at deploy.
    pub manifest: ContractManifest,
}

impl ContractUtxoData {
    pub fn new(contract_id: ContractId, datum: Datum, manifest: ContractManifest) -> Self {
        Self { contract_id, datum, manifest }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::upgrade_policy::UpgradePolicy;

    #[test]
    fn datum_new_len_is_empty() {
        let empty = Datum::new(vec![]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());

        let d = Datum::new(vec![1, 2, 3, 4]);
        assert_eq!(d.len(), 4);
        assert!(!d.is_empty());
        assert_eq!(d.0, vec![1, 2, 3, 4]);

        assert!(Datum::default().is_empty());
    }

    #[test]
    fn datum_borsh_roundtrip() {
        let d = Datum::new(vec![9, 8, 7]);
        let bytes = borsh::to_vec(&d).unwrap();
        let back: Datum = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back.0, d.0);
    }

    #[test]
    fn contract_utxo_data_new_holds_fields() {
        let cid = ContractId::from_bytes([3u8; 32]);
        let datum = Datum::new(vec![0xaa, 0xbb]);
        let manifest = ContractManifest::new(ContractId::from_bytes([4u8; 32]), UpgradePolicy::Immutable, vec![Capability::ReadUtxo]);
        let u = ContractUtxoData::new(cid, datum.clone(), manifest);
        assert_eq!(u.contract_id, cid);
        assert_eq!(u.datum.0, datum.0);
        assert!(u.manifest.has_capability(&Capability::ReadUtxo));

        let bytes = borsh::to_vec(&u).unwrap();
        let back: ContractUtxoData = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back.contract_id, cid);
        assert_eq!(back.datum.0, datum.0);
    }
}

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
///   Normal UTXO  → txscript (Schnorr/Dilithium)
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

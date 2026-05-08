use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;

use crate::utxo::ContractId;

/// Payload embedded in a contract deploy transaction (tx.payload).
/// tx.subnetwork_id must be NATIVE; tx must have at least one Contract UTXO output (version=1).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ContractDeployPayload {
    /// Raw WASM bytecode — validated by svm/runtime before acceptance.
    pub wasm: Vec<u8>,
}

impl ContractDeployPayload {
    /// Computes the ContractId (blake2b-256 with "ContractWasm" domain separation).
    pub fn contract_id(&self) -> ContractId {
        hash_wasm(&self.wasm)
    }
}

/// Domain-separated blake2b-256 hash of WASM bytecode → ContractId.
pub fn hash_wasm(wasm: &[u8]) -> ContractId {
    let hash = blake2b_simd::Params::new().hash_length(32).key(b"ContractWasm").hash(wasm);
    let bytes: [u8; 32] = hash.as_bytes().try_into().expect("blake2b-256 always 32 bytes");
    Hash::from_bytes(bytes)
}

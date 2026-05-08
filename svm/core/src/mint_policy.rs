use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::token::{TokenId, hash_mint_policy};

/// Payload embedded in a Minting Policy deploy transaction (`tx.payload`).
/// The tx must be native subnetwork, have a non-empty payload, and have at least
/// one Token UTXO output (version=2) whose `token_id == token_id()`.
///
/// Structurally identical to ContractDeployPayload but domain-separated via
/// `hash_mint_policy` — the same WASM deployed as a contract vs a minting policy
/// produces different IDs and occupies different slots in the ContractStore.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MintingPolicyPayload {
    pub wasm: Vec<u8>,
}

impl MintingPolicyPayload {
    pub fn token_id(&self) -> TokenId {
        hash_mint_policy(&self.wasm)
    }
}

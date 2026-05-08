use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;

use crate::utxo::ContractId;

pub type TokenId = Hash;

/// Domain-separated blake2b-256 of Minting Policy WASM → TokenId.
/// Uses a different key than hash_wasm ("ContractWasm") so IDs never collide
/// even if the same bytecode is deployed as both a contract and a minting policy.
pub fn hash_mint_policy(wasm: &[u8]) -> TokenId {
    let hash = blake2b_simd::Params::new().hash_length(32).key(b"MintPolicy").hash(wasm);
    let bytes: [u8; 32] = hash.as_bytes().try_into().expect("blake2b-256 always 32 bytes");
    Hash::from_bytes(bytes)
}

/// Maximum byte length of the `lock_script` inside a NativeTokenUtxoData.
/// Sized to fit P2PK (34 B), P2PKH (25 B), basic multisig, and Dilithium P2SH.
pub const MAX_TOKEN_LOCK_SCRIPT_LEN: usize = 200;

/// Borsh-serialized in `script_public_key.script()` for SCRIPT_VERSION_TOKEN (version=2) UTXOs.
///
/// `lock_script` is a standard version=0 locking script (P2PK, P2SH, etc.).
/// At spend time the consensus builds a synthetic v=0 UtxoEntry from `lock_script`
/// and runs it through TxScriptEngine — this ensures the sighash is identical
/// for both the wallet (signer) and the validator (verifier).
///
/// `transfer_policy_id`: if `Some(id)`, the WASM contract at `id` is executed on
/// every spend of this UTXO. Deployed as a regular contract (ContractDeployPayload,
/// v=1 output). `None` = no transfer restrictions (pure transfer, no policy runs).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct NativeTokenUtxoData {
    pub token_id: TokenId,
    pub token_amount: u64,
    pub lock_script: Vec<u8>,
    pub transfer_policy_id: Option<ContractId>,
}

impl NativeTokenUtxoData {
    pub fn new(token_id: TokenId, token_amount: u64, lock_script: Vec<u8>) -> Self {
        Self { token_id, token_amount, lock_script, transfer_policy_id: None }
    }

    pub fn with_transfer_policy(mut self, policy_id: ContractId) -> Self {
        self.transfer_policy_id = Some(policy_id);
        self
    }
}

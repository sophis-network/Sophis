use crate::imports::*;
use crate::result::Result;
use js_sys::Array;
use sophis_consensus_client::Transaction;
use sophis_consensus_core::hashing::wasm::SighashType;
use sophis_wallet_keys::privatekey::PrivateKey;
use sophis_wasm_core::types::HexString;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Array, is_type_of = Array::is_array, typescript_type = "(PrivateKey | HexString | Uint8Array)[]")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub type PrivateKeyArrayT;
}

impl TryFrom<PrivateKeyArrayT> for Vec<PrivateKey> {
    type Error = crate::error::Error;
    fn try_from(keys: PrivateKeyArrayT) -> std::result::Result<Self, Self::Error> {
        let mut private_keys: Vec<PrivateKey> = vec![];
        for key in keys.iter() {
            private_keys
                .push(PrivateKey::try_owned_from(key).map_err(|_| Self::Error::Custom("Unable to cast PrivateKey".to_string()))?);
        }

        Ok(private_keys)
    }
}

/// `signTransaction()` is a helper function to sign a transaction using a Dilithium private key array.
/// NOTE: Schnorr/ECDSA signing has been removed. This function currently returns an error.
/// Dilithium (ML-DSA-44) transaction signing via the full wallet flow is required.
/// @category Wallet SDK
#[wasm_bindgen(js_name = "signTransaction")]
pub fn js_sign_transaction(_tx: &Transaction, _signer: &PrivateKeyArrayT, _verify_sig: bool) -> Result<Transaction> {
    Err(Error::custom("signTransaction: Schnorr/ECDSA removed. Use Dilithium wallet signing flow."))
}

/// `createInputSignature()` — removed (Schnorr/ECDSA). Use Dilithium signing instead.
/// @category Wallet SDK
#[wasm_bindgen(js_name = "createInputSignature")]
pub fn create_input_signature(
    _tx: &Transaction,
    _input_index: u8,
    _private_key: &PrivateKey,
    _sighash_type: Option<SighashType>,
) -> Result<HexString> {
    Err(Error::custom("createInputSignature: Schnorr/ECDSA removed. Use Dilithium signing."))
}

/// @category Wallet SDK
#[wasm_bindgen(js_name=signScriptHash)]
pub fn sign_script_hash(_script_hash: JsValue, _privkey: &PrivateKey) -> Result<String> {
    Err(Error::custom("signScriptHash: Schnorr/ECDSA removed. Use Dilithium signing."))
}

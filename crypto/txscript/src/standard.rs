use crate::{
    opcodes::codes::{OpBlake2b, OpCheckSigDilithium, OpData32, OpEqual},
    script_builder::{ScriptBuilder, ScriptBuilderResult},
    script_class::ScriptClass,
};
use blake2b_simd::Params;
use smallvec::SmallVec;
use sophis_addresses::{Address, Prefix, Version};
use sophis_consensus_core::tx::{ScriptPublicKey, ScriptVec};
use sophis_txscript_errors::TxScriptError;
use std::iter::once;

mod multisig;

pub use multisig::{Error as MultisigCreateError, multisig_redeem_script};

/// Creates a new script to pay a transaction output to a script hash.
/// It is expected that the input is a valid hash.
fn pay_to_script_hash(script_hash: &[u8]) -> ScriptVec {
    // TODO: use ScriptBuilder when add_op and add_data fns or equivalents are available
    assert_eq!(script_hash.len(), 32);
    SmallVec::from_iter([OpBlake2b, OpData32].iter().copied().chain(script_hash.iter().copied()).chain(once(OpEqual)))
}

/// Creates a new script to pay a transaction output to the specified address.
pub fn pay_to_address_script(address: &Address) -> ScriptPublicKey {
    let script = match address.version {
        // Dilithium addresses carry the 32-byte hash of the Dilithium public key.
        // Locking uses the same P2SH pattern; the full public key and signature are
        // provided via the redeem script at spending time.
        Version::PubKeyDilithium => pay_to_script_hash(address.payload.as_slice()),
        Version::ScriptHash => pay_to_script_hash(address.payload.as_slice()),
    };
    ScriptPublicKey::new(ScriptClass::from(address.version).version(), script)
}

/// Builds the Dilithium P2SH redeem script for a given 1312-byte verification key.
/// Format: OP_PUSHDATA2 <len_lo> <len_hi> <vk: 1312 bytes> OP_CHECKSIG_DILITHIUM
/// This redeem script is hashed (Blake2b-256) to produce the 32-byte address payload.
/// Built manually because Dilithium VK (1312 bytes) exceeds MAX_SCRIPT_ELEMENT_SIZE (520 bytes).
pub fn dilithium_redeem_script(verification_key: &[u8; 1312]) -> ScriptBuilderResult<Vec<u8>> {
    const OP_PUSHDATA2: u8 = 0x4d;
    let len = verification_key.len() as u16;
    let mut script = Vec::with_capacity(1 + 2 + verification_key.len() + 1);
    script.push(OP_PUSHDATA2);
    script.push(len as u8);
    script.push((len >> 8) as u8);
    script.extend_from_slice(verification_key);
    script.push(OpCheckSigDilithium);
    Ok(script)
}

/// Derives a PubKeyDilithium address from a Dilithium-2 verification key.
/// The address payload is Blake2b-256(redeem_script).
pub fn dilithium_address(
    verification_key: &[u8; 1312],
    prefix: sophis_addresses::Prefix,
) -> ScriptBuilderResult<sophis_addresses::Address> {
    let redeem = dilithium_redeem_script(verification_key)?;
    let hash = Params::new().hash_length(32).to_state().update(&redeem).finalize();
    Ok(sophis_addresses::Address::new(prefix, sophis_addresses::Version::PubKeyDilithium, hash.as_bytes()))
}

/// Takes a script and returns an equivalent pay-to-script-hash script
pub fn pay_to_script_hash_script(redeem_script: &[u8]) -> ScriptPublicKey {
    let redeem_script_hash = Params::new().hash_length(32).to_state().update(redeem_script).finalize();
    let script = pay_to_script_hash(redeem_script_hash.as_bytes());
    ScriptPublicKey::new(ScriptClass::ScriptHash.version(), script)
}

/// Generates a signature script that fits a pay-to-script-hash script
pub fn pay_to_script_hash_signature_script(redeem_script: Vec<u8>, signature: Vec<u8>) -> ScriptBuilderResult<Vec<u8>> {
    let redeem_script_as_data = ScriptBuilder::new().add_data(&redeem_script)?.drain();
    Ok(Vec::from_iter(signature.iter().copied().chain(redeem_script_as_data.iter().copied())))
}

/// Returns the address encoded in a script public key.
///
/// Notes:
///  - This function only works for 'standard' transaction script types.
///    Any data such as public keys which are invalid will return the
///    `TxScriptError::PubKeyFormat` error.
///
///  - In case a ScriptClass is needed by the caller, call `ScriptClass::from(address.version)`
///    or use `address.version` directly instead, where address is the successfully
///    returned address.
pub fn extract_script_pub_key_address(script_public_key: &ScriptPublicKey, prefix: Prefix) -> Result<Address, TxScriptError> {
    let class = ScriptClass::from_script(script_public_key);
    if script_public_key.version() > class.version() {
        return Err(TxScriptError::PubKeyFormat);
    }
    let script = script_public_key.script();
    match class {
        ScriptClass::NonStandard => Err(TxScriptError::PubKeyFormat),
        ScriptClass::ScriptHash => Ok(Address::new(prefix, Version::ScriptHash, &script[2..34])),
    }
}

pub mod test_helpers {
    use super::*;
    use crate::{MAX_TX_IN_SEQUENCE_NUM, opcodes::codes::OpTrue};
    use sophis_consensus_core::{
        constants::TX_VERSION,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{Transaction, TransactionInput, TransactionOutpoint, TransactionOutput},
    };

    /// Returns a P2SH script paying to an anyone-can-spend address,
    /// The second return value is a redeemScript to be used with txscript.pay_to_script_hash_signature_script
    pub fn op_true_script() -> (ScriptPublicKey, Vec<u8>) {
        let redeem_script = vec![OpTrue];
        let script_public_key = pay_to_script_hash_script(&redeem_script);
        (script_public_key, redeem_script)
    }

    /// Creates a transaction that spends the first output of provided transaction.
    /// Assumes that the output being spent has opTrueScript as its scriptPublicKey.
    /// Creates the value of the spent output minus provided `fee` (in sompi).
    pub fn create_transaction(tx_to_spend: &Transaction, fee: u64) -> Transaction {
        let (script_public_key, redeem_script) = op_true_script();
        let signature_script = pay_to_script_hash_signature_script(redeem_script, vec![]).expect("the script is canonical");
        let previous_outpoint = TransactionOutpoint::new(tx_to_spend.id(), 0);
        let input = TransactionInput::new(previous_outpoint, signature_script, MAX_TX_IN_SEQUENCE_NUM, 1);
        let output = TransactionOutput::new(tx_to_spend.outputs[0].value - fee, script_public_key);
        Transaction::new(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    }

    /// Creates a transaction that spends the outputs of specified indexes (if they exist) of every provided transaction and returns an optional change.
    /// Assumes that the outputs being spent have opTrueScript as their scriptPublicKey.
    ///
    /// If some change is provided, creates two outputs, first one with the value of the spent outputs minus `change`
    /// and `fee` (in sompi) and second one of `change` amount.
    ///
    /// If no change is provided, creates only one output with the value of the spent outputs minus and `fee` (in sompi)
    pub fn create_transaction_with_change<'a>(
        txs_to_spend: impl Iterator<Item = &'a Transaction>,
        output_indexes: Vec<usize>,
        change: Option<u64>,
        fee: u64,
    ) -> Transaction {
        let (script_public_key, redeem_script) = op_true_script();
        let signature_script = pay_to_script_hash_signature_script(redeem_script, vec![]).expect("the script is canonical");
        let mut inputs_value: u64 = 0;
        let mut inputs = vec![];
        for tx_to_spend in txs_to_spend {
            for i in output_indexes.iter().copied() {
                if i < tx_to_spend.outputs.len() {
                    let previous_outpoint = TransactionOutpoint::new(tx_to_spend.id(), i as u32);
                    inputs.push(TransactionInput::new(previous_outpoint, signature_script.clone(), MAX_TX_IN_SEQUENCE_NUM, 1));
                    inputs_value += tx_to_spend.outputs[i].value;
                }
            }
        }
        let outputs = match change {
            Some(change) => vec![
                TransactionOutput::new(inputs_value - fee - change, script_public_key.clone()),
                TransactionOutput::new(change, script_public_key),
            ],
            None => vec![TransactionOutput::new(inputs_value - fee, script_public_key.clone())],
        };
        Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_utils::hex::FromHex;

    #[test]
    fn test_extract_address_and_encode_script() {
        struct Test {
            name: &'static str,
            script_pub_key: ScriptPublicKey,
            prefix: Prefix,
            expected_address: Result<Address, TxScriptError>,
        }

        // cspell:disable
        let tests = vec![
            Test {
                name: "Testnet non standard script",
                script_pub_key: ScriptPublicKey::new(
                    0,
                    ScriptVec::from_hex("2001fc5f4e9d9879599c69a3dafdb835a7255e5f2e934e9322ecd3af190ab0f60eab").unwrap(),
                ),
                prefix: Prefix::Testnet,
                expected_address: Err(TxScriptError::PubKeyFormat),
            },
            Test {
                name: "Mainnet script with unknown version",
                script_pub_key: ScriptPublicKey::new(
                    1,
                    ScriptVec::from_hex("207bc04196f1125e4f2676cd09ed14afb77223b1f62177da5488346323eaa91a69ac").unwrap(),
                ),
                prefix: Prefix::Mainnet,
                expected_address: Err(TxScriptError::PubKeyFormat),
            },
        ];
        // cspell:enable

        for test in tests {
            let extracted = extract_script_pub_key_address(&test.script_pub_key, test.prefix);
            assert_eq!(extracted, test.expected_address, "extract address test failed for '{}'", test.name);
        }
    }
}

use crate::error::Error;
use crate::prelude::*;
use crate::pskt::{Inner as PSKTInner, PSKT};
// use crate::wasm::result;

use sophis_addresses::{Address, Prefix};
// use sophis_bip39::Prefix;
use sophis_consensus_core::network::{NetworkId, NetworkType};
use sophis_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint, UtxoEntry};

use hex;
use serde::{Deserialize, Serialize};
use sophis_consensus_core::constants::UNACCEPTED_DAA_SCORE;
use sophis_txscript::{extract_script_pub_key_address, pay_to_address_script, pay_to_script_hash_script};
use std::ops::Deref;

///
/// Bundle is a [`PSKT`] bundle - a sequence of PSKT transactions
/// meant for batch processing and transport as a
/// single serialized payload.
///
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle(pub Vec<PSKTInner>);

impl<ROLE> From<PSKT<ROLE>> for Bundle {
    fn from(pskt: PSKT<ROLE>) -> Self {
        Bundle(vec![pskt.deref().clone()])
    }
}

impl<ROLE> From<Vec<PSKT<ROLE>>> for Bundle {
    fn from(pskts: Vec<PSKT<ROLE>>) -> Self {
        let inner_list = pskts.into_iter().map(|pskt| pskt.deref().clone()).collect();
        Bundle(inner_list)
    }
}

impl Bundle {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Adds an Inner instance to the bundle
    pub fn add_inner(&mut self, inner: PSKTInner) {
        self.0.push(inner);
    }

    /// Adds a PSKT instance to the bundle
    pub fn add_pskt<ROLE>(&mut self, pskt: PSKT<ROLE>) {
        self.0.push(pskt.deref().clone());
    }

    /// Merges another bundle into the current bundle
    pub fn merge(&mut self, other: Bundle) {
        for inner in other.0 {
            self.0.push(inner);
        }
    }

    /// Iterator over the inner PSKT instances
    pub fn iter(&self) -> std::slice::Iter<'_, PSKTInner> {
        self.0.iter()
    }

    pub fn serialize(&self) -> Result<String, Error> {
        Ok(format!("PSKB{}", hex::encode(serde_json::to_string(self)?)))
    }

    pub fn deserialize(hex_data: &str) -> Result<Self, Error> {
        if let Some(hex_data) = hex_data.strip_prefix("PSKB") {
            Ok(serde_json::from_slice(hex::decode(hex_data)?.as_slice())?)
        } else {
            Err(Error::PskbPrefixError)
        }
    }

    pub fn display_format<F>(&self, network_id: NetworkId, sompi_formatter: F) -> String
    where
        F: Fn(u64, &NetworkType) -> String,
    {
        let mut result = "".to_string();

        for (pskt_index, bundle_inner) in self.0.iter().enumerate() {
            let pskt: PSKT<Signer> = PSKT::<Signer>::from(bundle_inner.to_owned());

            result.push_str(&format!("\r\nPSKT #{:02}\r\n", pskt_index + 1));

            for (key_inner, input) in pskt.clone().inputs.iter().enumerate() {
                result.push_str(&format!("Input #{:02}\r\n", key_inner + 1));

                if let Some(utxo_entry) = &input.utxo_entry {
                    result.push_str(&format!("  amount: {}\r\n", sompi_formatter(utxo_entry.amount, &NetworkType::from(network_id))));
                    result.push_str(&format!(
                        "  address: {}\r\n",
                        extract_script_pub_key_address(&utxo_entry.script_public_key, Prefix::from(network_id))
                            .expect("Input address")
                    ));
                }
            }

            result.push_str("---\r\n");

            for (key_inner, output) in pskt.clone().outputs.iter().enumerate() {
                result.push_str(&format!("Output #{:02}\r\n", key_inner + 1));
                result.push_str(&format!("  amount: {}\r\n", sompi_formatter(output.amount, &NetworkType::from(network_id))));
                result.push_str(&format!(
                    "  address: {}\r\n",
                    extract_script_pub_key_address(&output.script_public_key, Prefix::from(network_id)).expect("Input address")
                ));
            }
        }
        result
    }
}

impl AsRef<[PSKTInner]> for Bundle {
    fn as_ref(&self) -> &[PSKTInner] {
        self.0.as_slice()
    }
}

impl TryFrom<String> for Bundle {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        Bundle::deserialize(&value)
    }
}

impl TryFrom<&str> for Bundle {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self, Error> {
        Bundle::deserialize(value)
    }
}
impl TryFrom<Bundle> for String {
    type Error = Error;
    fn try_from(value: Bundle) -> Result<String, Error> {
        match Bundle::serialize(&value) {
            Ok(output) => Ok(output.to_owned()),
            Err(e) => Err(Error::PskbSerializeError(e.to_string())),
        }
    }
}

impl Default for Bundle {
    fn default() -> Self {
        Self::new()
    }
}

// Replaces pubkey placeholder in payload string when pubkey_bytes is given.
pub fn lock_script_sig_templating(payload: String, pubkey_bytes: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let payload_bytes: Vec<u8> = hex::decode(payload)?;
    lock_script_sig_templating_bytes(payload_bytes.to_vec(), pubkey_bytes)
}

pub fn lock_script_sig_templating_bytes(payload: Vec<u8>, pubkey_bytes: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut payload_bytes = payload;

    if let Some(pubkey) = pubkey_bytes {
        let placeholder = b"{{pubkey}}";

        // Search for the placeholder in payload bytes to be replaced by public key.
        if let Some(pos) = payload_bytes.windows(placeholder.len()).position(|window| window == placeholder) {
            payload_bytes.splice(pos..pos + placeholder.len(), pubkey.iter().cloned());
        }
    }
    Ok(payload_bytes)
}

pub fn script_sig_to_address(script_sig: &[u8], prefix: sophis_addresses::Prefix) -> Result<Address, Error> {
    extract_script_pub_key_address(&pay_to_script_hash_script(script_sig), prefix).map_err(Error::P2SHExtractError)
}

pub fn unlock_utxos_as_pskb(
    utxo_references: Vec<(UtxoEntry, TransactionOutpoint)>,
    recipient: &Address,
    script_sig: Vec<u8>,
    priority_fee_sompi_per_transaction: u64,
) -> Result<Bundle, Error> {
    // Fee per transaction.
    // Check if each UTXO's amounts can cover priority fee.
    utxo_references
        .iter()
        .map(|(entry, _)| {
            if entry.amount <= priority_fee_sompi_per_transaction {
                return Err(Error::ExcessUnlockFeeError);
            }
            Ok(())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let recipient_spk = pay_to_address_script(recipient);
    let (successes, errors): (Vec<_>, Vec<_>) = utxo_references
        .into_iter()
        .map(|(utxo_entry, outpoint)| {
            unlock_utxo(&utxo_entry, &outpoint, &recipient_spk, &script_sig, priority_fee_sompi_per_transaction)
        })
        .partition(Result::is_ok);

    let successful_bundles: Vec<_> = successes.into_iter().filter_map(Result::ok).collect();
    let error_list: Vec<_> = errors.into_iter().filter_map(Result::err).collect();

    if !error_list.is_empty() {
        return Err(Error::MultipleUnlockUtxoError(error_list));
    }

    let merged_bundle = successful_bundles.into_iter().fold(None, |acc: Option<Bundle>, bundle| match acc {
        Some(mut merged_bundle) => {
            merged_bundle.merge(bundle);
            Some(merged_bundle)
        }
        None => Some(bundle),
    });

    match merged_bundle {
        None => Err("Generating an empty PSKB".into()),
        Some(bundle) => Ok(bundle),
    }
}

pub fn unlock_utxo(
    utxo_entry: &UtxoEntry,
    outpoint: &TransactionOutpoint,
    script_public_key: &ScriptPublicKey,
    script_sig: &[u8],
    priority_fee_sompi: u64,
) -> Result<Bundle, Error> {
    let input = InputBuilder::default()
        .utxo_entry(utxo_entry.to_owned())
        .previous_outpoint(outpoint.to_owned())
        .sig_op_count(1)
        .redeem_script(script_sig.to_vec())
        .build()?;

    let output = OutputBuilder::default()
        .amount(utxo_entry.amount - priority_fee_sompi)
        .script_public_key(script_public_key.clone())
        .build()?;

    let pskt: PSKT<Constructor> = PSKT::<Creator>::default().constructor().input(input).output(output);
    Ok(pskt.into())
}

// Build UTXO spending PSKB with custom input and multiple outputs
// to be used in atomic transaction batch.
pub fn unlock_utxo_outputs_as_batch_transaction_pskb(
    amount: u64,
    start_address: &Address,
    script_sig: &[u8],
    destination_outputs: Vec<(Address, u64)>,
) -> Result<Bundle, Error> {
    let origin_spk = pay_to_address_script(start_address);

    let utxo_entry = UtxoEntry { amount, script_public_key: origin_spk, block_daa_score: UNACCEPTED_DAA_SCORE, is_coinbase: false };

    let input =
        InputBuilder::default().utxo_entry(utxo_entry.to_owned()).sig_op_count(1).redeem_script(script_sig.to_vec()).build()?;

    let outputs: Vec<Output> = destination_outputs
        .iter()
        .filter_map(|(address, amount)| {
            OutputBuilder::default().amount(*amount).script_public_key(pay_to_address_script(address)).build().ok()
        })
        .collect();

    let pskt: PSKT<Constructor> =
        outputs.into_iter().fold(PSKT::<Creator>::default().constructor().input(input), |pskt, output| pskt.output(output));
    Ok(pskt.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DILITHIUM44_SIG_SIZE, DILITHIUM44_VK_SIZE, DilithiumPubKey, Signature};
    use crate::prelude::*;
    use crate::role::Creator;
    use crate::role::*;
    use libcrux_ml_dsa::ml_dsa_44;
    use sophis_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
    use sophis_txscript::pay_to_script_hash_script;
    use std::str::FromStr;
    use std::sync::LazyLock;

    /// Two Dilithium keypairs derived from deterministic seeds for stable
    /// test fixtures. Returns `((vk1, sk1), (vk2, sk2), redeem_script_mock)`.
    ///
    /// The redeem script here is a placeholder fixed-byte sequence — these
    /// tests cover *bundle serialization*, not script execution. A real
    /// Dilithium-aware multisig redeem script standard is a J1 / SCS Stack
    /// concern (see `wallet/pskt/DESIGN.md` §8 and SIP-1).
    type Keypair = ([u8; DILITHIUM44_VK_SIZE], [u8; 2560]);
    static CONTEXT: LazyLock<Box<([Keypair; 2], Vec<u8>)>> = LazyLock::new(|| {
        // Deterministic seeds — tests reproducible, no randomness leak across runs.
        let seed_a: [u8; 32] = *b"PSBS_test_seed_alpha____________";
        let seed_b: [u8; 32] = *b"PSBS_test_seed_beta_____________";
        let kp_a = {
            let kp = ml_dsa_44::generate_key_pair(seed_a);
            (*kp.verification_key.as_ref(), *kp.signing_key.as_ref())
        };
        let kp_b = {
            let kp = ml_dsa_44::generate_key_pair(seed_b);
            (*kp.verification_key.as_ref(), *kp.signing_key.as_ref())
        };
        // Placeholder redeem script — opaque bytes, not consensus-valid by design.
        // 32 bytes is plausible script size for early-stage tests.
        let redeem_script: Vec<u8> = (0..32u8).collect();
        Box::new(([kp_a, kp_b], redeem_script))
    });

    fn mock_context() -> &'static ([Keypair; 2], Vec<u8>) {
        CONTEXT.as_ref()
    }

    // Mock multisig PSKT from example
    fn mock_pskt_constructor() -> PSKT<Constructor> {
        let (_, redeem_script) = mock_context();
        let pskt = PSKT::<Creator>::default().inputs_modifiable().outputs_modifiable();
        let input_0 = InputBuilder::default()
            .utxo_entry(UtxoEntry {
                amount: 12793000000000,
                script_public_key: pay_to_script_hash_script(redeem_script),
                block_daa_score: 36151168,
                is_coinbase: false,
            })
            .previous_outpoint(TransactionOutpoint {
                transaction_id: TransactionId::from_str("63020db736215f8b1105a9281f7bcbb6473d965ecc45bb2fb5da59bd35e6ff84").unwrap(),
                index: 0,
            })
            .sig_op_count(2)
            .redeem_script(redeem_script.to_owned())
            .build()
            .expect("Mock PSKT constructor");

        pskt.constructor().input(input_0)
    }

    #[test]
    fn test_pskb_serialization() {
        let constructor = mock_pskt_constructor();
        let bundle = Bundle::from(constructor.clone());

        println!("Bundle: {}", serde_json::to_string(&bundle).unwrap());

        // Serialize Bundle
        let serialized = bundle.serialize().map_err(|err| format!("Unable to serialize bundle: {err}")).unwrap();
        println!("Serialized: {}", serialized);

        assert!(!bundle.0.is_empty());

        match Bundle::deserialize(&serialized) {
            Ok(bundle_constructor_deser) => {
                println!("Deserialized: {:?}", bundle_constructor_deser);
                let pskt_constructor_deser: Option<PSKT<Constructor>> =
                    bundle_constructor_deser.0.first().map(|inner| PSKT::from(inner.clone()));
                match pskt_constructor_deser {
                    Some(_) => println!("PSKT<Constructor> deserialized successfully"),
                    None => println!("No elements in the inner list to deserialize"),
                }
            }
            Err(e) => {
                eprintln!("Failed to deserialize: {}", e);
                panic!()
            }
        }
    }

    #[test]
    fn test_pskb_bundle_creation() {
        let bundle = Bundle::new();
        assert!(bundle.0.is_empty());
    }

    #[test]
    fn test_pskb_new_with_pskt() {
        let pskt = PSKT::<Creator>::default();
        let bundle = Bundle::from(pskt);
        assert_eq!(bundle.0.len(), 1);
    }

    #[test]
    fn test_pskb_add_pskt() {
        let mut bundle = Bundle::new();
        let pskt = PSKT::<Creator>::default();
        bundle.add_pskt(pskt);
        assert_eq!(bundle.0.len(), 1);
    }

    #[test]
    fn test_pskb_merge_bundles() {
        let mut bundle1 = Bundle::new();
        let mut bundle2 = Bundle::new();

        let inner1 = PSKTInner::default();
        let inner2 = PSKTInner::default();

        bundle1.add_inner(inner1.clone());
        bundle2.add_inner(inner2.clone());

        bundle1.merge(bundle2);

        assert_eq!(bundle1.0.len(), 2);
    }

    /// Dilithium-aware tests added in K1.3 — exercise the new `crypto::*` types
    /// inside a realistic PSBS workflow shape (Input.partial_sigs population,
    /// Bundle round-trip serialization with a populated DilithiumPubKey/Signature).

    #[test]
    fn test_pskt_with_dilithium_partial_sig_roundtrip() {
        let ([(vk_a, sk_a), _], redeem_script) = mock_context();

        // Sign a fixed message with kp_a → produce a real Dilithium signature.
        let signing_key = ml_dsa_44::MLDSA44SigningKey::new(*sk_a);
        let randomness = [0xa5u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
        let signature_bytes = ml_dsa_44::sign(&signing_key, b"PSBS K1.3 test message", b"", randomness).expect("Dilithium sign");

        // Build a PSKT with one input carrying this partial signature.
        let pubkey = DilithiumPubKey::from_bytes(*vk_a);
        let signature = Signature::dilithium_ml44_from_bytes(*signature_bytes.as_ref());

        let pskt = PSKT::<Creator>::default().inputs_modifiable().outputs_modifiable();
        let mut input_0 = InputBuilder::default()
            .utxo_entry(UtxoEntry {
                amount: 1_000_000_000,
                script_public_key: pay_to_script_hash_script(redeem_script),
                block_daa_score: 0,
                is_coinbase: false,
            })
            .previous_outpoint(TransactionOutpoint {
                transaction_id: TransactionId::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
                index: 0,
            })
            .sig_op_count(1)
            .redeem_script(redeem_script.to_owned())
            .build()
            .expect("input builder");
        input_0.partial_sigs.push((pubkey.clone(), signature.clone()));

        let pskt = pskt.constructor().input(input_0);
        let bundle = Bundle::from(pskt);

        // Round-trip serialize → deserialize must preserve the (DilithiumPubKey, Signature) pair.
        let serialized = bundle.serialize().expect("bundle serialize");
        let deserialized = Bundle::deserialize(&serialized).expect("bundle deserialize");
        assert_eq!(deserialized.0.len(), 1);

        let inner = deserialized.0.first().expect("non-empty bundle");
        assert_eq!(inner.inputs.len(), 1, "input count preserved");
        let recovered = &inner.inputs[0].partial_sigs;
        assert_eq!(recovered.len(), 1, "partial_sig count preserved");
        assert_eq!(recovered[0].0, pubkey, "DilithiumPubKey preserved across serde round-trip");
        assert_eq!(recovered[0].1, signature, "Signature preserved across serde round-trip");

        // Verify the signature is itself valid (not just byte-identical).
        let vk = ml_dsa_44::MLDSA44VerificationKey::new(*vk_a);
        let sig_recovered = ml_dsa_44::MLDSA44Signature::new(*recovered[0].1.as_dilithium_ml44().expect("DilithiumML44 variant"));
        ml_dsa_44::verify(&vk, b"PSBS K1.3 test message", b"", &sig_recovered).expect("Dilithium verify after serde round-trip");
    }

    #[test]
    fn test_pskt_with_two_dilithium_partial_sigs_combine_dedup() {
        let ([(vk_a, sk_a), (vk_b, sk_b)], redeem_script) = mock_context();

        // Build two independent PSKTs, each signing the same input with a different key.
        let mk_pskt_with_sig = |vk: &[u8; DILITHIUM44_VK_SIZE], sk: &[u8; 2560]| -> Bundle {
            let signing_key = ml_dsa_44::MLDSA44SigningKey::new(*sk);
            let randomness = [0x33u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
            let sig_bytes = ml_dsa_44::sign(&signing_key, b"shared message", b"", randomness).expect("sign");
            let pubkey = DilithiumPubKey::from_bytes(*vk);
            let signature = Signature::dilithium_ml44_from_bytes(*sig_bytes.as_ref());

            let mut input_0 = InputBuilder::default()
                .utxo_entry(UtxoEntry {
                    amount: 500,
                    script_public_key: pay_to_script_hash_script(redeem_script),
                    block_daa_score: 0,
                    is_coinbase: false,
                })
                .previous_outpoint(TransactionOutpoint {
                    transaction_id: TransactionId::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                        .unwrap(),
                    index: 0,
                })
                .sig_op_count(2)
                .redeem_script(redeem_script.to_owned())
                .build()
                .expect("input builder");
            input_0.partial_sigs.push((pubkey, signature));
            Bundle::from(PSKT::<Creator>::default().inputs_modifiable().outputs_modifiable().constructor().input(input_0))
        };

        let bundle_a = mk_pskt_with_sig(vk_a, sk_a);
        let bundle_b = mk_pskt_with_sig(vk_b, sk_b);

        // Sanity: both bundles serialize.
        let _ = bundle_a.serialize().expect("A serialize");
        let _ = bundle_b.serialize().expect("B serialize");

        // Re-applying the same Bundle's first input to itself (via direct push +
        // dedup combine logic in Input::Add) tests that duplicate pubkeys do not
        // accumulate twice. We exercise the dedup contract from PSBS DESIGN §5.4.
        let pubkey_a = DilithiumPubKey::from_bytes(*vk_a);
        let pubkey_b = DilithiumPubKey::from_bytes(*vk_b);

        let mut input = InputBuilder::default()
            .utxo_entry(UtxoEntry {
                amount: 500,
                script_public_key: pay_to_script_hash_script(redeem_script),
                block_daa_score: 0,
                is_coinbase: false,
            })
            .previous_outpoint(TransactionOutpoint {
                transaction_id: TransactionId::from_str("0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
                index: 0,
            })
            .sig_op_count(2)
            .build()
            .expect("input builder");

        let dummy_sig = Signature::dilithium_ml44_from_bytes([0u8; DILITHIUM44_SIG_SIZE]);
        input.partial_sigs.push((pubkey_a.clone(), dummy_sig.clone()));
        input.partial_sigs.push((pubkey_b.clone(), dummy_sig.clone()));
        // Duplicate entry of pubkey_a — combine should drop the second.
        let mut rhs = input.clone();
        rhs.partial_sigs.push((pubkey_a.clone(), dummy_sig.clone()));

        let combined = (input + rhs).expect("combine succeeds");
        // After combine, expect 2 sigs (pubkey_a + pubkey_b), not 3.
        assert_eq!(combined.partial_sigs.len(), 2, "duplicate pubkey deduplicated by combine logic");
    }
}

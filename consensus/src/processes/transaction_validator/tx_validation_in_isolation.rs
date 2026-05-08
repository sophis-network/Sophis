use crate::constants::{MAX_SOMPI, TX_VERSION};
use sophis_consensus_core::constants::{SCRIPT_VERSION_CARRIER, SCRIPT_VERSION_CONTRACT, SCRIPT_VERSION_TOKEN};
use sophis_consensus_core::da::{MAX_CARRIER_OUTPUTS_PER_TX, parse_carrier_header};
use sophis_consensus_core::tx::Transaction;
use std::collections::HashSet;

use borsh::BorshDeserialize;
use sophis_svm_core::{
    ContractDeployPayload, ContractUtxoData, MAX_TOKEN_LOCK_SCRIPT_LEN, MintingPolicyPayload, NativeTokenUtxoData, hash_mint_policy,
    hash_wasm, upgrade_policy::UPGRADE_MIN_BLOCKS,
};
use sophis_svm_runtime::config::MAX_BYTECODE_SIZE;
use sophis_svm_runtime::validator::validate_bytecode;

use super::{
    TransactionValidator,
    errors::{TxResult, TxRuleError},
};

impl TransactionValidator {
    /// Performs a variety of transaction validation checks which are independent of any
    /// context -- header or utxo. **Note** that any check performed here should be moved to
    /// header contextual validation if it becomes HF activation dependent. This is bcs we rely
    /// on checks here to be truly independent and avoid calling it multiple times wherever possible
    /// (e.g., BBT relies on mempool in isolation checks even though virtual daa score might have changed)   
    pub fn validate_tx_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_inputs_in_isolation(tx)?;
        self.check_transaction_outputs_in_isolation(tx)?;
        self.check_coinbase_in_isolation(tx)?;

        check_transaction_output_value_ranges(tx)?;
        check_duplicate_transaction_inputs(tx)?;
        check_gas(tx)?;
        check_transaction_subnetwork(tx)?;
        check_transaction_version(tx)?;
        validate_carrier_outputs(tx)?;
        if is_contract_deploy(tx) {
            validate_contract_deploy(tx)?;
        }
        if is_mint_policy_deploy(tx) {
            validate_mint_policy_deploy(tx)?;
        } else {
            validate_token_outputs(tx)?;
        }
        Ok(())
    }

    fn check_transaction_inputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_inputs_count(tx)?;
        self.check_transaction_signature_scripts(tx)
    }

    fn check_transaction_outputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_outputs_count(tx)?;
        self.check_transaction_script_public_keys(tx)
    }

    fn check_coinbase_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        if !tx.is_coinbase() {
            return Ok(());
        }
        if !tx.inputs.is_empty() {
            return Err(TxRuleError::CoinbaseHasInputs(tx.inputs.len()));
        }

        if tx.mass() > 0 {
            return Err(TxRuleError::CoinbaseNonZeroMassCommitment);
        }

        let outputs_limit = self.ghostdag_k as u64 + 2;
        if tx.outputs.len() as u64 > outputs_limit {
            return Err(TxRuleError::CoinbaseTooManyOutputs(tx.outputs.len(), outputs_limit));
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            // Rule 14 of §5: V3 carriers are forbidden in coinbase outputs.
            if output.script_public_key.version() == SCRIPT_VERSION_CARRIER {
                return Err(TxRuleError::CarrierInCoinbase(i));
            }
            if output.script_public_key.script().len() > self.coinbase_payload_script_public_key_max_len as usize {
                return Err(TxRuleError::CoinbaseScriptPublicKeyTooLong(i));
            }
        }
        Ok(())
    }

    fn check_transaction_outputs_count(&self, tx: &Transaction) -> TxResult<()> {
        if tx.is_coinbase() {
            // We already check coinbase outputs count vs. Ghostdag K + 2
            return Ok(());
        }
        if tx.outputs.len() > self.max_tx_outputs {
            return Err(TxRuleError::TooManyOutputs(tx.outputs.len(), self.max_tx_inputs));
        }

        Ok(())
    }

    fn check_transaction_inputs_count(&self, tx: &Transaction) -> TxResult<()> {
        if !tx.is_coinbase() && tx.inputs.is_empty() {
            return Err(TxRuleError::NoTxInputs);
        }

        if tx.inputs.len() > self.max_tx_inputs {
            return Err(TxRuleError::TooManyInputs(tx.inputs.len(), self.max_tx_inputs));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    fn check_transaction_signature_scripts(&self, tx: &Transaction) -> TxResult<()> {
        if let Some(i) = tx.inputs.iter().position(|input| input.signature_script.len() > self.max_signature_script_len) {
            return Err(TxRuleError::TooBigSignatureScript(i, self.max_signature_script_len));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    // Contract UTXOs (version=1) are exempt — their script carries ContractUtxoData, which may be large.
    fn check_transaction_script_public_keys(&self, tx: &Transaction) -> TxResult<()> {
        if let Some(i) = tx.outputs.iter().position(|out| {
            let v = out.script_public_key.version();
            // Contract UTXOs (v=1), Token UTXOs (v=2), and DA carrier UTXOs (v=3) carry
            // structured data with their own length policies — exempt from the
            // max_script_public_key_len check. Carriers cap at 64 + MAX_DATA_PER_CARRIER
            // bytes via `validate_carrier_outputs`.
            v != SCRIPT_VERSION_CONTRACT
                && v != SCRIPT_VERSION_TOKEN
                && v != SCRIPT_VERSION_CARRIER
                && out.script_public_key.script().len() > self.max_script_public_key_len
        }) {
            return Err(TxRuleError::TooBigScriptPublicKey(i, self.max_script_public_key_len));
        }
        Ok(())
    }
}

/// Returns true if `tx` is a contract deploy transaction:
/// native subnetwork + non-empty payload + at least one Contract UTXO output.
pub fn is_contract_deploy(tx: &Transaction) -> bool {
    tx.subnetwork_id.is_native()
        && !tx.payload.is_empty()
        && tx.outputs.iter().any(|o| o.script_public_key.version() == SCRIPT_VERSION_CONTRACT)
}

/// Validates the deploy payload of a contract deploy transaction:
/// 1. Decodes ContractDeployPayload from tx.payload
/// 2. Validates WASM bytecode (no floats, no threads, size limit)
/// 3. Verifies each Contract UTXO output's contract_id == hash(wasm)
pub fn validate_contract_deploy(tx: &Transaction) -> TxResult<()> {
    let payload = ContractDeployPayload::try_from_slice(&tx.payload)
        .map_err(|e| TxRuleError::SvmValidationFailed(format!("invalid deploy payload: {e}")))?;

    validate_bytecode(&payload.wasm, MAX_BYTECODE_SIZE).map_err(|e| TxRuleError::SvmValidationFailed(format!("invalid WASM: {e}")))?;

    let expected_id = hash_wasm(&payload.wasm);

    for (i, output) in tx.outputs.iter().enumerate() {
        if output.script_public_key.version() != SCRIPT_VERSION_CONTRACT {
            continue;
        }
        let contract_data = ContractUtxoData::try_from_slice(output.script_public_key.script())
            .map_err(|e| TxRuleError::SvmValidationFailed(format!("output {i} malformed ContractUtxoData: {e}")))?;

        if contract_data.contract_id != expected_id {
            return Err(TxRuleError::SvmValidationFailed(format!(
                "output {i} contract_id mismatch: expected {expected_id:?}, got {:?}",
                contract_data.contract_id
            )));
        }
        if !contract_data.manifest.upgrade_policy.is_valid() {
            return Err(TxRuleError::SvmValidationFailed(format!(
                "output {i} invalid upgrade policy: timelock must be >= {UPGRADE_MIN_BLOCKS} blocks; \
                 multisig threshold must be 1..=keys.len() with at most 16 keys"
            )));
        }
    }
    Ok(())
}

/// Returns true if `tx` is a Minting Policy deploy transaction:
/// native subnetwork + non-empty payload + at least one Token UTXO output (version=2).
pub fn is_mint_policy_deploy(tx: &Transaction) -> bool {
    tx.subnetwork_id.is_native()
        && !tx.payload.is_empty()
        && tx.outputs.iter().any(|o| o.script_public_key.version() == SCRIPT_VERSION_TOKEN)
}

/// Validates the deploy payload of a Minting Policy deploy transaction:
/// 1. Decodes MintingPolicyPayload from tx.payload
/// 2. Validates WASM bytecode (no floats, no threads, size limit)
/// 3. Verifies each Token UTXO output's token_id == hash_mint_policy(wasm)
/// 4. Validates lock_script size in each Token UTXO output
pub fn validate_mint_policy_deploy(tx: &Transaction) -> TxResult<()> {
    let payload = MintingPolicyPayload::try_from_slice(&tx.payload)
        .map_err(|e| TxRuleError::SvmValidationFailed(format!("invalid mint policy payload: {e}")))?;

    validate_bytecode(&payload.wasm, MAX_BYTECODE_SIZE)
        .map_err(|e| TxRuleError::SvmValidationFailed(format!("invalid minting policy WASM: {e}")))?;

    let expected_id = hash_mint_policy(&payload.wasm);

    for (i, output) in tx.outputs.iter().enumerate() {
        if output.script_public_key.version() != SCRIPT_VERSION_TOKEN {
            continue;
        }
        let token_data = NativeTokenUtxoData::try_from_slice(output.script_public_key.script())
            .map_err(|e| TxRuleError::TokenUtxoMalformed(i, e.to_string()))?;

        if token_data.token_id != expected_id {
            return Err(TxRuleError::SvmValidationFailed(format!(
                "output {i} token_id mismatch: expected {expected_id:?}, got {:?}",
                token_data.token_id
            )));
        }
        if token_data.lock_script.len() > MAX_TOKEN_LOCK_SCRIPT_LEN {
            return Err(TxRuleError::TokenUtxoMalformed(
                i,
                format!("lock_script {} bytes exceeds max {MAX_TOKEN_LOCK_SCRIPT_LEN}", token_data.lock_script.len()),
            ));
        }
    }
    Ok(())
}

/// Validates Token UTXO outputs in non-deploy transactions (no payload).
/// Ensures every version=2 output is well-formed and lock_script is within limits.
pub fn validate_token_outputs(tx: &Transaction) -> TxResult<()> {
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.script_public_key.version() != SCRIPT_VERSION_TOKEN {
            continue;
        }
        let token_data = NativeTokenUtxoData::try_from_slice(output.script_public_key.script())
            .map_err(|e| TxRuleError::TokenUtxoMalformed(i, e.to_string()))?;
        if token_data.lock_script.len() > MAX_TOKEN_LOCK_SCRIPT_LEN {
            return Err(TxRuleError::TokenUtxoMalformed(
                i,
                format!("lock_script {} bytes exceeds max {MAX_TOKEN_LOCK_SCRIPT_LEN}", token_data.lock_script.len()),
            ));
        }
    }
    Ok(())
}

fn check_duplicate_transaction_inputs(tx: &Transaction) -> TxResult<()> {
    let mut existing = HashSet::new();
    for input in &tx.inputs {
        if !existing.insert(input.previous_outpoint) {
            return Err(TxRuleError::TxDuplicateInputs);
        }
    }
    Ok(())
}

fn check_gas(tx: &Transaction) -> TxResult<()> {
    // This should be revised if subnetworks are activated (along with other validations that weren't copied from sophisd)
    if tx.gas > 0 {
        return Err(TxRuleError::TxHasGas);
    }
    Ok(())
}

fn check_transaction_version(tx: &Transaction) -> TxResult<()> {
    if tx.version != TX_VERSION {
        return Err(TxRuleError::UnknownTxVersion(tx.version));
    }
    Ok(())
}

fn check_transaction_output_value_ranges(tx: &Transaction) -> TxResult<()> {
    let mut total: u64 = 0;
    for (i, output) in tx.outputs.iter().enumerate() {
        // V3 carrier outputs MUST have value == 0 (rule 12 of §5). Their
        // value invariant is enforced by `validate_carrier_outputs`, which
        // produces the more specific `CarrierNonZeroValue` diagnostic.
        // Skipping here also keeps zero-value carriers from tripping the
        // generic TxOutZero check.
        if output.script_public_key.version() == SCRIPT_VERSION_CARRIER {
            continue;
        }

        if output.value == 0 {
            return Err(TxRuleError::TxOutZero(i));
        }

        if output.value > MAX_SOMPI {
            return Err(TxRuleError::TxOutTooHigh(i));
        }

        if let Some(new_total) = total.checked_add(output.value) {
            total = new_total
        } else {
            return Err(TxRuleError::OutputsValueOverflow);
        }

        if total > MAX_SOMPI {
            return Err(TxRuleError::TotalTxOutTooHigh);
        }
    }

    Ok(())
}

fn check_transaction_subnetwork(tx: &Transaction) -> TxResult<()> {
    if tx.is_coinbase() || tx.subnetwork_id.is_native() {
        Ok(())
    } else {
        Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id.clone()))
    }
}

/// Phase 6 — validate every V3 carrier output in `tx`. Implements rules
/// 1-13 of §5 in `oracle/docs/PHASE6_DA_DESIGN.md`. Rule 14 (no carriers
/// in coinbase) is enforced inside `check_coinbase_in_isolation`.
///
/// Rules 1-11 are delegated to `parse_carrier_header`; rules 12 and 13
/// are checked here because they need transaction-level context (the
/// output's `value` and the count of carriers per tx).
pub fn validate_carrier_outputs(tx: &Transaction) -> TxResult<()> {
    let mut carrier_count = 0usize;
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.script_public_key.version() != SCRIPT_VERSION_CARRIER {
            continue;
        }
        carrier_count += 1;

        // Rules 1-11
        parse_carrier_header(output.script_public_key.script()).map_err(|e| TxRuleError::CarrierMalformed(i, e.to_string()))?;

        // Rule 12
        if output.value != 0 {
            return Err(TxRuleError::CarrierNonZeroValue(i, output.value));
        }
    }

    // Rule 13
    if carrier_count > MAX_CARRIER_OUTPUTS_PER_TX {
        return Err(TxRuleError::TooManyCarrierOutputs(carrier_count, MAX_CARRIER_OUTPUTS_PER_TX));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use sophis_consensus_core::{
        subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE, SubnetworkId},
        tx::{ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, scriptvec},
    };
    use sophis_core::assert_match;

    use crate::{
        constants::TX_VERSION,
        params::MAINNET_PARAMS,
        processes::transaction_validator::{TransactionValidator, errors::TxRuleError},
    };

    #[test]
    fn validate_tx_in_isolation_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity(),
            params.ghostdag_k(),
            Default::default(),
        );

        let valid_cb = Transaction::new(
            0,
            vec![],
            vec![TransactionOutput {
                value: 0x12a05f200,
                script_public_key: ScriptPublicKey::new(
                    0,
                    scriptvec!(
                        0xa9, 0x14, 0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e, 0xba,
                        0x30, 0xcd, 0x5a, 0x4b, 0x87
                    ),
                ),
            }],
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        tv.validate_tx_in_isolation(&valid_cb).unwrap();

        let valid_tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint {
                    transaction_id: TransactionId::from_slice(&[
                        0x03, 0x2e, 0x38, 0xe9, 0xc0, 0xa8, 0x4c, 0x60, 0x46, 0xd6, 0x87, 0xd1, 0x05, 0x56, 0xdc, 0xac, 0xc4, 0x1d,
                        0x27, 0x5e, 0xc5, 0x5f, 0xc0, 0x07, 0x79, 0xac, 0x88, 0xfd, 0xf3, 0x57, 0xa1, 0x87,
                    ]),
                    index: 0,
                },
                signature_script: vec![
                    0x49, // OP_DATA_73
                    0x30, 0x46, 0x02, 0x21, 0x00, 0xc3, 0x52, 0xd3, 0xdd, 0x99, 0x3a, 0x98, 0x1b, 0xeb, 0xa4, 0xa6, 0x3a, 0xd1, 0x5c,
                    0x20, 0x92, 0x75, 0xca, 0x94, 0x70, 0xab, 0xfc, 0xd5, 0x7d, 0xa9, 0x3b, 0x58, 0xe4, 0xeb, 0x5d, 0xce, 0x82, 0x02,
                    0x21, 0x00, 0x84, 0x07, 0x92, 0xbc, 0x1f, 0x45, 0x60, 0x62, 0x81, 0x9f, 0x15, 0xd3, 0x3e, 0xe7, 0x05, 0x5c, 0xf7,
                    0xb5, 0xee, 0x1a, 0xf1, 0xeb, 0xcc, 0x60, 0x28, 0xd9, 0xcd, 0xb1, 0xc3, 0xaf, 0x77, 0x48,
                    0x01, // 73-byte signature
                    0x41, // OP_DATA_65
                    0x04, 0xf4, 0x6d, 0xb5, 0xe9, 0xd6, 0x1a, 0x9d, 0xc2, 0x7b, 0x8d, 0x64, 0xad, 0x23, 0xe7, 0x38, 0x3a, 0x4e, 0x6c,
                    0xa1, 0x64, 0x59, 0x3c, 0x25, 0x27, 0xc0, 0x38, 0xc0, 0x85, 0x7e, 0xb6, 0x7e, 0xe8, 0xe8, 0x25, 0xdc, 0xa6, 0x50,
                    0x46, 0xb8, 0x2c, 0x93, 0x31, 0x58, 0x6c, 0x82, 0xe0, 0xfd, 0x1f, 0x63, 0x3f, 0x25, 0xf8, 0x7c, 0x16, 0x1b, 0xc6,
                    0xf8, 0xa6, 0x30, 0x12, 0x1d, 0xf2, 0xb3, 0xd3, // 65-byte pubkey
                ],
                sequence: u64::MAX,
                sig_op_count: 0,
            }],
            vec![
                TransactionOutput {
                    value: 0x2123e300,
                    script_public_key: ScriptPublicKey::new(
                        0,
                        scriptvec!(
                            0x76, // OP_DUP
                            0xa9, // OP_HASH160
                            0x14, // OP_DATA_20
                            0xc3, 0x98, 0xef, 0xa9, 0xc3, 0x92, 0xba, 0x60, 0x13, 0xc5, 0xe0, 0x4e, 0xe7, 0x29, 0x75, 0x5e, 0xf7,
                            0xf5, 0x8b, 0x32, 0x88, // OP_EQUALVERIFY
                            0xac  // OP_CHECKSIG
                        ),
                    ),
                },
                TransactionOutput {
                    value: 0x108e20f00,
                    script_public_key: ScriptPublicKey::new(
                        0,
                        scriptvec!(
                            0x76, // OP_DUP
                            0xa9, // OP_HASH160
                            0x14, // OP_DATA_20
                            0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
                            0xde, 0x3d, 0x7c, 0x88, // OP_EQUALVERIFY
                            0xac  // OP_CHECKSIG
                        ),
                    ),
                },
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );

        tv.validate_tx_in_isolation(&valid_tx).unwrap();

        let mut tx: Transaction = valid_tx.clone();
        tx.subnetwork_id = SubnetworkId::from_byte(3);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::SubnetworksDisabled(_)));

        let mut tx = valid_tx.clone();
        tx.inputs = vec![];
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::NoTxInputs));

        let mut tx = valid_tx.clone();
        tx.inputs = (0..params.max_tx_inputs + 1).map(|_| valid_tx.inputs[0].clone()).collect();
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooManyInputs(_, _)));

        let mut tx = valid_tx.clone();
        tx.inputs[0].signature_script = vec![0; params.max_signature_script_len + 1];
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooBigSignatureScript(_, _)));

        let mut tx = valid_tx.clone();
        tx.outputs = (0..params.max_tx_outputs + 1).map(|_| valid_tx.outputs[0].clone()).collect();
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooManyOutputs(_, _)));

        let mut tx = valid_tx.clone();
        tx.outputs[0].script_public_key = ScriptPublicKey::new(0, scriptvec![0u8; params.max_script_public_key_len + 1]);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooBigScriptPublicKey(_, _)));

        let mut tx = valid_tx.clone();
        tx.inputs.push(tx.inputs[0].clone());
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TxDuplicateInputs));

        let mut tx = valid_tx.clone();
        tx.gas = 1;
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TxHasGas));

        let mut tx = valid_tx.clone();
        tx.payload = vec![0];
        assert_match!(tv.validate_tx_in_isolation(&tx), Ok(()));

        let mut tx = valid_tx;
        tx.version = TX_VERSION + 1;
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::UnknownTxVersion(_)));
    }

    // ----------------------------------------------------------------
    // Phase 6 — V3 carrier output validation (sub-fase 6.1)
    // ----------------------------------------------------------------

    use sophis_consensus_core::constants::SCRIPT_VERSION_CARRIER;
    use sophis_consensus_core::da::{
        CARRIER_FLAG_FRAGMENTED, CARRIER_FLAG_LAST, CARRIER_HEADER_LEN, CARRIER_MAGIC, MAX_CARRIER_OUTPUTS_PER_TX,
    };

    fn carrier_script(flags: u8, count: u8, index: u8, data: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(CARRIER_HEADER_LEN + data.len());
        s.extend_from_slice(&CARRIER_MAGIC);
        s.push(flags);
        s.push(0); // reserved
        s.push(count);
        s.push(index);
        s.extend_from_slice(&(data.len() as u32).to_le_bytes());
        s.extend_from_slice(&[0u8; 48]); // bundle_id
        s.extend_from_slice(data);
        s
    }

    fn carrier_output(script_bytes: Vec<u8>, value: u64) -> TransactionOutput {
        TransactionOutput {
            value,
            script_public_key: ScriptPublicKey::new(SCRIPT_VERSION_CARRIER, scriptvec_from_slice(&script_bytes)),
        }
    }

    fn scriptvec_from_slice(s: &[u8]) -> sophis_consensus_core::tx::ScriptVec {
        s.iter().copied().collect()
    }

    fn make_validator() -> TransactionValidator {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity(),
            params.ghostdag_k(),
            Default::default(),
        )
    }

    // Reuses the canonical valid tx body from validate_tx_in_isolation_test
    // but lets the caller swap outputs.
    fn tx_with_outputs(outputs: Vec<TransactionOutput>) -> Transaction {
        Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_slice(&[0u8; 32]), index: 0 },
                signature_script: vec![0u8; 16],
                sequence: u64::MAX,
                sig_op_count: 0,
            }],
            outputs,
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        )
    }

    #[test]
    fn carrier_happy_path_single_fragment() {
        let tv = make_validator();
        let script = carrier_script(CARRIER_FLAG_LAST, 1, 0, b"hello world");
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_with_outputs(vec![payment, carrier_output(script, 0)]);
        tv.validate_tx_in_isolation(&tx).expect("happy path must validate");
    }

    #[test]
    fn carrier_happy_path_multiple_within_cap() {
        let tv = make_validator();
        // 3 fragments of a 5-fragment bundle, all in one tx
        let mut outputs =
            vec![TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) }];
        for i in 0..3u8 {
            let flags = CARRIER_FLAG_FRAGMENTED;
            let s = carrier_script(flags, 5, i, b"chunk");
            outputs.push(carrier_output(s, 0));
        }
        let tx = tx_with_outputs(outputs);
        tv.validate_tx_in_isolation(&tx).expect("multi-carrier within cap must validate");
    }

    // Rule 12 — carrier output with non-zero value
    #[test]
    fn carrier_rule_12_nonzero_value_rejected() {
        let tv = make_validator();
        let script = carrier_script(CARRIER_FLAG_LAST, 1, 0, b"data");
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_with_outputs(vec![payment, carrier_output(script, 5_000)]);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::CarrierNonZeroValue(idx, v)) => {
                assert_eq!(idx, 1);
                assert_eq!(v, 5_000);
            }
            other => panic!("expected CarrierNonZeroValue, got {other:?}"),
        }
    }

    // Rule 13 — too many carriers in a single tx
    #[test]
    fn carrier_rule_13_too_many_in_single_tx() {
        let tv = make_validator();
        let mut outputs =
            vec![TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) }];
        // build MAX + 1 carriers (each treated as count=1, last fragment)
        for _ in 0..(MAX_CARRIER_OUTPUTS_PER_TX + 1) {
            let s = carrier_script(CARRIER_FLAG_LAST, 1, 0, b"x");
            outputs.push(carrier_output(s, 0));
        }
        let tx = tx_with_outputs(outputs);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::TooManyCarrierOutputs(actual, max)) => {
                assert_eq!(actual, MAX_CARRIER_OUTPUTS_PER_TX + 1);
                assert_eq!(max, MAX_CARRIER_OUTPUTS_PER_TX);
            }
            other => panic!("expected TooManyCarrierOutputs, got {other:?}"),
        }
    }

    // Rule 14 — carrier in a coinbase tx
    #[test]
    fn carrier_rule_14_in_coinbase_rejected() {
        let tv = make_validator();
        let script = carrier_script(CARRIER_FLAG_LAST, 1, 0, b"x");
        let coinbase = Transaction::new(
            0,
            vec![],
            vec![carrier_output(script, 0)],
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            // 19-byte coinbase payload (script_public_key length prefix is 1 byte + 18 zero bytes)
            vec![0; 19],
        );
        match tv.validate_tx_in_isolation(&coinbase) {
            Err(TxRuleError::CarrierInCoinbase(idx)) => assert_eq!(idx, 0),
            other => panic!("expected CarrierInCoinbase, got {other:?}"),
        }
    }

    // Sanity — structural error from parse_carrier_header lifts to CarrierMalformed
    #[test]
    fn carrier_parse_error_lifts_to_carrier_malformed() {
        let tv = make_validator();
        // bad magic
        let mut script = carrier_script(CARRIER_FLAG_LAST, 1, 0, b"x");
        script[0] = b'X';
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_with_outputs(vec![payment, carrier_output(script, 0)]);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::CarrierMalformed(idx, msg)) => {
                assert_eq!(idx, 1);
                assert!(msg.to_lowercase().contains("magic"), "expected message to mention magic, got: {msg}");
            }
            other => panic!("expected CarrierMalformed, got {other:?}"),
        }
    }

    // Sanity — non-V3 outputs are not subject to carrier rules at all
    #[test]
    fn carrier_validation_skips_non_v3_outputs() {
        let tv = make_validator();
        // a v=0 output with junk that would fail every carrier rule, but it is v=0 not v=3
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x00, 0x00, 0x00)) };
        let tx = tx_with_outputs(vec![payment]);
        tv.validate_tx_in_isolation(&tx).expect("non-V3 outputs must not invoke carrier rules");
    }
}

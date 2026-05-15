use crate::constants::MAX_SOMPI;
use sophis_consensus_core::alt::{
    AltScriptKind, MAX_ALT_CREATIONS_PER_TX, classify_alt_script, parse_alt_creation_header, parse_alt_reference,
};
use sophis_consensus_core::constants::{MAX_TX_VERSION, SCRIPT_VERSION_CARRIER, SCRIPT_VERSION_CONTRACT, SCRIPT_VERSION_TOKEN};
use sophis_consensus_core::da::{MAX_CARRIER_OUTPUTS_PER_TX, parse_carrier_header};
use sophis_consensus_core::tx::Transaction;
use std::collections::HashSet;

use borsh::BorshDeserialize;
use sophis_svm_core::{
    ContractDeployPayload, ContractUtxoData, MAX_TOKEN_LOCK_SCRIPT_LEN, MintingPolicyPayload, NativeTokenUtxoData, hash_mint_policy,
    hash_wasm, upgrade_policy::UPGRADE_MIN_BLOCKS,
};
use sophis_svm_runtime::config::MAX_BYTECODE_SIZE;
use sophis_svm_runtime::validator::{validate_bytecode, validate_imports_against_manifest};

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
        validate_alt_outputs_and_refs(tx)?;
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
            // L1 rule 19: ALT discriminators (creation or reference) are
            // forbidden in coinbase outputs. See `docs/L1_ALT_DESIGN.md` §5.
            if classify_alt_script(output.script_public_key.script()).is_some() {
                return Err(TxRuleError::AltInCoinbase(i));
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
            // bytes via `validate_carrier_outputs`. ALT outputs (discriminators
            // 0xFD / 0xFE) are also exempt: ALT-creation can grow up to ~1 MB
            // of entries (capped by `validate_alt_outputs_and_refs`), and ALT
            // references are exactly 8 bytes (well below any sane max).
            v != SCRIPT_VERSION_CONTRACT
                && v != SCRIPT_VERSION_TOKEN
                && v != SCRIPT_VERSION_CARRIER
                && classify_alt_script(out.script_public_key.script()).is_none()
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
        // Audit/F-10 (Session 8, 2026-05-15): reject deploys whose WASM
        // imports reference host fns that the manifest does not declare,
        // OR that reference an unknown `(env, fn_name)` pair. Closes the
        // silent-third-party-library scenario where a library imports
        // verify_dilithium internally but the parent contract forgets to
        // declare VerifyDilithium and silently gets a zero-return.
        validate_imports_against_manifest(&payload.wasm, &contract_data.manifest.required_capabilities)
            .map_err(|e| TxRuleError::SvmValidationFailed(format!("output {i} imports/manifest mismatch: {e}")))?;
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
    // Versions in `[TX_VERSION, MAX_TX_VERSION]` are accepted; each version
    // may enable additional features (currently v=1 is the L1 ALT gate —
    // see `consensus/core/src/alt/` and `docs/L1_ALT_DESIGN.md` §3.1).
    // Anything above MAX_TX_VERSION is rejected as "unknown". A check for
    // `version < TX_VERSION` is omitted because TX_VERSION = 0 and tx.version
    // is unsigned, making such a comparison structurally impossible.
    if tx.version > MAX_TX_VERSION {
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
        // L1 ALT-creation outputs MUST have value == 0 (rule 2). Their
        // value invariant is enforced by `validate_alt_outputs_and_refs`,
        // which produces `AltCreationNonZeroValue`. Skip here so the
        // generic TxOutZero check does not preempt the more specific
        // diagnostic.
        if classify_alt_script(output.script_public_key.script()) == Some(AltScriptKind::Creation) {
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

/// L1 — validate every ALT-creation and ALT-reference output in `tx`.
/// Implements rules 1-14 and 18 of §5 in `docs/L1_ALT_DESIGN.md`. Rule 19
/// (no ALT outputs in coinbase) is enforced inside
/// `check_coinbase_in_isolation`. Rules 15-16 (dangling reference, index in
/// range) are enforced at `tx_validation_in_utxo_context` time, where the
/// consensus ALT registry is in scope. Rule 17 (per-block creation cap) is
/// enforced at body-level validation.
///
/// Dispatch is by the leading byte of `output.script_public_key.script()`
/// (see `classify_alt_script`). Outputs that do not match an ALT
/// discriminator are passed through silently.
pub fn validate_alt_outputs_and_refs(tx: &Transaction) -> TxResult<()> {
    let mut creation_count = 0usize;
    for (i, output) in tx.outputs.iter().enumerate() {
        let kind = match classify_alt_script(output.script_public_key.script()) {
            Some(k) => k,
            None => continue,
        };

        // Rules 1 / 13 — ALT discriminators only legal in v >= 1 transactions.
        if tx.version < 1 {
            return Err(TxRuleError::AltOutputInLegacyTx(i));
        }

        match kind {
            AltScriptKind::Creation => {
                creation_count += 1;
                // Rule 2 — value MUST be zero.
                if output.value != 0 {
                    return Err(TxRuleError::AltCreationNonZeroValue(i, output.value));
                }
                // Rules 3-12 — header + entries + handle integrity.
                parse_alt_creation_header(output.script_public_key.script())
                    .map_err(|e| TxRuleError::AltCreationMalformed(i, e.to_string()))?;
            }
            AltScriptKind::Reference => {
                // Rule 14 — reference script length must be exactly 8.
                parse_alt_reference(output.script_public_key.script())
                    .map_err(|e| TxRuleError::AltReferenceMalformed(i, e.to_string()))?;
                // Rules 15-16 deferred to utxo-context validation.
            }
        }
    }

    // Rule 18 — per-tx cap on ALT-creation outputs.
    if creation_count > MAX_ALT_CREATIONS_PER_TX {
        return Err(TxRuleError::TooManyAltCreations(creation_count, MAX_ALT_CREATIONS_PER_TX));
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
        constants::MAX_TX_VERSION,
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

        let mut tx = valid_tx.clone();
        tx.version = MAX_TX_VERSION + 1;
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::UnknownTxVersion(_)));

        // L1: v=1 is now a valid version (ALT-aware tx). The legacy test
        // above used `TX_VERSION + 1 == 1` to probe the rejection path;
        // post-MAX_TX_VERSION introduction the rejection threshold moved
        // to `MAX_TX_VERSION + 1`. v=1 alone (with no ALT outputs) must
        // pass validation.
        let mut tx = valid_tx;
        tx.version = MAX_TX_VERSION;
        assert_match!(tv.validate_tx_in_isolation(&tx), Ok(()));
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

    // ----------------------------------------------------------------
    // L1 — ALT output validation (sub-fase L1.3.a)
    // See `docs/L1_ALT_DESIGN.md` §5 for the rule numbering. Rules 1, 2,
    // 3-12, 13, 14, 18, 19 are enforced in isolation; 15-16 (utxo context)
    // and 17 (per-block) live elsewhere and have their own test suites.
    // ----------------------------------------------------------------

    use sophis_consensus_core::alt::{
        ALT_DISCRIMINATOR_REFERENCE, ALT_HANDLE_LEN, MAX_ALT_CREATIONS_PER_TX, encode_alt_creation_script, encode_alt_reference_script,
    };

    fn alt_creation_output_from_entries(entries: &[(u16, &[u8])]) -> TransactionOutput {
        let script = encode_alt_creation_script(entries).expect("encode_alt_creation_script must succeed in tests");
        TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, scriptvec_from_slice(&script)) }
    }

    fn alt_creation_output_with_value(entries: &[(u16, &[u8])], value: u64) -> TransactionOutput {
        let script = encode_alt_creation_script(entries).expect("encode_alt_creation_script must succeed in tests");
        TransactionOutput { value, script_public_key: ScriptPublicKey::new(0, scriptvec_from_slice(&script)) }
    }

    fn alt_reference_output(handle: [u8; ALT_HANDLE_LEN], index: u8, value: u64) -> TransactionOutput {
        let script = encode_alt_reference_script(handle, index);
        TransactionOutput { value, script_public_key: ScriptPublicKey::new(0, scriptvec_from_slice(&script)) }
    }

    fn tx_v1_with_outputs(outputs: Vec<TransactionOutput>) -> Transaction {
        let mut tx = tx_with_outputs(outputs);
        tx.version = MAX_TX_VERSION; // = 1
        tx
    }

    fn coinbase_v1_with_outputs(outputs: Vec<TransactionOutput>) -> Transaction {
        Transaction::new(MAX_TX_VERSION, vec![], outputs, 0, SUBNETWORK_ID_COINBASE, 0, vec![9u8; 19])
    }

    // -- Happy paths -------------------------------------------------------

    #[test]
    fn alt_happy_v1_with_creation_passes() {
        let tv = make_validator();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_v1_with_outputs(vec![payment, alt_creation_output_from_entries(&[(0u16, b"abcd")])]);
        tv.validate_tx_in_isolation(&tx).expect("v=1 tx with valid ALT-creation must validate");
    }

    #[test]
    fn alt_happy_v1_with_reference_passes() {
        let tv = make_validator();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let r = alt_reference_output([0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE], 0, 5_000);
        let tx = tx_v1_with_outputs(vec![payment, r]);
        // Note: rules 15/16 (handle existence, index range) defer to utxo context;
        // isolation accepts any well-formed reference.
        tv.validate_tx_in_isolation(&tx).expect("v=1 tx with well-formed ALT reference must pass isolation");
    }

    #[test]
    fn alt_happy_v1_no_alt_outputs_passes() {
        let tv = make_validator();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_v1_with_outputs(vec![payment]);
        tv.validate_tx_in_isolation(&tx).expect("v=1 tx with no ALT outputs must validate");
    }

    #[test]
    fn alt_v1_max_creations_within_cap_passes() {
        let tv = make_validator();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        // Exactly the cap; each ALT must have distinct handle (use distinct payloads).
        let mut outputs = vec![payment];
        for n in 0..MAX_ALT_CREATIONS_PER_TX {
            let body = vec![n as u8; 4];
            outputs.push(alt_creation_output_from_entries(&[(0u16, &body)]));
        }
        let tx = tx_v1_with_outputs(outputs);
        tv.validate_tx_in_isolation(&tx).expect("MAX_ALT_CREATIONS_PER_TX creations must pass");
    }

    // -- Rule 1 / 13 — ALT discriminator requires v >= 1 ------------------

    #[test]
    fn alt_v0_with_creation_rejected() {
        let tv = make_validator();
        // tx version = 0 (default in tx_with_outputs)
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_with_outputs(vec![payment, alt_creation_output_from_entries(&[(0u16, b"x")])]);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::AltOutputInLegacyTx(idx)) => assert_eq!(idx, 1),
            other => panic!("expected AltOutputInLegacyTx, got {other:?}"),
        }
    }

    #[test]
    fn alt_v0_with_reference_rejected() {
        let tv = make_validator();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let r = alt_reference_output([0u8; ALT_HANDLE_LEN], 0, 100);
        let tx = tx_with_outputs(vec![payment, r]);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::AltOutputInLegacyTx(idx)) => assert_eq!(idx, 1),
            other => panic!("expected AltOutputInLegacyTx, got {other:?}"),
        }
    }

    // -- Rule 2 — ALT-creation must have value 0 --------------------------

    #[test]
    fn alt_v1_creation_nonzero_value_rejected() {
        let tv = make_validator();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let bad = alt_creation_output_with_value(&[(0u16, b"abcd")], 42);
        let tx = tx_v1_with_outputs(vec![payment, bad]);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::AltCreationNonZeroValue(idx, v)) => {
                assert_eq!(idx, 1);
                assert_eq!(v, 42);
            }
            other => panic!("expected AltCreationNonZeroValue, got {other:?}"),
        }
    }

    // -- Rules 3-12 — header / entries / handle integrity (parser delegated)

    #[test]
    fn alt_v1_creation_malformed_magic_rejected() {
        let tv = make_validator();
        // Build a valid script then corrupt the magic.
        let mut script = encode_alt_creation_script(&[(0u16, b"abcd")]).unwrap();
        script[1] = b'X'; // perturb the M of "SPHS-AL1"
        let bad = TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, scriptvec_from_slice(&script)) };
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_v1_with_outputs(vec![payment, bad]);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::AltCreationMalformed(idx, msg)) => {
                assert_eq!(idx, 1);
                assert!(msg.to_lowercase().contains("magic"), "expected message to mention magic, got: {msg}");
            }
            other => panic!("expected AltCreationMalformed, got {other:?}"),
        }
    }

    #[test]
    fn alt_v1_creation_handle_mismatch_rejected() {
        let tv = make_validator();
        let mut script = encode_alt_creation_script(&[(0u16, b"abcd")]).unwrap();
        // Flip one bit of the handle (offset 16..22).
        script[16] ^= 0x01;
        let bad = TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, scriptvec_from_slice(&script)) };
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_v1_with_outputs(vec![payment, bad]);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::AltCreationMalformed(_, _)));
    }

    // -- Rule 14 — reference script length must be exactly 8 -------------

    #[test]
    fn alt_v1_reference_bad_length_rejected() {
        let tv = make_validator();
        // Discriminator + only 5 handle bytes + index = 7 bytes total (one short).
        let mut bytes = vec![ALT_DISCRIMINATOR_REFERENCE];
        bytes.extend_from_slice(&[0u8; 5]);
        bytes.push(0); // index
        let bad = TransactionOutput { value: 100, script_public_key: ScriptPublicKey::new(0, scriptvec_from_slice(&bytes)) };
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_v1_with_outputs(vec![payment, bad]);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::AltReferenceMalformed(_, _)));
    }

    // -- Rule 18 — per-tx ALT-creation cap --------------------------------

    #[test]
    fn alt_v1_too_many_creations_rejected() {
        let tv = make_validator();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let mut outputs = vec![payment];
        // One more than the cap; each must have a distinct payload (handle).
        for n in 0..=MAX_ALT_CREATIONS_PER_TX {
            let body = vec![n as u8; 4];
            outputs.push(alt_creation_output_from_entries(&[(0u16, &body)]));
        }
        let tx = tx_v1_with_outputs(outputs);
        match tv.validate_tx_in_isolation(&tx) {
            Err(TxRuleError::TooManyAltCreations(actual, cap)) => {
                assert_eq!(actual, MAX_ALT_CREATIONS_PER_TX + 1);
                assert_eq!(cap, MAX_ALT_CREATIONS_PER_TX);
            }
            other => panic!("expected TooManyAltCreations, got {other:?}"),
        }
    }

    // -- Rule 19 — coinbase outputs must not contain ALT discriminators --

    #[test]
    fn alt_coinbase_rejects_creation_output() {
        let tv = make_validator();
        let cb = coinbase_v1_with_outputs(vec![alt_creation_output_from_entries(&[(0u16, b"abcd")])]);
        match tv.validate_tx_in_isolation(&cb) {
            Err(TxRuleError::AltInCoinbase(idx)) => assert_eq!(idx, 0),
            other => panic!("expected AltInCoinbase, got {other:?}"),
        }
    }

    #[test]
    fn alt_coinbase_rejects_reference_output() {
        let tv = make_validator();
        let r = alt_reference_output([1u8; ALT_HANDLE_LEN], 0, 100);
        let cb = coinbase_v1_with_outputs(vec![r]);
        match tv.validate_tx_in_isolation(&cb) {
            Err(TxRuleError::AltInCoinbase(idx)) => assert_eq!(idx, 0),
            other => panic!("expected AltInCoinbase, got {other:?}"),
        }
    }

    // -- ScriptPublicKey length exemption — ALT outputs bypass max_spk_len -

    #[test]
    fn alt_v1_creation_large_payload_passes_spk_length_check() {
        let tv = make_validator();
        // 16 entries × 1 KB = 16 KB total. max_script_public_key_len for the
        // test validator is below that for legacy outputs but ALT must be
        // exempt (rule lives in `check_transaction_script_public_keys`).
        let body = vec![0xAAu8; 1024];
        let entries: Vec<(u16, &[u8])> = (0..16usize).map(|_| (0u16, body.as_slice())).collect();
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_v1_with_outputs(vec![payment, alt_creation_output_from_entries(&entries)]);
        tv.validate_tx_in_isolation(&tx).expect("ALT-creation outputs must be exempt from max_script_public_key_len");
    }

    // -- Sanity — discriminator bytes inside v=0 outputs are passed through --

    #[test]
    fn alt_v0_passthrough_for_non_alt_scripts() {
        let tv = make_validator();
        // v=0 tx whose output script just happens to start with neither 0xFD nor 0xFE.
        let payment = TransactionOutput { value: 1_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xa9, 0x14)) };
        let tx = tx_with_outputs(vec![payment]);
        tv.validate_tx_in_isolation(&tx).expect("v=0 tx without ALT discriminators must remain unaffected by L1.3.a");
        // Also confirm we do not parse 0xFD or 0xFE bytes that appear later in the script.
        let mid = TransactionOutput { value: 2_000, script_public_key: ScriptPublicKey::new(0, scriptvec!(0x76, 0xFD, 0xFE)) };
        let tx2 = tx_with_outputs(vec![mid]);
        tv.validate_tx_in_isolation(&tx2).expect("only the FIRST byte of the script triggers ALT classification");
    }
}

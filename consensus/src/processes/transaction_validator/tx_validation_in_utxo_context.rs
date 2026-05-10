use crate::constants::{MAX_SOMPI, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_MASK};
use crate::model::stores::alt::AltStoreReader;
use rayon::ThreadPool;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sophis_consensus_core::alt::{AltHandleHash, AltScriptKind, classify_alt_script, parse_alt_reference};
use sophis_consensus_core::{
    hashing::sighash::{SigHashReusedValues, SigHashReusedValuesSync, SigHashReusedValuesUnsync},
    tx::{ScriptPublicKey, TransactionInput, UtxoEntry, VerifiableTransaction},
};
use sophis_txscript::{SigCacheKey, TxScriptEngine, caches::Cache};
use sophis_txscript_errors::TxScriptError;
use std::collections::HashMap;
use std::marker::Sync;

use std::sync::Arc;

use borsh::BorshDeserialize;
use smallvec::SmallVec;
use sophis_consensus_core::constants::{SCRIPT_VERSION_CONTRACT, SCRIPT_VERSION_TOKEN};
use sophis_svm_core::{Capability, ContractManifest, ContractUtxoData, GasConfig, NativeTokenUtxoData, TokenId, UpgradePolicy};
use sophis_svm_host::SophisHostCrypto;
use sophis_svm_runtime::{ExecutionContext, HostDa, StubDa, config::DEFAULT_FUEL_BUDGET};

use crate::svm_da::SophisDaBackend;

/// Phase 6 helper — picks the right `HostDa` backend for this validator.
///
/// Sub-fase 6.5.b: when both the DA store AND the last-known-good
/// virtual state are wired (production path), constructs a
/// `SophisDaBackend::from_lkg` that reads the chain-tip blue score
/// on every `sophis_verify_da` invocation. Without the LKG handle
/// (legacy / pre-6.5.b paths) falls back to a static-zero backend
/// so confirmations remain conservative. Without the DA store at all,
/// uses `StubDa` (every query returns false).
fn build_da_backend(svm: &SvmContext) -> Arc<dyn HostDa> {
    match (&svm.da_store, &svm.lkg_virtual_state) {
        (Some(store), Some(lkg)) => Arc::new(SophisDaBackend::from_lkg(Arc::clone(store), lkg.clone())),
        (Some(store), None) => Arc::new(SophisDaBackend::new(Arc::clone(store), 0)),
        (None, _) => Arc::new(StubDa),
    }
}

/// L1 helper — picks the right `HostAlt` backend for this validator.
/// Production wires `SophisAltBackend` bound to `DbAltStore`; tests / lite
/// builds without an alt_store fall back to `StubAlt` (every lookup
/// returns `None`).
fn build_alt_backend(svm: &SvmContext) -> Arc<dyn sophis_svm_runtime::HostAlt> {
    match &svm.alt_store {
        Some(store) => Arc::new(crate::svm_alt::SophisAltBackend::new(Arc::clone(store))),
        None => Arc::new(sophis_svm_runtime::StubAlt),
    }
}

use super::{
    SvmContext, TransactionValidator,
    errors::{TxResult, TxRuleError},
};

/// The threshold above which we apply parallelism to input script processing
const CHECK_SCRIPTS_PARALLELISM_THRESHOLD: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TxValidationFlags {
    /// Perform full validation including script verification
    Full,

    /// Perform fee and sequence/maturity validations but skip script checks. This is usually
    /// an optimization to be applied when it is known that scripts were already checked
    SkipScriptChecks,

    /// When validating mempool transactions, we just set this value ourselves
    SkipMassCheck,
}

impl TransactionValidator {
    pub fn validate_populated_transaction_and_get_fee(
        &self,
        tx: &(impl VerifiableTransaction + Sync),
        pov_daa_score: u64,
        flags: TxValidationFlags,
        mass_and_feerate_threshold: Option<(u64, f64)>,
    ) -> TxResult<u64> {
        self.check_transaction_coinbase_maturity(tx, pov_daa_score)?;
        let total_in = self.check_transaction_input_amounts(tx)?;
        let total_out = Self::check_transaction_output_values(tx, total_in)?;
        let fee = total_in - total_out;
        if flags != TxValidationFlags::SkipMassCheck {
            self.check_mass_commitment(tx)?;
        }
        Self::check_sequence_lock(tx, pov_daa_score)?;
        self.check_alt_references(tx)?;

        // The following call is not a consensus check (it could not be one in the first place since it uses a floating number)
        // but rather a mempool Replace by Fee validation rule. It is placed here purposely for avoiding unneeded script checks.
        Self::check_feerate_threshold(fee, mass_and_feerate_threshold)?;

        match flags {
            TxValidationFlags::Full | TxValidationFlags::SkipMassCheck => {
                self.check_scripts(tx, pov_daa_score)?;
                check_token_conservation(self.svm.as_ref(), tx, pov_daa_score)?;
            }
            TxValidationFlags::SkipScriptChecks => {}
        }
        Ok(fee)
    }

    fn check_feerate_threshold(fee: u64, mass_and_feerate_threshold: Option<(u64, f64)>) -> TxResult<()> {
        // An actual check can only occur if some mass and threshold are provided,
        // otherwise, the check does not verify anything and exits successfully.
        if let Some((contextual_mass, feerate_threshold)) = mass_and_feerate_threshold {
            assert!(contextual_mass > 0);
            if fee as f64 / contextual_mass as f64 <= feerate_threshold {
                return Err(TxRuleError::FeerateTooLow);
            }
        }
        Ok(())
    }

    fn check_transaction_coinbase_maturity(&self, tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
        if let Some((index, (input, entry))) = tx
            .populated_inputs()
            .enumerate()
            .find(|(_, (_, entry))| entry.is_coinbase && entry.block_daa_score + self.coinbase_maturity > pov_daa_score)
        {
            return Err(TxRuleError::ImmatureCoinbaseSpend(
                index,
                input.previous_outpoint,
                entry.block_daa_score,
                pov_daa_score,
                self.coinbase_maturity,
            ));
        }

        Ok(())
    }

    fn check_transaction_input_amounts(&self, tx: &impl VerifiableTransaction) -> TxResult<u64> {
        let mut total: u64 = 0;
        for (_, entry) in tx.populated_inputs() {
            if let Some(new_total) = total.checked_add(entry.amount) {
                total = new_total
            } else {
                return Err(TxRuleError::InputAmountOverflow);
            }

            if total > MAX_SOMPI {
                return Err(TxRuleError::InputAmountTooHigh);
            }
        }

        Ok(total)
    }

    fn check_transaction_output_values(tx: &impl VerifiableTransaction, total_in: u64) -> TxResult<u64> {
        // There's no need to check for overflow here because it was already checked by check_transaction_output_value_ranges
        let total_out: u64 = tx.outputs().iter().map(|out| out.value).sum();
        if total_in < total_out {
            return Err(TxRuleError::SpendTooHigh(total_out, total_in));
        }

        Ok(total_out)
    }

    /// Lowercase-hex of a 6-byte ALT handle, used inside diagnostics.
    /// Inlined here so the consensus crate does not need a hex util dep.
    fn fmt_hex_handle(bytes: &[u8; 6]) -> String {
        let mut out = String::with_capacity(12);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    fn check_mass_commitment(&self, tx: &impl VerifiableTransaction) -> TxResult<()> {
        let calculated_contextual_mass =
            self.mass_calculator.calc_contextual_masses(tx).ok_or(TxRuleError::MassIncomputable)?.storage_mass;
        let committed_contextual_mass = tx.tx().mass();
        if committed_contextual_mass != calculated_contextual_mass {
            return Err(TxRuleError::WrongMass(calculated_contextual_mass, committed_contextual_mass));
        }
        Ok(())
    }

    /// L1 — enforce rules 15 & 16 of `docs/L1_ALT_DESIGN.md` §5: every ALT
    /// reference output (script[0] == 0xFD) must resolve to an existing
    /// `AltEntry` whose `entry_count` strictly exceeds the cited `index`.
    ///
    /// Skipped silently when the validator was constructed without an
    /// `alt_store` handle (test / lite-build configurations). Production
    /// validators MUST attach the store via `SvmContext::with_alt_store`
    /// or dangling references would be silently accepted.
    ///
    /// Errors are converted via `to_string`-of-handle so the CLI / RPC
    /// surface gets a readable diagnostic without the consensus crate
    /// depending on hex-formatting helpers.
    fn check_alt_references(&self, tx: &impl VerifiableTransaction) -> TxResult<()> {
        let Some(alt_store) = self.svm.as_ref().and_then(|svm| svm.alt_store.as_ref()) else {
            return Ok(()); // alt_store not wired — skip rules 15-16
        };
        for (i, output) in tx.outputs().iter().enumerate() {
            let script = output.script_public_key.script();
            if classify_alt_script(script) != Some(AltScriptKind::Reference) {
                continue;
            }
            // The structural check (rule 14) was enforced at isolation
            // time; here `parse_alt_reference` is guaranteed to succeed,
            // but we re-enter the parser defensively rather than reach
            // into the byte slice manually.
            let r = parse_alt_reference(script)
                .map_err(|e| TxRuleError::AltReferenceMalformed(i, e.to_string()))?;
            let handle = AltHandleHash::new(r.handle);
            // Rule 15 — handle must exist in the consensus ALT registry.
            let entry = match alt_store.get_entry(handle) {
                Ok(Some(e)) => e,
                Ok(None) => {
                    return Err(TxRuleError::AltReferenceDanglingHandle(i, Self::fmt_hex_handle(&r.handle)));
                }
                Err(e) => {
                    // Treat store I/O errors as malformed-reference for now;
                    // higher-level retry policies live above this layer.
                    return Err(TxRuleError::AltReferenceMalformed(i, format!("alt_store error: {e}")));
                }
            };
            // Rule 16 — index must be strictly less than entry_count.
            let count = entry.entry_count();
            if (r.index as u16) >= count {
                return Err(TxRuleError::AltReferenceIndexOutOfRange(i, r.index, count));
            }
        }
        Ok(())
    }

    fn check_sequence_lock(tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
        let pov_daa_score: i64 = pov_daa_score as i64;
        if tx.populated_inputs().filter(|(input, _)| input.sequence & SEQUENCE_LOCK_TIME_DISABLED != SEQUENCE_LOCK_TIME_DISABLED).any(
            |(input, entry)| {
                // Given a sequence number, we apply the relative time lock
                // mask in order to obtain the time lock delta required before
                // this input can be spent.
                let relative_lock = (input.sequence & SEQUENCE_LOCK_TIME_MASK) as i64;

                // The relative lock-time for this input is expressed
                // in blocks so we calculate the relative offset from
                // the input's DAA score as its converted absolute
                // lock-time. We subtract one from the relative lock in
                // order to maintain the original lockTime semantics.
                //
                // Note: in the sophisd codebase there's a use in i64 in order to use the -1 value
                // as None. Here it's not needed, but we still use it to avoid breaking consensus.
                let lock_daa_score = entry.block_daa_score as i64 + relative_lock - 1;

                lock_daa_score >= pov_daa_score
            },
        ) {
            return Err(TxRuleError::SequenceLockConditionsAreNotMet);
        }
        Ok(())
    }

    pub fn check_scripts(&self, tx: &(impl VerifiableTransaction + Sync), pov_daa_score: u64) -> TxResult<()> {
        check_scripts_with_svm(&self.sig_cache, self.svm.as_ref(), tx, pov_daa_score)
    }
}

pub fn check_scripts(sig_cache: &Cache<SigCacheKey, bool>, tx: &(impl VerifiableTransaction + Sync)) -> TxResult<()> {
    check_scripts_with_svm(sig_cache, None, tx, 0)
}

pub fn check_scripts_with_svm(
    sig_cache: &Cache<SigCacheKey, bool>,
    svm: Option<&SvmContext>,
    tx: &(impl VerifiableTransaction + Sync),
    pov_daa_score: u64,
) -> TxResult<()> {
    if tx.inputs().len() > CHECK_SCRIPTS_PARALLELISM_THRESHOLD {
        check_scripts_par_iter(sig_cache, svm, tx, pov_daa_score)
    } else {
        check_scripts_sequential(sig_cache, svm, tx, pov_daa_score)
    }
}

pub fn check_scripts_sequential(
    sig_cache: &Cache<SigCacheKey, bool>,
    svm: Option<&SvmContext>,
    tx: &impl VerifiableTransaction,
    pov_daa_score: u64,
) -> TxResult<()> {
    let reused_values = SigHashReusedValuesUnsync::new();
    for (i, (input, entry)) in tx.populated_inputs().enumerate() {
        match entry.script_public_key.version() {
            SCRIPT_VERSION_CONTRACT => check_contract_input(svm, tx, i, entry, pov_daa_score)?,
            SCRIPT_VERSION_TOKEN => check_token_utxo_spend(svm, tx, input, i, entry, pov_daa_score, &reused_values, sig_cache)?,
            _ => TxScriptEngine::from_transaction_input(tx, input, i, entry, &reused_values, sig_cache)
                .execute()
                .map_err(|err| map_script_err(err, input))?,
        }
    }
    Ok(())
}

pub fn check_scripts_par_iter(
    sig_cache: &Cache<SigCacheKey, bool>,
    svm: Option<&SvmContext>,
    tx: &(impl VerifiableTransaction + Sync),
    pov_daa_score: u64,
) -> TxResult<()> {
    let reused_values = SigHashReusedValuesSync::new();
    (0..tx.inputs().len()).into_par_iter().try_for_each(|idx| {
        let (input, entry) = tx.populated_input(idx);
        match entry.script_public_key.version() {
            SCRIPT_VERSION_CONTRACT => check_contract_input(svm, tx, idx, entry, pov_daa_score),
            SCRIPT_VERSION_TOKEN => check_token_utxo_spend(svm, tx, input, idx, entry, pov_daa_score, &reused_values, sig_cache),
            _ => TxScriptEngine::from_transaction_input(tx, input, idx, entry, &reused_values, sig_cache)
                .execute()
                .map_err(|err| map_script_err(err, input)),
        }
    })
}

pub fn check_scripts_par_iter_pool(
    sig_cache: &Cache<SigCacheKey, bool>,
    tx: &(impl VerifiableTransaction + Sync),
    pool: &ThreadPool,
) -> TxResult<()> {
    pool.install(|| check_scripts_par_iter(sig_cache, None, tx, 0))
}

/// B3 sVM dispatch: validates a Contract UTXO input via Wasmtime.
fn check_contract_input(
    svm: Option<&SvmContext>,
    tx: &impl VerifiableTransaction,
    _input_idx: usize,
    entry: &sophis_consensus_core::tx::UtxoEntry,
    pov_daa_score: u64,
) -> TxResult<()> {
    let svm = svm.ok_or_else(|| TxRuleError::SvmValidationFailed("sVM not initialised".into()))?;

    // Deserialize ContractUtxoData from script_public_key.script() bytes
    let contract_data = ContractUtxoData::try_from_slice(entry.script_public_key.script())
        .map_err(|e| TxRuleError::SvmValidationFailed(format!("malformed contract UTXO: {e}")))?;

    // Look up WASM bytecode from contract store
    let wasm = svm
        .store
        .get_wasm(&contract_data.contract_id)
        .ok_or_else(|| TxRuleError::ContractNotDeployed(format!("{:x?}", contract_data.contract_id.as_bytes())))?;

    // Serialize all populated inputs and outputs for ExecutionContext (borsh)
    let input_utxos: Vec<Vec<u8>> = tx.populated_inputs().map(|(_, e)| borsh::to_vec(e).unwrap_or_default()).collect();
    let output_utxos: Vec<Vec<u8>> = tx.outputs().iter().map(|o| borsh::to_vec(o).unwrap_or_default()).collect();

    let ctx = ExecutionContext::new_with_da_and_alt(
        input_utxos,
        output_utxos,
        pov_daa_score,
        contract_data.manifest.clone(),
        GasConfig::default(),
        Arc::new(SophisHostCrypto),
        build_da_backend(svm),
        build_alt_backend(svm),
    );

    let result = svm
        .executor
        .execute(contract_data.contract_id, &wasm, ctx, DEFAULT_FUEL_BUDGET)
        .map_err(|e| TxRuleError::SvmValidationFailed(e.to_string()))?;

    if !result.valid {
        return Err(TxRuleError::SvmValidationFailed("contract rejected transaction".into()));
    }
    Ok(())
}

/// Validates spending of a Token UTXO (version=2).
///
/// 1. Spending lock: builds a synthetic v=0 UtxoEntry from `lock_script` and runs it
///    through TxScriptEngine — the sighash is identical for signer and verifier.
/// 2. Transfer Policy (optional): if `token_data.transfer_policy_id` is `Some(id)`,
///    retrieves the WASM from the ContractStore and executes it via sVM.
///    The Transfer Policy receives the full tx context and must return 1 to approve.
fn check_token_utxo_spend(
    svm: Option<&SvmContext>,
    tx: &impl VerifiableTransaction,
    input: &TransactionInput,
    idx: usize,
    entry: &UtxoEntry,
    pov_daa_score: u64,
    reused_values: &impl SigHashReusedValues,
    sig_cache: &Cache<SigCacheKey, bool>,
) -> TxResult<()> {
    let token_data = NativeTokenUtxoData::try_from_slice(entry.script_public_key.script())
        .map_err(|e| TxRuleError::TokenUtxoMalformed(idx, e.to_string()))?;

    // 1. Spending lock via synthetic P2PK entry
    let synthetic_entry =
        UtxoEntry { script_public_key: ScriptPublicKey::new(0, SmallVec::from(token_data.lock_script.as_slice())), ..entry.clone() };
    TxScriptEngine::from_transaction_input(tx, input, idx, &synthetic_entry, reused_values, sig_cache)
        .execute()
        .map_err(|err| map_script_err(err, input))?;

    // 2. Transfer Policy (optional)
    if let Some(policy_id) = token_data.transfer_policy_id {
        let svm = svm.ok_or_else(|| TxRuleError::TransferPolicyNotDeployed(format!("{policy_id:?}")))?;
        let wasm = svm.store.get_wasm(&policy_id).ok_or_else(|| TxRuleError::TransferPolicyNotDeployed(format!("{policy_id:?}")))?;

        let input_utxos: Vec<Vec<u8>> = tx.populated_inputs().map(|(_, e)| borsh::to_vec(e).unwrap_or_default()).collect();
        let output_utxos: Vec<Vec<u8>> = tx.outputs().iter().map(|o| borsh::to_vec(o).unwrap_or_default()).collect();

        // Transfer policies get all capabilities — they are trusted token issuer scripts.
        let policy_manifest = ContractManifest::new(
            policy_id,
            UpgradePolicy::Immutable,
            vec![Capability::ReadUtxo, Capability::ReadBlockHeight, Capability::VerifyDilithium, Capability::HashSha3],
        );
        let ctx = ExecutionContext::new_with_da_and_alt(
            input_utxos,
            output_utxos,
            pov_daa_score,
            policy_manifest,
            GasConfig::default(),
            Arc::new(SophisHostCrypto),
            build_da_backend(svm),
            build_alt_backend(svm),
        );

        let result = svm
            .executor
            .execute(policy_id, &wasm, ctx, DEFAULT_FUEL_BUDGET)
            .map_err(|e| TxRuleError::TransferPolicyRejected(e.to_string()))?;

        if !result.valid {
            return Err(TxRuleError::TransferPolicyRejected(format!(
                "token {token_id:?} policy {policy_id:?} rejected spend",
                token_id = token_data.token_id,
            )));
        }
    }
    Ok(())
}

/// Checks Native Token conservation across the transaction.
///
/// For every TokenId present in v=2 inputs or outputs:
///   - If Σinputs == Σoutputs → OK (pure transfer).
///   - If Σoutputs > Σinputs → net mint; executes the Minting Policy WASM.
///   - If Σoutputs < Σinputs → net burn; executes the Minting Policy WASM.
///
/// The Minting Policy WASM receives the full tx context (all UTXOs) and decides
/// whether the mint/burn is authorised.  Returns an error if conservation is
/// violated and no valid Minting Policy execution approves the delta.
pub fn check_token_conservation(
    svm: Option<&SvmContext>,
    tx: &(impl VerifiableTransaction + Sync),
    pov_daa_score: u64,
) -> TxResult<()> {
    // Collect token amounts from inputs (v=2 UtxoEntries)
    let mut input_tokens: HashMap<TokenId, u64> = HashMap::new();
    for (_, entry) in tx.populated_inputs() {
        if entry.script_public_key.version() != SCRIPT_VERSION_TOKEN {
            continue;
        }
        let data = NativeTokenUtxoData::try_from_slice(entry.script_public_key.script())
            .map_err(|e| TxRuleError::SvmValidationFailed(format!("malformed token input UTXO: {e}")))?;
        let current = input_tokens.get(&data.token_id).copied().unwrap_or(0);
        let new_val = current.checked_add(data.token_amount).ok_or(TxRuleError::InputAmountOverflow)?;
        input_tokens.insert(data.token_id, new_val);
    }

    // Collect token amounts from outputs (v=2 TransactionOutputs)
    let mut output_tokens: HashMap<TokenId, u64> = HashMap::new();
    for output in tx.outputs() {
        if output.script_public_key.version() != SCRIPT_VERSION_TOKEN {
            continue;
        }
        let data = NativeTokenUtxoData::try_from_slice(output.script_public_key.script())
            .map_err(|e| TxRuleError::SvmValidationFailed(format!("malformed token output UTXO: {e}")))?;
        let current = output_tokens.get(&data.token_id).copied().unwrap_or(0);
        let new_val = current.checked_add(data.token_amount).ok_or(TxRuleError::OutputsValueOverflow)?;
        output_tokens.insert(data.token_id, new_val);
    }

    // Check conservation for every token that appears in either side
    let all_ids: std::collections::HashSet<TokenId> = input_tokens.keys().chain(output_tokens.keys()).copied().collect();

    for token_id in all_ids {
        let in_amt = input_tokens.get(&token_id).copied().unwrap_or(0);
        let out_amt = output_tokens.get(&token_id).copied().unwrap_or(0);

        if in_amt == out_amt {
            continue; // conservation holds — no minting policy needed
        }

        // Net mint or burn — Minting Policy WASM must approve
        let svm = svm.ok_or_else(|| TxRuleError::MintingPolicyNotDeployed(format!("{token_id:?}")))?;
        let wasm = svm.store.get_wasm(&token_id).ok_or_else(|| TxRuleError::MintingPolicyNotDeployed(format!("{token_id:?}")))?;

        let input_utxos: Vec<Vec<u8>> = tx.populated_inputs().map(|(_, e)| borsh::to_vec(e).unwrap_or_default()).collect();
        let output_utxos: Vec<Vec<u8>> = tx.outputs().iter().map(|o| borsh::to_vec(o).unwrap_or_default()).collect();

        // Minting policies are privileged system scripts — grant all host capabilities.
        let mint_manifest = ContractManifest::new(
            token_id,
            UpgradePolicy::Immutable,
            vec![Capability::ReadUtxo, Capability::ReadBlockHeight, Capability::VerifyDilithium, Capability::HashSha3],
        );
        let ctx = ExecutionContext::new_with_da_and_alt(
            input_utxos,
            output_utxos,
            pov_daa_score,
            mint_manifest,
            GasConfig::default(),
            Arc::new(SophisHostCrypto),
            build_da_backend(svm),
            build_alt_backend(svm),
        );

        let result = svm
            .executor
            .execute(token_id, &wasm, ctx, DEFAULT_FUEL_BUDGET)
            .map_err(|e| TxRuleError::MintingPolicyRejected(e.to_string()))?;

        if !result.valid {
            return Err(TxRuleError::MintingPolicyRejected(format!("token {token_id:?}: input={in_amt} output={out_amt}")));
        }
    }
    Ok(())
}

fn map_script_err(script_err: TxScriptError, input: &TransactionInput) -> TxRuleError {
    if input.signature_script.is_empty() { TxRuleError::SignatureEmpty(script_err) } else { TxRuleError::SignatureInvalid(script_err) }
}

#[cfg(test)]
mod tests {
    use super::super::errors::TxRuleError;
    use core::str::FromStr;
    use smallvec::SmallVec;
    use sophis_consensus_core::subnets::SubnetworkId;
    use sophis_consensus_core::tx::{PopulatedTransaction, TransactionId, UtxoEntry};
    use sophis_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};
    use sophis_txscript_errors::TxScriptError;

    use crate::{params::MAINNET_PARAMS, processes::transaction_validator::TransactionValidator};

    /// Helper function to duplicate the last input
    fn duplicate_input(tx: &Transaction, entries: &[UtxoEntry]) -> (Transaction, Vec<UtxoEntry>) {
        let mut tx2 = tx.clone();
        let mut entries2 = entries.to_owned();
        tx2.inputs.push(tx2.inputs.last().unwrap().clone());
        entries2.push(entries2.last().unwrap().clone());
        (tx2, entries2)
    }

    #[test]
    fn check_non_push_only_script_sig_test() {
        // We test a situation where the script itself is valid, but the script signature is not push only
        let params = MAINNET_PARAMS.clone();
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

        let prev_tx_id = TransactionId::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();

        let mut bytes = [0u8; 2];
        faster_hex::hex_decode("5175".as_bytes(), &mut bytes).unwrap(); // OP_TRUE OP_DROP
        let signature_script = bytes.to_vec();

        let mut bytes = [0u8; 1];
        faster_hex::hex_decode("51".as_bytes(), &mut bytes) // OP_TRUE
            .unwrap();
        let script_pub_key_1 = SmallVec::from(bytes.to_vec());

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                signature_script,
                sequence: 0,
                sig_op_count: 4,
            }],
            vec![TransactionOutput { value: 2792999990000, script_public_key: ScriptPublicKey::new(0, script_pub_key_1.clone()) }],
            0,
            SubnetworkId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry {
                amount: 12793000000000,
                script_public_key: ScriptPublicKey::new(0, script_pub_key_1),
                block_daa_score: 36151168,
                is_coinbase: false,
            }],
        );

        assert_eq!(tv.check_scripts(&populated_tx, 0), Err(TxRuleError::SignatureInvalid(TxScriptError::SignatureScriptNotPushOnly)));

        // Test a tx with 2 inputs to cover parallelism split points in inner script checking code
        let (tx2, entries2) = duplicate_input(&tx, &populated_tx.entries);
        assert_eq!(
            tv.check_scripts(&PopulatedTransaction::new(&tx2, entries2), 0),
            Err(TxRuleError::SignatureInvalid(TxScriptError::SignatureScriptNotPushOnly))
        );
    }

    /// Replaced with Dilithium signing — Schnorr (secp256k1) signing removed.
    #[test]
    fn test_sign_schnorr_removed() {
        // Schnorr-based test_sign removed. See crypto/txscript/src/lib.rs for Dilithium signing tests.
    }

    // ----------------------------------------------------------------
    // L1 — sub-fase L1.3.b sanity: check_alt_references must silently
    // accept ALT references when no `alt_store` is wired (test / lite
    // build path). Full integration coverage with a real alt_store lives
    // in L1.7 adversarial tests.
    // ----------------------------------------------------------------

    #[test]
    fn check_alt_references_skips_without_alt_store() {
        use sophis_consensus_core::alt::encode_alt_reference_script;

        let params = MAINNET_PARAMS.clone();
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
        // No svm context attached, so alt_store is None -> rule 15-16 are
        // silently skipped. Build a v=1 tx whose output is an ALT reference
        // citing a totally fake handle: the function must NOT error.
        let prev = TransactionId::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let tx = Transaction::new(
            1, // v=1
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev, index: 0 },
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 0,
            }],
            vec![TransactionOutput {
                value: 100,
                script_public_key: ScriptPublicKey::new(0, SmallVec::from(encode_alt_reference_script([0xFFu8; 6], 7).to_vec())),
            }],
            0,
            SubnetworkId::from_bytes([0u8; 20]),
            0,
            vec![],
        );
        // Mass commitment irrelevant for this isolated check.
        tx.set_mass(0);
        let populated_tx = PopulatedTransaction::new(
            &tx,
            vec![UtxoEntry { amount: 1_000, script_public_key: ScriptPublicKey::new(0, SmallVec::new()), block_daa_score: 0, is_coinbase: false }],
        );
        // The validator's check_alt_references is `pub(crate)` indirectly
        // via the impl block; call it through the private module path.
        tv.check_alt_references(&populated_tx).expect("alt_store=None must skip rules 15-16");
    }
}

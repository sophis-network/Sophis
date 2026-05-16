//!
//! Partially Signed Sophis Transaction (PSKT)
//!

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sophis_bip39::{DerivationPath, KeyFingerprint};
use sophis_consensus_core::{Hash, hashing::sighash::SigHashReusedValuesUnsync};
use std::{fmt::Display, fmt::Formatter, future::Future, marker::PhantomData, ops::Deref};

pub use crate::crypto::{DilithiumPubKey, PartialSig, PartialSigs, Signature};
pub use crate::error::Error;
pub use crate::global::{Global, GlobalBuilder};
pub use crate::input::{Input, InputBuilder};
pub use crate::output::{Output, OutputBuilder};
pub use crate::role::{Combiner, Constructor, Creator, Extractor, Finalizer, Signer, Updater};
use sophis_consensus_core::config::params::Params;
use sophis_consensus_core::mass::{MassCalculator, NonContextualMasses};
use sophis_consensus_core::{
    hashing::sighash_type::SigHashType,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{MutableTransaction, SignableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutput},
};
use sophis_txscript::{TxScriptEngine, caches::Cache};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Inner {
    /// The global map.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Version {
    #[default]
    Zero = 0,
    One = 1,
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Version::Zero => write!(f, "{}", Version::Zero as u8),
            Version::One => write!(f, "{}", Version::One as u8),
        }
    }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeySource {
    #[serde(with = "sophis_utils::serde_bytes_fixed")]
    pub key_fingerprint: KeyFingerprint,
    pub derivation_path: DerivationPath,
}

impl KeySource {
    pub fn new(key_fingerprint: KeyFingerprint, derivation_path: DerivationPath) -> Self {
        Self { key_fingerprint, derivation_path }
    }
}

// `PartialSigs`, `PartialSig`, `Signature`, and `DilithiumPubKey` live in the
// `crypto` module — Dilithium ML-DSA-44 only (PSBS spec D3/D4). They are
// re-exported above for backward source-level compatibility.

///
/// A Partially Signed Sophis Transaction (PSKT) is a standardized format
/// that allows multiple participants to collaborate in creating and signing
/// a Sophis transaction. PSKT enables the exchange of incomplete transaction
/// data between different wallets or entities, allowing each participant
/// to add their signature or inputs in stages. This facilitates more complex
/// transaction workflows, such as multi-signature setups or hardware wallet
/// interactions, by ensuring that sensitive data remains secure while
/// enabling cooperation across different devices or platforms without
/// exposing private keys.
///
/// Please note that due to transaction mass limits and potential of
/// a wallet aggregating large UTXO sets, the PSKT [`Bundle`](crate::bundle::Bundle) primitive
/// is used to represent a collection of PSKTs and should be used for
/// PSKT serialization and transport. PSKT is an internal implementation
/// primitive that represents each transaction in the bundle.
///
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PSKT<ROLE> {
    #[serde(flatten)]
    inner_pskt: Inner,
    #[serde(skip_serializing, default)]
    role: PhantomData<ROLE>,
}

impl<ROLE> From<Inner> for PSKT<ROLE> {
    fn from(inner_pskt: Inner) -> Self {
        PSKT { inner_pskt, role: Default::default() }
    }
}

impl<ROLE> Clone for PSKT<ROLE> {
    fn clone(&self) -> Self {
        PSKT { inner_pskt: self.inner_pskt.clone(), role: Default::default() }
    }
}

impl<ROLE> Deref for PSKT<ROLE> {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.inner_pskt
    }
}

impl<R> PSKT<R> {
    fn unsigned_tx(&self) -> SignableTransaction {
        let tx = Transaction::new(
            self.global.tx_version,
            self.inputs
                .iter()
                .map(|Input { previous_outpoint, sequence, sig_op_count, .. }| TransactionInput {
                    previous_outpoint: *previous_outpoint,
                    signature_script: vec![],
                    sequence: sequence.unwrap_or(u64::MAX),
                    sig_op_count: sig_op_count.unwrap_or(0),
                })
                .collect(),
            self.outputs
                .iter()
                .map(|Output { amount, script_public_key, .. }: &Output| TransactionOutput {
                    value: *amount,
                    script_public_key: script_public_key.clone(),
                })
                .collect(),
            self.determine_lock_time(),
            SUBNETWORK_ID_NATIVE,
            0,
            // Only include payload if version supports it (Version::One or higher)
            if self.global.version >= Version::One { self.global.payload.clone().unwrap_or_default() } else { vec![] },
        );
        let entries = self.inputs.iter().filter_map(|Input { utxo_entry, .. }| utxo_entry.clone()).collect();
        SignableTransaction::with_entries(tx, entries)
    }

    fn calculate_id_internal(&self) -> TransactionId {
        self.unsigned_tx().tx.id()
    }

    fn determine_lock_time(&self) -> u64 {
        self.inputs.iter().map(|input: &Input| input.min_time).max().unwrap_or(self.global.fallback_lock_time).unwrap_or(0)
    }

    pub fn to_hex(&self) -> Result<String, Error> {
        Ok(format!("PSKT{}", hex::encode(serde_json::to_string(self)?)))
    }

    pub fn from_hex(hex_data: &str) -> Result<Self, Error> {
        if let Some(hex_data) = hex_data.strip_prefix("PSKT") {
            Ok(serde_json::from_slice(hex::decode(hex_data)?.as_slice())?)
        } else {
            Err(Error::PsktPrefixError)
        }
    }
}

impl Default for PSKT<Creator> {
    fn default() -> Self {
        PSKT { inner_pskt: Default::default(), role: Default::default() }
    }
}

impl PSKT<Creator> {
    /// Sets the fallback lock time.
    pub fn fallback_lock_time(mut self, fallback: u64) -> Self {
        self.inner_pskt.global.fallback_lock_time = Some(fallback);
        self
    }

    /// Sets the PSKT version.
    pub fn set_version(mut self, version: Version) -> Self {
        self.inner_pskt.global.version = version;
        self
    }

    // todo generic const
    /// Sets the inputs modifiable bit in the transaction modifiable flags.
    pub fn inputs_modifiable(mut self) -> Self {
        self.inner_pskt.global.inputs_modifiable = true;
        self
    }
    // todo generic const
    /// Sets the outputs modifiable bit in the transaction modifiable flags.
    pub fn outputs_modifiable(mut self) -> Self {
        self.inner_pskt.global.outputs_modifiable = true;
        self
    }

    pub fn constructor(self) -> PSKT<Constructor> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }
}

impl PSKT<Constructor> {
    // todo generic const
    /// Marks that the `PSKT` can not have any more inputs added to it.
    pub fn no_more_inputs(mut self) -> Self {
        self.inner_pskt.global.inputs_modifiable = false;
        self
    }
    // todo generic const
    /// Marks that the `PSKT` can not have any more outputs added to it.
    pub fn no_more_outputs(mut self) -> Self {
        self.inner_pskt.global.outputs_modifiable = false;
        self
    }

    /// Adds an input to the PSKT.
    pub fn input(mut self, input: Input) -> Self {
        self.inner_pskt.inputs.push(input);
        self.inner_pskt.global.input_count += 1;
        self
    }

    /// Adds an output to the PSKT.
    pub fn output(mut self, output: Output) -> Self {
        self.inner_pskt.outputs.push(output);
        self.inner_pskt.global.output_count += 1;
        self
    }

    pub fn payload(mut self, payload: Option<Vec<u8>>) -> Result<Self, Error> {
        // Only allow setting payload if version is One or greater
        if payload.is_some() && self.inner_pskt.global.version < Version::One {
            return Err(Error::PayloadRequiresVersion1(self.inner_pskt.global.version));
        }
        self.inner_pskt.global.payload = payload;
        Ok(self)
    }

    /// Returns a PSKT [`Updater`] once construction is completed.
    pub fn updater(self) -> PSKT<Updater> {
        let pskt = self.no_more_inputs().no_more_outputs();
        PSKT { inner_pskt: pskt.inner_pskt, role: Default::default() }
    }

    pub fn signer(self) -> PSKT<Signer> {
        self.updater().signer()
    }

    pub fn combiner(self) -> PSKT<Combiner> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }
}

impl PSKT<Updater> {
    pub fn set_sequence(mut self, n: u64, input_index: usize) -> Result<Self, Error> {
        self.inner_pskt.inputs.get_mut(input_index).ok_or(Error::OutOfBounds)?.sequence = Some(n);
        Ok(self)
    }

    pub fn signer(self) -> PSKT<Signer> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }

    pub fn combiner(self) -> PSKT<Combiner> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }
}

impl PSKT<Signer> {
    // todo use iterator instead of vector
    pub fn pass_signature_sync<SignFn, E>(mut self, sign_fn: SignFn) -> Result<Self, E>
    where
        E: Display,
        SignFn: FnOnce(SignableTransaction, Vec<SigHashType>) -> Result<Vec<SignInputOk>, E>,
    {
        let unsigned_tx = self.unsigned_tx();
        let sighashes = self.inputs.iter().map(|input| input.sighash_type).collect();
        self.inner_pskt.inputs.iter_mut().zip(sign_fn(unsigned_tx, sighashes)?).for_each(
            |(input, SignInputOk { signature, pub_key, key_source: _ })| {
                input.partial_sigs.push((pub_key, signature));
            },
        );

        Ok(self)
    }
    // todo use iterator instead of vector
    pub async fn pass_signature<SignFn, Fut, E>(mut self, sign_fn: SignFn) -> Result<Self, E>
    where
        E: Display,
        Fut: Future<Output = Result<Vec<SignInputOk>, E>>,
        SignFn: FnOnce(SignableTransaction, Vec<SigHashType>) -> Fut,
    {
        let unsigned_tx = self.unsigned_tx();
        let sighashes = self.inputs.iter().map(|input| input.sighash_type).collect();
        self.inner_pskt.inputs.iter_mut().zip(sign_fn(unsigned_tx, sighashes).await?).for_each(
            |(input, SignInputOk { signature, pub_key, key_source: _ })| {
                input.partial_sigs.push((pub_key, signature));
            },
        );
        Ok(self)
    }

    pub fn calculate_id(&self) -> TransactionId {
        self.calculate_id_internal()
    }

    pub fn finalizer(self) -> PSKT<Finalizer> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }

    pub fn combiner(self) -> PSKT<Combiner> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }

    // Unorphan batch transaction UTXO.
    pub fn set_input_prev_transaction_id(self, transaction_id: Hash) -> PSKT<Signer> {
        let mut new_inputs = self.inner_pskt.inputs.clone();

        new_inputs.iter_mut().for_each(|input| {
            input.previous_outpoint.transaction_id = transaction_id;
        });

        let mut updated_inner = self.inner_pskt.clone();
        updated_inner.inputs = new_inputs;

        PSKT { inner_pskt: updated_inner, role: Default::default() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInputOk {
    pub signature: Signature,
    pub pub_key: DilithiumPubKey,
    pub key_source: Option<KeySource>,
}

impl<R> std::ops::Add<PSKT<R>> for PSKT<Combiner> {
    type Output = Result<Self, CombineError>;

    fn add(mut self, mut rhs: PSKT<R>) -> Self::Output {
        self.inner_pskt.global = (self.inner_pskt.global + rhs.inner_pskt.global)?;
        macro_rules! combine {
            ($left:expr, $right:expr, $err: ty) => {
                if $left.len() > $right.len() {
                    $left.iter_mut().zip($right.iter_mut()).try_for_each(|(left, right)| -> Result<(), $err> {
                        *left = (std::mem::take(left) + std::mem::take(right))?;
                        Ok(())
                    })?;
                    $left
                } else {
                    $right.iter_mut().zip($left.iter_mut()).try_for_each(|(left, right)| -> Result<(), $err> {
                        *left = (std::mem::take(left) + std::mem::take(right))?;
                        Ok(())
                    })?;
                    $right
                }
            };
        }
        // todo add sort to build deterministic combination
        self.inner_pskt.inputs = combine!(self.inner_pskt.inputs, rhs.inner_pskt.inputs, crate::input::CombineError);
        self.inner_pskt.outputs = combine!(self.inner_pskt.outputs, rhs.inner_pskt.outputs, crate::output::CombineError);
        Ok(self)
    }
}

impl PSKT<Combiner> {
    pub fn signer(self) -> PSKT<Signer> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }
    pub fn finalizer(self) -> PSKT<Finalizer> {
        PSKT { inner_pskt: self.inner_pskt, role: Default::default() }
    }
}

impl PSKT<Finalizer> {
    pub fn finalize_sync<E: Display>(
        self,
        final_sig_fn: impl FnOnce(&Inner) -> Result<Vec<Vec<u8>>, E>,
    ) -> Result<Self, FinalizeError<E>> {
        let sigs = final_sig_fn(&self);
        self.finalize_internal(sigs)
    }

    pub async fn finalize<F, Fut, E>(self, final_sig_fn: F) -> Result<Self, FinalizeError<E>>
    where
        E: Display,
        F: FnOnce(&Inner) -> Fut,
        Fut: Future<Output = Result<Vec<Vec<u8>>, E>>,
    {
        let sigs = final_sig_fn(&self).await;
        self.finalize_internal(sigs)
    }

    pub fn id(&self) -> Option<TransactionId> {
        self.global.id
    }

    pub fn extractor(self) -> Result<PSKT<Extractor>, TxNotFinalized> {
        if self.global.id.is_none() {
            Err(TxNotFinalized {})
        } else {
            Ok(PSKT { inner_pskt: self.inner_pskt, role: Default::default() })
        }
    }

    fn finalize_internal<E: Display>(mut self, sigs: Result<Vec<Vec<u8>>, E>) -> Result<Self, FinalizeError<E>> {
        let sigs = sigs?;
        if sigs.len() != self.inputs.len() {
            return Err(FinalizeError::WrongFinalizedSigsCount { expected: self.inputs.len(), actual: sigs.len() });
        }
        self.inner_pskt.inputs.iter_mut().enumerate().zip(sigs).try_for_each(|((idx, input), sig)| {
            if sig.is_empty() {
                return Err(FinalizeError::EmptySignature(idx));
            }
            input.sequence = Some(input.sequence.unwrap_or(u64::MAX)); // todo discussable
            input.final_script_sig = Some(sig);
            Ok(())
        })?;
        self.inner_pskt.global.id = Some(self.calculate_id_internal());
        Ok(self)
    }
}

impl PSKT<Extractor> {
    pub fn extract_tx_unchecked(self, params: &Params) -> Result<MutableTransaction<Transaction>, TxNotFinalized> {
        let tx = self.unsigned_tx();
        let entries = tx.entries;
        let mut tx = tx.tx;
        tx.inputs.iter_mut().zip(self.inner_pskt.inputs).try_for_each(|(dest, src)| {
            dest.signature_script = src.final_script_sig.ok_or(TxNotFinalized {})?;
            Ok(())
        })?;
        let tx = MutableTransaction { tx, entries, calculated_fee: None, calculated_non_contextual_masses: None };
        let calculator = MassCalculator::new_with_consensus_params(params);
        let storage_mass = calculator.calc_contextual_masses(&tx.as_verifiable()).map(|mass| mass.storage_mass).unwrap_or_default();
        let NonContextualMasses { compute_mass, transient_mass } = calculator.calc_non_contextual_masses(&tx.tx);
        let mass = storage_mass.max(compute_mass).max(transient_mass);
        tx.tx.set_mass(mass);
        Ok(tx)
    }

    pub fn extract_tx(self, params: &Params) -> Result<MutableTransaction<Transaction>, ExtractError> {
        let tx = self.extract_tx_unchecked(params)?;
        use sophis_consensus_core::tx::VerifiableTransaction;
        {
            let tx = tx.as_verifiable();
            let cache = Cache::new(10_000);
            let reused_values = SigHashReusedValuesUnsync::new();

            tx.populated_inputs().enumerate().try_for_each(|(idx, (input, entry))| {
                TxScriptEngine::from_transaction_input(&tx, input, idx, entry, &reused_values, &cache).execute()?;
                <Result<(), ExtractError>>::Ok(())
            })?;
        }
        Ok(tx)
    }
}

/// Error combining pskt.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum CombineError {
    #[error(transparent)]
    Global(#[from] crate::global::CombineError),
    #[error(transparent)]
    Inputs(#[from] crate::input::CombineError),
    #[error(transparent)]
    Outputs(#[from] crate::output::CombineError),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum FinalizeError<E> {
    #[error("Signatures count mismatch")]
    WrongFinalizedSigsCount { expected: usize, actual: usize },
    #[error("Signatures at index: {0} is empty")]
    EmptySignature(usize),
    #[error(transparent)]
    FinalaziCb(#[from] E),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    #[error(transparent)]
    TxScriptError(#[from] sophis_txscript_errors::TxScriptError),
    #[error(transparent)]
    TxNotFinalized(#[from] TxNotFinalized),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("Transaction is not finalized")]
pub struct TxNotFinalized {}

// Audit category-D coverage closure (Session 16, 2026-05-16):
// `pskt.rs` (the PSKT role state machine) was at 7.56% line coverage.
// These exercise the role transitions (Creator → Constructor → Updater
// → Signer → Combiner → Finalizer → Extractor), the builder mutators,
// `unsigned_tx`/`determine_lock_time`/`calculate_id`, the hex
// round-trip, the Combiner `Add` (both macro branches), and the
// Finalizer/Extractor error paths. Bounded residual: `extract_tx`'s
// script-engine execution path needs real signed scripts — covered E2E
// by devnet; `extract_tx_unchecked` (the mechanical part) is covered.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DILITHIUM44_SIG_SIZE, DILITHIUM44_VK_SIZE};
    use sophis_consensus_core::config::params::DEVNET_PARAMS;
    use sophis_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionOutpoint, UtxoEntry};

    fn op(txid: u8, index: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(Hash::from_slice(&[txid; 32]), index)
    }
    fn spk(b: u8) -> ScriptPublicKey {
        ScriptPublicKey::new(0, ScriptVec::from_slice(&[b]))
    }
    fn inp(txid: u8, idx: u32, amount: u64) -> Input {
        InputBuilder::default()
            .previous_outpoint(op(txid, idx))
            .utxo_entry(UtxoEntry::new(amount, spk(1), 0, false))
            .sig_op_count(1)
            .build()
            .unwrap()
    }
    fn outp(amount: u64) -> Output {
        OutputBuilder::default().amount(amount).script_public_key(spk(2)).build().unwrap()
    }
    fn pkey(b: u8) -> DilithiumPubKey {
        DilithiumPubKey::from_bytes([b; DILITHIUM44_VK_SIZE])
    }
    fn sg(b: u8) -> Signature {
        Signature::dilithium_ml44_from_bytes([b; DILITHIUM44_SIG_SIZE])
    }

    fn constructed() -> PSKT<Constructor> {
        PSKT::<Creator>::default()
            .set_version(Version::One)
            .fallback_lock_time(42)
            .inputs_modifiable()
            .outputs_modifiable()
            .constructor()
            .input(inp(1, 0, 1000))
            .output(outp(600))
    }

    #[test]
    fn creator_to_constructor_builder_chain() {
        let c = PSKT::<Creator>::default()
            .set_version(Version::One)
            .fallback_lock_time(7)
            .inputs_modifiable()
            .outputs_modifiable()
            .constructor();
        assert_eq!(c.global.version, Version::One);
        assert_eq!(c.global.fallback_lock_time, Some(7));
        assert!(c.global.inputs_modifiable && c.global.outputs_modifiable);
    }

    #[test]
    fn constructor_input_output_payload_and_no_more() {
        let c = constructed();
        assert_eq!(c.inputs.len(), 1);
        assert_eq!(c.outputs.len(), 1);
        assert_eq!(c.global.input_count, 1);
        assert_eq!(c.global.output_count, 1);
        // payload allowed at Version::One
        let c = c.payload(Some(vec![1, 2, 3])).unwrap();
        assert_eq!(c.global.payload, Some(vec![1, 2, 3]));
        let c = c.no_more_inputs().no_more_outputs();
        assert!(!c.global.inputs_modifiable && !c.global.outputs_modifiable);
    }

    #[test]
    fn payload_requires_version_one() {
        let c = PSKT::<Creator>::default().constructor(); // version Zero
        assert!(matches!(c.payload(Some(vec![1])), Err(Error::PayloadRequiresVersion1(Version::Zero))));
    }

    #[test]
    fn updater_set_sequence_ok_and_out_of_bounds() {
        let u = constructed().updater();
        let u = u.set_sequence(99, 0).unwrap();
        assert_eq!(u.inputs[0].sequence, Some(99));
        assert!(matches!(u.set_sequence(1, 5), Err(Error::OutOfBounds)));
    }

    #[test]
    fn unsigned_tx_lock_time_and_id_deterministic() {
        let p = constructed();
        let tx = p.unsigned_tx();
        assert_eq!(tx.tx.inputs.len(), 1);
        assert_eq!(tx.tx.outputs.len(), 1);
        assert_eq!(tx.tx.outputs[0].value, 600);
        assert_eq!(p.calculate_id_internal(), p.calculate_id_internal());

        // determine_lock_time: with an input present whose min_time is
        // None, `.max()` yields Some(None) so the fallback is NOT used →
        // 0 (the fallback only applies when there are zero inputs).
        assert_eq!(p.determine_lock_time(), 0);

        // No inputs → empty iterator → fallback_lock_time is used.
        let no_inputs = PSKT::<Creator>::default().fallback_lock_time(42).constructor();
        assert_eq!(no_inputs.determine_lock_time(), 42);

        // An input min_time wins via the max().
        let with_min_time = PSKT::<Creator>::default().constructor().input(
            InputBuilder::default()
                .previous_outpoint(op(1, 0))
                .utxo_entry(UtxoEntry::new(1000, spk(1), 0, false))
                .sig_op_count(1)
                .min_time(Some(50))
                .build()
                .unwrap(),
        );
        assert_eq!(with_min_time.determine_lock_time(), 50);
    }

    #[test]
    fn hex_roundtrip_and_prefix_error() {
        let p = constructed();
        let hex = p.to_hex().unwrap();
        assert!(hex.starts_with("PSKT"));
        let back: PSKT<Constructor> = PSKT::from_hex(&hex).unwrap();
        assert_eq!(back.inputs.len(), 1);
        assert!(matches!(PSKT::<Constructor>::from_hex("NOPE"), Err(Error::PsktPrefixError)));
    }

    #[test]
    fn deref_clone_and_from_inner() {
        let inner = Inner { global: Global::default(), inputs: vec![inp(1, 0, 5)], outputs: vec![] };
        let p: PSKT<Signer> = PSKT::from(inner);
        assert_eq!(p.inputs.len(), 1); // Deref to Inner
        assert_eq!(p.clone().inputs.len(), 1);
    }

    #[test]
    fn signer_pass_signature_sync_populates_partial_sigs() {
        let s = constructed().signer();
        let signed = s
            .pass_signature_sync(|_tx, _sighashes| -> Result<Vec<SignInputOk>, String> {
                Ok(vec![SignInputOk { signature: sg(3), pub_key: pkey(4), key_source: None }])
            })
            .unwrap();
        assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
        assert_eq!(signed.inputs[0].partial_sigs[0].0, pkey(4));
        // role transitions
        let _ = signed.clone().finalizer();
        let _ = signed.clone().combiner();
        let rebased = signed.set_input_prev_transaction_id(Hash::from_slice(&[9; 32]));
        assert_eq!(rebased.inputs[0].previous_outpoint.transaction_id, Hash::from_slice(&[9; 32]));
    }

    #[test]
    fn combiner_add_merges_compatible_pskts() {
        let a = constructed().combiner();
        let b: PSKT<Constructor> = constructed();
        let combined = (a + b).unwrap();
        assert_eq!(combined.inputs.len(), 1);
        assert_eq!(combined.outputs.len(), 1);
        let _ = combined.clone().signer();
        let _ = combined.finalizer();
    }

    #[test]
    fn combiner_add_global_mismatch_errors() {
        let a = constructed().combiner(); // version One
        let b = PSKT::<Creator>::default().constructor().input(inp(1, 0, 1000)); // version Zero
        assert!(matches!(a + b, Err(CombineError::Global(_))));
    }

    #[test]
    fn finalizer_success_and_error_paths() {
        let s = constructed().signer();
        let f = s.finalizer();
        // wrong sig count
        let wrong = f.clone().finalize_sync(|_| -> Result<Vec<Vec<u8>>, String> { Ok(vec![]) });
        assert!(matches!(wrong, Err(FinalizeError::WrongFinalizedSigsCount { expected: 1, actual: 0 })));
        // empty signature
        let empty = f.clone().finalize_sync(|_| -> Result<Vec<Vec<u8>>, String> { Ok(vec![vec![]]) });
        assert!(matches!(empty, Err(FinalizeError::EmptySignature(0))));
        // callback error
        let cberr = f.clone().finalize_sync(|_| -> Result<Vec<Vec<u8>>, String> { Err("boom".into()) });
        assert!(matches!(cberr, Err(FinalizeError::FinalaziCb(_))));
        // success → global.id set, extractor ok
        let done = f.finalize_sync(|_| -> Result<Vec<Vec<u8>>, String> { Ok(vec![vec![1, 2, 3]]) }).unwrap();
        assert!(done.id().is_some());
        assert!(done.inputs[0].final_script_sig.is_some());
        assert!(done.extractor().is_ok());
    }

    #[test]
    fn finalizer_extractor_not_finalized() {
        let f = constructed().signer().finalizer();
        assert!(matches!(f.extractor(), Err(TxNotFinalized {})));
    }

    #[test]
    fn extractor_unchecked_builds_tx_with_mass() {
        let done = constructed()
            .signer()
            .finalizer()
            .finalize_sync(|_| -> Result<Vec<Vec<u8>>, String> { Ok(vec![vec![0xaa, 0xbb]]) })
            .unwrap();
        let ex = done.extractor().unwrap();
        let mtx = ex.extract_tx_unchecked(&DEVNET_PARAMS).unwrap();
        assert_eq!(mtx.tx.inputs[0].signature_script, vec![0xaa, 0xbb]);
        assert!(mtx.tx.mass() > 0);
    }

    #[test]
    fn error_displays() {
        assert_eq!(TxNotFinalized {}.to_string(), "Transaction is not finalized");
        let e: FinalizeError<String> = FinalizeError::EmptySignature(2);
        assert_eq!(e.to_string(), "Signatures at index: 2 is empty");
        let ce: CombineError = crate::input::CombineError::SpentOutputIndexMismatch { this: 0, that: 1 }.into();
        assert!(!ce.to_string().is_empty());
    }
}

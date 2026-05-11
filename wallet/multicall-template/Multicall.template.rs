//! Sophis Multicall contract — sample template.
//!
//! NOT compiled in the workspace. This file documents the canonical
//! shape of a Multicall contract per `docs/J7_MULTICALL_DESIGN.md`.
//! A real deployment compiles this (or a fork) to WASM via the Sophis
//! SDK and deploys to a well-known address per network.
//!
//! Frozen ABI per design §7:
//! - Input wire format: borsh-encoded `MulticallInput { calls: Vec<SubCall> }`
//! - Sub-call:           `(target_contract_id: [u8; 32], call_data: Vec<u8>, value_sompi: u64, allow_failure: bool)`
//! - Output wire format: borsh-encoded `MulticallOutput { results: Vec<SubCallResult> }`
//! - Sub-call result:    `(success: bool, return_data: Vec<u8>, gas_used: u64)`
//!
//! The Multicall contract MUST refuse to dispatch a sub-call whose
//! `target_contract_id` equals its own deployed contract id (re-entrancy
//! guard, design §3.4).

use borsh::{BorshDeserialize, BorshSerialize};

// ---------------------------------------------------------------------------
// Wire types (frozen per design §3)
// ---------------------------------------------------------------------------

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct SubCall {
    pub target_contract_id: [u8; 32],
    pub call_data: Vec<u8>,
    pub value_sompi: u64,
    /// If true, this call's failure does NOT revert the batch.
    pub allow_failure: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct MulticallInput {
    pub calls: Vec<SubCall>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct SubCallResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct MulticallOutput {
    pub results: Vec<SubCallResult>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum MulticallError {
    /// Input UTXO datum did not borsh-decode to `MulticallInput`.
    DecodeFailed,
    /// `MulticallInput.calls` is empty (no sub-calls to dispatch).
    EmptyBatch,
    /// A sub-call without `allow_failure = true` returned failure.
    /// Carries the index of the failing sub-call.
    SubCallFailed(usize),
    /// A sub-call attempted to target the Multicall contract itself
    /// (re-entrancy). Carries the index of the offending sub-call.
    ReentrancyDetected(usize),
    /// Aggregate gas exhausted mid-batch.
    GasExhausted,
}

// ---------------------------------------------------------------------------
// Contract entry point — sketch
// ---------------------------------------------------------------------------

/// Hand-rolled top-level execution. A real deployment uses the
/// `sophis_contract!` macro from `sophis-sdk` to wire the standard
/// `validate()` export expected by the sVM runtime.
///
/// Pseudo-code for the `validate()` body:
///
/// ```text
/// fn validate(env: &Env) -> i32 {
///     // 1. Read input UTXO 0 datum (the batched MulticallInput).
///     let input_utxo = match env.input_utxo(0) { Some(u) => u, None => return -1 };
///     let input_datum: Vec<u8> = input_utxo.datum;
///     let batch: MulticallInput = match MulticallInput::try_from_slice(&input_datum) {
///         Ok(b) => b,
///         Err(_) => return -2,  // DecodeFailed
///     };
///     if batch.calls.is_empty() { return -3; }  // EmptyBatch
///
///     // 2. The Multicall's own contract id (stamped onto context per J4.3
///     // pattern: env exposes the executing contract id via env.contract_id()).
///     let self_id: [u8; 32] = env.contract_id();
///
///     // 3. Dispatch each sub-call in order, accumulating results.
///     let mut results: Vec<SubCallResult> = Vec::with_capacity(batch.calls.len());
///     for (idx, call) in batch.calls.iter().enumerate() {
///         // Re-entrancy guard (design §3.4).
///         if call.target_contract_id == self_id {
///             return -((4 + idx) as i32);  // ReentrancyDetected(idx)
///         }
///
///         let gas_before = env.gas_used();
///         let outcome: Result<Vec<u8>, ()> = env.invoke_sub_contract(
///             &call.target_contract_id,
///             &call.call_data,
///             call.value_sompi,
///         );
///         let gas_used = env.gas_used().saturating_sub(gas_before);
///
///         match (outcome, call.allow_failure) {
///             (Ok(return_data), _) => {
///                 results.push(SubCallResult { success: true, return_data, gas_used });
///             }
///             (Err(_), true) => {
///                 // Failure tolerated by per-call opt-in; record + continue.
///                 results.push(SubCallResult { success: false, return_data: Vec::new(), gas_used });
///             }
///             (Err(_), false) => {
///                 // Hard atomic-revert path: SubCallFailed(idx).
///                 return -((1000 + idx) as i32);
///             }
///         }
///     }
///
///     // 4. Write the aggregated MulticallOutput into output UTXO 0's datum.
///     let output: MulticallOutput = MulticallOutput { results };
///     let output_bytes: Vec<u8> = match borsh::to_vec(&output) {
///         Ok(b) => b,
///         Err(_) => return -5,
///     };
///     // SDK helper: env.set_output_datum(0, &output_bytes);
///     1  // success
/// }
/// ```
///
/// Note: `env.invoke_sub_contract` is hypothetical — the real sVM does
/// not yet expose a "call this other contract" host fn (that's part of
/// what `Capability::ExecuteBatch` would add natively per D6). Until
/// then the Multicall pattern is realised by the *transaction
/// composition* layer: a single tx whose UTXOs spend N contract UTXOs
/// in order, with the Multicall contract serving as the orchestrator
/// that sequences the dispatch via UTXO state transitions.
///
/// In practice this means the v1 "Multicall" template is a documented
/// transaction-construction pattern + this contract template
/// (validating the batch shape + recording per-call results). Native
/// sub-contract dispatch lands with `Capability::ExecuteBatch` per the
/// future SIP gated on D6 criteria.
pub fn _validate_sketch_only() {
    // Intentionally empty — see the doc-comment pseudo-code above.
}

// ---------------------------------------------------------------------------
// SDK-side helpers (caller code)
// ---------------------------------------------------------------------------

/// Builds a `MulticallInput` from a list of sub-calls, ready to borsh-
/// serialise into a Multicall contract's input UTXO datum. Provided
/// here as a sketch; a real `sophis-multicall-sdk` crate (future J7.x.a)
/// would expose this as a builder pattern with strongly-typed call
/// arguments.
pub fn build_multicall_input(calls: Vec<SubCall>) -> MulticallInput {
    MulticallInput { calls }
}

/// Convenience constructor for one sub-call — atomic (allow_failure = false).
pub fn atomic_sub_call(target_contract_id: [u8; 32], call_data: Vec<u8>, value_sompi: u64) -> SubCall {
    SubCall { target_contract_id, call_data, value_sompi, allow_failure: false }
}

/// Convenience constructor for one sub-call — best-effort (allow_failure = true).
/// Use sparingly; D3 of the design doc reserves this for cosmetic /
/// optional sub-calls (e.g. emit a tracking event) that should not
/// tank a critical step.
pub fn optional_sub_call(target_contract_id: [u8; 32], call_data: Vec<u8>, value_sompi: u64) -> SubCall {
    SubCall { target_contract_id, call_data, value_sompi, allow_failure: true }
}

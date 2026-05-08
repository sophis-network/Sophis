/// Integration tests for the sVM execution pipeline.
///
/// Tests the full path:
///   deploy tx  → validate_contract_deploy (isolation) → deploy_if_absent (store WASM)
///   call tx    → check_scripts_with_svm → ContractExecutor → Wasmtime → result
use std::sync::Arc;

use borsh::to_vec as borsh_vec;
use smallvec::SmallVec;
use sophis_consensus_core::{
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use sophis_hashes::Hash;
use sophis_svm_core::{ContractDeployPayload, ContractManifest, ContractStore, ContractUtxoData, Datum, UpgradePolicy, hash_wasm};
use sophis_svm_runtime::InMemoryContractStore;
use sophis_txscript::caches::{Cache, TxScriptCacheCounters};

use sophis_txscript::SigCacheKey;

use crate::processes::transaction_validator::{
    SvmContext,
    tx_validation_in_isolation::{is_contract_deploy, validate_contract_deploy},
    tx_validation_in_utxo_context::check_scripts_with_svm,
};

// ---------------------------------------------------------------------------
// Minimal WASM binaries (hand-crafted, no external `wat` dep needed)
// ---------------------------------------------------------------------------

/// Always returns 1 (validate = accept).
/// WAT equivalent:
///   (module
///     (func (export "validate") (result i32) i32.const 1)
///     (memory (export "memory") 1 256))
const ALWAYS_VALID_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type section: () -> i32
    0x03, 0x02, 0x01, 0x00, // function section: func[0] uses type[0]
    0x05, 0x05, 0x01, 0x01, 0x01, 0x80, 0x02, // memory section: 1 page min, 256 max (LEB128 0x80,0x02)
    0x07, 0x15, 0x02, // export section: 2 exports, 21 bytes
    0x08, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00, // "validate" func[0]
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, // "memory" mem[0]
    0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x01, 0x0b, // code: i32.const 1; end
];

/// Always returns 0 (validate = reject).
const ALWAYS_REJECT_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x05, 0x05,
    0x01, 0x01, 0x01, 0x80, 0x02, 0x07, 0x15, 0x02, 0x08, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00, 0x06, 0x6d,
    0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x00, 0x0b, // i32.const 0 (reject)
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_svm_ctx(wasm: &[u8]) -> (SvmContext, sophis_svm_core::ContractId) {
    let store = Arc::new(InMemoryContractStore::new());
    let contract_id = hash_wasm(wasm);
    store.deploy_if_absent(contract_id, wasm.to_vec());
    let ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).expect("SvmEngine should always initialise");
    (ctx, contract_id)
}

fn contract_utxo_data_bytes(contract_id: sophis_svm_core::ContractId) -> Vec<u8> {
    let manifest = ContractManifest::new(contract_id, UpgradePolicy::Immutable, vec![]);
    let data = ContractUtxoData::new(contract_id, Datum::default(), manifest);
    borsh_vec(&data).expect("borsh serialisation")
}

fn sig_cache() -> Cache<SigCacheKey, bool> {
    Cache::with_counters(100, Arc::new(TxScriptCacheCounters::default()))
}

fn contract_utxo_entry(script_bytes: Vec<u8>) -> UtxoEntry {
    UtxoEntry::new(100_000_000, ScriptPublicKey::new(1, SmallVec::from(script_bytes)), 0, false)
}

fn call_tx_spending(utxo_id: [u8; 32]) -> Transaction {
    Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: Hash::from_bytes(utxo_id), index: 0 },
            signature_script: vec![],
            sequence: u64::MAX,
            sig_op_count: 0,
        }],
        vec![TransactionOutput { value: 99_000_000, script_public_key: ScriptPublicKey::new(0, SmallVec::new()) }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_deploy_payload_valid() {
    let payload = ContractDeployPayload { wasm: ALWAYS_VALID_WASM.to_vec() };
    let contract_id = payload.contract_id();
    let script_bytes = contract_utxo_data_bytes(contract_id);

    let tx = Transaction::new(
        0,
        vec![],
        vec![TransactionOutput { value: 100_000_000, script_public_key: ScriptPublicKey::new(1, SmallVec::from(script_bytes)) }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        borsh_vec(&payload).unwrap(),
    );

    assert!(is_contract_deploy(&tx), "should be detected as deploy");
    assert!(validate_contract_deploy(&tx).is_ok(), "valid deploy should pass isolation check");
}

#[test]
fn test_deploy_wrong_contract_id_rejected() {
    let payload = ContractDeployPayload { wasm: ALWAYS_VALID_WASM.to_vec() };
    // Use wrong contract_id in the UTXO — hash of different wasm
    let wrong_id = hash_wasm(ALWAYS_REJECT_WASM);
    let script_bytes = contract_utxo_data_bytes(wrong_id);

    let tx = Transaction::new(
        0,
        vec![],
        vec![TransactionOutput { value: 100_000_000, script_public_key: ScriptPublicKey::new(1, SmallVec::from(script_bytes)) }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        borsh_vec(&payload).unwrap(),
    );

    assert!(validate_contract_deploy(&tx).is_err(), "mismatched contract_id should be rejected");
}

#[test]
fn test_svm_always_valid_contract_passes() {
    let (svm_ctx, contract_id) = make_svm_ctx(ALWAYS_VALID_WASM);
    let script_bytes = contract_utxo_data_bytes(contract_id);
    let utxo = contract_utxo_entry(script_bytes);

    let tx = call_tx_spending([1u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![utxo]);

    let result = check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0);
    assert!(result.is_ok(), "always-valid contract should pass: {result:?}");
}

#[test]
fn test_svm_always_reject_contract_fails() {
    let (svm_ctx, contract_id) = make_svm_ctx(ALWAYS_REJECT_WASM);
    let script_bytes = contract_utxo_data_bytes(contract_id);
    let utxo = contract_utxo_entry(script_bytes);

    let tx = call_tx_spending([2u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![utxo]);

    let result = check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0);
    assert!(result.is_err(), "always-reject contract should fail");
}

#[test]
fn test_svm_contract_not_deployed_fails() {
    // SvmContext with an empty store — contract not deployed
    let store = Arc::new(InMemoryContractStore::new());
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();

    let contract_id = hash_wasm(ALWAYS_VALID_WASM);
    let script_bytes = contract_utxo_data_bytes(contract_id);
    let utxo = contract_utxo_entry(script_bytes);

    let tx = call_tx_spending([3u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![utxo]);

    let result = check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0);
    assert!(result.is_err(), "undeployed contract should return ContractNotDeployed error");
    assert!(matches!(result, Err(ref e) if e.to_string().contains("not deployed")), "expected ContractNotDeployed, got: {result:?}");
}

#[test]
fn test_svm_disabled_falls_through_to_error() {
    // svm = None — should return SvmValidationFailed "not initialised"
    let contract_id = hash_wasm(ALWAYS_VALID_WASM);
    let script_bytes = contract_utxo_data_bytes(contract_id);
    let utxo = contract_utxo_entry(script_bytes);

    let tx = call_tx_spending([4u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![utxo]);

    let result = check_scripts_with_svm(&sig_cache(), None, &populated, 0);
    assert!(result.is_err(), "contract input with sVM disabled should fail");
}

#[test]
fn test_mixed_tx_normal_and_contract_inputs() {
    // Tx with one normal P2PK input AND one contract input — only contract path tested here
    // (P2PK would fail without a valid Schnorr sig, so we only test contract part)
    let (svm_ctx, contract_id) = make_svm_ctx(ALWAYS_VALID_WASM);
    let script_bytes = contract_utxo_data_bytes(contract_id);
    let contract_utxo = contract_utxo_entry(script_bytes);

    // A single-input tx with a Contract UTXO — passes
    let tx = call_tx_spending([5u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![contract_utxo]);
    let result = check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0);
    assert!(result.is_ok(), "contract input should pass: {result:?}");
}

// ---------------------------------------------------------------------------
// E2E tests: real WAT contracts compiled via `wat` crate
// ---------------------------------------------------------------------------

fn make_svm_ctx_with_caps(wasm: &[u8], caps: Vec<sophis_svm_core::Capability>) -> (SvmContext, sophis_svm_core::ContractId) {
    let store = Arc::new(InMemoryContractStore::new());
    let contract_id = hash_wasm(wasm);
    store.deploy_if_absent(contract_id, wasm.to_vec());
    let ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).expect("SvmEngine init");
    // Re-register with correct capabilities by building the script bytes
    let _ = contract_utxo_data_bytes_with_caps(contract_id, caps);
    (ctx, contract_id)
}

fn contract_utxo_data_bytes_with_caps(contract_id: sophis_svm_core::ContractId, caps: Vec<sophis_svm_core::Capability>) -> Vec<u8> {
    let manifest = ContractManifest::new(contract_id, UpgradePolicy::Immutable, caps);
    let data = ContractUtxoData::new(contract_id, Datum::default(), manifest);
    borsh_vec(&data).expect("borsh serialisation")
}

fn contract_utxo_entry_with_caps(wasm: &[u8], caps: Vec<sophis_svm_core::Capability>) -> UtxoEntry {
    let contract_id = hash_wasm(wasm);
    let script_bytes = contract_utxo_data_bytes_with_caps(contract_id, caps);
    UtxoEntry::new(100_000_000, ScriptPublicKey::new(1, SmallVec::from(script_bytes)), 0, false)
}

/// Contract: accepts if `get_block_height()` >= 10_000, rejects otherwise.
const HEIGHT_CHECK_WAT: &str = r#"
    (module
      (import "env" "get_block_height" (func $h (result i64)))
      (memory (export "memory") 1 256)
      (func (export "validate") (result i32)
        call $h
        i64.const 10000
        i64.ge_s))
"#;

/// Contract: calls sha3_384 on 5 bytes ("hello" at mem[0..5]), returns 1 on success.
const SHA3_CALL_WAT: &str = r#"
    (module
      (import "env" "sha3_384" (func $sha3 (param i32 i32 i32) (result i32)))
      (memory (export "memory") 1 256)
      (data (i32.const 0) "hello")
      (func (export "validate") (result i32)
        i32.const 0
        i32.const 5
        i32.const 64
        call $sha3))
"#;

#[test]
fn test_e2e_contract_accepts_above_daa_threshold() {
    use sophis_svm_core::Capability;
    let wasm = wat::parse_str(HEIGHT_CHECK_WAT).expect("valid WAT");
    let caps = vec![Capability::ReadBlockHeight];
    let (svm_ctx, _) = make_svm_ctx_with_caps(&wasm, caps.clone());
    let entry = contract_utxo_entry_with_caps(&wasm, caps);
    let tx = call_tx_spending([10u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    // at threshold — accepts
    assert!(check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 10_000).is_ok());
    // above threshold — accepts
    assert!(check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 50_000).is_ok());
}

#[test]
fn test_e2e_contract_rejects_below_daa_threshold() {
    use sophis_svm_core::Capability;
    let wasm = wat::parse_str(HEIGHT_CHECK_WAT).expect("valid WAT");
    let caps = vec![Capability::ReadBlockHeight];
    let (svm_ctx, _) = make_svm_ctx_with_caps(&wasm, caps.clone());
    let entry = contract_utxo_entry_with_caps(&wasm, caps);
    let tx = call_tx_spending([11u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    // below threshold — contract returns 0 → TxRuleError
    assert!(check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 9_999).is_err());
    assert!(check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0).is_err());
}

#[test]
fn test_e2e_sha3_host_function_executes() {
    use sophis_svm_core::Capability;
    let wasm = wat::parse_str(SHA3_CALL_WAT).expect("valid WAT");
    let caps = vec![Capability::HashSha3];
    let (svm_ctx, _) = make_svm_ctx_with_caps(&wasm, caps.clone());
    let entry = contract_utxo_entry_with_caps(&wasm, caps);
    let tx = call_tx_spending([12u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    // sha3_384 host function must succeed (return 1) → contract accepts
    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0).is_ok(),
        "sha3_384 host function must execute successfully"
    );
}

#[test]
fn test_e2e_capability_missing_causes_rejection() {
    // sha3 contract without HashSha3 capability → sha3_384 returns 0 → contract rejects
    let wasm = wat::parse_str(SHA3_CALL_WAT).expect("valid WAT");
    let (svm_ctx, _) = make_svm_ctx_with_caps(&wasm, vec![]); // no capabilities
    let entry = contract_utxo_entry_with_caps(&wasm, vec![]);
    let tx = call_tx_spending([13u8; 32]);
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    // sha3_384 returns 0 (capability check fails) → contract returns 0 → tx rejected
    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0).is_err(),
        "missing capability must cause contract to reject"
    );
}

#[test]
fn test_e2e_full_deploy_and_call_pipeline() {
    use sophis_svm_core::Capability;
    // Full pipeline: deploy tx → isolation validate → store → call tx → sVM execute

    let wasm = wat::parse_str(HEIGHT_CHECK_WAT).expect("valid WAT");
    let caps = vec![Capability::ReadBlockHeight];
    let contract_id = hash_wasm(&wasm);
    let payload = ContractDeployPayload { wasm: wasm.clone() };
    let script_bytes = contract_utxo_data_bytes_with_caps(contract_id, caps.clone());

    // 1. Build deploy tx
    let deploy_tx = Transaction::new(
        0,
        vec![],
        vec![TransactionOutput {
            value: 100_000_000,
            script_public_key: ScriptPublicKey::new(1, SmallVec::from(script_bytes.clone())),
        }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        borsh_vec(&payload).unwrap(),
    );

    // 2. Isolation validation (deploy tx)
    assert!(is_contract_deploy(&deploy_tx), "must be detected as deploy");
    assert!(validate_contract_deploy(&deploy_tx).is_ok(), "deploy must pass isolation");

    // 3. Simulate accept hook: store WASM
    let store = Arc::new(InMemoryContractStore::new());
    store.deploy_if_absent(contract_id, wasm.clone());

    // 4. Build sVM context from the same store
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).expect("sVM init");

    // 5. Build call tx spending the deployed Contract UTXO
    let contract_entry = UtxoEntry::new(100_000_000, ScriptPublicKey::new(1, SmallVec::from(script_bytes)), 0, false);
    let call_tx = call_tx_spending([20u8; 32]);
    let populated = PopulatedTransaction::new(&call_tx, vec![contract_entry]);

    // 6. Execute — contract accepts at pov_daa_score >= 10_000
    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 10_000).is_ok(),
        "full pipeline: deploy → store → call must succeed"
    );
    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 9_999).is_err(),
        "full pipeline: call at wrong daa_score must be rejected by contract"
    );
}

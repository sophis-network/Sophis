/// Integration tests for Native Token (SCRIPT_VERSION_TOKEN = 2).
///
/// Tests the full path:
///   deploy tx      → is_mint_policy_deploy / validate_mint_policy_deploy
///   transfer       → check_token_utxo_spend (synthetic P2PK) + check_token_conservation
///   mint/burn      → check_token_conservation → Minting Policy WASM
///   transfer policy → check_token_utxo_spend → Transfer Policy WASM
use std::sync::Arc;

use borsh::to_vec as borsh_vec;
use smallvec::SmallVec;
use sophis_addresses::{Address, Prefix, Version};
use sophis_consensus_core::{
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use sophis_hashes::Hash;
use sophis_svm_core::{ContractStore, MintingPolicyPayload, NativeTokenUtxoData, hash_mint_policy, hash_wasm};
use sophis_svm_runtime::InMemoryContractStore;
use sophis_txscript::{
    SigCacheKey,
    caches::{Cache, TxScriptCacheCounters},
    standard::pay_to_address_script,
};

use crate::processes::transaction_validator::{
    SvmContext,
    tx_validation_in_isolation::{is_mint_policy_deploy, validate_mint_policy_deploy, validate_token_outputs},
    tx_validation_in_utxo_context::{check_scripts_with_svm, check_token_conservation},
};

// ---------------------------------------------------------------------------
// Minimal WASM: always-valid Minting Policy (approves any mint/burn)
// ---------------------------------------------------------------------------

/// Minting Policy WAT: always returns 1 (approve any mint/burn).
const ALWAYS_APPROVE_MINT_WAT: &str = r#"
    (module
      (memory (export "memory") 1 256)
      (func (export "validate") (result i32)
        i32.const 1))
"#;

/// Minting Policy WAT: always returns 0 (reject any mint/burn).
const ALWAYS_REJECT_MINT_WAT: &str = r#"
    (module
      (memory (export "memory") 1 256)
      (func (export "validate") (result i32)
        i32.const 0))
"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sig_cache() -> Cache<SigCacheKey, bool> {
    Cache::with_counters(100, Arc::new(TxScriptCacheCounters::default()))
}

/// Builds a simple pay-to-pubkey lock script for testing (using a fixed 32-byte pubkey).
fn test_lock_script() -> Vec<u8> {
    // Use a fixed x-only pubkey — we only test conservation here, not actual sig verification.
    let pubkey = [0x02u8; 32];
    let addr = Address::new(Prefix::Mainnet, Version::PubKeyDilithium, &pubkey);
    pay_to_address_script(&addr).script().to_vec()
}

fn token_utxo_entry(token_id: sophis_svm_core::TokenId, amount: u64) -> UtxoEntry {
    let data = NativeTokenUtxoData::new(token_id, amount, test_lock_script());
    let script_bytes = borsh_vec(&data).unwrap();
    UtxoEntry::new(
        1_000_000, // storage deposit in sompi
        ScriptPublicKey::new(2, SmallVec::from(script_bytes)),
        0,
        false,
    )
}

fn token_output(token_id: sophis_svm_core::TokenId, amount: u64) -> TransactionOutput {
    let data = NativeTokenUtxoData::new(token_id, amount, test_lock_script());
    let script_bytes = borsh_vec(&data).unwrap();
    TransactionOutput { value: 1_000_000, script_public_key: ScriptPublicKey::new(2, SmallVec::from(script_bytes)) }
}

fn dummy_tx_spending(utxo_id: [u8; 32]) -> Transaction {
    Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint { transaction_id: Hash::from_bytes(utxo_id), index: 0 },
            signature_script: vec![],
            sequence: u64::MAX,
            sig_op_count: 0,
        }],
        vec![],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    )
}

fn make_svm_with_mint_policy(wasm: &[u8]) -> (SvmContext, sophis_svm_core::TokenId) {
    let store = Arc::new(InMemoryContractStore::new());
    let token_id = hash_mint_policy(wasm);
    store.deploy_if_absent(token_id, wasm.to_vec());
    let ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();
    (ctx, token_id)
}

// ---------------------------------------------------------------------------
// Tests — Minting Policy deploy validation
// ---------------------------------------------------------------------------

#[test]
fn test_mint_policy_deploy_detected() {
    let wasm = wat::parse_str(ALWAYS_APPROVE_MINT_WAT).unwrap();
    let token_id = hash_mint_policy(&wasm);
    let payload = MintingPolicyPayload { wasm: wasm.clone() };
    let data = NativeTokenUtxoData::new(token_id, 1_000_000, test_lock_script());

    let tx = Transaction::new(
        0,
        vec![],
        vec![TransactionOutput {
            value: 1_000_000,
            script_public_key: ScriptPublicKey::new(2, SmallVec::from(borsh_vec(&data).unwrap())),
        }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        borsh_vec(&payload).unwrap(),
    );

    assert!(is_mint_policy_deploy(&tx));
    assert!(validate_mint_policy_deploy(&tx).is_ok());
}

#[test]
fn test_mint_policy_deploy_wrong_token_id_rejected() {
    let wasm = wat::parse_str(ALWAYS_APPROVE_MINT_WAT).unwrap();
    let wrong_wasm = wat::parse_str(ALWAYS_REJECT_MINT_WAT).unwrap();
    let wrong_token_id = hash_mint_policy(&wrong_wasm); // mismatched
    let payload = MintingPolicyPayload { wasm: wasm.clone() };
    let data = NativeTokenUtxoData::new(wrong_token_id, 1_000_000, test_lock_script());

    let tx = Transaction::new(
        0,
        vec![],
        vec![TransactionOutput {
            value: 1_000_000,
            script_public_key: ScriptPublicKey::new(2, SmallVec::from(borsh_vec(&data).unwrap())),
        }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        borsh_vec(&payload).unwrap(),
    );

    assert!(validate_mint_policy_deploy(&tx).is_err(), "mismatched token_id must be rejected");
}

// ---------------------------------------------------------------------------
// Tests — Token UTXO output validation (non-deploy txs)
// ---------------------------------------------------------------------------

#[test]
fn test_well_formed_token_output_passes() {
    let token_id = Hash::from_bytes([7u8; 32]);
    let tx = Transaction::new(0, vec![], vec![token_output(token_id, 500)], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    assert!(validate_token_outputs(&tx).is_ok());
}

// ---------------------------------------------------------------------------
// Tests — Token conservation
// ---------------------------------------------------------------------------

#[test]
fn test_token_conservation_transfer_ok() {
    let wasm = wat::parse_str(ALWAYS_APPROVE_MINT_WAT).unwrap();
    let (svm_ctx, token_id) = make_svm_with_mint_policy(&wasm);

    // 1 input with 500 tokens, 1 output with 500 tokens → pure transfer, no mint policy needed
    let entry = token_utxo_entry(token_id, 500);
    let mut tx = dummy_tx_spending([1u8; 32]);
    tx.outputs.push(token_output(token_id, 500));
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    assert!(check_token_conservation(Some(&svm_ctx), &populated, 0).is_ok(), "balanced transfer must pass conservation");
}

#[test]
fn test_token_mint_approved_by_policy() {
    let wasm = wat::parse_str(ALWAYS_APPROVE_MINT_WAT).unwrap();
    let (svm_ctx, token_id) = make_svm_with_mint_policy(&wasm);

    // 0 input tokens, 1000 output tokens → net mint; minting policy approves
    let mut tx = dummy_tx_spending([2u8; 32]);
    tx.outputs.push(token_output(token_id, 1_000));
    // No token input — we only have a normal SOF input
    let sof_entry = UtxoEntry::new(10_000_000, ScriptPublicKey::new(0, SmallVec::new()), 0, false);
    let populated = PopulatedTransaction::new(&tx, vec![sof_entry]);

    assert!(check_token_conservation(Some(&svm_ctx), &populated, 0).is_ok(), "mint approved by always-approve policy");
}

#[test]
fn test_token_mint_rejected_by_policy() {
    let wasm = wat::parse_str(ALWAYS_REJECT_MINT_WAT).unwrap();
    let (svm_ctx, token_id) = make_svm_with_mint_policy(&wasm);

    let mut tx = dummy_tx_spending([3u8; 32]);
    tx.outputs.push(token_output(token_id, 1_000));
    let sof_entry = UtxoEntry::new(10_000_000, ScriptPublicKey::new(0, SmallVec::new()), 0, false);
    let populated = PopulatedTransaction::new(&tx, vec![sof_entry]);

    assert!(check_token_conservation(Some(&svm_ctx), &populated, 0).is_err(), "mint must be rejected by always-reject policy");
}

#[test]
fn test_token_mint_no_policy_deployed_fails() {
    // Minting policy not stored — any net mint must be rejected
    let store = Arc::new(InMemoryContractStore::new());
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();
    let wasm = wat::parse_str(ALWAYS_APPROVE_MINT_WAT).unwrap();
    let token_id = hash_mint_policy(&wasm); // policy not deployed

    let mut tx = dummy_tx_spending([4u8; 32]);
    tx.outputs.push(token_output(token_id, 500));
    let sof_entry = UtxoEntry::new(10_000_000, ScriptPublicKey::new(0, SmallVec::new()), 0, false);
    let populated = PopulatedTransaction::new(&tx, vec![sof_entry]);

    assert!(check_token_conservation(Some(&svm_ctx), &populated, 0).is_err(), "undeployed minting policy must block mint");
}

#[test]
fn test_token_burn_approved_by_policy() {
    let wasm = wat::parse_str(ALWAYS_APPROVE_MINT_WAT).unwrap();
    let (svm_ctx, token_id) = make_svm_with_mint_policy(&wasm);

    // 1000 input tokens, 0 output tokens → net burn; policy approves
    let entry = token_utxo_entry(token_id, 1_000);
    let tx = dummy_tx_spending([5u8; 32]); // no token outputs
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    assert!(check_token_conservation(Some(&svm_ctx), &populated, 0).is_ok(), "burn approved by always-approve policy");
}

#[test]
fn test_multi_token_conservation() {
    // Two different tokens in the same tx — both balanced
    let wasm = wat::parse_str(ALWAYS_APPROVE_MINT_WAT).unwrap();
    let wasm2 = wat::parse_str(ALWAYS_REJECT_MINT_WAT).unwrap();
    let (svm_ctx, token_a) = make_svm_with_mint_policy(&wasm);
    let token_b = hash_mint_policy(&wasm2); // not deployed, but no delta so not needed
    let store = svm_ctx.store.clone();
    let svm_ctx2 = SvmContext::new(store).unwrap();

    let entry_a = token_utxo_entry(token_a, 200);
    let entry_b = token_utxo_entry(token_b, 300);
    let mut tx = Transaction::new(
        0,
        vec![
            TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: Hash::from_bytes([6u8; 32]), index: 0 },
                signature_script: vec![],
                sequence: u64::MAX,
                sig_op_count: 0,
            },
            TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: Hash::from_bytes([7u8; 32]), index: 0 },
                signature_script: vec![],
                sequence: u64::MAX,
                sig_op_count: 0,
            },
        ],
        vec![],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    tx.outputs.push(token_output(token_a, 200)); // balanced
    tx.outputs.push(token_output(token_b, 300)); // balanced — no policy needed

    let populated = PopulatedTransaction::new(&tx, vec![entry_a, entry_b]);
    assert!(check_token_conservation(Some(&svm_ctx2), &populated, 0).is_ok());
}

// ---------------------------------------------------------------------------
// Transfer Policy tests
// ---------------------------------------------------------------------------

/// Helper: deploys a WASM as a regular contract (hash_wasm domain) into the store
/// and returns the ContractId.
fn deploy_transfer_policy(store: &Arc<InMemoryContractStore>, wasm: &[u8]) -> sophis_svm_core::ContractId {
    let policy_id = hash_wasm(wasm);
    store.deploy_if_absent(policy_id, wasm.to_vec());
    policy_id
}

/// token_utxo_entry with a Transfer Policy attached.
fn token_utxo_entry_with_policy(token_id: sophis_svm_core::TokenId, amount: u64, policy_id: sophis_svm_core::ContractId) -> UtxoEntry {
    // lock_script = [OP_1] (0x51) — pushes 1 on the stack, trivially satisfiable
    // with an empty signature_script. Lets us test Transfer Policy logic in isolation.
    let data = NativeTokenUtxoData::new(token_id, amount, vec![0x51]).with_transfer_policy(policy_id);
    let script_bytes = borsh_vec(&data).unwrap();
    UtxoEntry::new(1_000_000, ScriptPublicKey::new(2, SmallVec::from(script_bytes)), 0, false)
}

/// Transfer Policy WAT: always approve.
const TRANSFER_APPROVE_WAT: &str = r#"
    (module
      (memory (export "memory") 1 256)
      (func (export "validate") (result i32)
        i32.const 1))
"#;

/// Transfer Policy WAT: always reject.
const TRANSFER_REJECT_WAT: &str = r#"
    (module
      (memory (export "memory") 1 256)
      (func (export "validate") (result i32)
        i32.const 0))
"#;

/// Transfer Policy WAT: accepts only if block_height >= 5000.
const TRANSFER_HEIGHT_WAT: &str = r#"
    (module
      (import "env" "get_block_height" (func $h (result i64)))
      (memory (export "memory") 1 256)
      (func (export "validate") (result i32)
        call $h
        i64.const 5000
        i64.ge_s))
"#;

#[test]
fn test_transfer_policy_approve() {
    let store = Arc::new(InMemoryContractStore::new());
    let tp_wasm = wat::parse_str(TRANSFER_APPROVE_WAT).unwrap();
    let policy_id = deploy_transfer_policy(&store, &tp_wasm);
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();

    let token_id = Hash::from_bytes([20u8; 32]);
    let entry = token_utxo_entry_with_policy(token_id, 100, policy_id);
    let mut tx = dummy_tx_spending([20u8; 32]);
    tx.outputs.push(token_output(token_id, 100));
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    // Transfer policy approves → both spending lock (empty sig passes trivially) and policy ok
    assert!(check_token_conservation(Some(&svm_ctx), &populated, 0).is_ok(), "conservation with approve policy");
    assert!(check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0).is_ok(), "scripts with approve transfer policy");
}

#[test]
fn test_transfer_policy_reject() {
    let store = Arc::new(InMemoryContractStore::new());
    let tp_wasm = wat::parse_str(TRANSFER_REJECT_WAT).unwrap();
    let policy_id = deploy_transfer_policy(&store, &tp_wasm);
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();

    let token_id = Hash::from_bytes([21u8; 32]);
    let entry = token_utxo_entry_with_policy(token_id, 100, policy_id);
    let mut tx = dummy_tx_spending([21u8; 32]);
    tx.outputs.push(token_output(token_id, 100));
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0).is_err(),
        "always-reject transfer policy must block spend"
    );
}

#[test]
fn test_transfer_policy_not_deployed_fails() {
    let store = Arc::new(InMemoryContractStore::new());
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();

    let tp_wasm = wat::parse_str(TRANSFER_APPROVE_WAT).unwrap();
    let policy_id = hash_wasm(&tp_wasm); // NOT stored in the store

    let token_id = Hash::from_bytes([22u8; 32]);
    let entry = token_utxo_entry_with_policy(token_id, 100, policy_id);
    let mut tx = dummy_tx_spending([22u8; 32]);
    tx.outputs.push(token_output(token_id, 100));
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &populated, 0).is_err(),
        "undeployed transfer policy must block spend"
    );
}

#[test]
fn test_transfer_policy_checks_daa_score() {
    let store = Arc::new(InMemoryContractStore::new());
    let tp_wasm = wat::parse_str(TRANSFER_HEIGHT_WAT).unwrap();
    let policy_id = deploy_transfer_policy(&store, &tp_wasm);
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();

    let token_id = Hash::from_bytes([23u8; 32]);
    let entry_above = token_utxo_entry_with_policy(token_id, 100, policy_id);
    let entry_below = token_utxo_entry_with_policy(token_id, 100, policy_id);

    let mut tx = dummy_tx_spending([23u8; 32]);
    tx.outputs.push(token_output(token_id, 100));

    let pop_above = PopulatedTransaction::new(&tx, vec![entry_above]);
    let pop_below = PopulatedTransaction::new(&tx, vec![entry_below]);

    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &pop_above, 5_000).is_ok(),
        "transfer policy passes at pov_daa_score=5000"
    );
    assert!(
        check_scripts_with_svm(&sig_cache(), Some(&svm_ctx), &pop_below, 4_999).is_err(),
        "transfer policy rejects at pov_daa_score=4999"
    );
}

#[test]
fn test_no_transfer_policy_no_overhead() {
    // Token UTXO without transfer_policy_id — sVM not needed at all
    let store = Arc::new(InMemoryContractStore::new());
    let svm_ctx = SvmContext::new(Arc::clone(&store) as Arc<dyn ContractStore>).unwrap();

    let token_id = Hash::from_bytes([24u8; 32]);
    let entry = token_utxo_entry(token_id, 100); // no transfer policy
    let mut tx = dummy_tx_spending([24u8; 32]);
    tx.outputs.push(token_output(token_id, 100));
    let populated = PopulatedTransaction::new(&tx, vec![entry]);

    // Empty store (no minting policy needed for balanced transfer), no Transfer Policy → passes
    assert!(check_token_conservation(Some(&svm_ctx), &populated, 0).is_ok(), "balanced transfer with no transfer policy needs no sVM");
}

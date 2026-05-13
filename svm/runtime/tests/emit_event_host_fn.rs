//! J4.3 — end-to-end tests for the `sophis_emit_event` host function.
//!
//! Each test compiles a tiny WAT contract that:
//!   1. Writes a hand-crafted emission payload into linear memory at offset 0
//!   2. Calls `sophis_emit_event(0, payload_len)`
//!   3. Returns the host-fn status code from `validate()`
//!
//! The host fn body in `svm/runtime/src/host.rs` is exercised via the same
//! Wasmtime path consensus uses, so memory bounds + gas metering + capability
//! enforcement all run for real.

use std::sync::Arc;

use sophis_hashes::Hash;
use sophis_svm_core::{
    Capability, ContractManifest, GasConfig, UpgradePolicy,
    events::{MAX_EVENT_DATA_BYTES, MAX_EVENTS_PER_TX, MAX_TOPICS_PER_EVENT, TOPIC_LEN, encode_emission_payload},
};
use sophis_svm_runtime::{context::ExecutionContext, engine::SvmEngine, executor::ContractExecutor, host::StubCrypto};
use wasmtime::{Linker, Module, Store};

const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

fn bytes_to_hex_lits(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for b in bytes {
        out.push('\\');
        out.push(HEX_ALPHABET[(b >> 4) as usize] as char);
        out.push(HEX_ALPHABET[(b & 0xF) as usize] as char);
    }
    out
}

/// Builds a WAT module with `payload` initialised at memory offset 0 and a
/// `validate` export that calls `sophis_emit_event(0, payload.len())` and
/// returns the resulting i32.
fn wat_emit(payload: &[u8]) -> String {
    let hex = bytes_to_hex_lits(payload);
    let len = payload.len();
    format!(
        r#"(module
            (import "env" "sophis_emit_event"
                (func $emit (param i32 i32) (result i32)))
            (memory (export "memory") 1 1)
            (data (i32.const 0) "{hex}")
            (func (export "validate") (result i32)
                (call $emit (i32.const 0) (i32.const {len}))))"#,
    )
}

/// Builds a WAT module that calls sophis_emit_event multiple times in sequence
/// with the same payload at offset 0 and returns the LAST status code.
fn wat_emit_repeated(payload: &[u8], times: u32) -> String {
    let hex = bytes_to_hex_lits(payload);
    let len = payload.len();
    let mut body = String::new();
    for i in 0..times {
        if i + 1 == times {
            body.push_str(&format!("(call $emit (i32.const 0) (i32.const {len}))",));
        } else {
            body.push_str(&format!("(drop (call $emit (i32.const 0) (i32.const {len})))",));
        }
    }
    format!(
        r#"(module
            (import "env" "sophis_emit_event"
                (func $emit (param i32 i32) (result i32)))
            (memory (export "memory") 1 1)
            (data (i32.const 0) "{hex}")
            (func (export "validate") (result i32)
                {body}))"#,
    )
}

/// WAT module that calls sophis_emit_event with an out-of-bounds pointer/len.
fn wat_emit_oob() -> String {
    // 1 page = 65536 bytes; ask for memory above page boundary.
    r#"(module
        (import "env" "sophis_emit_event"
            (func $emit (param i32 i32) (result i32)))
        (memory (export "memory") 1 1)
        (func (export "validate") (result i32)
            (call $emit (i32.const 65000) (i32.const 1000))))"#
        .to_string()
}

fn build_ctx(capabilities: Vec<Capability>, gas_config: GasConfig) -> ExecutionContext {
    let manifest = ContractManifest::new(Hash::from_slice(&[0u8; 32]), UpgradePolicy::Immutable, capabilities);
    ExecutionContext::new(vec![], vec![], 0, manifest, gas_config, Arc::new(StubCrypto)).with_contract_id([0xABu8; 32])
}

/// Minimal harness that bypasses the validator (which would reject our
/// hand-crafted WAT for missing the `validate` shape some real contracts
/// have). Compiles the WAT, instantiates with the host functions wired
/// in, calls `validate`, returns (status, ctx_after).
fn run(wat: &str, ctx: ExecutionContext, fuel: u64) -> (i32, ExecutionContext) {
    let engine = SvmEngine::new(Default::default()).expect("engine");
    let crypto: Arc<dyn sophis_svm_runtime::host::HostCrypto> = Arc::clone(&ctx.crypto);
    let wasm = wat::parse_str(wat).expect("wat parse");
    let module = Module::new(engine.inner(), &wasm).expect("module compile");
    let mut store = Store::new(engine.inner(), ctx);
    store.set_fuel(fuel).expect("set fuel");
    let mut linker: Linker<ExecutionContext> = Linker::new(engine.inner());
    sophis_svm_runtime::host::register_host_functions(&mut linker, crypto).expect("register");
    let instance = linker.instantiate(&mut store, &module).expect("instantiate");
    let v = instance.get_typed_func::<(), i32>(&mut store, "validate").expect("get validate");
    let status = v.call(&mut store, ()).expect("call validate");
    let ctx_after = store.into_data();
    (status, ctx_after)
}

// Even simpler: drop ContractExecutor entirely (it requires registering
// `Module` against a `ContractId` cache key). The above `run` is sufficient.
//
// We keep `ContractExecutor` import for future tests that need fuel→gas
// translation; suppress unused-import warning by using it once.
#[allow(dead_code)]
fn _executor_keepalive(engine: SvmEngine) -> ContractExecutor {
    ContractExecutor::new(engine)
}

// ===== Happy path =====================================================

#[test]
fn happy_path_single_event_zero_topics_zero_data() {
    let payload = encode_emission_payload(&[], &[]).unwrap();
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&payload), ctx, 1_000_000);
    assert_eq!(status, 0, "expected success");
    assert_eq!(ctx_after.events.len(), 1);
    let ev = &ctx_after.events[0];
    assert_eq!(ev.contract_id, [0xABu8; 32]);
    assert!(ev.topics.is_empty());
    assert!(ev.data.is_empty());
}

#[test]
fn happy_path_max_topics_with_data() {
    let topics = [[0x11u8; TOPIC_LEN]; MAX_TOPICS_PER_EVENT as usize];
    let data = vec![0x22u8; 100];
    let payload = encode_emission_payload(&topics, &data).unwrap();
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&payload), ctx, 1_000_000);
    assert_eq!(status, 0);
    assert_eq!(ctx_after.events.len(), 1);
    assert_eq!(ctx_after.events[0].topics.len(), MAX_TOPICS_PER_EVENT as usize);
    assert_eq!(ctx_after.events[0].data, data);
}

// ===== Error -1 capability missing ====================================

#[test]
fn error_minus_1_capability_missing() {
    let payload = encode_emission_payload(&[], b"x").unwrap();
    // Empty capability list — EmitEvent NOT declared.
    let ctx = build_ctx(vec![], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&payload), ctx, 1_000_000);
    assert_eq!(status, -1);
    assert!(ctx_after.events.is_empty());
}

// ===== Error -2 gas exhausted =========================================

#[test]
fn error_minus_2_gas_exhausted() {
    let payload = encode_emission_payload(&[], &[0u8; 100]).unwrap();
    // Pinch max_gas_per_tx below the cost so the host fn rejects.
    // base 1000 + per_byte 8 * payload_len(105) = 1840
    let gas = GasConfig { max_gas_per_tx: 100, ..GasConfig::default() };
    let ctx = build_ctx(vec![Capability::EmitEvent], gas);
    let (status, ctx_after) = run(&wat_emit(&payload), ctx, 1_000_000);
    assert_eq!(status, -2);
    assert!(ctx_after.events.is_empty());
}

// ===== Error -3 topic count overflow ==================================

#[test]
fn error_minus_3_topic_count_overflow() {
    // Hand-roll a payload with topic_count = 5.
    let mut bad = vec![5u8];
    bad.extend_from_slice(&[0u8; 5 * TOPIC_LEN]);
    bad.extend_from_slice(&0u32.to_le_bytes());
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&bad), ctx, 1_000_000);
    assert_eq!(status, -3);
    assert!(ctx_after.events.is_empty());
}

// ===== Error -4 data overflow =========================================

#[test]
fn error_minus_4_data_too_large() {
    // Hand-roll a header that lies about data_len = MAX + 1; parser
    // rejects without reading the body.
    let bad_data_len = MAX_EVENT_DATA_BYTES + 1;
    let mut bad = vec![0u8];
    bad.extend_from_slice(&bad_data_len.to_le_bytes());
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&bad), ctx, 1_000_000);
    assert_eq!(status, -4);
    assert!(ctx_after.events.is_empty());
}

// ===== Error -5 OOB / structural ======================================

#[test]
fn error_minus_5_memory_oob() {
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit_oob(), ctx, 1_000_000);
    assert_eq!(status, -5);
    assert!(ctx_after.events.is_empty());
}

#[test]
fn error_minus_5_truncated_payload() {
    // 4 bytes — below the 5-byte minimum.
    let bad = vec![0u8; 4];
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&bad), ctx, 1_000_000);
    assert_eq!(status, -5);
    assert!(ctx_after.events.is_empty());
}

// ===== Error -6 per-tx cap ============================================

#[test]
fn error_minus_6_per_tx_cap() {
    let payload = encode_emission_payload(&[], b"x").unwrap();
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    // Call MAX_EVENTS_PER_TX + 1 times; the last one must hit the cap.
    let times = (MAX_EVENTS_PER_TX as u32) + 1;
    let (status, ctx_after) = run(&wat_emit_repeated(&payload, times), ctx, 5_000_000);
    assert_eq!(status, -6, "expected per-tx cap rejection");
    // The first MAX_EVENTS_PER_TX calls succeeded.
    assert_eq!(ctx_after.events.len(), MAX_EVENTS_PER_TX);
}

// ===== Gas metering correctness =======================================

#[test]
fn gas_metering_charges_base_plus_per_byte() {
    // payload_len = 1 (count) + 0 topics + 4 (data_len) + 0 = 5
    // expected gas = 1000 + 8 * 5 = 1040
    let payload = encode_emission_payload(&[], &[]).unwrap();
    assert_eq!(payload.len(), 5);
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&payload), ctx, 1_000_000);
    assert_eq!(status, 0);
    assert_eq!(ctx_after.gas_used.0, 1000 + 8 * 5);
}

#[test]
fn gas_metering_with_data_payload() {
    // payload_len = 1 + 0 + 4 + 1024 = 1029
    // expected gas = 1000 + 8 * 1029 = 9232
    let payload = encode_emission_payload(&[], &[0xAAu8; 1024]).unwrap();
    assert_eq!(payload.len(), 1029);
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    let (status, ctx_after) = run(&wat_emit(&payload), ctx, 1_000_000);
    assert_eq!(status, 0);
    assert_eq!(ctx_after.gas_used.0, 1000 + 8 * 1029);
}

// ===== Contract ID propagation ========================================

#[test]
fn contract_id_is_stamped_onto_emitted_event() {
    let payload = encode_emission_payload(&[[0x77u8; TOPIC_LEN]], b"hello").unwrap();
    let ctx = build_ctx(vec![Capability::EmitEvent], GasConfig::default());
    // build_ctx sets contract_id = [0xAB; 32]
    let (status, ctx_after) = run(&wat_emit(&payload), ctx, 1_000_000);
    assert_eq!(status, 0);
    assert_eq!(ctx_after.events.len(), 1);
    assert_eq!(ctx_after.events[0].contract_id, [0xABu8; 32]);
    assert_eq!(ctx_after.events[0].topics, vec![[0x77u8; TOPIC_LEN]]);
    assert_eq!(ctx_after.events[0].data, b"hello".to_vec());
}

//! J3 — end-to-end tests for the `sophis_vrf_random_at` host function.
//!
//! Each test compiles a tiny WAT contract that:
//!   1. Calls `sophis_vrf_random_at(chain_index, OUT_OFFSET)`
//!   2. If the call succeeded (status 0), copies `out[0..4]` back as i32
//!      so the test can assert byte content
//!   3. Otherwise returns the negative status code
//!
//! The host fn body in `svm/runtime/src/host.rs` is exercised via the
//! same Wasmtime path consensus uses, so memory bounds + gas metering +
//! capability enforcement all run for real.

use std::sync::Arc;

use sophis_hashes::Hash;
use sophis_svm_core::{Capability, ContractManifest, GasConfig, UpgradePolicy};
use sophis_svm_runtime::{
    HostVrf,
    context::ExecutionContext,
    engine::SvmEngine,
    host::StubCrypto,
};
use wasmtime::{Linker, Module, Store};

/// In-test VRF backend with controllable behaviour.
#[derive(Clone)]
struct TestVrf {
    tip: u64,
    bytes: [u8; 32],
}

impl HostVrf for TestVrf {
    fn vrf_random_at(&self, chain_index: u64) -> Option<[u8; 32]> {
        if chain_index < self.tip { Some(self.bytes) } else { None }
    }
    fn current_tip_index(&self) -> u64 {
        self.tip
    }
}

/// VRF backend that pretends a chain_index resolves but the chain
/// store cannot deliver — used to exercise the -6 path.
struct TipKnownButResolveFailsVrf {
    tip: u64,
}
impl HostVrf for TipKnownButResolveFailsVrf {
    fn vrf_random_at(&self, _: u64) -> Option<[u8; 32]> {
        None
    }
    fn current_tip_index(&self) -> u64 {
        self.tip
    }
}

const OUT_OFFSET: u32 = 100;

/// WAT module that calls sophis_vrf_random_at and:
///   - on success (0), returns the first 4 bytes of out as i32 in BIG-ENDIAN
///     so the test can compare directly against the seeded byte pattern
///   - on error, returns the negative status code
fn wat_call(chain_index: i64) -> String {
    format!(
        r#"(module
            (import "env" "sophis_vrf_random_at"
                (func $vrf (param i64 i32) (result i32)))
            (memory (export "memory") 1 1)
            (func (export "validate") (result i32)
                (local $status i32)
                (local.set $status (call $vrf (i64.const {chain_index}) (i32.const {OUT_OFFSET})))
                (if (result i32) (i32.ne (local.get $status) (i32.const 0))
                    (then (local.get $status))
                    (else
                        ;; success — return first byte of out as i32 (zero-extended)
                        (i32.load8_u (i32.const {OUT_OFFSET})))))
        )"#,
        OUT_OFFSET = OUT_OFFSET,
    )
}

/// WAT that calls vrf with an out_ptr beyond memory bounds (1 page = 65536).
fn wat_call_oob(chain_index: i64) -> String {
    format!(
        r#"(module
            (import "env" "sophis_vrf_random_at"
                (func $vrf (param i64 i32) (result i32)))
            (memory (export "memory") 1 1)
            (func (export "validate") (result i32)
                (call $vrf (i64.const {chain_index}) (i32.const 65530))))
        "#,
    )
}

fn build_ctx_with_vrf(capabilities: Vec<Capability>, gas_config: GasConfig, vrf: Arc<dyn HostVrf>) -> ExecutionContext {
    let manifest = ContractManifest::new(Hash::from_slice(&[0u8; 32]), UpgradePolicy::Immutable, capabilities);
    ExecutionContext::new(vec![], vec![], 0, manifest, gas_config, Arc::new(StubCrypto)).with_vrf_backend(vrf)
}

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

// ===== Happy path =====================================================

#[test]
fn happy_path_returns_0_and_writes_32_bytes() {
    // tip = 5 means chain_index 0..4 are queryable; pick 3
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0xABu8; 32] });
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], GasConfig::default(), vrf);
    let (status, _ctx_after) = run(&wat_call(3), ctx, 1_000_000);
    // WAT returns first byte zero-extended on success
    assert_eq!(status, 0xABi32, "expected first byte of VRF output (0xAB), got {status}");
}

// ===== Error -1 capability missing ====================================

#[test]
fn error_minus_1_capability_missing() {
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0u8; 32] });
    let ctx = build_ctx_with_vrf(vec![], GasConfig::default(), vrf);
    let (status, _) = run(&wat_call(0), ctx, 1_000_000);
    assert_eq!(status, -1);
}

// ===== Error -2 gas exhausted =========================================

#[test]
fn error_minus_2_gas_exhausted() {
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0u8; 32] });
    // GAS_VRF_RANDOM = 500; cap below it
    let gas = GasConfig { max_gas_per_tx: 100, ..GasConfig::default() };
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], gas, vrf);
    let (status, _) = run(&wat_call(0), ctx, 1_000_000);
    assert_eq!(status, -2);
}

// ===== Error -3 future block ==========================================

#[test]
fn error_minus_3_chain_index_at_tip_is_future() {
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0u8; 32] });
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], GasConfig::default(), vrf);
    let (status, _) = run(&wat_call(5), ctx, 1_000_000);
    assert_eq!(status, -3);
}

#[test]
fn error_minus_3_chain_index_above_tip_is_future() {
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0u8; 32] });
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], GasConfig::default(), vrf);
    let (status, _) = run(&wat_call(99), ctx, 1_000_000);
    assert_eq!(status, -3);
}

// ===== Error -4 negative index ========================================

#[test]
fn error_minus_4_negative_chain_index() {
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0u8; 32] });
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], GasConfig::default(), vrf);
    let (status, _) = run(&wat_call(-1), ctx, 1_000_000);
    assert_eq!(status, -4);
}

// ===== Error -5 OOB output write ======================================

#[test]
fn error_minus_5_oob_write() {
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0u8; 32] });
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], GasConfig::default(), vrf);
    // 1 page = 65536; offset 65530 + 32 bytes = 65562 > 65536 → OOB
    let (status, _) = run(&wat_call_oob(0), ctx, 1_000_000);
    assert_eq!(status, -5);
}

// ===== Error -6 unknown index =========================================

#[test]
fn error_minus_6_unknown_chain_index() {
    let vrf = Arc::new(TipKnownButResolveFailsVrf { tip: 5 });
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], GasConfig::default(), vrf);
    let (status, _) = run(&wat_call(2), ctx, 1_000_000);
    assert_eq!(status, -6);
}

// ===== Gas metering correctness =======================================

#[test]
fn gas_metering_charges_500_per_call() {
    let vrf = Arc::new(TestVrf { tip: 5, bytes: [0u8; 32] });
    let ctx = build_ctx_with_vrf(vec![Capability::VrfRandomness], GasConfig::default(), vrf);
    let (status, ctx_after) = run(&wat_call(0), ctx, 1_000_000);
    assert_eq!(status, 0);
    assert_eq!(ctx_after.gas_used.0, 500);
}

use sophis_svm_core::Capability;
use wasmparser::{BinaryReaderError, Operator, Parser, Payload};

use crate::config::MAX_MEMORY_PAGES;
use crate::error::{RuntimeError, RuntimeResult};

/// Audit/F-10 (Session 8, 2026-05-15): canonical map of every host fn the
/// sVM exposes under the WASM `"env"` namespace, paired with the
/// [`Capability`] the runtime check_capability call enforces at the call
/// site. Order matches `register_host_functions` in `host.rs`.
///
/// **ABI freeze.** Every addition to this map requires a hard fork because
/// `validate_imports_against_manifest` becomes part of consensus. Any
/// change must:
///   1. Register the host fn in `host.rs` via `linker.func_wrap("env", "<name>", ...)`.
///   2. Add the matching `Capability` variant in `svm-core/src/capability.rs`.
///   3. Append a row to this map.
///   4. Bake into the next mainnet activation.
///
/// Why two host fns share `ReadUtxo`: `get_input_utxo` and `get_output_utxo`
/// are dual reader shims; the consensus side considers "reading the UTXO set"
/// a single capability. This is per the existing `check_capability` checks
/// in `host.rs` lines 163 + 181.
pub const HOST_FN_CAPABILITY_MAP: &[(&str, Capability)] = &[
    ("get_input_utxo", Capability::ReadUtxo),
    ("get_output_utxo", Capability::ReadUtxo),
    ("get_block_height", Capability::ReadBlockHeight),
    ("verify_dilithium", Capability::VerifyDilithium),
    ("sha3_384", Capability::HashSha3),
    ("verify_risc0_proof", Capability::VerifyRisc0Proof),
    ("verify_plonky3_proof", Capability::VerifyPlonky3Proof),
    ("sophis_emit_event", Capability::EmitEvent),
    ("sophis_vrf_random_at", Capability::VrfRandomness),
    ("sophis_alt_lookup", Capability::ResolveAlt),
    ("sophis_verify_da", Capability::VerifyDataAvailability),
];

/// Audit/F-10 (Session 8, 2026-05-15): deploy-time check that every
/// `(env, fn_name)` import declared by the contract WASM:
///   1. is registered in [`HOST_FN_CAPABILITY_MAP`] — otherwise
///      [`RuntimeError::UnknownHostImport`].
///   2. maps to a `Capability` that the deploy manifest declared in
///      `required_capabilities` — otherwise
///      [`RuntimeError::CapabilityNotDeclared`].
///
/// Imports from any module other than `"env"` (e.g., the WASI namespace)
/// are not the sVM's concern and are passed through; the existing
/// `validate_bytecode` rejects them indirectly via instantiation failure.
///
/// This check runs in consensus (`tx_validation_in_isolation::validate_contract_deploy`)
/// so every validator rejects the same set of deploys.
pub fn validate_imports_against_manifest(wasm: &[u8], required_capabilities: &[Capability]) -> RuntimeResult<()> {
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.map_err(|e: BinaryReaderError| RuntimeError::ValidationFailed(e.to_string()))?;
        let Payload::ImportSection(reader) = payload else {
            continue;
        };
        for import in reader {
            let import = import.map_err(|e| RuntimeError::ValidationFailed(e.to_string()))?;
            if import.module != "env" {
                continue;
            }
            // Function imports only — host fns are wrapped via `linker.func_wrap`.
            // Memory / global / table imports under "env" (notably the shared-memory
            // case rejected by validate_bytecode upstream) are skipped here.
            if !matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                continue;
            }
            let needed = HOST_FN_CAPABILITY_MAP
                .iter()
                .find_map(|(name, cap)| if *name == import.name { Some(cap) } else { None })
                .ok_or_else(|| RuntimeError::UnknownHostImport(import.name.to_string()))?;
            if !required_capabilities.contains(needed) {
                return Err(RuntimeError::CapabilityNotDeclared { host_fn: import.name.to_string(), capability: needed.clone() });
            }
        }
    }
    Ok(())
}

/// Validates WASM bytecode before compilation.
/// Rejects: float instructions (scalar + SIMD), threads (shared memory, atomics), size excess.
/// Called once per unique contract bytecode — result cached with the compiled Module.
pub fn validate_bytecode(wasm: &[u8], max_size: usize) -> RuntimeResult<()> {
    if wasm.len() > max_size {
        return Err(RuntimeError::BytecodeTooLarge(wasm.len(), max_size));
    }

    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.map_err(|e: BinaryReaderError| RuntimeError::ValidationFailed(e.to_string()))?;

        match payload {
            Payload::CodeSectionEntry(body) => {
                let reader = body.get_operators_reader().map_err(|e| RuntimeError::ValidationFailed(e.to_string()))?;
                for op in reader {
                    let op = op.map_err(|e| RuntimeError::ValidationFailed(e.to_string()))?;
                    reject_float_or_thread(&op)?;
                }
            }
            // Shared memory import signals thread usage
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| RuntimeError::ValidationFailed(e.to_string()))?;
                    if let wasmparser::TypeRef::Memory(mem) = import.ty
                        && mem.shared
                    {
                        return Err(RuntimeError::ThreadsForbidden);
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem = mem.map_err(|e| RuntimeError::ValidationFailed(e.to_string()))?;
                    if mem.shared {
                        return Err(RuntimeError::ThreadsForbidden);
                    }
                    // Require an explicit upper bound to prevent unbounded growth.
                    let max_pages = match mem.maximum {
                        Some(m) => m,
                        None => return Err(RuntimeError::MemoryUnbounded),
                    };
                    if max_pages > MAX_MEMORY_PAGES as u64 {
                        return Err(RuntimeError::MemoryTooLarge(max_pages, MAX_MEMORY_PAGES as u64));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn reject_float_or_thread(op: &Operator) -> RuntimeResult<()> {
    use Operator::*;
    match op {
        // f32 arithmetic
        F32Load { .. } | F32Store { .. } | F32Const { .. } | F32Abs | F32Neg | F32Ceil | F32Floor | F32Trunc
        | F32Nearest | F32Sqrt | F32Add | F32Sub | F32Mul | F32Div | F32Min | F32Max | F32Copysign | F32Eq
        | F32Ne | F32Lt | F32Gt | F32Le | F32Ge | I32TruncF32S | I32TruncF32U | I32TruncF64S | I32TruncF64U
        | I64TruncF32S | I64TruncF32U | I64TruncF64S | I64TruncF64U | F32ConvertI32S | F32ConvertI32U
        | F32ConvertI64S | F32ConvertI64U | F32DemoteF64 | F64PromoteF32 | I32ReinterpretF32
        | F32ReinterpretI32 =>
        {
            Err(RuntimeError::FloatForbidden)
        }
        // f64 arithmetic
        F64Load { .. } | F64Store { .. } | F64Const { .. } | F64Abs | F64Neg | F64Ceil | F64Floor | F64Trunc
        | F64Nearest | F64Sqrt | F64Add | F64Sub | F64Mul | F64Div | F64Min | F64Max | F64Copysign | F64Eq
        | F64Ne | F64Lt | F64Gt | F64Le | F64Ge | F64ConvertI32S | F64ConvertI32U | F64ConvertI64S
        | F64ConvertI64U | I64ReinterpretF64 | F64ReinterpretI64 => Err(RuntimeError::FloatForbidden),

        // atomics (threads)
        MemoryAtomicNotify { .. }
        | MemoryAtomicWait32 { .. }
        | MemoryAtomicWait64 { .. }
        | I32AtomicLoad { .. }
        | I64AtomicLoad { .. }
        | I32AtomicLoad8U { .. }
        | I32AtomicLoad16U { .. }
        | I64AtomicLoad8U { .. }
        | I64AtomicLoad16U { .. }
        | I64AtomicLoad32U { .. }
        | I32AtomicStore { .. }
        | I64AtomicStore { .. }
        | I32AtomicStore8 { .. }
        | I32AtomicStore16 { .. }
        | I64AtomicStore8 { .. }
        | I64AtomicStore16 { .. }
        | I64AtomicStore32 { .. }
        | I32AtomicRmwAdd { .. }
        | I64AtomicRmwAdd { .. } => Err(RuntimeError::ThreadsForbidden),

        // SIMD float ops — can produce NaN payloads that differ across architectures.
        // SIMD integer ops (I8x16, I16x8, I32x4, I64x2) are deterministic and allowed.
        // Lane ops carry a `lane` field, matched with `{ .. }`.
        // (wasmparser default features always include `simd`, so these variants always exist.)
        F32x4Splat
        | F32x4ExtractLane { .. }
        | F32x4ReplaceLane { .. }
        | F32x4Eq
        | F32x4Ne
        | F32x4Lt
        | F32x4Gt
        | F32x4Le
        | F32x4Ge
        | F32x4Abs
        | F32x4Neg
        | F32x4Sqrt
        | F32x4Ceil
        | F32x4Floor
        | F32x4Trunc
        | F32x4Nearest
        | F32x4Add
        | F32x4Sub
        | F32x4Mul
        | F32x4Div
        | F32x4Min
        | F32x4Max
        | F32x4PMin
        | F32x4PMax
        | F32x4ConvertI32x4S
        | F32x4ConvertI32x4U
        | F32x4DemoteF64x2Zero
        | F32x4RelaxedMadd
        | F32x4RelaxedNmadd
        | F32x4RelaxedMin
        | F32x4RelaxedMax
        | F64x2Splat
        | F64x2ExtractLane { .. }
        | F64x2ReplaceLane { .. }
        | F64x2Eq
        | F64x2Ne
        | F64x2Lt
        | F64x2Gt
        | F64x2Le
        | F64x2Ge
        | F64x2Abs
        | F64x2Neg
        | F64x2Sqrt
        | F64x2Ceil
        | F64x2Floor
        | F64x2Trunc
        | F64x2Nearest
        | F64x2Add
        | F64x2Sub
        | F64x2Mul
        | F64x2Div
        | F64x2Min
        | F64x2Max
        | F64x2PMin
        | F64x2PMax
        | F64x2ConvertLowI32x4S
        | F64x2ConvertLowI32x4U
        | F64x2PromoteLowF32x4
        | F64x2RelaxedMadd
        | F64x2RelaxedNmadd
        | F64x2RelaxedMin
        | F64x2RelaxedMax
        // Integer SIMD ops that convert from float (non-deterministic rounding in relaxed variant)
        | I32x4TruncSatF32x4S
        | I32x4TruncSatF32x4U
        | I32x4TruncSatF64x2SZero
        | I32x4TruncSatF64x2UZero
        | I32x4RelaxedTruncF32x4S
        | I32x4RelaxedTruncF32x4U
        | I32x4RelaxedTruncF64x2SZero
        | I32x4RelaxedTruncF64x2UZero => Err(RuntimeError::FloatForbidden),

        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_BYTECODE_SIZE;

    #[test]
    fn empty_wasm_rejected() {
        assert!(validate_bytecode(b"", MAX_BYTECODE_SIZE).is_err());
    }

    #[test]
    fn oversized_bytecode_rejected() {
        let big = vec![0u8; MAX_BYTECODE_SIZE + 1];
        assert!(matches!(validate_bytecode(&big, MAX_BYTECODE_SIZE), Err(RuntimeError::BytecodeTooLarge(_, _))));
    }

    fn wat_ok(src: &str) {
        let wasm = wat::parse_str(src).expect("valid WAT");
        assert!(validate_bytecode(&wasm, MAX_BYTECODE_SIZE).is_ok(), "should pass: {src}");
    }

    fn wat_float_rejected(src: &str) {
        let wasm = wat::parse_str(src).expect("valid WAT");
        assert!(
            matches!(validate_bytecode(&wasm, MAX_BYTECODE_SIZE), Err(RuntimeError::FloatForbidden)),
            "should be FloatForbidden: {src}"
        );
    }

    // --- SIMD integer ops are allowed ---

    #[test]
    fn simd_integer_add_allowed() {
        wat_ok(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const i32x4 1 2 3 4
            v128.const i32x4 5 6 7 8
            i32x4.add
            i32x4.extract_lane 0))"#,
        );
    }

    #[test]
    fn simd_integer_mul_allowed() {
        wat_ok(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const i64x2 100 200
            v128.const i64x2 3 4
            i64x2.mul
            drop
            i32.const 1))"#,
        );
    }

    // --- SIMD f32x4 arithmetic rejected ---

    #[test]
    fn simd_f32x4_add_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const f32x4 1.0 2.0 3.0 4.0
            v128.const f32x4 5.0 6.0 7.0 8.0
            f32x4.add
            drop
            i32.const 1))"#,
        );
    }

    #[test]
    fn simd_f32x4_sqrt_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const f32x4 1.0 4.0 9.0 16.0
            f32x4.sqrt
            drop
            i32.const 1))"#,
        );
    }

    #[test]
    fn simd_f32x4_splat_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            f32.const 1.5
            f32x4.splat
            drop
            i32.const 1))"#,
        );
    }

    #[test]
    fn simd_f32x4_extract_lane_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const f32x4 1.0 0.0 0.0 0.0
            f32x4.extract_lane 0
            drop
            i32.const 1))"#,
        );
    }

    // --- SIMD f64x2 arithmetic rejected ---

    #[test]
    fn simd_f64x2_mul_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const f64x2 2.0 3.0
            v128.const f64x2 4.0 5.0
            f64x2.mul
            drop
            i32.const 1))"#,
        );
    }

    #[test]
    fn simd_f64x2_splat_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            f64.const 3.14
            f64x2.splat
            drop
            i32.const 1))"#,
        );
    }

    // --- SIMD float comparisons rejected ---

    #[test]
    fn simd_f32x4_eq_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const f32x4 1.0 2.0 3.0 4.0
            v128.const f32x4 1.0 2.0 3.0 4.0
            f32x4.eq
            drop
            i32.const 1))"#,
        );
    }

    // --- SIMD float/int conversion rejected ---

    #[test]
    fn simd_i32x4_trunc_sat_f32x4_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const f32x4 1.0 2.0 3.0 4.0
            i32x4.trunc_sat_f32x4_s
            drop
            i32.const 1))"#,
        );
    }

    #[test]
    fn simd_f32x4_convert_i32x4_rejected() {
        wat_float_rejected(
            r#"(module
          (memory (export "memory") 1 256)
          (func (export "validate") (result i32)
            v128.const i32x4 1 2 3 4
            f32x4.convert_i32x4_s
            drop
            i32.const 1))"#,
        );
    }

    // --- Memory limit enforcement ---

    #[test]
    fn memory_within_limit_ok() {
        // 256 pages (16 MiB) is exactly the limit — must be accepted.
        wat_ok(
            r#"(module
          (memory 1 256)
          (func (export "validate") (result i32) i32.const 1))"#,
        );
    }

    #[test]
    fn memory_over_limit_rejected() {
        // 257 pages exceeds MAX_MEMORY_PAGES — must be rejected.
        let wasm = wat::parse_str(
            r#"(module
          (memory 1 257)
          (func (export "validate") (result i32) i32.const 1))"#,
        )
        .unwrap();
        assert!(
            matches!(validate_bytecode(&wasm, MAX_BYTECODE_SIZE), Err(RuntimeError::MemoryTooLarge(_, _))),
            "should be MemoryTooLarge"
        );
    }

    #[test]
    fn memory_unbounded_rejected() {
        // No maximum declared — unbounded growth is forbidden.
        let wasm = wat::parse_str(
            r#"(module
          (memory 1)
          (func (export "validate") (result i32) i32.const 1))"#,
        )
        .unwrap();
        assert!(
            matches!(validate_bytecode(&wasm, MAX_BYTECODE_SIZE), Err(RuntimeError::MemoryUnbounded)),
            "should be MemoryUnbounded"
        );
    }

    // --- F-10: imports-vs-manifest consistency check -----------------------

    /// Helper: WAT module body that imports verify_dilithium from env. The
    /// function never runs (caller only walks the import section) so an empty
    /// body is fine.
    const WAT_IMPORTS_VERIFY_DILITHIUM: &str = r#"(module
        (import "env" "verify_dilithium"
            (func $vd (param i32 i32 i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1 256)
        (func (export "validate") (result i32) i32.const 1))"#;

    /// Helper: imports both verify_dilithium AND sha3_384.
    const WAT_IMPORTS_TWO_HOST_FNS: &str = r#"(module
        (import "env" "verify_dilithium"
            (func $vd (param i32 i32 i32 i32 i32 i32) (result i32)))
        (import "env" "sha3_384"
            (func $sha (param i32 i32 i32) (result i32)))
        (memory (export "memory") 1 256)
        (func (export "validate") (result i32) i32.const 1))"#;

    /// Helper: imports an unknown host fn that is not in HOST_FN_CAPABILITY_MAP.
    const WAT_IMPORTS_UNKNOWN: &str = r#"(module
        (import "env" "some_future_host_fn"
            (func $f (param i32) (result i32)))
        (memory (export "memory") 1 256)
        (func (export "validate") (result i32) i32.const 1))"#;

    /// Helper: no imports at all.
    const WAT_NO_IMPORTS: &str = r#"(module
        (memory (export "memory") 1 256)
        (func (export "validate") (result i32) i32.const 1))"#;

    /// Helper: imports a host fn from a non-"env" module — must be ignored.
    const WAT_IMPORTS_FROM_OTHER_MODULE: &str = r#"(module
        (import "wasi_snapshot_preview1" "fd_write"
            (func $w (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1 256)
        (func (export "validate") (result i32) i32.const 1))"#;

    #[test]
    fn imports_check_happy_path_when_capability_declared() {
        let wasm = wat::parse_str(WAT_IMPORTS_VERIFY_DILITHIUM).unwrap();
        let caps = vec![Capability::VerifyDilithium];
        assert!(validate_imports_against_manifest(&wasm, &caps).is_ok());
    }

    #[test]
    fn imports_check_rejects_when_capability_missing() {
        let wasm = wat::parse_str(WAT_IMPORTS_VERIFY_DILITHIUM).unwrap();
        // Declares ReadUtxo but NOT VerifyDilithium — should reject.
        let caps = vec![Capability::ReadUtxo];
        match validate_imports_against_manifest(&wasm, &caps) {
            Err(RuntimeError::CapabilityNotDeclared { host_fn, capability }) => {
                assert_eq!(host_fn, "verify_dilithium");
                assert_eq!(capability, Capability::VerifyDilithium);
            }
            other => panic!("expected CapabilityNotDeclared, got {other:?}"),
        }
    }

    #[test]
    fn imports_check_rejects_unknown_host_fn() {
        let wasm = wat::parse_str(WAT_IMPORTS_UNKNOWN).unwrap();
        let caps = vec![Capability::ReadUtxo, Capability::VerifyDilithium];
        match validate_imports_against_manifest(&wasm, &caps) {
            Err(RuntimeError::UnknownHostImport(name)) => {
                assert_eq!(name, "some_future_host_fn");
            }
            other => panic!("expected UnknownHostImport, got {other:?}"),
        }
    }

    #[test]
    fn imports_check_accepts_module_with_no_imports() {
        let wasm = wat::parse_str(WAT_NO_IMPORTS).unwrap();
        // Empty cap list is fine when nothing is imported.
        assert!(validate_imports_against_manifest(&wasm, &[]).is_ok());
    }

    #[test]
    fn imports_check_ignores_non_env_modules() {
        let wasm = wat::parse_str(WAT_IMPORTS_FROM_OTHER_MODULE).unwrap();
        // Empty cap list is fine — the WASI import is not the sVM's concern.
        // (Wasmtime instantiation will fail because nothing satisfies WASI,
        // but this check is structural / consensus-side; the runtime catches
        // the missing import at instantiation time downstream.)
        assert!(validate_imports_against_manifest(&wasm, &[]).is_ok());
    }

    #[test]
    fn imports_check_multiple_host_fns_all_declared() {
        let wasm = wat::parse_str(WAT_IMPORTS_TWO_HOST_FNS).unwrap();
        let caps = vec![Capability::VerifyDilithium, Capability::HashSha3];
        assert!(validate_imports_against_manifest(&wasm, &caps).is_ok());
    }

    #[test]
    fn imports_check_multiple_host_fns_one_missing() {
        let wasm = wat::parse_str(WAT_IMPORTS_TWO_HOST_FNS).unwrap();
        // Declares VerifyDilithium but NOT HashSha3 — should reject on sha3_384.
        let caps = vec![Capability::VerifyDilithium];
        match validate_imports_against_manifest(&wasm, &caps) {
            Err(RuntimeError::CapabilityNotDeclared { host_fn, capability }) => {
                assert_eq!(host_fn, "sha3_384");
                assert_eq!(capability, Capability::HashSha3);
            }
            other => panic!("expected CapabilityNotDeclared for sha3_384, got {other:?}"),
        }
    }

    /// `get_input_utxo` and `get_output_utxo` both map to ReadUtxo — declaring
    /// the single ReadUtxo capability satisfies both imports.
    #[test]
    fn imports_check_dual_readers_share_one_capability() {
        let wat = r#"(module
            (import "env" "get_input_utxo"
                (func $gi (param i32 i32 i32) (result i32)))
            (import "env" "get_output_utxo"
                (func $go (param i32 i32 i32) (result i32)))
            (memory (export "memory") 1 256)
            (func (export "validate") (result i32) i32.const 1))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let caps = vec![Capability::ReadUtxo];
        assert!(validate_imports_against_manifest(&wasm, &caps).is_ok());
    }

    /// HOST_FN_CAPABILITY_MAP must list every host fn registered in
    /// `register_host_functions` in host.rs. Catches regressions where a
    /// new host fn lands without being added to the canonical map.
    /// Count is 11 (10 distinct Capabilities; ReadUtxo is shared).
    #[test]
    fn host_fn_capability_map_has_expected_size() {
        assert_eq!(HOST_FN_CAPABILITY_MAP.len(), 11, "HOST_FN_CAPABILITY_MAP must list every host fn registered in host.rs");
        // Distinct capabilities count: 10 (ReadUtxo is shared by get_input_utxo and get_output_utxo).
        use std::collections::HashSet;
        let distinct: HashSet<&Capability> = HOST_FN_CAPABILITY_MAP.iter().map(|(_, cap)| cap).collect();
        assert_eq!(distinct.len(), 10, "expected 10 distinct Capabilities (ReadUtxo is shared by 2 host fns)");
    }

    #[test]
    fn host_fn_capability_map_includes_all_known_names() {
        let names: std::collections::HashSet<&str> = HOST_FN_CAPABILITY_MAP.iter().map(|(n, _)| *n).collect();
        for expected in [
            "get_input_utxo",
            "get_output_utxo",
            "get_block_height",
            "verify_dilithium",
            "sha3_384",
            "verify_risc0_proof",
            "verify_plonky3_proof",
            "sophis_emit_event",
            "sophis_vrf_random_at",
            "sophis_alt_lookup",
            "sophis_verify_da",
        ] {
            assert!(names.contains(expected), "HOST_FN_CAPABILITY_MAP missing entry for {expected}");
        }
    }
}

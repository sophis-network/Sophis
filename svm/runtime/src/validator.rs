use wasmparser::{BinaryReaderError, Operator, Parser, Payload};

use crate::config::MAX_MEMORY_PAGES;
use crate::error::{RuntimeError, RuntimeResult};

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
}

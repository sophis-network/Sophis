//! `field25519::mod_p` — modular reduction by `p = 2²⁵⁵ - 19`.
//!
//! Sub-phase 5.2.1.1.e ships the **witness function** (Rust implementation
//! of the algorithm) plus an end-to-end pipeline test confirming
//! `mul → carry_fold → limb_assembly → mod_p_reduce` agrees with
//! `(a · b) mod p` computed independently.
//!
//! Sub-phase 5.2.1.1.e.1 refactors the algorithm into two standalone
//! witness functions:
//!
//!   - `compute_first_fold` (18 30-bit limbs → 10 loose limbs as `[u128; 10]`)
//!   - `compute_second_fold_and_canonicalize` (10 loose limbs → 9 canonical mod-p)
//!
//! `compute_mod_p_reduction` now composes both. Each step is independently
//! testable, simplifying validation when the AIR chips land.
//!
//! ## AIR design challenges (deferred to a dedicated session)
//!
//! The first-fold AIR is non-trivial because of BabyBear overflow:
//!
//!   - Each high limb `L[k+9]` is decomposed into 3 10-bit pieces; partial
//!     products `q_x = M · piece_x` (M = 19·2¹⁵ = 622592) are < 2³⁰ each,
//!     fitting BabyBear.
//!   - But each output limb `m` accumulates **4 terms each up to 2³⁰**:
//!     `L[m]`, `q_a_m`, `q_b_m_low << 10`, `q_c_m_low << 20`. Their sum
//!     can reach 2³², which **exceeds BabyBear's ~2³¹ field**.
//!
//! Three viable AIR design paths, each with trade-offs:
//!
//!   1. **Partial-sum columns**: chain of intermediate accumulators
//!      (~30-50 extra columns), each constraint adds two values < 2³⁰.
//!      Most BabyBear-friendly, biggest column footprint.
//!   2. **Extension field columns**: use `BinomialExtensionField<BabyBear, 4>`
//!      to hold the wide intermediate. Requires `PermutationAirBuilder`
//!      plumbing and roughly 4× larger proof.
//!   3. **Direct base-field with witness splits at every overflow point**:
//!      ~64 constraints + careful per-limb decomposition. Hardest to audit,
//!      easiest to get wrong.
//!
//! Path 1 is the most likely candidate. The AIR chip lands in a dedicated
//! follow-up session after the design has been carefully audited end-to-end
//! against the witness function shipped here.
//!
//! ## Algorithm
//!
//! Input: 18 30-bit limbs `L[0..18]` representing a value `V < 2⁵⁴⁰`.
//!
//! Pass 1 (high → low):
//!   `V = V_lo + V_hi · 2²⁷⁰ ≡ V_lo + V_hi · M (mod p)`
//!   where `V_lo = sum L[k]·2³⁰ᵏ` for `k ∈ [0,9)`,
//!         `V_hi = sum L[k+9]·2³⁰ᵏ` for `k ∈ [0,9)`,
//!         `M = 19 · 2¹⁵ = 622592`.
//!   `V_hi · M < 2²⁹⁰`, so `V_lo + V_hi · M < 2²⁹¹` (~10 30-bit limbs).
//!
//! Pass 2 (limb 9 → low):
//!   The pass-1 result has up to 10 limbs with limb 9 < 2²¹.
//!   `limb_9 · 2²⁷⁰ ≡ limb_9 · M (mod p)`.
//!   Adding `limb_9 · M` to limbs 0..1 shrinks the value back to 9 limbs.
//!   `limb_9 · M < 2²¹·2²⁰ = 2⁴¹` — fits in 2 limbs cleanly.
//!
//! Final canonicalization:
//!   The pass-2 result is `< p + (2¹⁰ correction)`. If `result ≥ p`,
//!   subtract `p`. Output is the canonical `[0, p)` representative.
//!
//! ## Reference
//!
//! Standard ed25519 implementations (`libsodium` ref10, `curve25519-dalek`)
//! use the same two-pass + conditional-subtraction structure. We adapt
//! it to our 9·30-bit limb representation.

use super::limb_assembly::{LimbAssemblyWitness, NUM_OUTPUT_LIMBS};
use super::{Field25519Element, LIMB_MOD, NUM_LIMBS, P_LIMBS};

/// `M = 19 · 2¹⁵ = 622592`. The fold multiplier carrying high limbs back
/// into low ones via `2²⁷⁰ ≡ M (mod p)`.
pub const FOLD_M: u64 = 19 << 15;

/// Pass 1 of mod-p reduction: fold high 9 limbs into low ones.
///
/// Algorithm: `V = V_lo + V_hi · 2²⁷⁰ ≡ V_lo + V_hi · M (mod p)` where
/// `M = 19 · 2¹⁵ = 622592`.
///
/// Returns 10 loose `u128` limbs (each up to ~2³³ before final carry).
/// The carry-propagation that turns these into ≤ 30-bit values is
/// deliberately included here so the output is ready to feed into pass 2.
pub fn compute_first_fold(eighteen: &[u64; NUM_OUTPUT_LIMBS]) -> [u128; 10] {
    let mut acc = [0u128; 10];
    for i in 0..NUM_LIMBS {
        acc[i] = eighteen[i] as u128;
    }
    for k in 0..NUM_LIMBS {
        let prod = (eighteen[k + NUM_LIMBS] as u128) * (FOLD_M as u128);
        // prod < 2^30 · 2^20 = 2^50 — splits across limbs k and k+1.
        acc[k] += prod & ((1u128 << 30) - 1);
        acc[k + 1] += prod >> 30;
    }
    // Carry-propagate so each output limb is ≤ 30-bit.
    for i in 0..9 {
        let carry = acc[i] >> 30;
        acc[i] &= (1u128 << 30) - 1;
        acc[i + 1] += carry;
    }
    acc
}

/// Pass 2 of mod-p reduction: fold any residual content above bit 254
/// (limb 9 plus high bits 15..29 of limb 8) back into low limbs, then
/// canonicalize via conditional `p`-subtraction (up to 2 passes).
///
/// Input: 10 limbs from `compute_first_fold`. Output: a canonical
/// `Field25519Element` in `[0, p)`.
pub fn compute_second_fold_and_canonicalize(first_fold: &[u128; 10]) -> Field25519Element {
    let mut acc = *first_fold;

    // Iterated overflow fold (limb 9 + high bits of limb 8).
    for _ in 0..3 {
        let limb_9 = acc[9];
        let high_8 = acc[8] >> 15;
        if limb_9 == 0 && high_8 == 0 {
            break;
        }
        acc[9] = 0;
        acc[8] &= (1u128 << 15) - 1;

        // Fold limb 9 (weight 2²⁷⁰): contribution is limb_9 · M.
        if limb_9 > 0 {
            let prod = limb_9 * (FOLD_M as u128);
            acc[0] += prod & ((1u128 << 30) - 1);
            acc[1] += prod >> 30;
        }
        // Fold limb 8 high bits (weight 2²⁵⁵): contribution is high_8 · 19.
        if high_8 > 0 {
            let prod = high_8 * 19u128;
            acc[0] += prod & ((1u128 << 30) - 1);
            acc[1] += prod >> 30;
        }

        // Re-canonicalize via carry propagation up through limb 9.
        for i in 0..9 {
            let carry = acc[i] >> 30;
            acc[i] &= (1u128 << 30) - 1;
            acc[i + 1] += carry;
        }
    }

    // Final canonicalization: subtract p while result ≥ p.
    let mut limbs = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        limbs[i] = acc[i] as u64;
    }
    for _ in 0..2 {
        if cmp_lt(&limbs, &P_LIMBS) {
            break;
        }
        sub_p_in_place(&mut limbs);
    }
    debug_assert!(cmp_lt(&limbs, &P_LIMBS), "final value not < p: {limbs:?}");
    Field25519Element { limbs }
}

/// Reduce 18 30-bit limbs (loose) to 9 canonical 30-bit limbs in `[0, p)`.
/// Composition of `compute_first_fold` + `compute_second_fold_and_canonicalize`.
pub fn compute_mod_p_reduction(eighteen: &[u64; NUM_OUTPUT_LIMBS]) -> Field25519Element {
    let first = compute_first_fold(eighteen);
    compute_second_fold_and_canonicalize(&first)
}

/// Convenience composer: reduce the output of `compute_limb_assembly`.
pub fn compute_mod_p_reduction_from_assembly(w: &LimbAssemblyWitness) -> Field25519Element {
    compute_mod_p_reduction(&w.limbs)
}

/// Compare two 9-limb little-endian values. Returns `true` iff `a < b`.
fn cmp_lt(a: &[u64; NUM_LIMBS], b: &[u64; NUM_LIMBS]) -> bool {
    for i in (0..NUM_LIMBS).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false // equal
}

/// In-place subtraction: `limbs -= P_LIMBS` (assumes `limbs ≥ P_LIMBS`).
fn sub_p_in_place(limbs: &mut [u64; NUM_LIMBS]) {
    let mut borrow: i64 = 0;
    for i in 0..NUM_LIMBS {
        let lhs = limbs[i] as i64;
        let rhs = P_LIMBS[i] as i64;
        let diff = lhs - rhs - borrow;
        if diff < 0 {
            limbs[i] = (diff + LIMB_MOD as i64) as u64;
            borrow = 1;
        } else {
            limbs[i] = diff as u64;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "underflow — caller violated precondition");
}

/// Reconstruct the canonical mod-p value as a 256-bit integer (split
/// into the low 128 and high 128 bits for u128 ergonomics). Used by tests.
pub fn to_u128_pair(elem: &Field25519Element) -> (u128, u128) {
    let mut acc_lo: u128 = 0;
    let mut acc_hi: u128 = 0;
    for i in 0..NUM_LIMBS {
        let bit = 30 * i;
        let v = elem.limbs[i] as u128;
        if bit < 128 {
            acc_lo = acc_lo.wrapping_add(v << bit);
            // Spill into hi if v's contribution crosses bit 128.
            if bit + 30 > 128 {
                let spill_bits = bit + 30 - 128;
                acc_hi = acc_hi.wrapping_add(v >> (30 - spill_bits));
            }
        } else {
            acc_hi = acc_hi.wrapping_add(v << (bit - 128));
        }
    }
    (acc_lo, acc_hi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::carry_fold::compute_carry_fold;
    use super::super::limb_assembly::compute_limb_assembly_from_carry_fold;
    use super::super::mul::compute_mul;

    fn elem_from_u64(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    fn assert_canonical(e: &Field25519Element) {
        for (i, &l) in e.limbs.iter().enumerate() {
            assert!(l < LIMB_MOD, "limb {i} = {l} not canonical 30-bit");
        }
        assert!(cmp_lt(&e.limbs, &P_LIMBS), "value not in [0, p): {:?}", e.limbs);
    }

    #[test]
    fn reduce_zero_is_zero() {
        let zero = [0u64; NUM_OUTPUT_LIMBS];
        let r = compute_mod_p_reduction(&zero);
        assert_eq!(r.limbs, [0u64; NUM_LIMBS]);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_one_is_one() {
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[0] = 1;
        let r = compute_mod_p_reduction(&input);
        let expected = elem_from_u64(1);
        assert_eq!(r.limbs, expected.limbs);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_p_minus_1_is_p_minus_1() {
        // P - 1 fits in 9 limbs already canonical.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        for i in 0..NUM_LIMBS {
            input[i] = P_LIMBS[i];
        }
        // Subtract 1 from limb 0.
        input[0] -= 1;
        let r = compute_mod_p_reduction(&input);
        // Output should equal P - 1.
        let mut expected = P_LIMBS;
        expected[0] -= 1;
        assert_eq!(r.limbs, expected);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_p_is_zero() {
        // P itself reduces to 0.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        for i in 0..NUM_LIMBS {
            input[i] = P_LIMBS[i];
        }
        let r = compute_mod_p_reduction(&input);
        assert_eq!(r.limbs, [0u64; NUM_LIMBS]);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_2p_is_zero() {
        // 2P should also reduce to 0.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        let mut carry = 0u64;
        for i in 0..NUM_LIMBS {
            let v = 2 * P_LIMBS[i] + carry;
            input[i] = v & (LIMB_MOD - 1);
            carry = v >> 30;
        }
        input[NUM_LIMBS] = carry;
        let r = compute_mod_p_reduction(&input);
        assert_eq!(r.limbs, [0u64; NUM_LIMBS], "got {:?}", r.limbs);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_2_to_255_is_19() {
        // 2^255 mod p = 19. Position bit 255 = bit 15 of limb 8.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[8] = 1u64 << 15;
        let r = compute_mod_p_reduction(&input);
        let expected = elem_from_u64(19);
        assert_eq!(r.limbs, expected.limbs);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_2_to_270_is_19_times_2_to_15() {
        // 2^270 mod p = 19 * 2^15 = M = 622592. Position bit 270 = limb 9 bit 0.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[9] = 1;
        let r = compute_mod_p_reduction(&input);
        let expected = elem_from_u64(FOLD_M);
        assert_eq!(r.limbs, expected.limbs);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_2_to_510_is_361() {
        // 2^510 = (2^255)^2 ≡ 19^2 = 361 (mod p). Position bit 510 = limb 17 bit 0.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[17] = 1;
        let r = compute_mod_p_reduction(&input);
        let expected = elem_from_u64(361);
        assert_eq!(r.limbs, expected.limbs);
        assert_canonical(&r);
    }

    #[test]
    fn reduce_max_loose_value_is_canonical() {
        // Every limb at 2^30 - 1: maximum loose 18-limb value.
        let input = [LIMB_MOD - 1; NUM_OUTPUT_LIMBS];
        let r = compute_mod_p_reduction(&input);
        assert_canonical(&r);
    }

    #[test]
    fn end_to_end_mul_pipeline_3x7_is_21() {
        let a = elem_from_u64(3);
        let b = elem_from_u64(7);
        let mul_w = compute_mul(&a, &b);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let result = compute_mod_p_reduction_from_assembly(&assembly_w);
        let expected = elem_from_u64(21);
        assert_eq!(result.limbs, expected.limbs);
        assert_canonical(&result);
    }

    #[test]
    fn end_to_end_mul_pipeline_arbitrary() {
        // (12345 * 67890) mod p = 838102050 (well below p, no actual reduction)
        let a = elem_from_u64(12345);
        let b = elem_from_u64(67890);
        let mul_w = compute_mul(&a, &b);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let result = compute_mod_p_reduction_from_assembly(&assembly_w);
        let expected = elem_from_u64(12345 * 67890);
        assert_eq!(result.limbs, expected.limbs);
        assert_canonical(&result);
    }

    #[test]
    fn end_to_end_mul_pipeline_p_minus_1_squared() {
        // (p - 1)^2 mod p = 1 (since (p-1)^2 = p^2 - 2p + 1 ≡ 1 mod p).
        let mut p_minus_1 = Field25519Element::P;
        p_minus_1.limbs[0] -= 1;
        let mul_w = compute_mul(&p_minus_1, &p_minus_1);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let result = compute_mod_p_reduction_from_assembly(&assembly_w);
        let expected = elem_from_u64(1);
        assert_eq!(result.limbs, expected.limbs, "(p-1)^2 mod p should be 1");
        assert_canonical(&result);
    }

    #[test]
    fn end_to_end_mul_pipeline_2_squared() {
        let two = elem_from_u64(2);
        let mul_w = compute_mul(&two, &two);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let result = compute_mod_p_reduction_from_assembly(&assembly_w);
        let expected = elem_from_u64(4);
        assert_eq!(result.limbs, expected.limbs);
        assert_canonical(&result);
    }

    #[test]
    fn end_to_end_max_canonical_squared_is_canonical() {
        // (max canonical, every limb 2^30-1) squared — stress-tests the
        // full pipeline including all carry/fold passes.
        let max = Field25519Element { limbs: [LIMB_MOD - 1; NUM_LIMBS] };
        let mul_w = compute_mul(&max, &max);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let result = compute_mod_p_reduction_from_assembly(&assembly_w);
        assert_canonical(&result);
    }

    // ── Tests for the standalone fold passes ─────────────────────────

    #[test]
    fn first_fold_zero_is_zero() {
        let zero = [0u64; NUM_OUTPUT_LIMBS];
        let r = compute_first_fold(&zero);
        assert_eq!(r, [0u128; 10]);
    }

    #[test]
    fn first_fold_low_limbs_pass_through() {
        // High limbs all zero — pass 1 just propagates V_lo.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[0] = 100;
        input[5] = 999;
        let r = compute_first_fold(&input);
        assert_eq!(r[0], 100);
        assert_eq!(r[5], 999);
        for i in [1, 2, 3, 4, 6, 7, 8, 9] {
            assert_eq!(r[i], 0, "limb {i} should be untouched");
        }
    }

    #[test]
    fn first_fold_single_high_limb_produces_m() {
        // L[9] = 1 → contribution 1 · M = 622592 at limb 0.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[9] = 1;
        let r = compute_first_fold(&input);
        assert_eq!(r[0], FOLD_M as u128);
        for i in 1..10 {
            assert_eq!(r[i], 0);
        }
    }

    #[test]
    fn first_fold_high_limb_at_position_10_shifts() {
        // L[10] = 1 → contribution 1 · M at limb 1 (one limb shift).
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[10] = 1;
        let r = compute_first_fold(&input);
        assert_eq!(r[0], 0);
        assert_eq!(r[1], FOLD_M as u128);
        for i in 2..10 {
            assert_eq!(r[i], 0);
        }
    }

    #[test]
    fn first_fold_max_high_limb_spans_two_positions() {
        // L[9] = 2^30 - 1 → contribution (2^30 - 1) · M ≈ 2^50, spans 2 limbs.
        let mut input = [0u64; NUM_OUTPUT_LIMBS];
        input[9] = LIMB_MOD - 1;
        let r = compute_first_fold(&input);
        let expected = (LIMB_MOD as u128 - 1) * (FOLD_M as u128);
        assert_eq!(r[0], expected & ((1u128 << 30) - 1));
        assert_eq!(r[1], expected >> 30);
        for i in 2..10 {
            assert_eq!(r[i], 0);
        }
    }

    #[test]
    fn second_fold_zero_is_zero() {
        let zero = [0u128; 10];
        let r = compute_second_fold_and_canonicalize(&zero);
        assert_eq!(r.limbs, [0u64; NUM_LIMBS]);
        assert_canonical(&r);
    }

    #[test]
    fn second_fold_canonical_input_is_identity() {
        // Already-canonical input below p: should pass through unchanged.
        let mut input = [0u128; 10];
        input[0] = 12345;
        let r = compute_second_fold_and_canonicalize(&input);
        assert_eq!(r.limbs[0], 12345);
        for i in 1..NUM_LIMBS {
            assert_eq!(r.limbs[i], 0);
        }
        assert_canonical(&r);
    }

    #[test]
    fn second_fold_input_with_limb_9_folds() {
        // limb_9 = 1 → after fold, limb 0 = M.
        let mut input = [0u128; 10];
        input[9] = 1;
        let r = compute_second_fold_and_canonicalize(&input);
        assert_eq!(r.limbs[0], FOLD_M);
        for i in 1..NUM_LIMBS {
            assert_eq!(r.limbs[i], 0);
        }
        assert_canonical(&r);
    }

    #[test]
    fn second_fold_input_with_high_bits_in_limb_8() {
        // limb_8 = 2^15 (= bit 255) → folds to 19 at limb 0, limb_8 becomes 0.
        let mut input = [0u128; 10];
        input[8] = 1u128 << 15;
        let r = compute_second_fold_and_canonicalize(&input);
        assert_eq!(r.limbs[0], 19);
        assert_eq!(r.limbs[8], 0);
        assert_canonical(&r);
    }

    #[test]
    fn first_then_second_fold_matches_mod_p_reduction() {
        // Pipeline equivalence: compose(first, second) === compute_mod_p_reduction.
        let inputs: Vec<[u64; NUM_OUTPUT_LIMBS]> = vec![
            [0; NUM_OUTPUT_LIMBS],
            {
                let mut a = [0; NUM_OUTPUT_LIMBS];
                a[0] = 1;
                a
            },
            {
                let mut a = [0; NUM_OUTPUT_LIMBS];
                a[8] = 1u64 << 15; // bit 255
                a
            },
            {
                let mut a = [0; NUM_OUTPUT_LIMBS];
                a[17] = 1; // bit 510
                a
            },
            [LIMB_MOD - 1; NUM_OUTPUT_LIMBS], // max loose
        ];
        for input in inputs {
            let composed = compute_second_fold_and_canonicalize(&compute_first_fold(&input));
            let direct = compute_mod_p_reduction(&input);
            assert_eq!(composed.limbs, direct.limbs, "fold composition must match for input {input:?}");
        }
    }

    #[test]
    fn cmp_lt_basic() {
        let z = [0u64; NUM_LIMBS];
        let one = {
            let mut l = [0u64; NUM_LIMBS];
            l[0] = 1;
            l
        };
        assert!(cmp_lt(&z, &one));
        assert!(!cmp_lt(&one, &z));
        assert!(!cmp_lt(&z, &z));
        assert!(cmp_lt(&one, &P_LIMBS));
        assert!(!cmp_lt(&P_LIMBS, &P_LIMBS));
    }
}

//! High-level canonical mod-`p` field arithmetic helpers.
//!
//! Wraps the lower-level chip witness functions (`compute_add`,
//! `compute_sub`, `compute_mul`, `compute_carry_fold`,
//! `compute_limb_assembly_from_carry_fold`, `compute_mod_p_reduction`)
//! into a tidy `field_add` / `field_sub` / `field_mul` / `field_double`
//! API operating on canonical `Field25519Element` values.
//!
//! These are **witness-side helpers** — they do not emit AIR constraints.
//! They are used by the ed25519 point-op witness (sub-phase 5.2.1.4+)
//! to build up Edwards group operations in pure Rust before designing
//! the corresponding AIR chips.
//!
//! Subtraction uses `2p` (not `p`) per limb to guarantee non-negativity
//! across all canonical inputs:
//!
//!   `a[i] + 2p[i] - b[i] >= 0`   for `a, b ∈ [0, p)`.
//!
//! The lower-level `sub::compute_sub` chip uses `p` per limb, which is
//! correct for the inputs its tests exercise but underflows for
//! adversarial canonical inputs. This helper sidesteps that boundary
//! case for downstream ed25519 work.

use super::carry_fold::compute_carry_fold;
use super::limb_assembly::compute_limb_assembly_from_carry_fold;
use super::mod_p::compute_mod_p_reduction;
use super::mul::compute_mul;
use super::{Field25519Element, NUM_LIMBS, P_LIMBS};

/// Canonical mod-`p` addition: `c = (a + b) mod p`.
pub fn field_add(a: &Field25519Element, b: &Field25519Element) -> Field25519Element {
    let mut eighteen = [0u64; 18];
    for i in 0..NUM_LIMBS {
        eighteen[i] = a.limbs[i] + b.limbs[i]; // loose, < 2^31
    }
    compute_mod_p_reduction(&eighteen)
}

/// Canonical mod-`p` subtraction: `c = (a - b) mod p`. Uses `2p` per
/// limb to keep all per-limb values non-negative for any canonical
/// inputs.
pub fn field_sub(a: &Field25519Element, b: &Field25519Element) -> Field25519Element {
    let mut eighteen = [0u64; 18];
    for i in 0..NUM_LIMBS {
        eighteen[i] = a.limbs[i] + 2 * P_LIMBS[i] - b.limbs[i]; // loose, < 2^32
    }
    compute_mod_p_reduction(&eighteen)
}

/// Canonical mod-`p` doubling: `c = 2a mod p`.
pub fn field_double(a: &Field25519Element) -> Field25519Element {
    field_add(a, a)
}

/// Canonical mod-`p` multiplication: `c = (a · b) mod p`.
///
/// Composes the chip pipeline: `mul → carry_fold → limb_assembly → mod_p_reduce`.
pub fn field_mul(a: &Field25519Element, b: &Field25519Element) -> Field25519Element {
    let mul_w = compute_mul(a, b);
    let fold_w = compute_carry_fold(&mul_w.out_positions);
    let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
    compute_mod_p_reduction(&assembly_w.limbs)
}

/// Canonical zero element.
pub fn field_zero() -> Field25519Element {
    Field25519Element::ZERO
}

/// Canonical one element.
pub fn field_one() -> Field25519Element {
    let mut limbs = [0u64; NUM_LIMBS];
    limbs[0] = 1;
    Field25519Element { limbs }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn add_basic() {
        let a = small(100);
        let b = small(200);
        let c = field_add(&a, &b);
        assert_eq!(c, small(300));
    }

    #[test]
    fn add_with_zero_is_identity() {
        let a = small(0xDEAD_BEEF);
        let zero = field_zero();
        assert_eq!(field_add(&a, &zero), a);
        assert_eq!(field_add(&zero, &a), a);
    }

    #[test]
    fn sub_basic() {
        let a = small(500);
        let b = small(123);
        assert_eq!(field_sub(&a, &b), small(377));
    }

    #[test]
    fn sub_self_is_zero() {
        let a = small(0xCAFEBABE);
        assert_eq!(field_sub(&a, &a), field_zero());
    }

    #[test]
    fn sub_p_minus_one_yields_pminus_one() {
        // 0 - 1 mod p = p - 1.
        let zero = field_zero();
        let one = field_one();
        let r = field_sub(&zero, &one);
        let mut p_minus_1 = P_LIMBS;
        p_minus_1[0] -= 1;
        assert_eq!(r.limbs, p_minus_1);
    }

    #[test]
    fn sub_handles_adversarial_low_limb() {
        // a = 0, b = 2^30 - 1 (canonical max for non-limb-0). a - b mod p must
        // produce a canonical value without panicking on per-limb underflow.
        let a = field_zero();
        let mut b = field_zero();
        b.limbs[0] = (1 << 30) - 1; // maximal limb-0 value
        let r = field_sub(&a, &b);
        // r = -(2^30 - 1) mod p = p - (2^30 - 1).
        // First limb: p[0] - (2^30 - 1) = (2^30 - 19) - (2^30 - 1) = -18.
        // Borrow from limb 1: limb 1 becomes p[1] - 1 = 2^30 - 2, limb 0
        // becomes (2^30) - 18 = 2^30 - 18.
        assert_eq!(r.limbs[0], (1 << 30) - 18);
        assert_eq!(r.limbs[1], (1 << 30) - 2);
        for i in 2..8 {
            assert_eq!(r.limbs[i], P_LIMBS[i]);
        }
        assert_eq!(r.limbs[8], P_LIMBS[8]);
    }

    #[test]
    fn double_basic() {
        let a = small(0x1234);
        assert_eq!(field_double(&a), small(0x2468));
    }

    #[test]
    fn double_zero_is_zero() {
        assert_eq!(field_double(&field_zero()), field_zero());
    }

    #[test]
    fn mul_basic() {
        let a = small(7);
        let b = small(13);
        assert_eq!(field_mul(&a, &b), small(91));
    }

    #[test]
    fn mul_with_one_is_identity() {
        let a = small(0xDEADBEEF);
        let one = field_one();
        assert_eq!(field_mul(&a, &one), a);
        assert_eq!(field_mul(&one, &a), a);
    }

    #[test]
    fn mul_with_zero_is_zero() {
        let a = small(0xDEADBEEF);
        let zero = field_zero();
        assert_eq!(field_mul(&a, &zero), zero);
    }

    #[test]
    fn fermat_little_check_for_small_a() {
        // a + (p - a) = p ≡ 0. Round-trip via add+sub.
        let a = small(0x12345678);
        let neg_a = field_sub(&field_zero(), &a);
        let sum = field_add(&a, &neg_a);
        assert_eq!(sum, field_zero());
    }

    #[test]
    fn distributivity_a_times_b_plus_c() {
        // a * (b + c) == a*b + a*c
        let a = small(0x1234);
        let b = small(0x5678);
        let c = small(0x9ABC);
        let lhs = field_mul(&a, &field_add(&b, &c));
        let rhs = field_add(&field_mul(&a, &b), &field_mul(&a, &c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn mul_commutativity() {
        let a = small(0xDEADBEEF);
        let b = small(0xCAFEBABE);
        assert_eq!(field_mul(&a, &b), field_mul(&b, &a));
    }
}

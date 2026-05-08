//! `scalar25519` — arithmetic chips operating modulo the Curve25519 group
//! order `ℓ = 2²⁵² + 27742317777372353535851937790883648493`.
//!
//! This is **not the same** as the `field25519` module, which operates
//! modulo the base prime `p = 2²⁵⁵ - 19`. The two moduli serve different
//! parts of the ed25519 stack:
//!
//!   - `field25519` (mod p): point coordinates `(X, Y, Z, T)` and the
//!     Edwards group law arithmetic.
//!   - `scalar25519` (mod ℓ): scalar values used as exponents in
//!     scalar multiplication, and the SHA-512 → ℓ reduction (RFC 8032
//!     §5.1.3 step 2).
//!
//! ## Sub-fase 5.6.d.1 roadmap
//!
//! Closes the trust shim in `reduce_mod_l_air_stark`. Multi-step:
//!
//! | Sub | Item | Esforço |
//! |---|---|---|
//! | 5.6.d.1.a | Module scaffold + `compute_reduce_mod_l_witness` | this commit |
//! | 5.6.d.1.b | Single-row schoolbook AIR (byte cells + carry chain) | next |
//! | 5.6.d.1.c | Range checks (bit decomposition for q, product, carry) | |
//! | 5.6.d.1.d | `scalar < ℓ` strict-less-than check | |
//! | 5.6.d.1.e | PV bind + wrapper rewrite (trust-shim removal) | |
//!
//! Architecturally distinct from `field25519` because all the arithmetic
//! is byte-level integer arithmetic against a fixed 32-byte modulus,
//! not 30-bit-limb modular reduction. Sharing chips between the two
//! would conflate moduli; cleaner to keep them separate.

pub mod reduce_mod_l;
pub mod reduce_mod_l_air;

pub use reduce_mod_l::{L_BYTES, ReduceModLWitness, compute_reduce_mod_l_witness};
pub use reduce_mod_l_air::{NUM_COLS, ReduceModLAirChip, build_reduce_mod_l_trace};

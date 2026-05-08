//! Lookup / range-check chips (Etapa 3 + sub-fase 5.2.1.x).
//!
//! Two flavours, both sound stand-alone (no permutation arguments needed):
//!
//!   - `byte_range::Range8Chip` — 8-bit range check, the original implementation
//!     shipped in sub-fase 5.2.1.1.a (kept for backwards compatibility with
//!     existing chips). Equivalent to `RangeNChip<8>`.
//!   - `range_n::RangeNChip<N>` — generic `N`-bit range chip (Etapa 3.0/3.1).
//!     Public aliases `Range10Chip` and `Range16Chip` cover the sizes used
//!     in Phase 5 to close the BabyBear-overflow soundness gaps documented
//!     in `feedback_babybear_air_overflow.md`.
//!
//! Both chips use bit decomposition (`NUM_BITS + 1` columns: value + bits),
//! and the recomposition constraint forces the value to equal the bit
//! representation. Sound regardless of prover plumbing — verified via
//! `check_constraints` adversarial tests.

pub mod byte_range;
pub mod range_n;

//! Chip modules for sub-phase 5.2.1 (ed25519 verification in AIR).
//!
//! Decision 2026-05-05 (the four "yes" answers): 9-limb 30-bit field
//! representation, native SHA-512 in AIR, Edwards extended coordinates
//! with in-circuit scalar multiplication, multiple AIRs glued by
//! permutation arguments at the top level.
//!
//! Plonky3 0.5.2 ships only `p3-uni-stark` (single AIR per proof) on
//! crates.io — `p3-batch-stark` is not published. So in practice each
//! "chip" is a Rust module that emits constraints into a shared
//! `AirBuilder`, and the top-level `OracleAir` (sub-phase 5.2.1.7)
//! aggregates them inline. For incremental development each chip also
//! ships a standalone wrapper AIR so it can be proven and validated
//! against `check_constraints` independently.
//!
//! Roadmap of sub-sub-phases:
//!
//! | Phase    | Module             | Status |
//! |----------|--------------------|--------|
//! | 5.2.1.0  | field25519/{add,sub} | ✅ this commit |
//! | 5.2.1.1  | field25519/{mul,reduce} | ⏳ |
//! | 5.2.1.2  | sha512/round       | ⏳ |
//! | 5.2.1.3  | sha512 (full)      | ⏳ |
//! | 5.2.1.4  | ed25519/point      | ⏳ |
//! | 5.2.1.5  | ed25519/scalar_mul | ⏳ |
//! | 5.2.1.6  | ed25519/decompress | ⏳ |
//! | 5.2.1.7  | ed25519/verify (top-level integration) | ⏳ |

pub mod ed25519;
pub mod field25519;
pub mod lookup;
pub mod scalar25519;
pub mod sha512;

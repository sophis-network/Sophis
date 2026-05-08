//! SHA-512 in AIR (sub-phases 5.2.1.2 and 5.2.1.3).
//!
//! Used by ed25519 to compute `H(R || A || M)` where `R` is the signature
//! prefix, `A` is the public key, `M` is the message hash, and `H` is
//! SHA-512. The hash output (a 512-bit integer mod the group order `ℓ`)
//! is the challenge in the verification equation.
//!
//! Sub-phase 5.2.1.2 ships the **witness foundation** in Rust: constants,
//! round, message schedule, full compression, full SHA-512 with padding,
//! validated against FIPS 180-4 test vectors (Appendix C).
//!
//! The AIR chips proper (sub-phase 5.2.1.2.air for the round chip,
//! 5.2.1.3 for the full hash) require bit-decomposition of every 64-bit
//! word (64 boolean columns each), bit-level XOR/AND/NOT constraints,
//! and 64-bit modular adders with carries — many hundreds of columns
//! per round. They land in dedicated sessions on top of this witness.

pub mod big_sigma;
pub mod ch;
pub mod compression;
pub mod compression_chip;
pub mod constants;
pub mod maj;
pub mod round;
pub mod round_chip;
pub mod schedule;
pub mod schedule_step;
pub mod small_sigma;
pub mod word64_add;
pub mod word64_add3;
pub mod word64_and;
pub mod word64_eq;
pub mod word64_is_zero;
pub mod word64_not;
pub mod word64_rotr_const;
pub mod word64_shr_const;
pub mod word64_xor;

pub use compression::{compute_compression, sha512};
pub use constants::{H_INITIAL, K};
pub use round::{Sha512State, ch, compute_round, big_sigma0, big_sigma1, maj};
pub use schedule::{compute_schedule, small_sigma0, small_sigma1};

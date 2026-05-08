//! Plonky3 STARK configuration for the Phase 5 ZK-Oracle.
//!
//! Sub-phase 5.2.0.1 wiring:
//!
//!   - **Field**: BabyBear (~31-bit prime, two-adicity 27, fast on CPU).
//!   - **Extension**: 4-element binomial extension (sound for ~120-bit security).
//!   - **Hash**: Poseidon2 width-16, BabyBear-native, with the canonical
//!     round constants distributed in `p3-baby-bear`. Sponge wraps the
//!     permutation as `PaddingFreeSponge<perm, 16, 8, 8>` and compression
//!     uses `TruncatedPermutation<perm, 2, 8, 16>` — these are the same
//!     constants used in the reference Plonky3 FRI test, so the security
//!     analysis carries over directly.
//!   - **MMCS**: `MerkleTreeMmcs` over BabyBear's packing for the trace,
//!     `ExtensionMmcs` over the 4-element extension for FRI.
//!   - **PCS**: `TwoAdicFriPcs` with `log_blowup = 1` and 100 query rounds
//!     (~100-bit conjectured FRI soundness for our trace heights).
//!   - **Challenger**: `DuplexChallenger` over the same Poseidon2.
//!
//! The same round constants are used by both prover and verifier — the
//! `oracle_stark_config()` constructor returns a struct value that both
//! sides instantiate identically. For now we use the in-binary constants
//! (no dynamic parameter loading).

use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;

pub type Perm = Poseidon2BabyBear<16>;
/// Plonky3 STARK trace hash. Uses `PaddingFreeSponge` per the canonical
/// Plonky3 reference config (`width = 16`, `rate = 8`, `out = 8`).
///
/// **Security note (risk-accepted, GHSA `dependabot/26` 2026-05-06):**
/// `PaddingFreeSponge` has a known collision pre-image when the attacker can
/// freely vary the *number of field elements* fed into a single hash. The
/// Plonky3 advisory itself states the construction remains collision-
/// resistant *"in circumstances where the number of elements to be hashed
/// is known and fixed in advance, (as is the case for most STARKS)."*
///
/// In Sophis Phase 5 the sponge is only ever consumed by `MerkleTreeMmcs`
/// hashing trace leaves whose width is structurally fixed at 8 BabyBear
/// elements (`Field::Packing` width). The trace height itself is a public
/// circuit parameter the verifier checks against the AIR — a malicious
/// relayer cannot vary the per-leaf element count to mount the collision.
///
/// The upstream fix (`Pad10Sponge`) lives on `Plonky3/Plonky3@main` and is
/// **not yet released to crates.io** (latest = 0.5.2, the same we pin). We
/// will pick up the fix when it ships in a tagged release; switching to a
/// git dependency in the meantime would replace a non-applicable advisory
/// with unaudited upstream churn.
pub type OracleHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type OracleCompress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, OracleHash, OracleCompress, 2, 8>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type OraclePcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type OracleChallenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type OracleStarkConfig = StarkConfig<OraclePcs, Challenge, OracleChallenger>;

/// FRI security parameters. 100 queries with `log_blowup=1` and 16-bit
/// query proof-of-work yields ~100 bits of conjectured FRI soundness,
/// which is the standard target for production Plonky3 deployments.
const LOG_BLOWUP: usize = 1;
const LOG_FINAL_POLY_LEN: usize = 0;
const NUM_QUERIES: usize = 100;
const COMMIT_PROOF_OF_WORK_BITS: usize = 0;
const QUERY_PROOF_OF_WORK_BITS: usize = 16;

/// Build a `(permutation, config)` pair. The permutation is returned
/// separately because the challenger constructor needs it.
pub fn oracle_stark_config() -> (Perm, OracleStarkConfig) {
    let perm = default_babybear_poseidon2_16();
    let hash = OracleHash::new(perm.clone());
    let compress = OracleCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone(), 0);
    let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress, 0));
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: COMMIT_PROOF_OF_WORK_BITS,
        query_proof_of_work_bits: QUERY_PROOF_OF_WORK_BITS,
        mmcs: challenge_mmcs,
    };
    let dft = Dft::default();
    let pcs = OraclePcs::new(dft, val_mmcs, fri_params);
    let challenger = OracleChallenger::new(perm.clone());
    let config = OracleStarkConfig::new(pcs, challenger);
    (perm, config)
}

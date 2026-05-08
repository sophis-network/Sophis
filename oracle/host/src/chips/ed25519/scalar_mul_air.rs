//! `ed25519::scalar_mul_air` — multi-row scalar multiplication AIR (WIRED).
//!
//! Fixed-position MSB-first double-and-add. Trace height is exactly 256
//! rows (a power of two — Plonky3 native — so no FRI padding is needed).
//! Row `r` always processes bit `255 - r` of the scalar:
//!
//! ```text
//! row 0          row 1          ...    row 255
//! processes      processes              processes
//! bit 255        bit 254               bit 0
//!
//! PRE_ACC[0] = O (neutral, (0,1,1,0))
//! doubled[r] = PRE_ACC[r] + PRE_ACC[r]                  // doubling
//! added[r]   = doubled[r] + BASE_POINT
//! POST_ACC[r] = bit_(255-r) ? added[r] : doubled[r]
//! PRE_ACC[r+1] = POST_ACC[r]
//! ```
//!
//! After 256 rounds, `POST_ACC[255]` holds `[scalar] · BASE_POINT`. This
//! fixed-position layout (vs. the original dynamic MSB-first that started
//! `acc` at `BASE_POINT` and only ran from the highest set bit downward)
//! gives a static row→bit mapping `r ↔ 255-r`, which is what the
//! sub-fase 5.6.b.1 binding constraints rely on to bind the AIR's bit
//! choices to the public-input scalar bytes.
//!
//! Per row layout:
//!   - Bit selector: 1 boolean (= bit (255-r) of scalar)
//!   - PRE_ACC: 36 cols (current accumulator)
//!   - POST_ACC: 36 cols (next accumulator after this bit step)
//!   - DOUBLED: 36 cols (acc + acc result)
//!   - ADDED: 36 cols (doubled + base_point result)
//!   - BASE_POINT: 36 cols (constant — the scalar's base point)
//!   - DOUBLE chip: PointAddAirChip computing acc + acc
//!   - ADD chip: PointAddAirChip computing doubled + base
//!
//! Per-row constraints:
//!   - bit boolean
//!   - DOUBLE.P1 = DOUBLE.P2 = PRE_ACC; DOUBLE.P3 = DOUBLED
//!   - ADD.P1 = DOUBLED, ADD.P2 = BASE_POINT, ADD.P3 = ADDED
//!   - Conditional select:
//!     POST_ACC[i] - DOUBLED[i] = bit · (ADDED[i] - DOUBLED[i])
//!
//! First-row boundary:
//!   - PRE_ACC[0] = neutral_limbs (X=0, Y=1, Z=1, T=0)
//!
//! Transitions (when_transition):
//!   - row[t+1].PRE_ACC = row[t].POST_ACC
//!   - row[t+1].BASE_POINT = row[t].BASE_POINT
//!
//! ## Status
//!
//! Sub-fase 5.6.b.1.a (this commit): rewired to fixed-position MSB-first
//! with HEIGHT = 256 — replaces the previous dynamic MSB-first variant.
//! No PV yet; binding lands in 5.6.b.1.b/c.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::point_add_air::{self, PointAddAirChip, NUM_COLS as PA_COLS};
use crate::chips::field25519::NUM_LIMBS;

const POINT_LIMBS: usize = 4 * NUM_LIMBS; // 36

/// Number of bit cells per row used by the scalar↔bit shift register.
///
/// At row 0 the shift register holds the canonical bit decomposition of
/// the public-input scalar (BIT[i] == bit (255-i) of scalar). Each
/// transition shifts the register left: `next.BIT[i] = cur.BIT[i+1]`.
/// As a result, at every row `r`, `BIT[0]` is the bit currently being
/// consumed (= bit `255-r` of scalar), and we can bind `SELECTOR == BIT[0]`
/// without ever needing to know the row index `r` inside the AIR.
pub const SCALAR_BITS: usize = 256;

pub mod col {
    use super::*;
    pub const SELECTOR: usize = 0;
    pub const PRE_ACC: usize = 1;
    pub const POST_ACC: usize = PRE_ACC + POINT_LIMBS;        // 37
    pub const DOUBLED: usize = POST_ACC + POINT_LIMBS;        // 73
    pub const ADDED: usize = DOUBLED + POINT_LIMBS;           // 109
    pub const BASE_POINT: usize = ADDED + POINT_LIMBS;        // 145
    pub const DOUBLE_START: usize = BASE_POINT + POINT_LIMBS; // 181
    pub const ADD_START: usize = DOUBLE_START + PA_COLS;
    /// Sub-fase 5.6.b.1.b — start of the 256-cell bit shift register.
    pub const BITS_START: usize = ADD_START + PA_COLS;
    pub const TOTAL: usize = BITS_START + SCALAR_BITS;

    pub const X_OFF: usize = 0;
    pub const Y_OFF: usize = NUM_LIMBS;
    pub const Z_OFF: usize = 2 * NUM_LIMBS;
    pub const T_OFF: usize = 3 * NUM_LIMBS;
}

pub const NUM_COLS: usize = col::TOTAL;

/// Public-values count exposed to the STARK verifier (sub-fase 5.6.b.1.c).
///
/// Layout (104 BabyBear elements total):
///   [0..32]    scalar bytes (canonical LE bytes, one BabyBear per byte)
///   [32..41]   base_point.X limbs
///   [41..50]   base_point.Y limbs
///   [50..59]   base_point.Z limbs
///   [59..68]   base_point.T limbs
///   [68..77]   output.X limbs
///   [77..86]   output.Y limbs
///   [86..95]   output.Z limbs
///   [95..104]  output.T limbs
///
/// Closes the trust shim from 5.6.b: the wrapper verifier no longer
/// re-derives `[scalar]·base` in Rust to compare against the supplied
/// `expected_output`. The STARK constraints inside the AIR enforce:
///
///   - row 0 boundary: BIT shift register's bytewise sum matches PV scalar bytes
///   - row 0 boundary: BASE_POINT cols match PV base limbs
///   - row 255 boundary (when_last_row): POST_ACC cols match PV output limbs
pub const NUM_BOUNDARY_LIMBS: usize = 4 * NUM_LIMBS; // 36
pub const NUM_PUBLIC_VALUES: usize = 32 + NUM_BOUNDARY_LIMBS + NUM_BOUNDARY_LIMBS; // 104

#[derive(Debug, Clone, Copy)]
pub struct ScalarMulAirChip;

impl<F: Field> BaseAir<F> for ScalarMulAirChip {
    fn width(&self) -> usize { NUM_COLS }
    fn num_public_values(&self) -> usize { NUM_PUBLIC_VALUES }
    fn main_next_row_columns(&self) -> Vec<usize> { (0..NUM_COLS).collect() }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

/// Neutral (identity) element of the Edwards group in extended
/// homogeneous coordinates: `(X=0, Y=1, Z=1, T=0)`.
fn neutral_limb_at(off_in_point: usize) -> u64 {
    // off_in_point ∈ [0, 4·NUM_LIMBS).
    // X limbs (0..NUM_LIMBS):           0
    // Y limbs (NUM_LIMBS..2·NUM_LIMBS): 1 at limb 0, else 0
    // Z limbs (2·NUM_LIMBS..3·NUM_LIMBS): 1 at limb 0, else 0
    // T limbs (3·NUM_LIMBS..4·NUM_LIMBS): 0
    let limb_in_field = off_in_point % NUM_LIMBS;
    let field_idx = off_in_point / NUM_LIMBS;
    match (field_idx, limb_in_field) {
        (1, 0) | (2, 0) => 1, // Y[0] = 1, Z[0] = 1
        _ => 0,
    }
}

impl<AB: AirBuilder> Air<AB> for ScalarMulAirChip
where AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Embed the two PointAddAirChip per row.
        PointAddAirChip::at(col::DOUBLE_START).emit(builder);
        PointAddAirChip::at(col::ADD_START).emit(builder);

        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();

        builder.assert_bool(cur[col::SELECTOR].clone());

        let assert_chunks = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(cur[off_a + i].clone(), cur[off_b + i].clone());
            }
        };

        // DOUBLE chip: P1 = P2 = PRE_ACC; P3 = DOUBLED
        assert_chunks(builder, col::DOUBLE_START + point_add_air::col::P1, col::PRE_ACC, POINT_LIMBS);
        assert_chunks(builder, col::DOUBLE_START + point_add_air::col::P2, col::PRE_ACC, POINT_LIMBS);
        assert_chunks(builder, col::DOUBLE_START + point_add_air::col::P3, col::DOUBLED, POINT_LIMBS);

        // ADD chip: P1 = DOUBLED, P2 = BASE_POINT, P3 = ADDED
        assert_chunks(builder, col::ADD_START + point_add_air::col::P1, col::DOUBLED, POINT_LIMBS);
        assert_chunks(builder, col::ADD_START + point_add_air::col::P2, col::BASE_POINT, POINT_LIMBS);
        assert_chunks(builder, col::ADD_START + point_add_air::col::P3, col::ADDED, POINT_LIMBS);

        // Conditional select per limb (degree 2):
        // POST_ACC = bit ? ADDED : DOUBLED
        // POST_ACC - DOUBLED = bit · (ADDED - DOUBLED)
        for i in 0..POINT_LIMBS {
            let post = cur[col::POST_ACC + i].clone();
            let doubled = cur[col::DOUBLED + i].clone();
            let added = cur[col::ADDED + i].clone();
            let bit = cur[col::SELECTOR].clone();
            builder.assert_eq(post - doubled.clone(), bit * (added - doubled));
        }

        // First-row boundary: PRE_ACC[0] = neutral. With the fixed-position
        // MSB-first iteration (acc starts at neutral, row r processes bit
        // 255-r), this is the necessary anchor that links PRE_ACC's
        // transition chain to a single canonical starting point.
        for i in 0..POINT_LIMBS {
            builder
                .when_first_row()
                .assert_eq(cur[col::PRE_ACC + i].clone(), AB::Expr::from_u64(neutral_limb_at(i)));
        }

        // Sub-fase 5.6.b.1.b — bit shift register binding.
        //
        // The 256-cell shift register lets us connect the per-row
        // SELECTOR to a deterministic position of the scalar without
        // needing a row-index expression inside the AIR. Constraints:
        //
        //   1. SELECTOR equals the head of the register at every row.
        //   2. At row 0, every register cell is a boolean (the canonical
        //      bit decomposition of the scalar is loaded as the boundary).
        //   3. Each transition shifts the register left by one position:
        //      `next.BIT[i] = cur.BIT[i+1]` for i in 0..SCALAR_BITS-1.
        //      Since this preserves cell values across the lifetime of
        //      each bit, the boolean property at row 0 carries to every
        //      later row where that cell still holds a real bit.
        //
        // The byte-decomposition that ties these bits to the public-input
        // scalar bytes lands in 5.6.b.1.c (along with PV exposure).
        builder.assert_eq(cur[col::SELECTOR].clone(), cur[col::BITS_START].clone());
        // Bit booleans hold at every row (degree 2). Wrapping with
        // `when_first_row()` would push the constraint to degree 3 and
        // exceed `max_constraint_degree(2)` — instead the trace builder
        // pads expired tail cells with 0 so the all-rows assertion is
        // satisfied for free.
        for i in 0..SCALAR_BITS {
            builder.assert_bool(cur[col::BITS_START + i].clone());
        }
        for i in 0..SCALAR_BITS - 1 {
            builder
                .when_transition()
                .assert_eq(next[col::BITS_START + i].clone(), cur[col::BITS_START + i + 1].clone());
        }

        // Transitions: PRE_ACC and BASE_POINT propagate.
        for i in 0..POINT_LIMBS {
            builder.when_transition().assert_eq(next[col::PRE_ACC + i].clone(), cur[col::POST_ACC + i].clone());
            builder.when_transition().assert_eq(next[col::BASE_POINT + i].clone(), cur[col::BASE_POINT + i].clone());
        }

        // Sub-fase 5.6.b.1.c — PV boundary binding.
        //
        // Public values layout (104 BabyBear elements):
        //   [0..32]        scalar bytes (canonical LE)
        //   [32..68]       base_point limbs (X || Y || Z || T)
        //   [68..104]      output limbs at row 255's POST_ACC
        //
        // Bytes are bound via per-byte decomposition over the BIT shift
        // register at row 0. Base point at row 0. Output at row 255 via
        // when_last_row. After this commit the wrapper drops its
        // re-derive trust shim — STARK constraints enforce the binding.
        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };

        // PV[0..32]: scalar bytes. byte j = sum_{k=0..7} BIT[255 - 8j - k] * 2^k
        // (at row 0 the bit register holds the canonical decomposition).
        let pow2: [u64; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
        for j in 0..32 {
            let mut sum = AB::Expr::ZERO;
            for k in 0..8 {
                let bit_idx = 255 - (8 * j + k);
                let coeff = AB::Expr::from_u64(pow2[k]);
                sum = sum + cur[col::BITS_START + bit_idx].clone() * coeff;
            }
            builder.when_first_row().assert_eq(sum, pub_copies[j].into());
        }

        // PV[32..68]: base_point limbs at row 0 (already replicated by transition).
        for i in 0..POINT_LIMBS {
            builder
                .when_first_row()
                .assert_eq(cur[col::BASE_POINT + i].clone(), pub_copies[32 + i].into());
        }

        // PV[68..104]: output limbs at row 255's POST_ACC.
        for i in 0..POINT_LIMBS {
            builder
                .when_last_row()
                .assert_eq(cur[col::POST_ACC + i].clone(), pub_copies[32 + POINT_LIMBS + i].into());
        }
    }
}

fn put_point<F: Field + PrimeCharacteristicRing>(values: &mut [F], off: usize, p: &ExtendedPoint) {
    for i in 0..NUM_LIMBS {
        values[off + col::X_OFF + i] = F::from_u64(p.x.limbs[i]);
        values[off + col::Y_OFF + i] = F::from_u64(p.y.limbs[i]);
        values[off + col::Z_OFF + i] = F::from_u64(p.z.limbs[i]);
        values[off + col::T_OFF + i] = F::from_u64(p.t.limbs[i]);
    }
}

/// Build a multi-row trace for `scalar_mul` of `scalar` (LE bytes) over
/// `base_point`. Trace height is exactly 256 rows (a power of 2 — Plonky3
/// FRI native — so no padding rows are needed).
///
/// Row `r` processes bit `255 - r` of the scalar. Acc starts at the
/// Edwards group's neutral element `(0, 1, 1, 0)`, so at row 255's
/// `POST_ACC` we have `[scalar] · base_point`.
pub fn build_scalar_mul_trace<F: Field + PrimeCharacteristicRing>(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
) -> RowMajorMatrix<F> {
    use crate::chips::ed25519::point::point_add;

    const TOTAL_BITS: usize = 256;
    const HEIGHT: usize = TOTAL_BITS;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Fixed-position MSB-first iteration: `acc` starts at neutral and at
    // each row absorbs one bit, top-down. After 256 rows we have the
    // canonical scalar product. Both the "no set bits" and "all set bits"
    // edge cases reduce to the same loop body.
    let mut acc = ExtendedPoint::neutral();

    // Pre-compute the canonical 256-bit decomposition of the scalar so
    // we can populate the shift register on every row in O(1).
    // `bits[k]` = bit `255 - k` of `scalar` for `k` in 0..256.
    let mut bits = [0u8; SCALAR_BITS];
    for k in 0..SCALAR_BITS {
        let bit_pos = 255 - k;
        let byte_idx = bit_pos / 8;
        let bit_in_byte = bit_pos % 8;
        bits[k] = (scalar_le_bytes[byte_idx] >> bit_in_byte) & 1;
    }

    for row in 0..TOTAL_BITS {
        let row_off = row * NUM_COLS;
        put_point::<F>(&mut values, row_off + col::PRE_ACC, &acc);
        put_point::<F>(&mut values, row_off + col::BASE_POINT, base_point);

        // Shift register: at row `r`, position `k` holds bit `255 - r - k`
        // when that bit still exists, otherwise zero (the boundary doesn't
        // constrain past-tail cells, so any value is sound).
        for k in 0..SCALAR_BITS {
            let src = row + k;
            let val = if src < SCALAR_BITS { bits[src] } else { 0 };
            values[row_off + col::BITS_START + k] = F::from_u64(val as u64);
        }

        let bit = bits[row];
        values[row_off + col::SELECTOR] = F::from_u64(bit as u64);

        // DOUBLED = acc + acc, ADDED = DOUBLED + base.
        let doubled = point_add(&acc, &acc);
        put_point::<F>(&mut values, row_off + col::DOUBLED, &doubled);
        let added = point_add(&doubled, base_point);
        put_point::<F>(&mut values, row_off + col::ADDED, &added);

        // POST_ACC = bit ? added : doubled.
        let new_acc = if bit == 1 { added.clone() } else { doubled.clone() };
        put_point::<F>(&mut values, row_off + col::POST_ACC, &new_acc);

        // Populate the two embedded PointAddAirChip witnesses.
        point_add_air::populate_row::<F>(&mut values, row_off, col::DOUBLE_START, &acc, &acc);
        point_add_air::populate_row::<F>(&mut values, row_off, col::ADD_START, &doubled, base_point);

        acc = new_acc;
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

/// Compute the AIR-canonical output of `[scalar]·base` by running the
/// same fixed-position MSB-first iteration the chip uses internally.
///
/// This is **distinct** from the witness function `scalar_mul` in
/// `chips::ed25519::scalar_mul`, which short-circuits at the highest set
/// bit. Both produce equivalent group elements, but with different
/// projective coordinates `(X, Y, Z, T)`. The PV layout binds against the
/// AIR's projective representation specifically (POST_ACC at row 255),
/// so this helper is what the wrapper / aggregator must use.
pub fn derive_scalar_mul_air_output(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
) -> ExtendedPoint {
    use crate::chips::ed25519::point::point_add;
    let mut acc = ExtendedPoint::neutral();
    for row in 0..SCALAR_BITS {
        let i = 255 - row;
        let byte_idx = i / 8;
        let bit_in_byte = i % 8;
        let bit = (scalar_le_bytes[byte_idx] >> bit_in_byte) & 1;
        let doubled = point_add(&acc, &acc);
        let added = point_add(&doubled, base_point);
        acc = if bit == 1 { added } else { doubled };
    }
    acc
}

/// Build the public-values vector from `(scalar, base, output)`.
///
/// Layout (104 BabyBear elements):
///   [0..32]    scalar bytes (canonical LE)
///   [32..68]   base limbs (X || Y || Z || T)
///   [68..104]  output limbs (X || Y || Z || T)
pub fn build_public_values<F: Field + PrimeCharacteristicRing>(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
    output: &ExtendedPoint,
) -> Vec<F> {
    let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for &b in scalar_le_bytes { out.push(F::from_u64(b as u64)); }
    for &l in &base_point.x.limbs { out.push(F::from_u64(l)); }
    for &l in &base_point.y.limbs { out.push(F::from_u64(l)); }
    for &l in &base_point.z.limbs { out.push(F::from_u64(l)); }
    for &l in &base_point.t.limbs { out.push(F::from_u64(l)); }
    for &l in &output.x.limbs { out.push(F::from_u64(l)); }
    for &l in &output.y.limbs { out.push(F::from_u64(l)); }
    for &l in &output.z.limbs { out.push(F::from_u64(l)); }
    for &l in &output.t.limbs { out.push(F::from_u64(l)); }
    debug_assert_eq!(out.len(), NUM_PUBLIC_VALUES);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn basepoint() -> ExtendedPoint {
        use crate::chips::ed25519::decompress::decompress;
        let mut bp = [0x66u8; 32];
        bp[0] = 0x58;
        decompress(&bp).expect("basepoint must decompress")
    }

    fn run_check(scalar: &[u8; 32], base: &ExtendedPoint) {
        let trace = build_scalar_mul_trace::<BabyBear>(scalar, base);
        let output = derive_scalar_mul_air_output(scalar, base);
        let pv = build_public_values::<BabyBear>(scalar, base, &output);
        check_constraints(&ScalarMulAirChip, &trace, &pv);
    }

    #[test]
    fn scalar_mul_zero_yields_neutral() {
        run_check(&[0u8; 32], &basepoint());
    }

    #[test]
    fn scalar_mul_one_yields_base() {
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        run_check(&scalar, &basepoint());
    }

    #[test]
    fn scalar_mul_small_value() {
        let mut scalar = [0u8; 32];
        scalar[0] = 0x55; // 5 set bits
        run_check(&scalar, &basepoint());
    }

    #[test]
    fn shift_register_holds_for_random_scalar() {
        // Validates the bit shift register binds correctly to SELECTOR
        // for a non-trivial scalar (mix of 0s and 1s across all bytes).
        let mut scalar = [0u8; 32];
        for (i, b) in scalar.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        run_check(&scalar, &basepoint());
    }

    #[test]
    fn constraint_count_documented() {
        // 3.2-3.8 + 3.9: 18 MCF per row × +3144 = 56_592. 15787 + 56_592 = 72_379.
        // Sub-fase 5.6.b.1.b: + 256 BIT shift register cells = 72_635.
        assert_eq!(NUM_COLS, 72_635);
        // Sub-fase 5.6.b.1.c: 32 scalar bytes + 36 base limbs + 36 output limbs.
        assert_eq!(NUM_PUBLIC_VALUES, 104);
    }

    #[test]
    fn pv_byte_decomposition_matches_scalar_for_byte0() {
        // Sanity: for scalar = 1 (only bit 0 set), the byte-decomposition
        // boundary at row 0 should recover byte[0] = 1 from BIT[255] = 1.
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        let trace = build_scalar_mul_trace::<BabyBear>(&scalar, &basepoint());
        // BITS_START + 255 holds bit (255 - 255) = bit 0 = 1.
        let row0 = &trace.values[..NUM_COLS];
        assert_eq!(row0[col::BITS_START + 255], BabyBear::from_u64(1));
        // BIT[0..255] are 0 for scalar = 1.
        for k in 0..255 {
            assert_eq!(row0[col::BITS_START + k], BabyBear::ZERO);
        }
    }
}

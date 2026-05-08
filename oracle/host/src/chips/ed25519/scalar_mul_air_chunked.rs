//! `ed25519::scalar_mul_air_chunked` — chunked-sound scalar mul AIR
//! (Etapa 3.10.3).
//!
//! Drop-in chunked variant de `ScalarMulAirChip`. Substitui os 2× embeds
//! `PointAddAirChip` por `PointAddAirChunkedChip` (NUM_COLS ~99540 each).
//! Wire format invariance preservada: PRE_ACC/POST_ACC/DOUBLED/ADDED/
//! BASE_POINT/SELECTOR/BITS_START nos mesmos offsets, todas as
//! transitions e PV bindings idênticas.
//!
//! Layout per row: ~199198 cols (vs 8163 do ScalarMulAirChip não-chunked).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::point_add_air_chunked::{
    self, PointAddAirChunkedChip, NUM_COLS as PA_COLS,
};
use crate::chips::field25519::NUM_LIMBS;

const POINT_LIMBS: usize = 4 * NUM_LIMBS;

pub const SCALAR_BITS: usize = 256;

pub mod col {
    use super::*;
    pub const SELECTOR: usize = 0;
    pub const PRE_ACC: usize = 1;
    pub const POST_ACC: usize = PRE_ACC + POINT_LIMBS;
    pub const DOUBLED: usize = POST_ACC + POINT_LIMBS;
    pub const ADDED: usize = DOUBLED + POINT_LIMBS;
    pub const BASE_POINT: usize = ADDED + POINT_LIMBS;
    pub const DOUBLE_START: usize = BASE_POINT + POINT_LIMBS;
    pub const ADD_START: usize = DOUBLE_START + PA_COLS;
    pub const BITS_START: usize = ADD_START + PA_COLS;
    pub const TOTAL: usize = BITS_START + SCALAR_BITS;

    pub const X_OFF: usize = 0;
    pub const Y_OFF: usize = NUM_LIMBS;
    pub const Z_OFF: usize = 2 * NUM_LIMBS;
    pub const T_OFF: usize = 3 * NUM_LIMBS;
}

pub const NUM_COLS: usize = col::TOTAL;

pub const NUM_BOUNDARY_LIMBS: usize = 4 * NUM_LIMBS;
pub const NUM_PUBLIC_VALUES: usize = 32 + NUM_BOUNDARY_LIMBS + NUM_BOUNDARY_LIMBS;

#[derive(Debug, Clone, Copy)]
pub struct ScalarMulAirChunkedChip;

impl<F: Field> BaseAir<F> for ScalarMulAirChunkedChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..NUM_COLS).collect()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

fn neutral_limb_at(off_in_point: usize) -> u64 {
    let limb_in_field = off_in_point % NUM_LIMBS;
    let field_idx = off_in_point / NUM_LIMBS;
    match (field_idx, limb_in_field) {
        (1, 0) | (2, 0) => 1,
        _ => 0,
    }
}

impl<AB: AirBuilder> Air<AB> for ScalarMulAirChunkedChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        PointAddAirChunkedChip::at(col::DOUBLE_START).emit(builder);
        PointAddAirChunkedChip::at(col::ADD_START).emit(builder);

        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();

        builder.assert_bool(cur[col::SELECTOR]);

        let assert_chunks = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(cur[off_a + i], cur[off_b + i]);
            }
        };

        // DOUBLE: P1 = P2 = PRE_ACC; P3 = DOUBLED
        assert_chunks(builder, col::DOUBLE_START + point_add_air_chunked::col::P1, col::PRE_ACC, POINT_LIMBS);
        assert_chunks(builder, col::DOUBLE_START + point_add_air_chunked::col::P2, col::PRE_ACC, POINT_LIMBS);
        assert_chunks(builder, col::DOUBLE_START + point_add_air_chunked::col::P3, col::DOUBLED, POINT_LIMBS);

        // ADD: P1 = DOUBLED, P2 = BASE_POINT, P3 = ADDED
        assert_chunks(builder, col::ADD_START + point_add_air_chunked::col::P1, col::DOUBLED, POINT_LIMBS);
        assert_chunks(builder, col::ADD_START + point_add_air_chunked::col::P2, col::BASE_POINT, POINT_LIMBS);
        assert_chunks(builder, col::ADD_START + point_add_air_chunked::col::P3, col::ADDED, POINT_LIMBS);

        // POST_ACC = bit ? ADDED : DOUBLED
        for i in 0..POINT_LIMBS {
            let post = cur[col::POST_ACC + i];
            let doubled = cur[col::DOUBLED + i];
            let added = cur[col::ADDED + i];
            let bit = cur[col::SELECTOR];
            builder.assert_eq(post.into() - doubled.into(), bit.into() * (added.into() - doubled.into()));
        }

        // First-row boundary: PRE_ACC[0] = neutral.
        for i in 0..POINT_LIMBS {
            builder
                .when_first_row()
                .assert_eq(cur[col::PRE_ACC + i], AB::Expr::from_u64(neutral_limb_at(i)));
        }

        // Bit shift register binding.
        builder.assert_eq(cur[col::SELECTOR], cur[col::BITS_START]);
        for i in 0..SCALAR_BITS {
            builder.assert_bool(cur[col::BITS_START + i]);
        }
        for i in 0..SCALAR_BITS - 1 {
            builder
                .when_transition()
                .assert_eq(next[col::BITS_START + i], cur[col::BITS_START + i + 1]);
        }

        // Transitions: PRE_ACC and BASE_POINT propagate.
        for i in 0..POINT_LIMBS {
            builder.when_transition().assert_eq(next[col::PRE_ACC + i], cur[col::POST_ACC + i]);
            builder.when_transition().assert_eq(next[col::BASE_POINT + i], cur[col::BASE_POINT + i]);
        }

        // PV boundary binding.
        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };

        let pow2: [u64; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
        for j in 0..32 {
            let mut sum = AB::Expr::ZERO;
            for k in 0..8 {
                let bit_idx = 255 - (8 * j + k);
                let coeff = AB::Expr::from_u64(pow2[k]);
                sum = sum + cur[col::BITS_START + bit_idx].into() * coeff;
            }
            builder.when_first_row().assert_eq(sum, pub_copies[j].into());
        }

        for i in 0..POINT_LIMBS {
            builder
                .when_first_row()
                .assert_eq(cur[col::BASE_POINT + i], pub_copies[32 + i].into());
        }

        for i in 0..POINT_LIMBS {
            builder
                .when_last_row()
                .assert_eq(cur[col::POST_ACC + i], pub_copies[32 + POINT_LIMBS + i].into());
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

pub fn build_scalar_mul_trace_chunked<F: Field + PrimeCharacteristicRing>(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
) -> RowMajorMatrix<F> {
    use crate::chips::ed25519::point::point_add;

    const TOTAL_BITS: usize = 256;
    const HEIGHT: usize = TOTAL_BITS;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let mut acc = ExtendedPoint::neutral();

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

        for k in 0..SCALAR_BITS {
            let src = row + k;
            let val = if src < SCALAR_BITS { bits[src] } else { 0 };
            values[row_off + col::BITS_START + k] = F::from_u64(val as u64);
        }

        let bit = bits[row];
        values[row_off + col::SELECTOR] = F::from_u64(bit as u64);

        let doubled = point_add(&acc, &acc);
        put_point::<F>(&mut values, row_off + col::DOUBLED, &doubled);
        let added = point_add(&doubled, base_point);
        put_point::<F>(&mut values, row_off + col::ADDED, &added);

        let new_acc = if bit == 1 { added.clone() } else { doubled.clone() };
        put_point::<F>(&mut values, row_off + col::POST_ACC, &new_acc);

        // Embedded chunked PointAddAir witnesses.
        point_add_air_chunked::populate_row::<F>(&mut values, row_off, col::DOUBLE_START, &acc, &acc);
        point_add_air_chunked::populate_row::<F>(&mut values, row_off, col::ADD_START, &doubled, base_point);

        acc = new_acc;
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

pub fn build_public_values<F: Field + PrimeCharacteristicRing>(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
    output: &ExtendedPoint,
) -> Vec<F> {
    let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for &b in scalar_le_bytes {
        out.push(F::from_u64(b as u64));
    }
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
    use crate::chips::ed25519::scalar_mul_air::derive_scalar_mul_air_output;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn basepoint() -> ExtendedPoint {
        use crate::chips::ed25519::decompress::decompress;
        let mut bp = [0x66u8; 32];
        bp[0] = 0x58;
        decompress(&bp).expect("basepoint must decompress")
    }

    fn run_check(scalar: &[u8; 32], base: &ExtendedPoint) {
        let trace = build_scalar_mul_trace_chunked::<BabyBear>(scalar, base);
        let output = derive_scalar_mul_air_output(scalar, base);
        let pv = build_public_values::<BabyBear>(scalar, base, &output);
        check_constraints(&ScalarMulAirChunkedChip, &trace, &pv);
    }

    #[test]
    #[ignore = "slow (~30s release); 256 rows × 2 chunked PointAdd embeds per row"]
    fn scalar_mul_chunked_zero_yields_neutral() {
        run_check(&[0u8; 32], &basepoint());
    }

    #[test]
    #[ignore = "slow"]
    fn scalar_mul_chunked_one_yields_base() {
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        run_check(&scalar, &basepoint());
    }

    #[test]
    fn layout_documented() {
        assert_eq!(col::SELECTOR, 0);
        assert_eq!(col::PRE_ACC, 1);
        assert_eq!(col::POST_ACC, 37);
        assert_eq!(col::DOUBLE_START, 181);
        assert!(col::ADD_START > col::DOUBLE_START);
        assert!(col::BITS_START > col::ADD_START);
    }
}

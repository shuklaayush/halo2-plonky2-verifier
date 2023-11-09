use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use plonky2::field::extension::Extendable;

use crate::fields::fp::{Fp, FpChip};
use crate::fields::fp2::{Fp2, Fp2Chip};
use crate::fields::FieldChip;

use plonky2::hash::poseidon::{
    Poseidon, ALL_ROUND_CONSTANTS, HALF_N_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_ROUNDS, SPONGE_RATE,
    SPONGE_WIDTH,
};

#[derive(Debug, Clone)]
pub struct PoseidonChip<F: ScalarField, F64: Poseidon + Extendable<2>> {
    pub fp2_chip: Fp2Chip<F, F64>,
}

// TODO: Combine normal and _extension functions by abstracting away trait.
//       Maybe make generic over chip type?
//       Change back to Self::f(ctx, chip, state) instead of self.f(ctx, state)?
//       No magic numbers
//       Create separate hash element chip with a load_constant function (load_hash),
//       assert_equal for hash
impl<F: ScalarField, F64: Poseidon + Extendable<2>> PoseidonChip<F, F64> {
    // type Digest = Digest<F, 4>;

    // TODO: Do I need this function? Isn't it just the default constructor?
    pub fn new(fp2_chip: Fp2Chip<F, F64>) -> Self {
        Self { fp2_chip }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.fp2_chip.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.fp2_chip.range()
    }
    pub fn fp_chip(&self) -> &FpChip<F, F64> {
        &self.fp2_chip.fp_chip
    }

    pub fn fp2_chip(&self) -> &Fp2Chip<F, F64> {
        &self.fp2_chip
    }

    pub fn hash_no_pad(&self, ctx: &mut Context<F>, values: &[Fp<F, F64>]) -> [Fp<F, F64>; 4] {
        let chip = self.fp_chip();
        let mut state: [Fp<F, F64>; SPONGE_WIDTH] = (0..SPONGE_WIDTH)
            .map(|_| chip.load_constant(ctx, F64::ZERO)) // TODO: Load only required number of constants?
            .collect::<Vec<Fp<F, F64>>>()
            .try_into() // TODO: Remove try_into(), do at compile time
            .unwrap();

        // Absorb all input chunks.
        for input_chunk in values.chunks(SPONGE_RATE) {
            // Overwrite the first r elements with the inputs. This differs from a standard sponge,
            // where we would xor or add in the inputs. This is a well-known variant, though,
            // sometimes called "overwrite mode".
            state[..input_chunk.len()].clone_from_slice(input_chunk);
            self.permute(ctx, &mut state);
        }

        // Squeeze until we have the desired number of outputs.
        // TODO: Fix this
        [
            state[0].clone(),
            state[1].clone(),
            state[2].clone(),
            state[3].clone(),
        ]
    }

    // TODO: Dedup by reusing hash_no_pad
    pub fn two_to_one(
        &self,
        ctx: &mut Context<F>,
        left: &[Fp<F, F64>; 4],
        right: &[Fp<F, F64>; 4],
    ) -> [Fp<F, F64>; 4] {
        let chip = self.fp_chip();
        let mut state: [Fp<F, F64>; SPONGE_WIDTH] = (0..SPONGE_WIDTH)
            .map(|_| chip.load_constant(ctx, F64::ZERO))
            .collect::<Vec<Fp<F, F64>>>()
            .try_into() // TODO: Remove try_into(), do at compile time
            .unwrap();

        state[0..4].clone_from_slice(left);
        state[4..8].clone_from_slice(right);

        self.permute(ctx, &mut state);

        // TODO: Fix this
        [
            state[0].clone(),
            state[1].clone(),
            state[2].clone(),
            state[3].clone(),
        ]
    }

    fn full_rounds<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; SPONGE_WIDTH],
        round_ctr: &mut usize,
    ) {
        for _ in 0..HALF_N_FULL_ROUNDS {
            self.constant_layer(ctx, state, *round_ctr);
            self.sbox_layer(ctx, state);
            *state = self.mds_layer(ctx, state);
            *round_ctr += 1;
        }
    }

    fn partial_rounds<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; SPONGE_WIDTH],
        round_ctr: &mut usize,
    ) {
        let chip = self.fp_chip();

        self.partial_first_constant_layer(ctx, state);
        *state = self.mds_partial_layer_init(ctx, state);
        for i in 0..N_PARTIAL_ROUNDS {
            state[0] = self.sbox_monomial(ctx, state[0].clone());
            let c = chip.load_constant(
                ctx,
                F64::from_canonical_u64(F64::FAST_PARTIAL_ROUND_CONSTANTS[i]),
            );
            state[0] = chip.add(ctx, &state[0], &c);
            *state = self.mds_partial_layer_fast(ctx, state, i);
        }
        *round_ctr += N_PARTIAL_ROUNDS;
    }

    pub fn permute<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        input: &mut [Fp<F, F64>; SPONGE_WIDTH],
    ) {
        let mut state = input;
        let mut round_ctr = 0;

        self.full_rounds(ctx, &mut state, &mut round_ctr);
        self.partial_rounds(ctx, &mut state, &mut round_ctr);
        self.full_rounds(ctx, &mut state, &mut round_ctr);
        debug_assert_eq!(round_ctr, N_ROUNDS);
    }

    fn constant_layer<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; SPONGE_WIDTH],
        round_ctr: usize,
    ) {
        let chip = self.fp_chip();

        for i in 0..12 {
            let round_constant = chip.load_constant(
                ctx,
                F64::from_canonical_u64(ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * round_ctr]),
            );
            state[i] = chip.add(ctx, &state[i], &round_constant);
        }
    }

    fn constant_layer_extension<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; SPONGE_WIDTH],
        round_ctr: usize,
    ) {
        let chip = self.fp2_chip();

        for i in 0..12 {
            let round_constant = chip.load_constant(
                ctx,
                F64::from_canonical_u64(ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * round_ctr]).into(),
            );
            state[i] = chip.add(ctx, &state[i], &round_constant);
        }
    }

    fn sbox_monomial(&self, ctx: &mut Context<F>, x: Fp<F, F64>) -> Fp<F, F64> {
        let chip = self.fp_chip();

        let x2 = chip.mul(ctx, &x, &x);
        let x4 = chip.mul(ctx, &x2, &x2);
        let x6 = chip.mul(ctx, &x4, &x2);
        chip.mul(ctx, &x6, &x)
    }

    // TODO: Combine with above with proper trait abstractions
    fn sbox_monomial_extension(&self, ctx: &mut Context<F>, x: Fp2<F, F64>) -> Fp2<F, F64> {
        let chip = self.fp2_chip();

        let x2 = chip.mul(ctx, &x, &x);
        let x4 = chip.mul(ctx, &x2, &x2);
        let x6 = chip.mul(ctx, &x4, &x2);
        chip.mul(ctx, &x6, &x)
    }

    fn sbox_layer<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; SPONGE_WIDTH],
    ) {
        for i in 0..SPONGE_WIDTH {
            state[i] = self.sbox_monomial(ctx, state[i].clone());
        }
    }

    fn sbox_layer_extension<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; SPONGE_WIDTH],
    ) {
        for i in 0..SPONGE_WIDTH {
            state[i] = self.sbox_monomial_extension(ctx, state[i].clone());
        }
    }

    fn mds_row_shf<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        r: usize,
        v: &[Fp<F, F64>; SPONGE_WIDTH],
    ) -> Fp<F, F64> {
        let chip = self.fp_chip();
        let mut res = chip.load_constant(ctx, F64::ZERO);

        for i in 0..SPONGE_WIDTH {
            let c = chip.load_constant(ctx, F64::from_canonical_u64(F64::MDS_MATRIX_CIRC[i]));
            res = chip.mul_add(ctx, &c, &v[(i + r) % SPONGE_WIDTH], &res);
        }
        {
            let c = chip.load_constant(ctx, F64::from_canonical_u64(F64::MDS_MATRIX_DIAG[r]));
            res = chip.mul_add(ctx, &c, &v[r], &res);
        }

        res
    }

    fn mds_row_shf_extension<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        r: usize,
        v: &[Fp2<F, F64>; SPONGE_WIDTH],
    ) -> Fp2<F, F64> {
        let chip = self.fp2_chip();
        let mut res = chip.load_constant(ctx, F64::ZERO.into()); // TODO

        for i in 0..SPONGE_WIDTH {
            let c =
                chip.load_constant(ctx, F64::from_canonical_u64(F64::MDS_MATRIX_CIRC[i]).into());
            res = chip.mul_add(ctx, &c, &v[(i + r) % SPONGE_WIDTH], &res);
        }
        {
            let c =
                chip.load_constant(ctx, F64::from_canonical_u64(F64::MDS_MATRIX_DIAG[r]).into());
            res = chip.mul_add(ctx, &c, &v[r], &res);
        }

        res
    }

    fn mds_layer<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &[Fp<F, F64>; SPONGE_WIDTH],
    ) -> [Fp<F, F64>; SPONGE_WIDTH] {
        let mut result = vec![];
        for r in 0..SPONGE_WIDTH {
            let res = self.mds_row_shf(ctx, r, state);
            result.push(res);
        }

        result.try_into().unwrap()
    }

    fn mds_layer_extension<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &[Fp2<F, F64>; SPONGE_WIDTH],
    ) -> [Fp2<F, F64>; SPONGE_WIDTH] {
        let mut result = vec![];
        for r in 0..SPONGE_WIDTH {
            let res = self.mds_row_shf_extension(ctx, r, state);
            result.push(res);
        }

        result.try_into().unwrap()
    }

    fn partial_first_constant_layer<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; SPONGE_WIDTH],
    ) {
        let chip = self.fp_chip();

        for i in 0..SPONGE_WIDTH {
            let c = chip.load_constant(
                ctx,
                F64::from_canonical_u64(F64::FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]),
            );
            state[i] = chip.add(ctx, &state[i], &c);
        }
    }

    fn partial_first_constant_layer_extension<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; SPONGE_WIDTH],
    ) {
        let chip = self.fp2_chip();

        for i in 0..SPONGE_WIDTH {
            let c = chip.load_constant(
                ctx,
                F64::from_canonical_u64(F64::FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]).into(),
            );
            state[i] = chip.add(ctx, &state[i], &c);
        }
    }

    fn mds_partial_layer_init<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; SPONGE_WIDTH],
    ) -> [Fp<F, F64>; SPONGE_WIDTH] {
        let chip = self.fp_chip();

        let mut result = (0..SPONGE_WIDTH)
            .map(|_| chip.load_constant(ctx, F64::ZERO))
            .collect::<Vec<_>>();
        result[0] = state[0].clone();

        // TODO: Use inner product gate instead of nested for loop
        for r in 1..SPONGE_WIDTH {
            for c in 1..SPONGE_WIDTH {
                let t = chip.load_constant(
                    ctx,
                    F64::from_canonical_u64(F64::FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1]),
                );
                result[c] = chip.mul_add(ctx, &t, &state[r], &result[c]);
            }
        }
        result.try_into().unwrap()
    }

    fn mds_partial_layer_init_extension<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; SPONGE_WIDTH],
    ) -> [Fp2<F, F64>; SPONGE_WIDTH] {
        let chip = self.fp2_chip();

        let mut result = (0..SPONGE_WIDTH)
            .map(|_| chip.load_constant(ctx, F64::ZERO.into()))
            .collect::<Vec<_>>();
        result[0] = state[0].clone();

        // TODO: Use inner product gate instead of nested for loop
        for r in 1..SPONGE_WIDTH {
            for c in 1..SPONGE_WIDTH {
                let t = chip.load_constant(
                    ctx,
                    F64::from_canonical_u64(F64::FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1])
                        .into(),
                );
                result[c] = chip.mul_add(ctx, &t, &state[r], &result[c]);
            }
        }
        result.try_into().unwrap()
    }

    fn mds_partial_layer_fast<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; SPONGE_WIDTH],
        r: usize,
    ) -> [Fp<F, F64>; SPONGE_WIDTH] {
        let chip = self.fp_chip();

        let s0 = state[0].clone();
        let mds0to0 = chip.load_constant(
            ctx,
            F64::from_canonical_u64(F64::MDS_MATRIX_CIRC[0] + F64::MDS_MATRIX_DIAG[0]),
        );
        let mut d = chip.mul(ctx, &mds0to0, &s0);
        for i in 1..SPONGE_WIDTH {
            let t = chip.load_constant(
                ctx,
                F64::from_canonical_u64(F64::FAST_PARTIAL_ROUND_W_HATS[r][i - 1]),
            );
            d = chip.mul_add(ctx, &t, &state[i], &d);
        }

        let mut result = vec![];
        result.push(d);
        for i in 1..SPONGE_WIDTH {
            let t = chip.load_constant(
                ctx,
                F64::from_canonical_u64(F64::FAST_PARTIAL_ROUND_VS[r][i - 1]),
            );
            let res = chip.mul_add(ctx, &t, &state[0], &state[i]);
            result.push(res);
        }
        result.try_into().unwrap()
    }

    fn mds_partial_layer_fast_extension<const SPONGE_WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; SPONGE_WIDTH],
        r: usize,
    ) -> [Fp2<F, F64>; SPONGE_WIDTH] {
        let chip = self.fp2_chip();

        let s0 = state[0].clone();
        let mds0to0 = chip.load_constant(
            ctx,
            F64::from_canonical_u64(F64::MDS_MATRIX_CIRC[0] + F64::MDS_MATRIX_DIAG[0]).into(),
        );
        let mut d = chip.mul(ctx, &mds0to0, &s0);
        for i in 1..SPONGE_WIDTH {
            let t = chip.load_constant(
                ctx,
                F64::from_canonical_u64(F64::FAST_PARTIAL_ROUND_W_HATS[r][i - 1]).into(),
            );
            d = chip.mul_add(ctx, &t, &state[i], &d);
        }

        let mut result = vec![];
        result.push(d);
        for i in 1..SPONGE_WIDTH {
            let t = chip.load_constant(
                ctx,
                F64::from_canonical_u64(F64::FAST_PARTIAL_ROUND_VS[r][i - 1]).into(),
            );
            let res = chip.mul_add(ctx, &t, &state[0], &state[i]);
            result.push(res);
        }
        result.try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Sample};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_hash_no_pad() {
        let mut rng = StdRng::seed_from_u64(0);

        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = RangeCircuitBuilder::default().use_k(k as usize);
        builder.set_lookup_bits(lookup_bits);

        let fp_chip =
            FpChip::<Fr, GoldilocksField>::new(lookup_bits, builder.lookup_manager().clone());
        let fp2_chip = Fp2Chip::new(fp_chip);
        let poseidon_chip = PoseidonChip::new(fp2_chip);

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);

        for _ in 0..10 {
            let fp_chip = poseidon_chip.fp_chip();

            let preimage = GoldilocksField::sample(&mut rng);

            let hash = PoseidonHash::hash_no_pad(&[preimage]);
            let hash_wire1 = fp_chip.load_constants(ctx, &hash.elements);

            let preimage_wire = fp_chip.load_witness(ctx, preimage);
            let hash_wire2 = poseidon_chip.hash_no_pad(ctx, &[preimage_wire]);

            for i in 0..4 {
                fp_chip.assert_equal(ctx, &hash_wire1[i], &hash_wire2[i]);
            }
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn test_hash_two_to_one() {
        let mut rng = StdRng::seed_from_u64(0);

        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = RangeCircuitBuilder::default().use_k(k as usize);
        builder.set_lookup_bits(lookup_bits);

        let fp_chip =
            FpChip::<Fr, GoldilocksField>::new(lookup_bits, builder.lookup_manager().clone());
        let fp2_chip = Fp2Chip::new(fp_chip);
        let poseidon_chip = PoseidonChip::new(fp2_chip);

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);

        for _ in 0..10 {
            let fp_chip = poseidon_chip.fp_chip();

            let hash1 = PoseidonHash::hash_no_pad(&[GoldilocksField::sample(&mut rng)]);
            let hash2 = PoseidonHash::hash_no_pad(&[GoldilocksField::sample(&mut rng)]);

            let hash_res1 = PoseidonHash::two_to_one(hash1, hash2);
            let hash_res_wire1 = fp_chip.load_constants(ctx, &hash_res1.elements);

            let hash1_wire = fp_chip.load_constants(ctx, &hash1.elements);
            let hash2_wire = fp_chip.load_constants(ctx, &hash2.elements);

            let hash_res_wire2 = poseidon_chip.two_to_one(ctx, &hash1_wire, &hash2_wire);

            for i in 0..4 {
                fp_chip.assert_equal(ctx, &hash_res_wire1[i], &hash_res_wire2[i]);
            }
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }
}

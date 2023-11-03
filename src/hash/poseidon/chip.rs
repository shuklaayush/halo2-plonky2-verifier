use goldilocks::fp2::Extendable; // TODO: Move trait to root of goldilocks crate
use goldilocks::Field64;
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use std::marker::PhantomData;

use crate::fields::fp::{Fp, FpChip};
use crate::fields::fp2::{Fp2, Fp2Chip};

use super::{Poseidon, ALL_ROUND_CONSTANTS, HALF_N_FULL_ROUNDS, N_PARTIAL_ROUNDS};

#[derive(Debug, Clone)]
pub struct PoseidonChip<F: ScalarField, F64: Field64 + Extendable<2>> {
    pub fp2_chip: Fp2Chip<F, F64>,
    _marker: PhantomData<F>,
}

// TODO: Combine normal nd _extension functions by abstracting away trait.
//       Maybe make generic over chip type?
//       Change back to Self::f(ctx, chip, state) instead of self.f(ctx, state)?
impl<F: ScalarField, F64: Field64 + Extendable<2>> PoseidonChip<F, F64> {
    // type Digest = Digest<F, 4>;

    fn new(_ctx: &mut Context<F>, _flex_gate: &FlexGateConfig<F>) -> Self {
        Self {
            _marker: PhantomData::<F>,
        }
    }

    pub fn fp_chip(&self) -> &FpChip<F, F64> {
        &self.fp2_chip.fp_chip
    }

    pub fn fp2_chip(&self) -> &Fp2Chip<F, F64> {
        &self.fp2_chip
    }

    // fn hash_elements(
    //     &self,
    //     ctx: &mut Context<F>,
    //     main_chip: &FlexGateConfig<F>,
    //     values: &[AssignedValue<F>],
    // ) -> Result<Self::Digest, Error> {
    //     let mut state: [AssignedValue<F>; WIDTH] = main_chip
    //         .assign_region(ctx, (0..WIDTH).map(|_| Constant(F::ZERO)), vec![])
    //         .try_into()
    //         .unwrap();

    //     // Absorb all input chunks.
    //     for input_chunk in values.chunks(8) {
    //         // Overwrite the first r elements with the inputs. This differs from a standard sponge,
    //         // where we would xor or add in the inputs. This is a well-known variant, though,
    //         // sometimes called "overwrite mode".
    //         state[..input_chunk.len()].clone_from_slice(input_chunk);
    //         self.permute(ctx, main_chip, &mut state)?;
    //     }

    //     // Squeeze until we have the desired number of outputs.
    //     self.permute(ctx, main_chip, &mut state)?;
    //     Ok(Digest::new(state[..4].to_vec()))
    // }

    // fn hash_no_pad(input: &[F]) -> Self::Hash {
    //     hash_n_to_hash_no_pad::<F, Self::Permutation>(input)
    // }

    // fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
    //     compress::<F, Self::Permutation>(left, right)
    // }

    fn full_rounds<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; WIDTH],
        round_ctr: &mut usize,
    ) {
        for _ in 0..HALF_N_FULL_ROUNDS {
            self.constant_layer(ctx, state, *round_ctr);
            self.sbox_layer(ctx, state);
            *state = self.mds_layer(ctx, state);
            *round_ctr += 1;
        }
    }

    fn partial_rounds<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; WIDTH],
        round_ctr: &mut usize,
    ) {
        let chip = self.fp_chip();

        self.partial_first_constant_layer(ctx, state);
        *state = self.mds_partial_layer_init(ctx, state);
        for i in 0..N_PARTIAL_ROUNDS {
            state[0] = self.sbox_monomial(ctx, state[0].clone());
            let c = chip.load_constant(ctx, F64::from(Poseidon::FAST_PARTIAL_ROUND_CONSTANTS[i]));
            state[0] = chip.add(ctx, &state[0], &c);
            *state = self.mds_partial_layer_fast(ctx, state, i);
        }
        *round_ctr += N_PARTIAL_ROUNDS;
    }

    pub fn permute<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        input: [Fp<F, F64>; WIDTH],
    ) -> [Fp<F, F64>; WIDTH] {
        let mut state = input;
        let mut round_ctr = 0;

        self.full_rounds(ctx, &mut state, &mut round_ctr);
        self.partial_rounds(ctx, &mut state, &mut round_ctr);
        self.full_rounds(ctx, &mut state, &mut round_ctr);
        debug_assert_eq!(round_ctr, Poseidon::N_ROUNDS);

        state
    }

    fn constant_layer<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; WIDTH],
        round_ctr: usize,
    ) {
        let chip = self.fp_chip();

        for i in 0..12 {
            let round_constant =
                chip.load_constant(ctx, F64::from(ALL_ROUND_CONSTANTS[i + WIDTH * round_ctr]));
            state[i] = chip.add(ctx, &state[i], &round_constant);
        }
    }

    fn constant_layer_extension<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; WIDTH],
        round_ctr: usize,
    ) {
        let chip = self.fp2_chip();

        for i in 0..12 {
            let round_constant =
                chip.load_constant(ctx, ALL_ROUND_CONSTANTS[i + WIDTH * round_ctr]);
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

    fn sbox_layer<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; WIDTH],
    ) {
        for i in 0..WIDTH {
            state[i] = self.sbox_monomial(ctx, state[i].clone());
        }
    }

    fn sbox_layer_extension<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; WIDTH],
    ) {
        for i in 0..WIDTH {
            state[i] = self.sbox_monomial(ctx, state[i].clone());
        }
    }

    fn mds_row_shf<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        r: usize,
        v: &[Fp<F, F64>; WIDTH],
    ) -> Fp<F, F64> {
        let chip = self.fp_chip();
        let mut res = chip.load_constant(ctx, F64::ZERO);

        for i in 0..WIDTH {
            let c = chip.load_constant(ctx, F64::from(Poseidon::MDS_MATRIX_CIRC[i]));
            res = chip.mul_add(ctx, &c, &v[(i + r) % WIDTH], &res);
        }
        {
            let c = chip.load_constant(ctx, F64::from(Poseidon::MDS_MATRIX_DIAG[r]));
            res = chip.mul_add(ctx, &c, &v[r], &res);
        }

        res
    }

    fn mds_row_shf_extension<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        r: usize,
        v: &[Fp2<F, F64>; WIDTH],
    ) -> Fp2<F, F64> {
        let chip = self.fp2_chip();
        let mut res = chip.load_constant(ctx, F64::ZERO); // TODO

        for i in 0..WIDTH {
            let c = chip.load_constant(ctx, Poseidon::MDS_MATRIX_CIRC[i]);
            res = chip.mul_add(ctx, &c, &v[(i + r) % WIDTH], &res);
        }
        {
            let c = chip.load_constant(ctx, Poseidon::MDS_MATRIX_DIAG[r]);
            res = chip.mul_add(ctx, &c, &v[r], &res);
        }

        res
    }

    fn mds_layer<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &[Fp<F, F64>; WIDTH],
    ) -> [Fp<F, F64>; WIDTH] {
        let mut result = vec![];
        for r in 0..WIDTH {
            let res = self.mds_row_shf(ctx, r, state);
            result.push(res);
        }

        result.try_into().unwrap()
    }

    fn mds_layer_extension<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &[Fp2<F, F64>; WIDTH],
    ) -> [Fp2<F, F64>; WIDTH] {
        let mut result = vec![];
        for r in 0..WIDTH {
            let res = self.mds_row_shf_extension(ctx, r, state);
            result.push(res);
        }

        result.try_into().unwrap()
    }

    fn partial_first_constant_layer<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; WIDTH],
    ) {
        let chip = self.fp_chip();

        for i in 0..WIDTH {
            let c = chip.load_constant(
                ctx,
                F64::from(Poseidon::FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]),
            );
            state[i] = chip.add(ctx, &state[i], &c);
        }
    }

    fn partial_first_constant_layer_extension<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; WIDTH],
    ) {
        let chip = self.fp2_chip();

        for i in 0..WIDTH {
            let c = chip.load_constant(
                ctx,
                F64::from(Poseidon::FAST_PARTIAL_FIRST_ROUND_CONSTANT[i]),
            );
            state[i] = chip.add(ctx, &state[i], &c);
        }
    }

    fn mds_partial_layer_init<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; WIDTH],
    ) -> [Fp<F, F64>; WIDTH] {
        let chip = self.fp_chip();

        let mut result = (0..WIDTH)
            .map(|_| chip.load_constant(ctx, F64::ZERO))
            .collect::<Vec<_>>();
        result[0] = state[0].clone();

        // TODO: Use inner product gate instead of nested for loop
        for r in 1..WIDTH {
            for c in 1..WIDTH {
                let t = chip.load_constant(
                    ctx,
                    F64::from(Poseidon::FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1]),
                );
                result[c] = chip.mul_add(ctx, &t, &state[r], &result[c]);
            }
        }
        result
    }

    fn mds_partial_layer_init_extension<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; WIDTH],
    ) -> [Fp2<F, F64>; WIDTH] {
        let chip = self.fp2_chip();

        let mut result = (0..WIDTH)
            .map(|_| chip.load_constant(ctx, F64::ZERO))
            .collect::<Vec<_>>();
        result[0] = state[0].clone();

        // TODO: Use inner product gate instead of nested for loop
        for r in 1..WIDTH {
            for c in 1..WIDTH {
                let t = chip.load_constant(
                    ctx,
                    F64::from(Poseidon::FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1]),
                );
                result[c] = chip.mul_add(ctx, &t, &state[r], &result[c]);
            }
        }
        result
    }

    fn mds_partial_layer_fast<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp<F, F64>; WIDTH],
        r: usize,
    ) -> [Fp<F, F64>; WIDTH] {
        let chip = self.fp_chip();

        let s0 = state[0].clone();
        let mds0to0 = chip.load_constant(
            ctx,
            F64::from(Poseidon::MDS_MATRIX_CIRC[0] + Poseidon::MDS_MATRIX_DIAG[0]),
        );
        let mut d = chip.mul(ctx, &mds0to0, &s0);
        for i in 1..WIDTH {
            let t = chip.load_constant(
                ctx,
                F64::from(Poseidon::FAST_PARTIAL_ROUND_W_HATS[r][i - 1]),
            );
            d = chip.mul_add(ctx, &t, &state[i], &d);
        }

        let mut result = vec![];
        result.push(d);
        for i in 1..WIDTH {
            let t = chip.load_constant(ctx, F64::from(Poseidon::FAST_PARTIAL_ROUND_VS[r][i - 1]));
            let res = chip.mul_add(ctx, &t, &state[0], &state[i]);
            result.push(res);
        }
        result.try_into().unwrap()
    }

    fn mds_partial_layer_fast_extension<const WIDTH: usize>(
        &self,
        ctx: &mut Context<F>,
        state: &mut [Fp2<F, F64>; WIDTH],
        r: usize,
    ) -> [Fp2<F, F64>; WIDTH] {
        let chip = self.fp2_chip();

        let s0 = state[0].clone();
        let mds0to0 = chip.load_constant(
            ctx,
            F64::from(Poseidon::MDS_MATRIX_CIRC[0] + Poseidon::MDS_MATRIX_DIAG[0]),
        );
        let mut d = chip.mul(ctx, &mds0to0, &s0);
        for i in 1..WIDTH {
            let t = chip.load_constant(
                ctx,
                F64::from(Poseidon::FAST_PARTIAL_ROUND_W_HATS[r][i - 1]),
            );
            d = chip.mul_add(ctx, &t, &state[i], &d);
        }

        let mut result = vec![];
        result.push(d);
        for i in 1..WIDTH {
            let t = chip.load_constant(ctx, F64::from(Poseidon::FAST_PARTIAL_ROUND_VS[r][i - 1]));
            let res = chip.mul_add(ctx, &t, &state[0], &state[i]);
            result.push(res);
        }
        result.try_into().unwrap()
    }
}

use halo2_base::gates::RangeChip;
use halo2_base::utils::BigPrimeField;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::{
    Poseidon, ALL_ROUND_CONSTANTS, HALF_N_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_ROUNDS, SPONGE_RATE,
    SPONGE_WIDTH,
};

use verifier_macro::count;

use crate::goldilocks::base::{GoldilocksChip, GoldilocksWire};
use crate::hash::{PermutationChip, StateWire};
use crate::util::ContextWrapper;

#[derive(Copy, Clone, Debug)]
pub struct PoseidonStateWire<F: BigPrimeField>(pub [GoldilocksWire<F>; SPONGE_WIDTH]);

impl<F: BigPrimeField> From<[GoldilocksWire<F>; SPONGE_WIDTH]> for PoseidonStateWire<F> {
    fn from(state: [GoldilocksWire<F>; SPONGE_WIDTH]) -> Self {
        Self(state)
    }
}

impl<F: BigPrimeField> StateWire<F> for PoseidonStateWire<F> {
    type Item = GoldilocksWire<F>;
}

#[derive(Debug, Clone)]
pub struct PoseidonPermutationChip<F: BigPrimeField> {
    goldilocks_chip: GoldilocksChip<F>,
}

// TODO: Use custom poseidon gate and mds gate?
impl<F: BigPrimeField> PoseidonPermutationChip<F> {
    pub fn new(goldilocks_chip: GoldilocksChip<F>) -> Self {
        Self { goldilocks_chip }
    }

    pub fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        &self.goldilocks_chip
    }

    #[count]
    fn mds_row_shf(
        &self,
        ctx: &mut ContextWrapper<F>,
        r: usize,
        v: &[GoldilocksWire<F>; SPONGE_WIDTH],
    ) -> GoldilocksWire<F> {
        debug_assert!(r < SPONGE_WIDTH);

        let chip = self.goldilocks_chip();
        let mut res = chip.load_constant(ctx, GoldilocksField::ZERO);

        for i in 0..SPONGE_WIDTH {
            let c = chip.load_constant(
                ctx,
                GoldilocksField::from_canonical_u64(GoldilocksField::MDS_MATRIX_CIRC[i]),
            );
            // TODO: Replace with mul_const_add
            res = chip.mul_add(ctx, &c, &v[(i + r) % SPONGE_WIDTH], &res);
        }
        {
            let c = chip.load_constant(
                ctx,
                GoldilocksField::from_canonical_u64(GoldilocksField::MDS_MATRIX_DIAG[r]),
            );
            // TODO: Replace with mul_const_add
            res = chip.mul_add(ctx, &c, &v[r], &res);
        }

        res
    }

    // TODO: Why not mutate state?
    #[count]
    fn mds_layer(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &PoseidonStateWire<F>,
    ) -> PoseidonStateWire<F> {
        let chip = self.goldilocks_chip();

        // TODO: Ugly
        let mut result = chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]);
        for r in 0..SPONGE_WIDTH {
            result[r] = self.mds_row_shf(ctx, r, &state.0);
        }

        result.into()
    }

    #[count]
    fn partial_first_constant_layer(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &mut PoseidonStateWire<F>,
    ) {
        let chip = self.goldilocks_chip();

        for i in 0..SPONGE_WIDTH {
            let c = chip.load_constant(
                ctx,
                GoldilocksField::from_canonical_u64(
                    GoldilocksField::FAST_PARTIAL_FIRST_ROUND_CONSTANT[i],
                ),
            );
            state.0[i] = chip.add(ctx, &state.0[i], &c);
        }
    }

    #[count]
    fn mds_partial_layer_init(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &PoseidonStateWire<F>,
    ) -> PoseidonStateWire<F> {
        let chip = self.goldilocks_chip();

        let mut result = chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]);
        result[0] = state.0[0];

        // TODO: Can I use inner product gate instead of nested for loop?
        //       Reduce at end
        for r in 1..SPONGE_WIDTH {
            for c in 1..SPONGE_WIDTH {
                let t = chip.load_constant(
                    ctx,
                    GoldilocksField::from_canonical_u64(
                        GoldilocksField::FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1],
                    ),
                );
                result[c] = chip.mul_add(ctx, &t, &state.0[r], &result[c]);
            }
        }
        result.into()
    }

    #[count]
    fn mds_partial_layer_fast(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &PoseidonStateWire<F>,
        r: usize,
    ) -> PoseidonStateWire<F> {
        let chip = self.goldilocks_chip();

        let s0 = state.0[0];
        let mds0to0 = chip.load_constant(
            ctx,
            GoldilocksField::from_canonical_u64(
                GoldilocksField::MDS_MATRIX_CIRC[0] + GoldilocksField::MDS_MATRIX_DIAG[0],
            ),
        );
        let mut d = chip.mul(ctx, &mds0to0, &s0);
        for i in 1..SPONGE_WIDTH {
            let t = chip.load_constant(
                ctx,
                GoldilocksField::from_canonical_u64(
                    GoldilocksField::FAST_PARTIAL_ROUND_W_HATS[r][i - 1],
                ),
            );
            d = chip.mul_add(ctx, &t, &state.0[i], &d);
        }

        let mut result = chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]);
        result[0] = d;
        for i in 1..SPONGE_WIDTH {
            let t = chip.load_constant(
                ctx,
                GoldilocksField::from_canonical_u64(
                    GoldilocksField::FAST_PARTIAL_ROUND_VS[r][i - 1],
                ),
            );
            result[i] = chip.mul_add(ctx, &t, &state.0[0], &state.0[i]);
        }
        result.into()
    }

    #[count]
    fn constant_layer(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &mut PoseidonStateWire<F>,
        round_ctr: usize,
    ) {
        let chip = self.goldilocks_chip();

        for i in 0..SPONGE_WIDTH {
            let round_constant = chip.load_constant(
                ctx,
                GoldilocksField::from_canonical_u64(
                    ALL_ROUND_CONSTANTS[i + SPONGE_WIDTH * round_ctr],
                ),
            );
            state.0[i] = chip.add(ctx, &state.0[i], &round_constant);
        }
    }

    #[count]
    fn sbox_monomial(
        &self,
        ctx: &mut ContextWrapper<F>,
        x: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let chip = self.goldilocks_chip();

        let x2 = chip.mul(ctx, x, x);
        let x4 = chip.mul(ctx, &x2, &x2);
        let x6 = chip.mul(ctx, &x4, &x2);
        chip.mul(ctx, &x6, x)
    }

    #[count]
    fn sbox_layer(&self, ctx: &mut ContextWrapper<F>, state: &mut PoseidonStateWire<F>) {
        for i in 0..SPONGE_WIDTH {
            state.0[i] = self.sbox_monomial(ctx, &state.0[i]);
        }
    }

    #[count]
    fn partial_rounds(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &mut PoseidonStateWire<F>,
        round_ctr: &mut usize,
    ) {
        let chip = self.goldilocks_chip();

        self.partial_first_constant_layer(ctx, state);
        *state = self.mds_partial_layer_init(ctx, state);
        for r in 0..N_PARTIAL_ROUNDS {
            state.0[0] = self.sbox_monomial(ctx, &state.0[0]);
            let c = chip.load_constant(
                ctx,
                GoldilocksField::from_canonical_u64(
                    GoldilocksField::FAST_PARTIAL_ROUND_CONSTANTS[r],
                ),
            );
            state.0[0] = chip.add(ctx, &state.0[0], &c);
            *state = self.mds_partial_layer_fast(ctx, state, r);
        }
        *round_ctr += N_PARTIAL_ROUNDS;
    }

    #[count]
    fn full_rounds(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &mut PoseidonStateWire<F>,
        round_ctr: &mut usize,
    ) {
        for _ in 0..HALF_N_FULL_ROUNDS {
            self.constant_layer(ctx, state, *round_ctr);
            // TODO: Check if &mut state ensures that inputs and outputs are properly constrained
            self.sbox_layer(ctx, state);
            *state = self.mds_layer(ctx, state);
            *round_ctr += 1;
        }
    }
    // TODO: Add `poseidon` function?
}

impl<F: BigPrimeField> PermutationChip<F> for PoseidonPermutationChip<F> {
    type StateWire = PoseidonStateWire<F>;

    fn range(&self) -> &RangeChip<F> {
        self.goldilocks_chip.range()
    }

    fn load_zero(&self, ctx: &mut ContextWrapper<F>) -> PoseidonStateWire<F> {
        let chip = self.goldilocks_chip();
        chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH])
            .into()
    }

    fn permute(
        &self,
        ctx: &mut ContextWrapper<F>,
        state_in: &PoseidonStateWire<F>,
    ) -> PoseidonStateWire<F> {
        let mut round_ctr = 0;

        let mut state = *state_in;
        self.full_rounds(ctx, &mut state, &mut round_ctr);
        self.partial_rounds(ctx, &mut state, &mut round_ctr);
        self.full_rounds(ctx, &mut state, &mut round_ctr);
        debug_assert_eq!(round_ctr, N_ROUNDS);

        state
    }

    fn absorb_goldilocks(
        &self,
        ctx: &mut ContextWrapper<F>,
        state_in: &PoseidonStateWire<F>,
        input: &[GoldilocksWire<F>],
    ) -> PoseidonStateWire<F> {
        let mut state = *state_in;
        for input_chunk in input.chunks(SPONGE_RATE) {
            // Overwrite the first r elements with the inputs. This differs from a standard sponge,
            // where we would xor or add in the inputs. This is a well-known variant, though,
            // sometimes called "overwrite mode".
            state.0[..input_chunk.len()].copy_from_slice(input_chunk);
            state = self.permute(ctx, &state);
        }
        state
    }

    fn squeeze(&self, state: &PoseidonStateWire<F>) -> Vec<GoldilocksWire<F>> {
        state.0[..SPONGE_RATE].to_vec()
    }

    fn squeeze_goldilocks(
        &self,
        _ctx: &mut ContextWrapper<F>,
        state: &PoseidonStateWire<F>,
    ) -> Vec<GoldilocksWire<F>> {
        self.squeeze(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Sample};

    #[test]
    fn test_permute() {
        base_test().k(14).run(|ctx, range| {
            let mut ctx = ContextWrapper::new(ctx);
            let ctx = &mut ctx;

            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let permutation_chip = PoseidonPermutationChip::new(goldilocks_chip.clone()); // TODO: Remove clone, use reference

            for _ in 0..10 {
                let state_in = GoldilocksField::rand_array();
                let state_in_wire =
                    PoseidonStateWire(goldilocks_chip.load_constant_array(ctx, &state_in));

                let state_out = Poseidon::poseidon(state_in);
                let state_out_wire = permutation_chip.permute(ctx, &state_in_wire);

                for i in 0..SPONGE_WIDTH {
                    assert_eq!(state_out[i], state_out_wire.0[i].value());
                }
            }
        })
    }
}
use ff::PrimeField;
use halo2_base::gates::{GateChip, GateInstructions, RangeChip, RangeInstructions};
use halo2_base::utils::BigPrimeField;
use halo2_base::AssignedValue;
use itertools::Itertools;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2x::backend::wrapper::poseidon_bn128::{FULL_ROUNDS, PARTIAL_ROUNDS, RATE, WIDTH};
use plonky2x::backend::wrapper::poseidon_bn128_constants::{
    C_CONSTANTS, M_MATRIX, P_MATRIX, S_CONSTANTS,
};
use plonky2x::backend::wrapper::utils::Fr as Fr_plonky2x;

use verifier_macro::count;

use crate::goldilocks::base::GoldilocksWire;
use crate::hash::{PermutationChip, StateWire};
use crate::util::context_wrapper::ContextWrapper;

#[derive(Copy, Clone, Debug)]
pub struct PoseidonBN254StateWire<F: BigPrimeField>(pub [AssignedValue<F>; WIDTH]);

impl<F: BigPrimeField> StateWire<F> for PoseidonBN254StateWire<F> {
    type Item = AssignedValue<F>;
}

impl<F: BigPrimeField> From<[AssignedValue<F>; WIDTH]> for PoseidonBN254StateWire<F> {
    fn from(state: [AssignedValue<F>; WIDTH]) -> Self {
        Self(state)
    }
}

fn from_fr<F: BigPrimeField>(val: Fr_plonky2x) -> F {
    F::from_bytes_le(val.to_repr().as_ref())
}

#[derive(Debug, Clone)]
pub struct PoseidonBN254PermutationChip<F: BigPrimeField> {
    range: RangeChip<F>,
}

// TODO: Make this more elegant
impl<F: BigPrimeField> PoseidonBN254PermutationChip<F> {
    pub fn new(range: RangeChip<F>) -> Self {
        Self { range }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.range.gate()
    }

    #[count]
    fn exp5(&self, ctx: &mut ContextWrapper<F>, x: AssignedValue<F>) -> AssignedValue<F> {
        let gate = self.gate();

        let x2 = gate.mul(ctx.ctx, x, x);
        let x4 = gate.mul(ctx.ctx, x2, x2);
        gate.mul(ctx.ctx, x4, x)
    }

    #[count]
    fn exp5_state(&self, ctx: &mut ContextWrapper<F>, state: &mut PoseidonBN254StateWire<F>) {
        for i in 0..WIDTH {
            state.0[i] = self.exp5(ctx, state.0[i]);
        }
    }

    #[count]
    fn mix(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &mut PoseidonBN254StateWire<F>,
        constant_matrix: &[Vec<AssignedValue<F>>],
    ) {
        let gate = self.gate();

        let mut new_state = [ctx.ctx.load_zero(); WIDTH];
        // TODO: Use inner product gate
        for i in 0..WIDTH {
            for j in 0..WIDTH {
                new_state[i] =
                    gate.mul_add(ctx.ctx, constant_matrix[j][i], state.0[j], new_state[i]);
            }
        }
        state.0 = new_state;
    }

    #[count]
    fn partial_rounds(&self, ctx: &mut ContextWrapper<F>, state: &mut PoseidonBN254StateWire<F>) {
        let gate = self.gate();
        for i in 0..PARTIAL_ROUNDS {
            state.0[0] = self.exp5(ctx, state.0[0]);
            let c = ctx
                .ctx
                .load_constant(from_fr(C_CONSTANTS[(FULL_ROUNDS / 2 + 1) * WIDTH + i]));
            state.0[0] = gate.add(ctx.ctx, state.0[0], c);

            let mut new_state0 = ctx.ctx.load_zero();
            for j in 0..WIDTH {
                let c = ctx
                    .ctx
                    .load_constant(from_fr(S_CONSTANTS[(WIDTH * 2 - 1) * i + j]));
                new_state0 = gate.mul_add(ctx.ctx, c, state.0[j], new_state0);
            }

            for k in 1..WIDTH {
                let c = ctx
                    .ctx
                    .load_constant(from_fr(S_CONSTANTS[(WIDTH * 2 - 1) * i + WIDTH + k - 1]));
                state.0[k] = gate.mul_add(ctx.ctx, c, state.0[0], state.0[k]);
            }

            state.0[0] = new_state0;
        }
    }

    #[count]
    fn full_rounds(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &mut PoseidonBN254StateWire<F>,
        is_first: bool,
    ) {
        // TODO: Ugly, cache this somewhere
        let m_matrix = M_MATRIX
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&x| ctx.ctx.load_constant(from_fr(x)))
                    .collect_vec()
            })
            .collect_vec();
        let p_matrix = P_MATRIX
            .iter()
            .map(|row| {
                row.iter()
                    .map(|&x| ctx.ctx.load_constant(from_fr(x)))
                    .collect_vec()
            })
            .collect_vec();

        for i in 0..(FULL_ROUNDS / 2 - 1) {
            self.exp5_state(ctx, state);

            if is_first {
                self.ark(ctx, state, (i + 1) * WIDTH);
            } else {
                self.ark(
                    ctx,
                    state,
                    (FULL_ROUNDS / 2 + 1) * WIDTH + PARTIAL_ROUNDS + i * WIDTH,
                );
            }
            self.mix(ctx, state, m_matrix.as_slice());
        }

        self.exp5_state(ctx, state);
        if is_first {
            self.ark(ctx, state, (FULL_ROUNDS / 2) * WIDTH);
            self.mix(ctx, state, p_matrix.as_slice());
        } else {
            self.mix(ctx, state, m_matrix.as_slice());
        }
    }

    #[count]
    fn ark(&self, ctx: &mut ContextWrapper<F>, state: &mut PoseidonBN254StateWire<F>, it: usize) {
        let gate = self.gate();

        for i in 0..WIDTH {
            let c = ctx.ctx.load_constant(from_fr(C_CONSTANTS[it + i]));
            state.0[i] = gate.add(ctx.ctx, state.0[i], c);
        }
    }
}

impl<F: BigPrimeField> PermutationChip<F> for PoseidonBN254PermutationChip<F> {
    type StateWire = PoseidonBN254StateWire<F>;

    fn range(&self) -> &RangeChip<F> {
        &self.range
    }

    fn load_zero(&self, ctx: &mut ContextWrapper<F>) -> PoseidonBN254StateWire<F> {
        PoseidonBN254StateWire(
            ctx.ctx
                .load_constants(&[F::ZERO; WIDTH])
                .try_into()
                .unwrap(),
        )
    }

    fn permute(
        &self,
        ctx: &mut ContextWrapper<F>,
        state_in: &PoseidonBN254StateWire<F>,
    ) -> PoseidonBN254StateWire<F> {
        let mut state = *state_in;

        self.ark(ctx, &mut state, 0);
        self.full_rounds(ctx, &mut state, true);
        self.partial_rounds(ctx, &mut state);
        self.full_rounds(ctx, &mut state, false);

        state
    }

    fn absorb_goldilocks(
        &self,
        ctx: &mut ContextWrapper<F>,
        state_in: &PoseidonBN254StateWire<F>,
        input: &[GoldilocksWire<F>],
    ) -> PoseidonBN254StateWire<F> {
        let range = self.range();

        let mut state = *state_in;
        // TODO: No hardcode
        for rate_chunk in input.chunks(RATE * 3) {
            for (j, bn254chunk) in rate_chunk.chunks(3).enumerate() {
                // TODO: Does this mean state[0] is always 0? Why?
                state.0[j + 1] = range.limbs_to_num(
                    ctx.ctx,
                    bn254chunk.iter().map(|x| x.0).collect_vec().as_slice(),
                    GoldilocksField::BITS,
                );
            }
            state = self.permute(ctx, &state);
        }

        state
    }

    fn squeeze(&self, state: &PoseidonBN254StateWire<F>) -> Vec<AssignedValue<F>> {
        state.0[..RATE].to_vec()
    }

    fn squeeze_goldilocks(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &PoseidonBN254StateWire<F>,
    ) -> Vec<GoldilocksWire<F>> {
        let range = self.range();

        self.squeeze(state)
            .iter()
            .flat_map(|&x| {
                range
                    // TODO: No hardcode
                    .decompose_le(ctx.ctx, x, 56, 5)
                    .iter()
                    .map(|&x| GoldilocksWire(x))
                    .collect_vec()
            })
            .collect_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use itertools::Itertools;
    // TODO: typo
    use plonky2x::backend::wrapper::poseidon_bn128::permution;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_permute() {
        let mut rng = StdRng::seed_from_u64(0u64);

        base_test().k(14).run(|ctx, range| {
            let mut ctx = ContextWrapper::new(ctx);
            let ctx = &mut ctx;

            let permutation_chip = PoseidonBN254PermutationChip::new(range.clone()); // TODO: Remove clone, use reference

            for _ in 0..10 {
                let mut state: [Fr_plonky2x; WIDTH] = (0..WIDTH)
                    .map(|_| Fr_plonky2x::random(&mut rng))
                    .collect_vec()
                    .try_into()
                    .unwrap();

                let state_in_wire = PoseidonBN254StateWire(
                    ctx.ctx
                        .load_constants(&state.iter().map(|&x| from_fr(x)).collect_vec())
                        .try_into()
                        .unwrap(),
                );

                permution(&mut state);
                let state_out_wire = permutation_chip.permute(ctx, &state_in_wire);

                for i in 0..WIDTH {
                    assert_eq!(from_fr::<Fr>(state[i]), *state_out_wire.0[i].value());
                }
            }
        })
    }
}

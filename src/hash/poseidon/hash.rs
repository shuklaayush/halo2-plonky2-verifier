use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;
use plonky2::hash::poseidon::{SPONGE_RATE, SPONGE_WIDTH};

use super::permutation::{PoseidonPermutationChip, PoseidonStateWire};
use crate::goldilocks::field::{GoldilocksChip, GoldilocksWire};
use crate::hash::HashOutWire;

pub struct PoseidonChip<F: ScalarField> {
    pub permutation_chip: PoseidonPermutationChip<F>,
}

// TODO: Maybe make generic over chip type?
//       Change back to Self::f(ctx, chip, state) instead of self.f(ctx, state)?
//       assert_equal for hash
//       Generic HasherChip trait?
impl<F: ScalarField> PoseidonChip<F> {
    pub fn new(goldilocks_chip: GoldilocksChip<F>) -> Self {
        let permutation_chip = PoseidonPermutationChip::new(goldilocks_chip);
        Self { permutation_chip }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.goldilocks_chip().gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.goldilocks_chip().range()
    }
    pub fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        self.permutation_chip().goldilocks_chip()
    }

    pub fn permutation_chip(&self) -> &PoseidonPermutationChip<F> {
        &self.permutation_chip
    }

    pub fn hash_or_noop(
        &self,
        ctx: &mut Context<F>,
        inputs: &[GoldilocksWire<F>],
    ) -> HashOutWire<F> {
        let chip = self.goldilocks_chip();

        let zero = chip.load_zero(ctx);
        if inputs.len() <= NUM_HASH_OUT_ELTS {
            HashOutWire::from_partial(&inputs, zero)
        } else {
            self.hash_no_pad(ctx, &inputs)
        }
    }

    pub fn hash_no_pad(
        &self,
        ctx: &mut Context<F>,
        values: &[GoldilocksWire<F>],
    ) -> HashOutWire<F> {
        let gl_chip = self.goldilocks_chip();
        let permutation_chip = self.permutation_chip();

        let mut state = PoseidonStateWire(
            gl_chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]),
        );

        // Absorb all input chunks.
        for input_chunk in values.chunks(SPONGE_RATE) {
            // Overwrite the first r elements with the inputs. This differs from a standard sponge,
            // where we would xor or add in the inputs. This is a well-known variant, though,
            // sometimes called "overwrite mode".
            state.0[..input_chunk.len()].copy_from_slice(input_chunk);
            state = permutation_chip.permute(ctx, &state);
        }

        // Squeeze until we have the desired number of outputs.
        // TODO: Fix
        HashOutWire(state.0[..4].try_into().unwrap())
    }

    // TODO: Dedup by reusing hash_no_pad
    pub fn two_to_one(
        &self,
        ctx: &mut Context<F>,
        left: &HashOutWire<F>,
        right: &HashOutWire<F>,
    ) -> HashOutWire<F> {
        let gl_chip = self.goldilocks_chip();
        let permutation_chip = self.permutation_chip();

        let mut state = PoseidonStateWire(
            gl_chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]),
        );

        state.0[0..4].copy_from_slice(left.0.as_slice());
        state.0[4..8].copy_from_slice(right.0.as_slice());

        state = permutation_chip.permute(ctx, &state);

        // TODO: Fix
        HashOutWire(state.0[..4].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
    use halo2_base::halo2_proofs::dev::MockProver;
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

        let mut builder = BaseCircuitBuilder::default().use_k(k as usize);
        builder.set_lookup_bits(lookup_bits);

        let goldilocks_chip =
            GoldilocksChip::<Fr>::new(lookup_bits, builder.lookup_manager().clone());
        let poseidon_chip = PoseidonChip::new(goldilocks_chip);

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);

        for _ in 0..10 {
            let goldilocks_chip = poseidon_chip.goldilocks_chip();

            let preimage = GoldilocksField::sample(&mut rng);

            let hash = PoseidonHash::hash_no_pad(&[preimage]);
            let hash_wire1 = goldilocks_chip.load_constant_array(ctx, &hash.elements);

            let preimage_wire = goldilocks_chip.load_witness(ctx, preimage);
            let hash_wire2 = poseidon_chip.hash_no_pad(ctx, &[preimage_wire]);

            for i in 0..NUM_HASH_OUT_ELTS {
                goldilocks_chip.assert_equal(ctx, &hash_wire1[i], &hash_wire2.0[i]);
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

        let mut builder = BaseCircuitBuilder::default().use_k(k as usize);
        builder.set_lookup_bits(lookup_bits);

        let goldilocks_chip =
            GoldilocksChip::<Fr>::new(lookup_bits, builder.lookup_manager().clone());
        let poseidon_chip = PoseidonChip::new(goldilocks_chip);

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);

        for _ in 0..10 {
            let goldilocks_chip = poseidon_chip.goldilocks_chip();

            let hash1 = PoseidonHash::hash_no_pad(&[GoldilocksField::sample(&mut rng)]);
            let hash2 = PoseidonHash::hash_no_pad(&[GoldilocksField::sample(&mut rng)]);

            let hash_res1 = PoseidonHash::two_to_one(hash1, hash2);
            let hash_res_wire1 = goldilocks_chip.load_constant_array(ctx, &hash_res1.elements);

            let hash1_wire = HashOutWire(goldilocks_chip.load_constant_array(ctx, &hash1.elements));
            let hash2_wire = HashOutWire(goldilocks_chip.load_constant_array(ctx, &hash2.elements));

            let hash_res_wire2 = poseidon_chip.two_to_one(ctx, &hash1_wire, &hash2_wire);

            for i in 0..NUM_HASH_OUT_ELTS {
                goldilocks_chip.assert_equal(ctx, &hash_res_wire1[i], &hash_res_wire2.0[i]);
            }
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }
}
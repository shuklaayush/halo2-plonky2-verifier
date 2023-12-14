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

#[derive(Debug, Clone)]
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
            HashOutWire::from_partial(inputs, zero)
        } else {
            self.hash_no_pad(ctx, inputs)
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
        HashOutWire {
            elements: state.squeeze()[..NUM_HASH_OUT_ELTS].try_into().unwrap(),
        }
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

        state.0[0..NUM_HASH_OUT_ELTS].copy_from_slice(left.elements.as_slice());
        state.0[NUM_HASH_OUT_ELTS..2 * NUM_HASH_OUT_ELTS]
            .copy_from_slice(right.elements.as_slice());

        state = permutation_chip.permute(ctx, &state);

        // TODO: Fix
        HashOutWire {
            elements: state.squeeze()[..NUM_HASH_OUT_ELTS].try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Sample};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    #[test]
    fn test_hash_no_pad() {
        base_test().k(14).run(|ctx, range| {
            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone()); // TODO: Remove clone, store reference

            // for _ in 0..10 {
            let goldilocks_chip = poseidon_chip.goldilocks_chip();

            let preimage = GoldilocksField::rand();
            let preimage_wire = goldilocks_chip.load_witness(ctx, preimage);

            let hash = PoseidonHash::hash_no_pad(&[preimage]);
            let hash_wire = poseidon_chip.hash_no_pad(ctx, &[preimage_wire]);

            for i in 0..NUM_HASH_OUT_ELTS {
                assert_eq!(hash.elements[i], hash_wire.elements[i].value());
            }
            // }
        })
    }

    #[test]
    fn test_hash_two_to_one() {
        base_test().k(14).run(|ctx, range| {
            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone()); // TODO: Remove clone, store reference

            for _ in 0..10 {
                let hash1 = PoseidonHash::hash_no_pad(&[GoldilocksField::rand()]);
                let hash1_wire = HashOutWire {
                    elements: goldilocks_chip.load_constant_array(ctx, &hash1.elements),
                };

                let hash2 = PoseidonHash::hash_no_pad(&[GoldilocksField::rand()]);
                let hash2_wire = HashOutWire {
                    elements: goldilocks_chip.load_constant_array(ctx, &hash2.elements),
                };

                let hash_res = PoseidonHash::two_to_one(hash1, hash2);
                let hash_res_wire = poseidon_chip.two_to_one(ctx, &hash1_wire, &hash2_wire);

                for i in 0..NUM_HASH_OUT_ELTS {
                    assert_eq!(hash_res.elements[i], hash_res_wire.elements[i].value());
                }
            }
        })
    }
}

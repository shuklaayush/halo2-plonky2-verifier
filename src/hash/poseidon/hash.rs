use halo2_base::gates::RangeChip;
use halo2_base::utils::BigPrimeField;
use itertools::Itertools;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS};
use plonky2::hash::poseidon::{PoseidonHash, SPONGE_WIDTH};

use super::permutation::{PoseidonPermutationChip, PoseidonStateWire};
use crate::count;
use crate::goldilocks::base::{GoldilocksChip, GoldilocksWire};
use crate::goldilocks::BoolWire;
use crate::hash::{HashWire, HasherChip, PermutationChip};
use crate::util::ContextWrapper;

/// Represents a ~256 bit hash output.
#[derive(Copy, Clone, Debug)]
pub struct PoseidonHashWire<F: BigPrimeField> {
    pub elements: [GoldilocksWire<F>; NUM_HASH_OUT_ELTS],
}

impl<F: BigPrimeField> HashWire<F> for PoseidonHashWire<F> {
    fn to_goldilocks_vec(
        &self,
        _ctx: &mut ContextWrapper<F>,
        _range: &RangeChip<F>,
    ) -> Vec<GoldilocksWire<F>> {
        self.elements.to_vec()
    }
}

impl<F: BigPrimeField> From<[GoldilocksWire<F>; NUM_HASH_OUT_ELTS]> for PoseidonHashWire<F> {
    fn from(elements: [GoldilocksWire<F>; NUM_HASH_OUT_ELTS]) -> Self {
        Self { elements }
    }
}

// impl<F: BigPrimeField> TryFrom<&[GoldilocksWire<F>]> for PoseidonHashWire<F> {
//     type Error = anyhow::Error;

//     fn try_from(elements: &[GoldilocksWire<F>]) -> Result<Self, Self::Error> {
//         ensure!(elements.len() == NUM_HASH_OUT_ELTS);
//         Ok(Self(elements.try_into().unwrap()))
//     }
// }

#[derive(Debug, Clone)]
pub struct PoseidonChip<F: BigPrimeField> {
    pub permutation_chip: PoseidonPermutationChip<F>,
}

// TODO: Maybe make generic over chip type?
//       Change back to Self::f(ctx, chip, state) instead of self.f(ctx, state)?
//       assert_equal for hash
//       Generic HasherChip trait?
impl<F: BigPrimeField> PoseidonChip<F> {
    pub fn new(goldilocks_chip: GoldilocksChip<F>) -> Self {
        let permutation_chip = PoseidonPermutationChip::new(goldilocks_chip);
        Self { permutation_chip }
    }

    fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        self.permutation_chip().goldilocks_chip()
    }
}

impl<F: BigPrimeField> HasherChip<F> for PoseidonChip<F> {
    const MAX_GOLDILOCKS: usize = NUM_HASH_OUT_ELTS;

    type Hasher = PoseidonHash;
    type HashWire = PoseidonHashWire<F>;
    type PermutationChip = PoseidonPermutationChip<F>;

    fn permutation_chip(&self) -> &PoseidonPermutationChip<F> {
        &self.permutation_chip
    }

    fn load_constant(
        &self,
        ctx: &mut ContextWrapper<F>,
        h: HashOut<GoldilocksField>,
    ) -> PoseidonHashWire<F> {
        let goldilocks_chip = self.goldilocks_chip();
        PoseidonHashWire {
            elements: h
                .elements
                .iter()
                .map(|&x| goldilocks_chip.load_constant(ctx, x))
                .collect_vec()
                .try_into()
                .unwrap(),
        }
    }

    fn load_goldilocks_slice(
        &self,
        ctx: &mut ContextWrapper<F>,
        elements_in: &[GoldilocksWire<F>],
    ) -> PoseidonHashWire<F> {
        debug_assert!(elements_in.len() <= NUM_HASH_OUT_ELTS);
        let goldilocks_chip = self.goldilocks_chip();
        let mut elements =
            goldilocks_chip.load_constant_array(ctx, &[GoldilocksField::ZERO; NUM_HASH_OUT_ELTS]);
        elements[0..elements_in.len()].copy_from_slice(elements_in);
        PoseidonHashWire {
            elements: elements.into(),
        }
    }

    fn select(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &PoseidonHashWire<F>,
        b: &PoseidonHashWire<F>,
        sel: &BoolWire<F>,
    ) -> PoseidonHashWire<F> {
        let goldilocks_chip = self.goldilocks_chip();
        PoseidonHashWire {
            elements: goldilocks_chip.select_array(ctx, a.elements, b.elements, sel),
        }
    }

    fn select_from_idx(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &[PoseidonHashWire<F>],
        idx: &GoldilocksWire<F>,
    ) -> PoseidonHashWire<F> {
        let goldilocks_chip = self.goldilocks_chip();
        PoseidonHashWire {
            elements: goldilocks_chip.select_array_from_idx(
                ctx,
                a.iter()
                    .map(|hash| hash.elements)
                    .collect::<Vec<_>>()
                    .as_slice(),
                idx,
            ),
        }
    }

    fn assert_equal(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &PoseidonHashWire<F>,
        b: &PoseidonHashWire<F>,
    ) {
        let goldilocks_chip = self.goldilocks_chip();
        for i in 0..NUM_HASH_OUT_ELTS {
            goldilocks_chip.assert_equal(ctx, &a.elements[i], &b.elements[i])
        }
    }

    fn hash_no_pad(
        &self,
        ctx: &mut ContextWrapper<F>,
        values: &[GoldilocksWire<F>],
    ) -> PoseidonHashWire<F> {
        let goldilocks_chip = self.goldilocks_chip();
        let permutation_chip = self.permutation_chip();

        let mut state = PoseidonStateWire(
            goldilocks_chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]),
        );

        // Absorb all input chunks.
        state = permutation_chip.absorb_goldilocks(ctx, &state, values);

        // Squeeze until we have the desired number of outputs.
        // TODO: Fix
        PoseidonHashWire {
            elements: permutation_chip.squeeze(&state)[..NUM_HASH_OUT_ELTS]
                .try_into()
                .unwrap(),
        }
    }

    // TODO: Dedup by reusing hash_no_pad
    fn two_to_one(
        &self,
        ctx: &mut ContextWrapper<F>,
        left: &PoseidonHashWire<F>,
        right: &PoseidonHashWire<F>,
    ) -> PoseidonHashWire<F> {
        let goldilocks_chip = self.goldilocks_chip();
        let permutation_chip = self.permutation_chip();

        // TODO: Remove extra cell assignments
        let mut state = PoseidonStateWire(
            goldilocks_chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]),
        );

        state.0[0..NUM_HASH_OUT_ELTS].copy_from_slice(left.elements.as_slice());
        state.0[NUM_HASH_OUT_ELTS..2 * NUM_HASH_OUT_ELTS]
            .copy_from_slice(right.elements.as_slice());

        state = count!(ctx, "permute", permutation_chip.permute(ctx, &state));

        // TODO: Fix
        PoseidonHashWire {
            elements: permutation_chip.squeeze(&state)[..NUM_HASH_OUT_ELTS]
                .try_into()
                .unwrap(),
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
            let mut ctx = ContextWrapper::new(ctx);
            let ctx = &mut ctx;

            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone()); // TODO: Remove clone, store reference

            for _ in 0..10 {
                let preimage = GoldilocksField::rand();
                let preimage_wire = goldilocks_chip.load_witness(ctx, preimage);

                let hash = PoseidonHash::hash_no_pad(&[preimage]);
                let hash_wire = poseidon_chip.hash_no_pad(ctx, &[preimage_wire]);

                for i in 0..NUM_HASH_OUT_ELTS {
                    assert_eq!(hash.elements[i], hash_wire.elements[i].value());
                }
            }
        })
    }

    #[test]
    fn test_hash_two_to_one() {
        base_test().k(14).run(|ctx, range| {
            let mut ctx = ContextWrapper::new(ctx);
            let ctx = &mut ctx;

            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone()); // TODO: Remove clone, store reference

            for _ in 0..10 {
                let hash1 = PoseidonHash::hash_no_pad(&[GoldilocksField::rand()]);
                let hash1_wire = PoseidonHashWire {
                    elements: goldilocks_chip.load_constant_array(ctx, &hash1.elements),
                };

                let hash2 = PoseidonHash::hash_no_pad(&[GoldilocksField::rand()]);
                let hash2_wire = PoseidonHashWire {
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

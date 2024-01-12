use halo2_base::utils::BigPrimeField;
use halo2_base::AssignedValue;
use itertools::Itertools;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::config::GenericHashOut;
use plonky2x::backend::wrapper::plonky2_config::{PoseidonBN128Hash, PoseidonBN128HashOut};
use plonky2x::backend::wrapper::poseidon_bn128::WIDTH;

use verifier_macro::count;

use super::permutation::{PoseidonBN254PermutationChip, PoseidonBN254StateWire};
use crate::field::bool::BoolWire;
use crate::field::goldilocks::base::GoldilocksWire;
use crate::field::native::NativeChip;
use crate::hash::{HashWire, HasherChip, PermutationChip};
use crate::util::context_wrapper::ContextWrapper;

fn hash_to_fr<F: BigPrimeField>(hash: PoseidonBN128HashOut<GoldilocksField>) -> F {
    F::from_bytes_le(hash.to_bytes().as_slice())
}

/// Represents a ~256 bit hash output.
#[derive(Copy, Clone, Debug)]
pub struct PoseidonBN254HashWire<F: BigPrimeField> {
    pub value: AssignedValue<F>,
}

impl<F: BigPrimeField> HashWire<F> for PoseidonBN254HashWire<F> {
    #[count]
    fn to_goldilocks_vec(
        &self,
        ctx: &mut ContextWrapper<F>,
        native: &NativeChip<F>,
    ) -> Vec<GoldilocksWire<F>> {
        // TODO: Move to helper
        native
            // TODO: No hardcode
            .decompose_le(ctx, self.value, 56, 5)
            .iter()
            .map(|&x| GoldilocksWire(x))
            .collect_vec()
    }
}

#[derive(Debug, Clone)]
pub struct PoseidonBN254Chip<F: BigPrimeField> {
    pub permutation_chip: PoseidonBN254PermutationChip<F>,
}

// TODO: Maybe make generic over chip type?
//       Change back to Self::f(ctx, chip, state) instead of self.f(ctx, state)?
//       assert_equal for hash
//       Generic HasherChip trait?
//       Assert Somewhere that F = BN254Field or abstract it away
impl<F: BigPrimeField> PoseidonBN254Chip<F> {
    pub fn new(native: NativeChip<F>) -> Self {
        let permutation_chip = PoseidonBN254PermutationChip::new(native);
        Self { permutation_chip }
    }

    fn native(&self) -> &NativeChip<F> {
        self.permutation_chip().native()
    }
}

impl<F: BigPrimeField> HasherChip<F> for PoseidonBN254Chip<F> {
    const MAX_GOLDILOCKS: usize = 3;

    type Hasher = PoseidonBN128Hash;
    type HashWire = PoseidonBN254HashWire<F>;
    type PermutationChip = PoseidonBN254PermutationChip<F>;

    fn permutation_chip(&self) -> &PoseidonBN254PermutationChip<F> {
        &self.permutation_chip
    }

    #[count]
    fn load_constant(
        &self,
        ctx: &mut ContextWrapper<F>,
        h: PoseidonBN128HashOut<GoldilocksField>,
    ) -> PoseidonBN254HashWire<F> {
        let native = self.native();
        let value = native.load_constant(ctx, hash_to_fr(h));
        PoseidonBN254HashWire { value }
    }

    #[count]
    fn load_goldilocks_slice(
        &self,
        ctx: &mut ContextWrapper<F>,
        elements: &[GoldilocksWire<F>],
    ) -> PoseidonBN254HashWire<F> {
        let native = self.native();
        PoseidonBN254HashWire {
            value: native.limbs_to_num(
                ctx,
                elements.iter().map(|x| x.0).collect_vec().as_slice(),
                GoldilocksField::BITS,
            ),
        }
    }

    #[count]
    fn select(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &PoseidonBN254HashWire<F>,
        b: &PoseidonBN254HashWire<F>,
        sel: &BoolWire<F>,
    ) -> PoseidonBN254HashWire<F> {
        let native = self.native();
        let value = native.select(ctx, a.value, b.value, sel.0);
        PoseidonBN254HashWire { value }
    }

    #[count]
    fn select_from_idx(
        &self,
        ctx: &mut ContextWrapper<F>,
        arr: &[PoseidonBN254HashWire<F>],
        idx: &GoldilocksWire<F>,
    ) -> PoseidonBN254HashWire<F> {
        let native = self.native();
        let value = native.select_from_idx(
            ctx,
            arr.iter().map(|x| x.value).collect_vec().as_slice(),
            idx.0,
        );
        PoseidonBN254HashWire { value }
    }

    #[count]
    fn assert_equal(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &PoseidonBN254HashWire<F>,
        b: &PoseidonBN254HashWire<F>,
    ) {
        let native = self.native();
        native.assert_equal(ctx, &a.value, &b.value);
    }

    #[count]
    fn hash_no_pad(
        &self,
        ctx: &mut ContextWrapper<F>,
        values: &[GoldilocksWire<F>],
    ) -> PoseidonBN254HashWire<F> {
        let permutation_chip = self.permutation_chip();
        let native = self.native();

        let mut state = PoseidonBN254StateWire(
            native
                .load_constants(ctx, &[F::ZERO; WIDTH])
                .try_into()
                .unwrap(),
        );

        // Absorb all input chunks.
        state = permutation_chip.absorb_goldilocks(ctx, &state, values);

        // Squeeze until we have the desired number of outputs.
        PoseidonBN254HashWire {
            value: permutation_chip.squeeze(&state)[0],
        }
    }

    // TODO: Dedup by reusing hash_no_pad
    #[count]
    fn two_to_one(
        &self,
        ctx: &mut ContextWrapper<F>,
        left: &PoseidonBN254HashWire<F>,
        right: &PoseidonBN254HashWire<F>,
    ) -> PoseidonBN254HashWire<F> {
        let permutation_chip = self.permutation_chip();
        let native = self.native();

        // TODO: Remove extra allocations
        let mut state = PoseidonBN254StateWire(
            native
                .load_constants(ctx, &[F::ZERO; WIDTH])
                .try_into()
                .unwrap(),
        );

        // TODO: Why 2, 3?
        state.0[2] = left.value;
        state.0[3] = right.value;

        state = permutation_chip.permute(ctx, &state);

        PoseidonBN254HashWire {
            value: permutation_chip.squeeze(&state)[0],
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Sample};
    use plonky2::plonk::config::Hasher;
    use plonky2x::backend::wrapper::plonky2_config::PoseidonBN128Hash;

    use crate::field::goldilocks::base::GoldilocksChip;
    use crate::field::native::NativeChip;

    #[test]
    fn test_hash_no_pad() {
        base_test().k(14).run(|ctx, range| {
            let mut ctx = ContextWrapper::new(ctx);
            let ctx = &mut ctx;

            let native = NativeChip::<Fr>::new(range.clone());
            let goldilocks_chip = GoldilocksChip::new(native.clone()); // TODO: Remove clone, store reference
            let poseidon_chip = PoseidonBN254Chip::new(native);

            for _ in 0..10 {
                let preimage = GoldilocksField::rand();
                let preimage_wire = goldilocks_chip.load_witness(ctx, preimage);

                let hash = PoseidonBN128Hash::hash_no_pad(&[preimage]);
                let hash_wire = poseidon_chip.hash_no_pad(ctx, &[preimage_wire]);

                assert_eq!(hash_to_fr::<Fr>(hash), *hash_wire.value.value());
            }
        })
    }

    #[test]
    fn test_hash_two_to_one() {
        base_test().k(14).run(|ctx, range| {
            let mut ctx = ContextWrapper::new(ctx);
            let ctx = &mut ctx;

            let native = NativeChip::<Fr>::new(range.clone());
            let poseidon_chip = PoseidonBN254Chip::new(native.clone()); // TODO: Remove clone, store reference

            for _ in 0..10 {
                let hash1 = PoseidonBN128Hash::hash_no_pad(&[GoldilocksField::rand()]);
                let hash1_wire = PoseidonBN254HashWire {
                    value: native.load_constant(ctx, hash_to_fr(hash1)),
                };

                let hash2 = PoseidonBN128Hash::hash_no_pad(&[GoldilocksField::rand()]);
                let hash2_wire = PoseidonBN254HashWire {
                    value: native.load_constant(ctx, hash_to_fr(hash2)),
                };

                let hash_res = PoseidonBN128Hash::two_to_one(hash1, hash2);
                let hash_res_wire = poseidon_chip.two_to_one(ctx, &hash1_wire, &hash2_wire);

                assert_eq!(hash_to_fr::<Fr>(hash_res), *hash_res_wire.value.value());
            }
        })
    }
}

use halo2_base::utils::ScalarField;
use halo2_base::Context;
use plonky2::field::extension::Extendable;
use plonky2::hash::poseidon::Poseidon;

use crate::fields::fp::{Fp, FpChip};
use crate::fields::fp2::Fp2Chip;
use crate::hash::poseidon::chip::PoseidonChip;

pub struct MerkleTreeChip<F: ScalarField, F64: Poseidon + Extendable<2>> {
    poseidon_chip: PoseidonChip<F, F64>,
}

// TODO: Generalize for field extensions
impl<F: ScalarField, F64: Poseidon + Extendable<2>> MerkleTreeChip<F, F64> {
    // TODO: Do I need this function? Isn't it just the default constructor?
    pub fn new(poseidon_chip: PoseidonChip<F, F64>) -> Self {
        Self { poseidon_chip }
    }

    pub fn fp_chip(&self) -> &FpChip<F, F64> {
        &self.poseidon_chip.fp_chip()
    }

    pub fn fp2_chip(&self) -> &Fp2Chip<F, F64> {
        &self.poseidon_chip.fp2_chip()
    }

    pub fn poseidon_chip(&self) -> &PoseidonChip<F, F64> {
        &self.poseidon_chip
    }

    // TODO: handle references properly. Use vectors?
    //       hash_or_noop for leaves
    pub fn get_root(&self, ctx: &mut Context<F>, leaves: &[&[Fp<F, F64>; 4]]) -> [Fp<F, F64>; 4] {
        let poseidon_chip = self.poseidon_chip();

        let mut nodes = leaves.iter().map(|&leaf| leaf.clone()).collect::<Vec<_>>();
        let depth = leaves.len().ilog2();
        for _ in 0..depth {
            nodes = nodes
                .chunks(2)
                .map(|pair| poseidon_chip.two_to_one(ctx, &pair[0], &pair[1]))
                .collect();
        }
        nodes[0].clone()
    }

    pub fn verify_proof(
        &self,
        ctx: &mut Context<F>,
        root: &[Fp<F, F64>; 4],
        leaf: &[Fp<F, F64>; 4],
        index_bits: &[AssignedValue<F>], // To select whether current element is left or right child
        proof: &[&[Fp<F, F64>; 4]],
    ) {
        let poseidon_chip = self.poseidon_chip();

        let mut node = leaf;
        for (bit, sibling) in index_bits.iter().zip(proof.iter()) {
            let mut values = vec![];
            let left = select(node, sibling, bit);
            let right = select(sibling, node, bit); // TODO: Optimize to single select
            node = poseidon_chip.two_to_one(ctx, &pair[0], &pair[1]);
        }

        for (e1, e2) in root.to_assigned().iter().zip(digest.to_assigned().iter()) {
            ctx.constrain_equal(e1, e2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Sample};
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    use crate::fields::fp::FpChip;
    use crate::fields::fp2::Fp2Chip;
    use crate::fields::FieldChip;

    #[test]
    fn test_get_root() {
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
        let merkle_chip = MerkleTreeChip::new(poseidon_chip);

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);

        for _ in 0..2 {
            let fp_chip = merkle_chip.fp_chip();

            let leaves = (0..8)
                .map(|_| GoldilocksField::rand_vec(4))
                .collect::<Vec<_>>();

            let merkle_tree = MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves, 0);
            let root_wire1 = fp_chip.load_constants(ctx, &merkle_tree.cap.0[0].elements);

            let leaf_wires = merkle_tree
                .leaves
                .iter()
                .map(|leaf| fp_chip.load_constants(ctx, leaf.as_slice().try_into().unwrap()))
                .collect::<Vec<_>>();
            let root_wire2 = merkle_chip.get_root(
                ctx,
                leaf_wires.iter().map(|x| x).collect::<Vec<_>>().as_slice(),
            );

            for i in 0..4 {
                fp_chip.assert_equal(ctx, &root_wire1[i], &root_wire2[i]);
            }
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn test_verify_proof() {
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
        let merkle_chip = MerkleTreeChip::new(poseidon_chip);

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);

        for _ in 0..2 {
            let fp_chip = merkle_chip.fp_chip();

            let leaves = (0..8)
                .map(|_| GoldilocksField::rand_vec(4))
                .collect::<Vec<_>>();

            let merkle_tree = MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves, 0);

            let leaf_idx = 3;
            let merkle_proof = merkle_tree.prove(leaf_idx);

            let root_wire = fp_chip.load_constants(ctx, &merkle_tree.cap.0[0].elements);
            let leaf_wires = merkle_tree
                .leaves
                .iter()
                .map(|leaf| fp_chip.load_constants(ctx, leaf.as_slice().try_into().unwrap()))
                .collect::<Vec<_>>();
            let proof_wires = merkle_proof
                .siblings
                .iter()
                .map(|sibling| {
                    fp_chip.load_constants(ctx, sibling.elements.as_slice().try_into().unwrap())
                })
                .collect::<Vec<_>>();
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }
}

/*
// MERKLE TREE CHIP
// =========================================================================

// TODO: Modify to verify merkle caps
pub struct MerkleTreeChip<const N: usize, F: FieldExt, H: HasherChip<F>> {
    _marker: PhantomData<(F, H)>,
}

impl<const N: usize, F: FieldExt, H> MerkleTreeChip<N, F, H>
where
    H: for<'v> HasherChip<F, Digest<'v> = Digest<'v, F, N>>,
{
    pub fn get_root<'v>(
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &'v H,
        leaves: &[H::Digest<'v>],
    ) -> Result<H::Digest<'v>, Error> {
        let depth = leaves.len().ilog2();
        let mut nodes = leaves.to_vec();
        for _ in 0..depth {
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    // Hash digests
                    let elements = pair
                        .to_vec()
                        .iter()
                        .flat_map(|x| x.0.to_vec())
                        .collect::<Vec<_>>();
                    hasher_chip
                        .hash_elements(ctx, main_chip, &elements)
                        .unwrap()
                })
                .collect::<Vec<_>>();
        }
        Ok(nodes[0].clone())
    }

    pub fn verify_merkle_proof<'v>(
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &H,
        root: &H::Digest<'v>,
        index_bits: &[AssignedValue<F>],
        leaves: &[AssignedExtensionValue<'_, F>],
        proof: &[H::Digest<'v>],
    ) -> Result<(), Error> {
        // Hash leaves to a single digest
        let mut digest = hasher_chip.hash_elements(
            ctx,
            main_chip,
            &leaves.iter().flat_map(|x| x.coeffs()).collect::<Vec<_>>(),
        )?;
        for (bit, sibling) in index_bits.iter().zip(proof.iter().skip(1)) {
            let mut values = vec![];
            let a = sibling
                .to_assigned()
                .iter()
                .zip(digest.0.iter())
                .map(|(s, d)| main_chip.select(ctx, Existing(&s), Existing(&d), Existing(&bit)))
                .collect::<Vec<_>>();
            let b = sibling
                .to_assigned()
                .iter()
                .zip(digest.0.iter())
                .map(|(s, d)| main_chip.select(ctx, Existing(&d), Existing(&s), Existing(&bit)))
                .collect::<Vec<_>>();
            values.extend(a);
            values.extend(b);
            digest = hasher_chip.hash_elements(ctx, main_chip, &values)?;
        }

        for (e1, e2) in root.to_assigned().iter().zip(digest.to_assigned().iter()) {
            ctx.constrain_equal(e1, e2);
        }

        Ok(())
    }
}
*/

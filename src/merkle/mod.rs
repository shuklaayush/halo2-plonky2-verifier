use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::utils::{log2_ceil, ScalarField};
use halo2_base::Context;
use plonky2::field::extension::Extendable;
use plonky2::hash::poseidon::Poseidon;

use crate::fields::fp::{Fp, FpChip};
use crate::fields::fp2::Fp2Chip;
use crate::fields::FieldChip;
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

    pub fn gate(&self) -> &GateChip<F> {
        self.poseidon_chip.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.poseidon_chip.range()
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

    // TODO: Should I return vector?
    pub fn get_cap(
        &self,
        ctx: &mut Context<F>,
        leaves: &[&[Fp<F, F64>; 4]],
        height: u32,
    ) -> Vec<[Fp<F, F64>; 4]> {
        let poseidon_chip = self.poseidon_chip();

        let mut nodes = leaves.iter().map(|&leaf| leaf.clone()).collect::<Vec<_>>();
        let depth = leaves.len().ilog2();
        for _ in 0..(depth - height) {
            nodes = nodes
                .chunks(2)
                .map(|pair| poseidon_chip.two_to_one(ctx, &pair[0], &pair[1]))
                .collect();
        }

        nodes
    }

    // TODO: handle references properly. Use vectors?
    //       hash_or_noop for leaves
    //       Reuse get_cap
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

    // TODO: This is effectively checking doing merkle proof for a subtree
    //       Maybe there's a bettter abstraction?
    pub fn verify_proof_to_cap(
        &self,
        ctx: &mut Context<F>,
        leaf: &[Fp<F, F64>; 4],
        leaf_index: &Fp<F, F64>,
        cap: &[&[Fp<F, F64>; 4]],
        proof: &[&[Fp<F, F64>; 4]],
    ) {
        let poseidon_chip = self.poseidon_chip();
        let fp_chip = poseidon_chip.fp_chip();

        // To select whether current element is left or right child
        let log_n = proof.len() + log2_ceil(cap.len() as u64);
        let leaf_index_bits = fp_chip.num_to_bits(ctx, leaf_index, log_n);

        // leaf_index / 2^(depth - cap_height)
        let cap_index = fp_chip.bits_to_num(ctx, &leaf_index_bits[proof.len()..]);

        let one = fp_chip.load_constant(ctx, F64::ONE); // TODO: Move somewhere else
        let mut node = leaf.clone(); // TODO: Remove clone
        for (&sibling, bit) in proof.iter().zip(leaf_index_bits.iter()) {
            let one_minus_bit = fp_chip.sub(ctx, &one, bit);

            // TODO: Implement select for a hash type or array
            //       Is there a more efficient to way to select both at once?
            let left = node
                .iter()
                .zip(sibling)
                .map(|(ni, si)| fp_chip.select(ctx, ni, si, &one_minus_bit))
                .collect::<Vec<_>>();
            let right = node
                .iter()
                .zip(sibling)
                .map(|(ni, si)| fp_chip.select(ctx, ni, si, bit))
                .collect::<Vec<_>>();
            node = poseidon_chip.two_to_one(
                ctx,
                &left.try_into().unwrap(),
                &right.try_into().unwrap(),
            );
        }

        let fp_chip = self.fp_chip();
        let root = fp_chip.select_array_from_idx(
            ctx,
            cap.iter()
                .map(|node| node.as_slice())
                .collect::<Vec<_>>()
                .as_slice(),
            &cap_index,
        );
        for i in 0..4 {
            fp_chip.assert_equal(ctx, &root[i], &node[i])
        }
    }

    // TODO: Merge with above if zero cost
    pub fn verify_proof(
        &self,
        ctx: &mut Context<F>,
        leaf: &[Fp<F, F64>; 4],
        leaf_index: &Fp<F, F64>,
        root: &[Fp<F, F64>; 4],
        proof: &[&[Fp<F, F64>; 4]],
    ) {
        // TODO: Debug assert lenghts are same
        let poseidon_chip = self.poseidon_chip();
        let fp_chip = poseidon_chip.fp_chip();

        // To select whether current element is left or right child
        let log_n = proof.len();
        let leaf_index_bits = fp_chip.num_to_bits(ctx, leaf_index, log_n);

        let one = fp_chip.load_constant(ctx, F64::ONE); // TODO: Move somewhere else
        let mut node = leaf.clone(); // TODO: Remove clone
        for (bit, &sibling) in leaf_index_bits.iter().zip(proof.iter()) {
            let one_minus_bit = fp_chip.sub(ctx, &one, bit);

            // TODO: Implement select for a hash type or array
            let left = node
                .iter()
                .zip(sibling)
                .map(|(ni, si)| fp_chip.select(ctx, ni, si, &one_minus_bit))
                .collect::<Vec<_>>();
            let right = node
                .iter()
                .zip(sibling)
                .map(|(ni, si)| fp_chip.select(ctx, ni, si, bit))
                .collect::<Vec<_>>();
            node = poseidon_chip.two_to_one(
                ctx,
                &left.try_into().unwrap(),
                &right.try_into().unwrap(),
            );
        }

        let fp_chip = self.fp_chip();
        for i in 0..4 {
            fp_chip.assert_equal(ctx, &root[i], &node[i])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use plonky2::field::types::Field;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Sample};
    use plonky2::hash::merkle_proofs::{verify_merkle_proof, verify_merkle_proof_to_cap};
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand_core::SeedableRng;

    use crate::fields::fp::FpChip;
    use crate::fields::fp2::Fp2Chip;
    use crate::fields::FieldChip;

    #[test]
    fn test_get_root() {
        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = BaseCircuitBuilder::default().use_k(k as usize);
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
    fn test_verify_proof_to_cap() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = BaseCircuitBuilder::default().use_k(k as usize);
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

            let leaves = (0..8) // TODO: No hardcode
                .map(|_| GoldilocksField::rand_vec(4))
                .collect::<Vec<_>>();

            let cap_height = 1;
            let merkle_tree =
                MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves.clone(), cap_height);

            let leaf_idx = rng.gen_range(0..leaves.len());
            let leaf_idx_wire =
                fp_chip.load_constant(ctx, GoldilocksField::from_canonical_usize(leaf_idx));
            let merkle_proof = merkle_tree.prove(leaf_idx);

            verify_merkle_proof_to_cap(
                leaves[leaf_idx].clone(),
                leaf_idx,
                &merkle_tree.cap,
                &merkle_proof,
            )
            .unwrap();

            let cap_wires = (0..merkle_tree.cap.0.len())
                .map(|i| {
                    fp_chip.load_constants(
                        ctx,
                        &merkle_tree.cap.0[i].elements.as_slice().try_into().unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let leaf_wire: [Fp<Fr, GoldilocksField>; 4] = fp_chip.load_constants(
                ctx,
                merkle_tree.leaves[leaf_idx].as_slice().try_into().unwrap(),
            );
            let proof_wires = merkle_proof
                .siblings
                .iter()
                .map(|sibling| {
                    fp_chip.load_constants(ctx, sibling.elements.as_slice().try_into().unwrap())
                })
                .collect::<Vec<_>>();

            merkle_chip.verify_proof_to_cap(
                ctx,
                &leaf_wire,
                &leaf_idx_wire,
                cap_wires.iter().map(|x| x).collect::<Vec<_>>().as_slice(),
                proof_wires.iter().map(|x| x).collect::<Vec<_>>().as_slice(),
            );
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn test_verify_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = BaseCircuitBuilder::default().use_k(k as usize);
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

            let leaves = (0..8) // TODO: No hardcode
                .map(|_| GoldilocksField::rand_vec(4))
                .collect::<Vec<_>>();

            let merkle_tree = MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves.clone(), 0);

            let leaf_idx = rng.gen_range(0..leaves.len());
            let leaf_idx_wire =
                fp_chip.load_constant(ctx, GoldilocksField::from_canonical_usize(leaf_idx));
            let merkle_proof = merkle_tree.prove(leaf_idx);

            verify_merkle_proof(
                leaves[leaf_idx].clone(),
                leaf_idx,
                merkle_tree.cap.0[0],
                &merkle_proof,
            )
            .unwrap();

            let root_wire = fp_chip.load_constants(ctx, &merkle_tree.cap.0[0].elements);
            let leaf_wire: [Fp<Fr, GoldilocksField>; 4] = fp_chip.load_constants(
                ctx,
                merkle_tree.leaves[leaf_idx].as_slice().try_into().unwrap(),
            );
            let proof_wires = merkle_proof
                .siblings
                .iter()
                .map(|sibling| {
                    fp_chip.load_constants(ctx, sibling.elements.as_slice().try_into().unwrap())
                })
                .collect::<Vec<_>>();

            merkle_chip.verify_proof(
                ctx,
                &leaf_wire,
                &leaf_idx_wire,
                &root_wire,
                proof_wires.iter().map(|x| x).collect::<Vec<_>>().as_slice(),
            );
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }
}

use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::utils::{log2_ceil, ScalarField};
use halo2_base::Context;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;

use crate::goldilocks::field::{GoldilocksChip, GoldilocksWire};
use crate::hash::poseidon::hash::PoseidonChip;
use crate::hash::HashOutWire;

pub struct MerkleCapWire<F: ScalarField>(pub Vec<HashOutWire<F>>);

pub struct MerkleProofWire<F: ScalarField>(pub Vec<HashOutWire<F>>);

pub struct MerkleTreeChip<F: ScalarField> {
    poseidon_chip: PoseidonChip<F>,
}

// TODO: Generalize for field extensions
impl<F: ScalarField> MerkleTreeChip<F> {
    // TODO: Do I need this function? Isn't it just the default constructor?
    pub fn new(poseidon_chip: PoseidonChip<F>) -> Self {
        Self { poseidon_chip }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.poseidon_chip.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.poseidon_chip.range()
    }

    pub fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        &self.poseidon_chip.goldilocks_chip()
    }

    pub fn poseidon_chip(&self) -> &PoseidonChip<F> {
        &self.poseidon_chip
    }

    // TODO: This is effectively checking doing merkle proof for a subtree
    //       Maybe there's a bettter abstraction?
    pub fn verify_merkle_proof_to_cap(
        &self,
        ctx: &mut Context<F>,
        leaf_data: &[GoldilocksWire<F>],
        leaf_index: &GoldilocksWire<F>,
        merkle_cap: &MerkleCapWire<F>,
        proof: &MerkleProofWire<F>,
    ) {
        let poseidon_chip = self.poseidon_chip();
        let goldilocks_chip = poseidon_chip.goldilocks_chip();

        // To select whether current element is left or right child
        let log_n = proof.0.len() + log2_ceil(merkle_cap.0.len() as u64);
        let leaf_index_bits = goldilocks_chip.num_to_bits(ctx, leaf_index, log_n);

        // leaf_index / 2^(depth - cap_height)
        let cap_index = goldilocks_chip.bits_to_num(ctx, &leaf_index_bits[proof.0.len()..]);

        let one = goldilocks_chip.load_constant(ctx, GoldilocksField::ONE); // TODO: Move somewhere else
        let mut node = poseidon_chip.hash_or_noop(ctx, leaf_data);
        for (&sibling, bit) in proof.0.iter().zip(leaf_index_bits.iter()) {
            let one_minus_bit = goldilocks_chip.sub(ctx, &one, bit);
            // TODO: Is there a more efficient to way to select both at once?
            let left =
                HashOutWire(goldilocks_chip.select_array(ctx, node.0, sibling.0, &one_minus_bit));
            let right = HashOutWire(goldilocks_chip.select_array(ctx, node.0, sibling.0, bit));
            node = poseidon_chip.two_to_one(ctx, &left, &right);
        }

        let goldilocks_chip = self.goldilocks_chip();
        // TODO: Abstract this away to hash chip
        let root = goldilocks_chip.select_array_from_idx(
            ctx,
            merkle_cap
                .0
                .iter()
                .map(|node| node.0)
                .collect::<Vec<_>>()
                .as_slice(),
            &cap_index,
        );
        for i in 0..NUM_HASH_OUT_ELTS {
            goldilocks_chip.assert_equal(ctx, &root[i], &node.0[i])
        }
    }

    pub fn verify_merkle_proof(
        &self,
        ctx: &mut Context<F>,
        leaf_data: &[GoldilocksWire<F>],
        leaf_index: &GoldilocksWire<F>,
        merkle_root: &HashOutWire<F>,
        proof: &MerkleProofWire<F>,
    ) {
        let merkle_cap = MerkleCapWire(vec![*merkle_root]);
        self.verify_merkle_proof_to_cap(ctx, leaf_data, leaf_index, &merkle_cap, proof);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use plonky2::field::types::Field;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Sample};
    use plonky2::hash::merkle_proofs::{verify_merkle_proof, verify_merkle_proof_to_cap};
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_verify_proof_to_cap() {
        let mut rng = StdRng::seed_from_u64(0u64);

        base_test().k(12).run(|ctx, range| {
            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone()); // TODO: Remove clone, store reference
            let merkle_chip = MerkleTreeChip::new(poseidon_chip);

            for _ in 0..2 {
                let leaves = (0..8) // TODO: No hardcode
                    .map(|_| GoldilocksField::rand_vec(20))
                    .collect::<Vec<_>>();

                let cap_height = 1;
                let merkle_tree =
                    MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves.clone(), cap_height);

                let leaf_idx = rng.gen_range(0..leaves.len());
                let leaf_idx_wire = goldilocks_chip
                    .load_constant(ctx, GoldilocksField::from_canonical_usize(leaf_idx));
                let merkle_proof = merkle_tree.prove(leaf_idx);

                verify_merkle_proof_to_cap(
                    leaves[leaf_idx].clone(),
                    leaf_idx,
                    &merkle_tree.cap,
                    &merkle_proof,
                )
                .unwrap();

                let cap_wire = MerkleCapWire(
                    (0..merkle_tree.cap.0.len())
                        .map(|i| {
                            HashOutWire(
                                goldilocks_chip
                                    .load_constant_array(ctx, &merkle_tree.cap.0[i].elements),
                            )
                        })
                        .collect::<Vec<_>>(),
                );
                let leaf_wire = goldilocks_chip
                    .load_constant_slice(ctx, merkle_tree.leaves[leaf_idx].as_slice());
                let proof_wire = MerkleProofWire(
                    merkle_proof
                        .siblings
                        .iter()
                        .map(|sibling| {
                            HashOutWire(goldilocks_chip.load_constant_array(ctx, &sibling.elements))
                        })
                        .collect::<Vec<_>>(),
                );

                merkle_chip.verify_merkle_proof_to_cap(
                    ctx,
                    &leaf_wire,
                    &leaf_idx_wire,
                    &cap_wire,
                    &proof_wire,
                );
            }
        });
    }

    #[test]
    fn test_verify_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);

        base_test().k(14).run(|ctx, range| {
            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone()); // TODO: Remove clone, store reference
            let merkle_chip = MerkleTreeChip::new(poseidon_chip);

            for _ in 0..2 {
                let leaves = (0..8) // TODO: No hardcode
                    .map(|_| GoldilocksField::rand_vec(20))
                    .collect::<Vec<_>>();

                let merkle_tree =
                    MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves.clone(), 0);

                let leaf_idx = rng.gen_range(0..leaves.len());
                let leaf_idx_wire = goldilocks_chip
                    .load_constant(ctx, GoldilocksField::from_canonical_usize(leaf_idx));
                let merkle_proof = merkle_tree.prove(leaf_idx);

                verify_merkle_proof(
                    leaves[leaf_idx].clone(),
                    leaf_idx,
                    merkle_tree.cap.0[0],
                    &merkle_proof,
                )
                .unwrap();

                let root_wire = HashOutWire(
                    goldilocks_chip.load_constant_array(ctx, &merkle_tree.cap.0[0].elements),
                );
                let leaf_wire = goldilocks_chip
                    .load_constant_slice(ctx, merkle_tree.leaves[leaf_idx].as_slice());
                let proof_wire = MerkleProofWire(
                    merkle_proof
                        .siblings
                        .iter()
                        .map(|sibling| {
                            HashOutWire(goldilocks_chip.load_constant_array(ctx, &sibling.elements))
                        })
                        .collect::<Vec<_>>(),
                );

                merkle_chip.verify_merkle_proof(
                    ctx,
                    &leaf_wire,
                    &leaf_idx_wire,
                    &root_wire,
                    &proof_wire,
                );
            }
        })
    }
}

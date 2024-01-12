use halo2_base::utils::BigPrimeField;
use std::marker::PhantomData;

use verifier_macro::count;

use crate::field::bool::BoolWire;
use crate::field::goldilocks::base::{GoldilocksChip, GoldilocksWire};
use crate::hash::{HashWire, HasherChip};
use crate::util::context_wrapper::ContextWrapper;

#[derive(Clone, Debug)]
pub struct MerkleCapWire<F: BigPrimeField, HW: HashWire<F>>(pub Vec<HW>, PhantomData<F>);

impl<F: BigPrimeField, HW: HashWire<F>> MerkleCapWire<F, HW> {
    pub fn new(hashes: Vec<HW>) -> Self {
        Self(hashes, PhantomData)
    }
}

#[derive(Debug)]
pub struct MerkleProofWire<F: BigPrimeField, HW: HashWire<F>> {
    pub siblings: Vec<HW>,
    _marker: PhantomData<F>,
}

impl<F: BigPrimeField, HW: HashWire<F>> MerkleProofWire<F, HW> {
    pub fn new(hashes: Vec<HW>) -> Self {
        Self {
            siblings: hashes,
            _marker: PhantomData,
        }
    }
}

pub struct MerkleTreeChip<F: BigPrimeField, HC: HasherChip<F>> {
    goldilocks_chip: GoldilocksChip<F>,
    hasher_chip: HC,
}

impl<F: BigPrimeField, HC: HasherChip<F>> MerkleTreeChip<F, HC> {
    pub fn new(goldilocks_chip: GoldilocksChip<F>, hasher_chip: HC) -> Self {
        Self {
            goldilocks_chip,
            hasher_chip,
        }
    }

    pub fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        &self.goldilocks_chip
    }

    pub fn hasher_chip(&self) -> &HC {
        &self.hasher_chip
    }

    #[count]
    pub fn verify_proof_to_cap_with_cap_index(
        &self,
        ctx: &mut ContextWrapper<F>,
        leaf_data: &[GoldilocksWire<F>],
        leaf_index_bits: &[BoolWire<F>],
        cap_index: &GoldilocksWire<F>,
        merkle_cap: &MerkleCapWire<F, HC::HashWire>,
        proof: &MerkleProofWire<F, HC::HashWire>,
    ) {
        let hasher_chip = self.hasher_chip();

        let mut node = hasher_chip.hash_or_noop(ctx, leaf_data);
        for (&sibling, bit) in proof.siblings.iter().zip(leaf_index_bits.iter()) {
            // TODO: Is there a more efficient to way to select both at once?
            let left = hasher_chip.select(ctx, &sibling, &node, bit);
            let right = hasher_chip.select(ctx, &node, &sibling, bit);
            node = hasher_chip.two_to_one(ctx, &left, &right);
        }

        let root = hasher_chip.select_from_idx(ctx, merkle_cap.0.as_slice(), cap_index);
        hasher_chip.assert_equal(ctx, &root, &node);
    }

    #[count]
    pub fn verify_proof_to_cap(
        &self,
        ctx: &mut ContextWrapper<F>,
        leaf_data: &[GoldilocksWire<F>],
        leaf_index_bits: &[BoolWire<F>],
        merkle_cap: &MerkleCapWire<F, HC::HashWire>,
        proof: &MerkleProofWire<F, HC::HashWire>,
    ) {
        let goldilocks_chip = self.goldilocks_chip();

        // leaf_index / 2^(depth - cap_height)
        let cap_index = goldilocks_chip.bits_to_num(ctx, &leaf_index_bits[proof.siblings.len()..]);

        self.verify_proof_to_cap_with_cap_index(
            ctx,
            leaf_data,
            leaf_index_bits,
            &cap_index,
            merkle_cap,
            proof,
        );
    }

    #[count]
    pub fn verify_proof(
        &self,
        ctx: &mut ContextWrapper<F>,
        leaf_data: &[GoldilocksWire<F>],
        leaf_index_bits: &[BoolWire<F>],
        merkle_root: &HC::HashWire,
        proof: &MerkleProofWire<F, HC::HashWire>,
    ) {
        let merkle_cap = MerkleCapWire::new(vec![*merkle_root]);
        self.verify_proof_to_cap(ctx, leaf_data, leaf_index_bits, &merkle_cap, proof);
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
    use plonky2::util::log2_ceil;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand_core::SeedableRng;

    use crate::field::native::NativeChip;
    use crate::hash::poseidon::hash::{PoseidonChip, PoseidonHashWire};

    #[test]
    fn test_verify_proof_to_cap() {
        let mut rng = StdRng::seed_from_u64(0u64);

        base_test().k(14).run(|ctx, range| {
            let ctx = &mut ContextWrapper::new(ctx);

            let native = NativeChip::<Fr>::new(range.clone());
            let goldilocks_chip = GoldilocksChip::new(native);
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone());
            let merkle_chip = MerkleTreeChip::new(goldilocks_chip.clone(), poseidon_chip);

            for _ in 0..2 {
                let n = 8;
                let leaves = (0..n)
                    .map(|_| GoldilocksField::rand_vec(20))
                    .collect::<Vec<_>>();

                let cap_height = 1;
                let merkle_tree =
                    MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves.clone(), cap_height);

                let leaf_idx = rng.gen_range(0..leaves.len());
                let leaf_idx_wire = goldilocks_chip
                    .load_constant(ctx, GoldilocksField::from_canonical_usize(leaf_idx));
                let leaf_idx_bits_wire =
                    goldilocks_chip.num_to_bits(ctx, &leaf_idx_wire, log2_ceil(n));
                let merkle_proof = merkle_tree.prove(leaf_idx);

                verify_merkle_proof_to_cap(
                    leaves[leaf_idx].clone(),
                    leaf_idx,
                    &merkle_tree.cap,
                    &merkle_proof,
                )
                .unwrap();

                let cap_wire = MerkleCapWire::new(
                    (0..merkle_tree.cap.0.len())
                        .map(|i| PoseidonHashWire {
                            elements: goldilocks_chip
                                .load_constant_array(ctx, &merkle_tree.cap.0[i].elements),
                        })
                        .collect::<Vec<_>>(),
                );
                let leaf_wire = goldilocks_chip
                    .load_constant_slice(ctx, merkle_tree.leaves[leaf_idx].as_slice());
                let proof_wire = MerkleProofWire::new(
                    merkle_proof
                        .siblings
                        .iter()
                        .map(|sibling| PoseidonHashWire {
                            elements: goldilocks_chip.load_constant_array(ctx, &sibling.elements),
                        })
                        .collect::<Vec<_>>(),
                );

                merkle_chip.verify_proof_to_cap(
                    ctx,
                    &leaf_wire,
                    &leaf_idx_bits_wire,
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
            let ctx = &mut ContextWrapper::new(ctx);

            let native = NativeChip::<Fr>::new(range.clone());
            let goldilocks_chip = GoldilocksChip::new(native);
            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone());
            let merkle_chip = MerkleTreeChip::new(goldilocks_chip.clone(), poseidon_chip);

            for _ in 0..2 {
                let n = 8;
                let leaves = (0..n)
                    .map(|_| GoldilocksField::rand_vec(20))
                    .collect::<Vec<_>>();

                let merkle_tree =
                    MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves.clone(), 0);

                let leaf_idx = rng.gen_range(0..leaves.len());
                let leaf_idx_wire = goldilocks_chip
                    .load_constant(ctx, GoldilocksField::from_canonical_usize(leaf_idx));
                let leaf_idx_bits_wire =
                    goldilocks_chip.num_to_bits(ctx, &leaf_idx_wire, log2_ceil(n));
                let merkle_proof = merkle_tree.prove(leaf_idx);

                verify_merkle_proof(
                    leaves[leaf_idx].clone(),
                    leaf_idx,
                    merkle_tree.cap.0[0],
                    &merkle_proof,
                )
                .unwrap();

                let root_wire = PoseidonHashWire {
                    elements: goldilocks_chip
                        .load_constant_array(ctx, &merkle_tree.cap.0[0].elements),
                };
                let leaf_wire = goldilocks_chip
                    .load_constant_slice(ctx, merkle_tree.leaves[leaf_idx].as_slice());
                let proof_wire = MerkleProofWire::new(
                    merkle_proof
                        .siblings
                        .iter()
                        .map(|sibling| PoseidonHashWire {
                            elements: goldilocks_chip.load_constant_array(ctx, &sibling.elements),
                        })
                        .collect::<Vec<_>>(),
                );

                merkle_chip.verify_proof(
                    ctx,
                    &leaf_wire,
                    &leaf_idx_bits_wire,
                    &root_wire,
                    &proof_wire,
                );
            }
        })
    }
}

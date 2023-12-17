use halo2_base::{utils::ScalarField, Context};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::Hasher};

use self::poseidon::permutation::PoseidonPermutationChip;
use crate::goldilocks::{
    field::{GoldilocksChip, GoldilocksWire},
    BoolWire,
};

pub mod poseidon;
pub mod poseidon_bn254;

// TODO: Is there a way to avoid the empty trait?
pub trait HashWire<F: ScalarField>: Copy + Clone {}

pub trait PermutationChip<F: ScalarField> {
    type StateWire;

    fn permute(&self, ctx: &mut Context<F>, state: &StateWire) -> StateWire;
}

/// Trait for hash functions.
pub trait HasherChip<F: ScalarField> {
    /// Size of `Hash` in number of Goldilocks elements.
    const HASH_SIZE: usize;

    type Hasher: Hasher<GoldilocksField>;
    // TODO: Why doesn't something like this work?
    // type Hash: Self::Hasher::Hash;

    /// Hash Output
    type HashWire: HashWire<F>;

    fn goldilocks_chip(&self) -> &GoldilocksChip<F>;

    fn permutation_chip(&self) -> &PoseidonPermutationChip<F>;

    fn load_constant(
        &self,
        ctx: &mut Context<F>,
        constant: <Self::Hasher as Hasher<GoldilocksField>>::Hash,
    ) -> Self::HashWire;

    fn load_goldilocks_slice(
        &self,
        ctx: &mut Context<F>,
        elements: &[GoldilocksWire<F>],
    ) -> Self::HashWire;

    fn to_goldilocks_vec(
        &self,
        ctx: &mut Context<F>,
        hash: &Self::HashWire,
    ) -> Vec<GoldilocksWire<F>>;

    fn select(
        &self,
        ctx: &mut Context<F>,
        a: &Self::HashWire,
        b: &Self::HashWire,
        sel: &BoolWire<F>,
    ) -> Self::HashWire;

    fn select_from_idx(
        &self,
        ctx: &mut Context<F>,
        a: &[Self::HashWire],
        idx: &GoldilocksWire<F>,
    ) -> Self::HashWire;

    fn assert_equal(&self, ctx: &mut Context<F>, a: &Self::HashWire, b: &Self::HashWire);

    /// Hash a message without any padding step. Note that this can enable length-extension attacks.
    /// However, it is still collision-resistant in cases where the input has a fixed length.
    fn hash_no_pad(&self, ctx: &mut Context<F>, input: &[GoldilocksWire<F>]) -> Self::HashWire;

    /// Hash the slice if necessary to reduce its length to ~256 bits. If it already fits, this is a
    /// no-op.
    fn hash_or_noop(&self, ctx: &mut Context<F>, inputs: &[GoldilocksWire<F>]) -> Self::HashWire {
        if inputs.len() <= Self::HASH_SIZE {
            self.load_goldilocks_slice(ctx, inputs)
        } else {
            self.hash_no_pad(ctx, inputs)
        }
    }

    fn two_to_one(
        &self,
        ctx: &mut Context<F>,
        left: &Self::HashWire,
        right: &Self::HashWire,
    ) -> Self::HashWire;
}

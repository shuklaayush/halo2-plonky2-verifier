use halo2_base::utils::BigPrimeField;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::Hasher};

use crate::{
    field::{
        goldilocks::{base::GoldilocksWire, BoolWire},
        native::NativeChip,
    },
    util::context_wrapper::ContextWrapper,
};

pub mod poseidon;
pub mod poseidon_bn254;

// TODO: Is there a way to avoid the empty trait?
// TODO: Rename to GenericHashWire?
pub trait HashWire<F: BigPrimeField>: Copy + Clone {
    fn to_goldilocks_vec(
        &self,
        ctx: &mut ContextWrapper<F>,
        native: &NativeChip<F>,
    ) -> Vec<GoldilocksWire<F>>;
}

// TODO: Rename to GenericStateWire?
pub trait StateWire<F: BigPrimeField>: Copy + Clone {
    type Item: Copy + Clone;
}

// This is a combination of PlonkyPermutation and AlgebraicHasher.
pub trait PermutationChip<F: BigPrimeField>: Clone {
    type StateWire: StateWire<F>;

    fn native(&self) -> &NativeChip<F>;

    fn load_zero(&self, ctx: &mut ContextWrapper<F>) -> Self::StateWire;

    fn permute(&self, ctx: &mut ContextWrapper<F>, state: &Self::StateWire) -> Self::StateWire;

    fn absorb_goldilocks(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &Self::StateWire,
        input: &[GoldilocksWire<F>],
    ) -> Self::StateWire;

    // TODO: Return fixed size arrays?
    fn squeeze(&self, state: &Self::StateWire) -> Vec<<Self::StateWire as StateWire<F>>::Item>;

    fn squeeze_goldilocks(
        &self,
        ctx: &mut ContextWrapper<F>,
        state: &Self::StateWire,
    ) -> Vec<GoldilocksWire<F>>;
}

/// Trait for hash functions.
pub trait HasherChip<F: BigPrimeField> {
    /// Maximum number of goldilocks elements that can be uniquely represented as a Hash element.
    const MAX_GOLDILOCKS: usize;

    type Hasher: Hasher<GoldilocksField>;
    // TODO: Why doesn't something like this work?
    // type Hash: Self::Hasher::Hash;

    type PermutationChip: PermutationChip<F>;

    /// Hash Output
    type HashWire: HashWire<F>;

    fn permutation_chip(&self) -> &Self::PermutationChip;

    fn load_constant(
        &self,
        ctx: &mut ContextWrapper<F>,
        constant: <Self::Hasher as Hasher<GoldilocksField>>::Hash,
    ) -> Self::HashWire;

    fn load_goldilocks_slice(
        &self,
        ctx: &mut ContextWrapper<F>,
        elements: &[GoldilocksWire<F>],
    ) -> Self::HashWire;

    fn select(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &Self::HashWire,
        b: &Self::HashWire,
        sel: &BoolWire<F>,
    ) -> Self::HashWire;

    fn select_from_idx(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &[Self::HashWire],
        idx: &GoldilocksWire<F>,
    ) -> Self::HashWire;

    fn assert_equal(&self, ctx: &mut ContextWrapper<F>, a: &Self::HashWire, b: &Self::HashWire);

    /// Hash a message without any padding step. Note that this can enable length-extension attacks.
    /// However, it is still collision-resistant in cases where the input has a fixed length.
    fn hash_no_pad(
        &self,
        ctx: &mut ContextWrapper<F>,
        input: &[GoldilocksWire<F>],
    ) -> Self::HashWire;

    /// Hash the slice if necessary to reduce its length to ~256 bits. If it already fits, this is a
    /// no-op.
    fn hash_or_noop(
        &self,
        ctx: &mut ContextWrapper<F>,
        inputs: &[GoldilocksWire<F>],
    ) -> Self::HashWire {
        if inputs.len() <= Self::MAX_GOLDILOCKS {
            self.load_goldilocks_slice(ctx, inputs)
        } else {
            self.hash_no_pad(ctx, inputs)
        }
    }

    fn two_to_one(
        &self,
        ctx: &mut ContextWrapper<F>,
        left: &Self::HashWire,
        right: &Self::HashWire,
    ) -> Self::HashWire;
}

pub mod poseidon;

use halo2_base::utils::ScalarField;
use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;

use crate::goldilocks::field::GoldilocksWire;

/// Represents a ~256 bit hash output.
#[derive(Copy, Clone, Debug)]
pub struct HashOutWire<F: ScalarField>(pub [GoldilocksWire<F>; NUM_HASH_OUT_ELTS]);

impl<F: ScalarField> HashOutWire<F> {
    pub fn from_partial(elements_in: &[GoldilocksWire<F>], zero: GoldilocksWire<F>) -> Self {
        let mut elements = [zero; NUM_HASH_OUT_ELTS];
        elements[0..elements_in.len()].copy_from_slice(elements_in);
        Self(elements)
    }
}

impl<F: ScalarField> From<[GoldilocksWire<F>; NUM_HASH_OUT_ELTS]> for HashOutWire<F> {
    fn from(elements: [GoldilocksWire<F>; NUM_HASH_OUT_ELTS]) -> Self {
        Self(elements)
    }
}

// impl<F: ScalarField> TryFrom<&[GoldilocksWire<F>]> for HashOutWire<F> {
//     type Error = anyhow::Error;

//     fn try_from(elements: &[GoldilocksWire<F>]) -> Result<Self, Self::Error> {
//         ensure!(elements.len() == NUM_HASH_OUT_ELTS);
//         Ok(Self(elements.try_into().unwrap()))
//     }
// }

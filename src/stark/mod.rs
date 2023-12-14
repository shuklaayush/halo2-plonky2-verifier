use halo2_base::{utils::ScalarField, Context};

use crate::{
    fri::{FriChip, FriProofWire},
    goldilocks::{extension::GoldilocksQuadExtWire, field::GoldilocksWire},
    merkle::MerkleCapWire,
};

pub struct StarkOpeningSetWire<F: ScalarField> {
    pub local_values: Vec<GoldilocksQuadExtWire<F>>,
    pub next_values: Vec<GoldilocksQuadExtWire<F>>,
    pub permutation_zs: Option<Vec<GoldilocksQuadExtWire<F>>>,
    pub permutation_zs_next: Option<Vec<GoldilocksQuadExtWire<F>>>,
    pub quotient_polys: Vec<GoldilocksQuadExtWire<F>>,
}

pub struct StarkProofWire<F: ScalarField> {
    pub trace_cap: MerkleCapWire<F>,
    pub permutation_zs_cap: Option<MerkleCapWire<F>>,
    pub quotient_polys_cap: MerkleCapWire<F>,
    pub openings: StarkOpeningSetWire<F>,
    pub opening_proof: FriProofWire<F>,
}

pub struct StarkProofWithPublicInputsWire<F: ScalarField> {
    pub proof: StarkProofWire<F>,
    pub public_inputs: Vec<GoldilocksWire<F>>,
}

pub struct StarkChip<F: ScalarField> {
    fri_chip: FriChip<F>,
}

impl<F: ScalarField> StarkChip<F> {
    pub fn new(fri_chip: FriChip<F>) -> Self {
        Self { fri_chip }
    }

    pub fn verify_proof(&self, ctx: &mut Context<F>) {
        todo!()
    }
}

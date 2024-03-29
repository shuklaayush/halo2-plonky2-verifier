use halo2_base::utils::BigPrimeField;
use itertools::Itertools;
use plonky2::{
    field::{
        extension::{quadratic::QuadraticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
    },
    fri::{proof::FriProof, structure::FriOpenings},
    hash::merkle_tree::MerkleCap,
    plonk::config::{GenericConfig, Hasher},
};
use starky::proof::{StarkOpeningSet, StarkProof, StarkProofWithPublicInputs};

use verifier_macro::count;

use crate::{
    field::goldilocks::{
        base::{GoldilocksChip, GoldilocksWire},
        extension::GoldilocksQuadExtWire,
    },
    fri::{
        FriInitialTreeProofWire, FriOpeningBatchWire, FriOpeningsWire, FriProofWire,
        FriQueryRoundWire, FriQueryStepWire, PolynomialCoeffsExtWire,
    },
    hash::HasherChip,
    merkle::{MerkleCapWire, MerkleProofWire},
    stark::{StarkOpeningSetWire, StarkProofWire, StarkProofWithPublicInputsWire},
    util::context_wrapper::ContextWrapper,
};

pub struct WitnessChip<F: BigPrimeField, HC: HasherChip<F>> {
    goldilocks_chip: GoldilocksChip<F>,
    hasher_chip: HC,
}

impl<F: BigPrimeField, HC: HasherChip<F>> WitnessChip<F, HC> {
    pub fn new(goldilocks_chip: GoldilocksChip<F>, hasher_chip: HC) -> Self {
        Self {
            goldilocks_chip,
            hasher_chip,
        }
    }

    fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        &self.goldilocks_chip
    }

    #[count]
    fn load(&self, ctx: &mut ContextWrapper<F>, value: GoldilocksField) -> GoldilocksWire<F> {
        self.goldilocks_chip().load_witness(ctx, value)
    }

    #[count]
    fn load_hash(
        &self,
        ctx: &mut ContextWrapper<F>,
        value: <HC::Hasher as Hasher<GoldilocksField>>::Hash,
    ) -> HC::HashWire {
        self.hasher_chip.load_witness(ctx, value)
    }

    #[count]
    fn load_cap(
        &self,
        ctx: &mut ContextWrapper<F>,
        value: &MerkleCap<GoldilocksField, HC::Hasher>,
    ) -> MerkleCapWire<F, HC::HashWire> {
        MerkleCapWire::new(
            value
                .0
                .iter()
                .map(|&x| self.load_hash(ctx, x))
                .collect_vec(),
        )
    }

    #[count]
    fn load_array(
        &self,
        ctx: &mut ContextWrapper<F>,
        values: &[GoldilocksField],
    ) -> Vec<GoldilocksWire<F>> {
        values
            .iter()
            .map(|&value| self.load(ctx, value))
            .collect_vec()
    }

    #[count]
    fn load_extension(
        &self,
        ctx: &mut ContextWrapper<F>,
        value: QuadraticExtension<GoldilocksField>,
    ) -> GoldilocksQuadExtWire<F> {
        let values: [GoldilocksField; 2] = value.to_basefield_array();
        GoldilocksQuadExtWire(self.load_array(ctx, &values).try_into().unwrap())
    }

    #[count]
    fn load_extensions(
        &self,
        ctx: &mut ContextWrapper<F>,
        values: &[QuadraticExtension<GoldilocksField>],
    ) -> Vec<GoldilocksQuadExtWire<F>> {
        values
            .iter()
            .map(|&v| self.load_extension(ctx, v))
            .collect_vec()
    }

    #[count]
    fn load_fri_openings(
        &self,
        ctx: &mut ContextWrapper<F>,
        fri_openings: &FriOpenings<GoldilocksField, 2>,
    ) -> FriOpeningsWire<F> {
        FriOpeningsWire {
            batches: fri_openings
                .batches
                .iter()
                .map(|batch| FriOpeningBatchWire {
                    values: self.load_extensions(ctx, &batch.values),
                })
                .collect_vec(),
        }
    }

    // TODO: Plonky2 only constraints equality of .to_fri_openings() instead of whole struct
    #[count]
    fn load_openings_set(
        &self,
        ctx: &mut ContextWrapper<F>,
        openings_set: &StarkOpeningSet<GoldilocksField, 2>,
    ) -> StarkOpeningSetWire<F> {
        StarkOpeningSetWire {
            local_values: self.load_extensions(ctx, openings_set.local_values.as_slice()),
            next_values: self.load_extensions(ctx, openings_set.next_values.as_slice()),
            permutation_zs: openings_set
                .permutation_zs
                .as_ref()
                .map(|permutation_zs| self.load_extensions(ctx, permutation_zs.as_slice())),
            permutation_zs_next: openings_set.permutation_zs_next.as_ref().map(
                |permutation_zs_next| self.load_extensions(ctx, permutation_zs_next.as_slice()),
            ),
            quotient_polys: self.load_extensions(ctx, openings_set.quotient_polys.as_slice()),
        }
    }

    #[count]
    pub fn load_fri_proof(
        &self,
        ctx: &mut ContextWrapper<F>,
        fri_proof: &FriProof<GoldilocksField, HC::Hasher, 2>,
    ) -> FriProofWire<F, HC::HashWire> {
        let pow_witness = self.load(ctx, fri_proof.pow_witness);

        let final_poly = PolynomialCoeffsExtWire(
            fri_proof
                .final_poly
                .coeffs
                .iter()
                .map(|&x| self.load_extension(ctx, x))
                .collect_vec(),
        );

        let commit_phase_merkle_caps = fri_proof
            .commit_phase_merkle_caps
            .iter()
            .map(|cap| self.load_cap(ctx, cap))
            .collect_vec();

        let query_round_proofs = fri_proof
            .query_round_proofs
            .iter()
            .map(|proof| {
                let initial_trees_proof = FriInitialTreeProofWire {
                    evals_proofs: proof
                        .initial_trees_proof
                        .evals_proofs
                        .iter()
                        .map(|(evals, proof)| {
                            (
                                evals.iter().map(|&x| self.load(ctx, x)).collect_vec(),
                                MerkleProofWire::new(
                                    proof
                                        .siblings
                                        .iter()
                                        .map(|&x| self.load_hash(ctx, x))
                                        .collect_vec(),
                                ),
                            )
                        })
                        .collect_vec(),
                };

                let steps = proof
                    .steps
                    .iter()
                    .map(|step| {
                        let evals = step
                            .evals
                            .iter()
                            .map(|&x| self.load_extension(ctx, x))
                            .collect_vec();
                        let merkle_proof = MerkleProofWire::new(
                            step.merkle_proof
                                .siblings
                                .iter()
                                .map(|&x| self.load_hash(ctx, x))
                                .collect_vec(),
                        );

                        FriQueryStepWire {
                            evals,
                            merkle_proof,
                        }
                    })
                    .collect_vec();

                FriQueryRoundWire {
                    initial_trees_proof,
                    steps,
                }
            })
            .collect_vec();

        FriProofWire {
            commit_phase_merkle_caps,
            query_round_proofs,
            final_poly,
            pow_witness,
        }
    }

    #[count]
    pub fn load_proof(
        &self,
        ctx: &mut ContextWrapper<F>,
        proof: &StarkProof<
            GoldilocksField,
            impl GenericConfig<2, F = GoldilocksField, Hasher = HC::Hasher>,
            2,
        >,
    ) -> StarkProofWire<F, HC::HashWire> {
        let trace_cap = self.load_cap(ctx, &proof.trace_cap);
        let quotient_polys_cap = self.load_cap(ctx, &proof.quotient_polys_cap);

        let openings = self.load_openings_set(ctx, &proof.openings);
        // let fri_openings = self.load_fri_openings(ctx, &proof.openings.to_fri_openings());

        let permutation_zs_cap = proof
            .permutation_zs_cap
            .as_ref()
            .map(|permutation_zs_cap| self.load_cap(ctx, permutation_zs_cap));

        let opening_proof = self.load_fri_proof(ctx, &proof.opening_proof);

        StarkProofWire {
            trace_cap,
            quotient_polys_cap,
            permutation_zs_cap,
            openings,
            opening_proof,
        }
    }

    #[count]
    pub fn load_proof_with_pis(
        &self,
        ctx: &mut ContextWrapper<F>,
        // TODO: Make generic
        proof_with_pis: StarkProofWithPublicInputs<
            GoldilocksField,
            impl GenericConfig<2, F = GoldilocksField, Hasher = HC::Hasher>,
            2,
        >,
    ) -> StarkProofWithPublicInputsWire<F, HC::HashWire> {
        let StarkProofWithPublicInputs {
            proof,
            public_inputs,
        } = proof_with_pis;

        let proof_wire = self.load_proof(ctx, &proof);

        let public_inputs_wire = public_inputs
            .iter()
            .map(|&x| self.load(ctx, x))
            .collect_vec();

        StarkProofWithPublicInputsWire {
            proof: proof_wire,
            public_inputs: public_inputs_wire,
        }
    }
}

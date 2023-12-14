use core::iter::once;
use halo2_base::{utils::ScalarField, Context};
use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    fri::structure::{FriOracleInfo, FriPolynomialInfo},
};
use starky::{config::StarkConfig, permutation::PermutationChallengeSet, stark::Stark};

use crate::{
    challenger::ChallengerChip,
    fri::{
        FriBatchInfoWire, FriChallengesWire, FriChip, FriInstanceInfoWire, FriOpeningBatchWire,
        FriOpeningsWire, FriProofWire,
    },
    goldilocks::{
        extension::{GoldilocksQuadExtChip, GoldilocksQuadExtWire},
        field::GoldilocksWire,
    },
    merkle::MerkleCapWire,
};

pub struct StarkOpeningSetWire<F: ScalarField> {
    pub local_values: Vec<GoldilocksQuadExtWire<F>>,
    pub next_values: Vec<GoldilocksQuadExtWire<F>>,
    pub permutation_zs: Option<Vec<GoldilocksQuadExtWire<F>>>,
    pub permutation_zs_next: Option<Vec<GoldilocksQuadExtWire<F>>>,
    pub quotient_polys: Vec<GoldilocksQuadExtWire<F>>,
}

impl<F: ScalarField> StarkOpeningSetWire<F> {
    pub fn to_fri_openings(&self) -> FriOpeningsWire<F> {
        let zeta_batch = FriOpeningBatchWire {
            values: self
                .local_values
                .iter()
                .chain(self.permutation_zs.iter().flatten())
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatchWire {
            values: self
                .next_values
                .iter()
                .chain(self.permutation_zs_next.iter().flatten())
                .copied()
                .collect_vec(),
        };
        FriOpeningsWire {
            batches: vec![zeta_batch, zeta_next_batch],
        }
    }
}

pub struct StarkProofWire<F: ScalarField> {
    pub trace_cap: MerkleCapWire<F>,
    pub permutation_zs_cap: Option<MerkleCapWire<F>>,
    pub quotient_polys_cap: MerkleCapWire<F>,
    pub openings: StarkOpeningSetWire<F>,
    pub opening_proof: FriProofWire<F>,
}

impl<F: ScalarField> StarkProofWire<F> {
    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }
}

pub struct StarkProofWithPublicInputsWire<F: ScalarField> {
    pub proof: StarkProofWire<F>,
    pub public_inputs: Vec<GoldilocksWire<F>>,
}

pub struct StarkProofChallengesWire<F: ScalarField> {
    pub permutation_challenge_sets: Option<Vec<PermutationChallengeSet<GoldilocksWire<F>>>>,
    pub stark_alphas: Vec<GoldilocksWire<F>>,
    pub stark_zeta: GoldilocksQuadExtWire<F>,
    pub fri_challenges: FriChallengesWire<F>,
}

pub struct StarkChip<F: ScalarField> {
    challenger_chip: ChallengerChip<F>,
    fri_chip: FriChip<F>,
}

impl<F: ScalarField> StarkChip<F> {
    pub fn new(challenger_chip: ChallengerChip<F>, fri_chip: FriChip<F>) -> Self {
        Self {
            challenger_chip,
            fri_chip,
        }
    }

    pub fn extension_chip(&self) -> &GoldilocksQuadExtChip<F> {
        self.fri_chip.extension_chip()
    }

    /// Computes the FRI instance used to prove this Stark.
    fn fri_instance_info<S: Stark<GoldilocksField, 2>>(
        &self,
        ctx: &mut Context<F>,
        stark: S,
        zeta: GoldilocksQuadExtWire<F>,
        g: GoldilocksField,
        config: &StarkConfig,
    ) -> FriInstanceInfoWire<F> {
        let extension_chip = self.extension_chip();

        let mut oracles = vec![];

        let trace_info = FriPolynomialInfo::from_range(oracles.len(), 0..S::COLUMNS);
        oracles.push(FriOracleInfo {
            num_polys: S::COLUMNS,
            blinding: false,
        });

        let permutation_zs_info = if stark.uses_permutation_args() {
            let num_z_polys = stark.num_permutation_batches(config);
            let polys = FriPolynomialInfo::from_range(oracles.len(), 0..num_z_polys);
            oracles.push(FriOracleInfo {
                num_polys: num_z_polys,
                blinding: false,
            });
            polys
        } else {
            vec![]
        };

        let num_quotient_polys = stark.quotient_degree_factor() * config.num_challenges;
        let quotient_info = FriPolynomialInfo::from_range(oracles.len(), 0..num_quotient_polys);
        oracles.push(FriOracleInfo {
            num_polys: num_quotient_polys,
            blinding: false,
        });

        let zeta_batch = FriBatchInfoWire {
            point: zeta,
            polynomials: [
                trace_info.clone(),
                permutation_zs_info.clone(),
                quotient_info,
            ]
            .concat(),
        };
        let g = extension_chip.load_constant(ctx, g.into());
        let zeta_next = extension_chip.mul(ctx, &g, &zeta);
        let zeta_next_batch = FriBatchInfoWire {
            point: zeta_next,
            polynomials: [trace_info, permutation_zs_info].concat(),
        };
        let batches = vec![zeta_batch, zeta_next_batch];

        FriInstanceInfoWire { oracles, batches }
    }

    pub fn verify_proof<S: Stark<GoldilocksField, 2>>(
        &mut self, // TODO: Make this immutable
        ctx: &mut Context<F>,
        stark: S,
        proof_with_pis: StarkProofWithPublicInputsWire<F>,
        inner_config: &StarkConfig,
    ) {
        assert_eq!(proof_with_pis.public_inputs.len(), S::PUBLIC_INPUTS);
        let degree_bits = proof_with_pis.proof.recover_degree_bits(inner_config);
        let challenges = self.challenger_chip.get_stark_challenges::<S>(
            ctx,
            &proof_with_pis.proof,
            &stark,
            inner_config,
        );

        self.verify_proof_with_challenges::<S>(
            ctx,
            stark,
            proof_with_pis,
            challenges,
            inner_config,
            degree_bits,
        );
    }

    pub fn verify_proof_with_challenges<S: Stark<GoldilocksField, 2>>(
        &self,
        ctx: &mut Context<F>,
        stark: S,
        proof_with_pis: StarkProofWithPublicInputsWire<F>,
        challenges: StarkProofChallengesWire<F>,
        inner_config: &StarkConfig,
        degree_bits: usize,
    ) {
        // check_permutation_options(&stark, &proof_with_pis, &challenges).unwrap();
        // let one = builder.one_extension();

        let StarkProofWithPublicInputsWire {
            proof,
            public_inputs,
        } = proof_with_pis;
        let StarkOpeningSetWire {
            local_values,
            next_values,
            permutation_zs,
            permutation_zs_next,
            quotient_polys,
        } = &proof.openings;

        // TODO: Add these back in
        // let vars = S::EvaluationFrameTarget::from_values(
        //     local_values,
        //     next_values,
        //     &public_inputs
        //         .into_iter()
        //         .map(|t| builder.convert_to_ext(t))
        //         .collect::<Vec<_>>(),
        // );

        // let zeta_pow_deg = builder.exp_power_of_2_extension(challenges.stark_zeta, degree_bits);
        // let z_h_zeta = builder.sub_extension(zeta_pow_deg, one);
        // let (l_0, l_last) =
        //     eval_l_0_and_l_last_circuit(builder, degree_bits, challenges.stark_zeta, z_h_zeta);
        // let last = builder
        //     .constant_extension(F::Extension::primitive_root_of_unity(degree_bits).inverse());
        // let z_last = builder.sub_extension(challenges.stark_zeta, last);

        // let mut consumer = RecursiveConstraintConsumer::<F, D>::new(
        //     builder.zero_extension(),
        //     challenges.stark_alphas,
        //     z_last,
        //     l_0,
        //     l_last,
        // );

        // let permutation_data = stark
        //     .uses_permutation_args()
        //     .then(|| PermutationCheckDataTarget {
        //         local_zs: permutation_zs.as_ref().unwrap().clone(),
        //         next_zs: permutation_zs_next.as_ref().unwrap().clone(),
        //         permutation_challenge_sets: challenges.permutation_challenge_sets.unwrap(),
        //     });

        // eval_vanishing_poly_circuit::<F, S, D>(
        //     builder,
        //     &stark,
        //     inner_config,
        //     &vars,
        //     permutation_data,
        //     &mut consumer,
        // );
        // let vanishing_polys_zeta = consumer.accumulators();

        // // Check each polynomial identity, of the form `vanishing(x) = Z_H(x) quotient(x)`, at zeta.
        // let mut scale = ReducingFactorTarget::new(zeta_pow_deg);
        // for (i, chunk) in quotient_polys
        //     .chunks(stark.quotient_degree_factor())
        //     .enumerate()
        // {
        //     let recombined_quotient = scale.reduce(chunk, builder);
        //     let computed_vanishing_poly = builder.mul_extension(z_h_zeta, recombined_quotient);
        //     builder.connect_extension(vanishing_polys_zeta[i], computed_vanishing_poly);
        // }

        let merkle_caps = once(proof.trace_cap)
            .chain(proof.permutation_zs_cap)
            .chain(once(proof.quotient_polys_cap))
            .collect_vec();

        let fri_instance = self.fri_instance_info(
            ctx,
            stark,
            challenges.stark_zeta,
            GoldilocksField::primitive_root_of_unity(degree_bits),
            inner_config,
        );
        self.fri_chip.verify_fri_proof(
            ctx,
            &fri_instance,
            &proof.openings.to_fri_openings(),
            &challenges.fri_challenges,
            &merkle_caps,
            &proof.opening_proof,
            &inner_config.fri_params(degree_bits),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use plonky2::field::types::Field;
    use plonky2::hash::poseidon::SPONGE_WIDTH;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use starky::config::StarkConfig;
    use starky::fibonacci_stark::FibonacciStark;
    use starky::prover::prove;
    use starky::verifier::verify_stark_proof;

    use crate::goldilocks::field::GoldilocksChip;
    use crate::hash::poseidon::hash::PoseidonChip;
    use crate::hash::poseidon::permutation::PoseidonStateWire;
    use crate::merkle::MerkleTreeChip;
    use crate::witness::WitnessChip;

    fn fibonacci<F: Field>(n: usize, x0: F, x1: F) -> F {
        (0..n).fold((x0, x1), |x, _| (x.1, x.0 + x.1)).1
    }

    #[test]
    fn test_fibonacci_stark() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = FibonacciStark<F, D>;

        let config = StarkConfig::standard_fast_config();
        let num_rows = 1 << 5;
        let public_inputs = [F::ZERO, F::ONE, fibonacci(num_rows - 1, F::ZERO, F::ONE)];
        let stark = S::new(num_rows);
        let trace = stark.generate_trace(public_inputs[0], public_inputs[1]);
        let proof_with_pis = prove::<F, C, S, D>(
            stark,
            &config,
            trace,
            &public_inputs,
            &mut TimingTree::default(),
        )?;

        verify_stark_proof(stark, proof_with_pis.clone(), &config)?;

        base_test().k(14).run(|ctx, range| {
            let goldilocks_chip = GoldilocksChip::<Fr>::new(range.clone());
            let extension_chip = GoldilocksQuadExtChip::new(goldilocks_chip.clone());

            let poseidon_chip = PoseidonChip::new(goldilocks_chip.clone());
            let permutation_chip = poseidon_chip.permutation_chip();
            let merkle_chip = MerkleTreeChip::new(poseidon_chip.clone());

            let state = PoseidonStateWire(
                goldilocks_chip.load_constant_array(ctx, &[GoldilocksField::ZERO; SPONGE_WIDTH]),
            );
            let challenger_chip = ChallengerChip::new(permutation_chip.clone(), state);
            let fri_chip = FriChip::new(extension_chip, merkle_chip);
            let mut stark_chip = StarkChip::new(challenger_chip, fri_chip);

            let witness_chip = WitnessChip::new();

            let proof_with_pis = witness_chip.load_proof_with_pis(ctx, proof_with_pis);

            stark_chip.verify_proof(ctx, stark, proof_with_pis, &config);
        });

        Ok(())
    }
}

use halo2_base::gates::{GateChip, RangeChip, RangeInstructions};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use itertools::Itertools;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::interpolation::barycentric_weights;
use plonky2::field::types::Field;
use plonky2::fri::structure::{FriOracleInfo, FriPolynomialInfo};
use plonky2::fri::{FriConfig, FriParams};
use plonky2::util::{log2_strict, reverse_index_bits_in_place};

use crate::goldilocks::extension::{GoldilocksQuadExtChip, GoldilocksQuadExtWire};
use crate::goldilocks::field::{GoldilocksChip, GoldilocksWire};
use crate::goldilocks::BoolWire;
use crate::hash::poseidon::hash::PoseidonChip;
use crate::hash::HashOutWire;
use crate::merkle::{MerkleCapWire, MerkleProofWire, MerkleTreeChip};

pub struct FriInstanceInfoWire<F: ScalarField> {
    pub oracles: Vec<FriOracleInfo>,
    pub batches: Vec<FriBatchInfoWire<F>>,
}

pub struct FriBatchInfoWire<F: ScalarField> {
    pub point: GoldilocksQuadExtWire<F>,
    pub polynomials: Vec<FriPolynomialInfo>,
}

pub struct FriOpeningsWire<F: ScalarField> {
    pub batches: Vec<FriOpeningBatchWire<F>>,
}

pub struct FriOpeningBatchWire<F: ScalarField> {
    pub values: Vec<GoldilocksQuadExtWire<F>>,
}

pub struct PrecomputedReducedOpeningsWire<F: ScalarField> {
    reduced_openings_at_point: Vec<GoldilocksQuadExtWire<F>>,
}

pub struct ReducingFactorWire<F: ScalarField> {
    base: GoldilocksQuadExtWire<F>,
    count: u64,
}

impl<F: ScalarField> PrecomputedReducedOpeningsWire<F> {
    fn from_os_and_alpha(
        ctx: &mut Context<F>,
        extension_chip: &GoldilocksQuadExtChip<F>,
        openings: &FriOpeningsWire<F>,
        alpha: &GoldilocksQuadExtWire<F>,
    ) -> Self {
        let reduced_openings_at_point = openings
            .batches
            .iter()
            .map(|batch| extension_chip.reduce_with_powers(ctx, &batch.values, alpha))
            .collect();
        Self {
            reduced_openings_at_point,
        }
    }
}

pub struct FriChallengesWire<F: ScalarField> {
    pub fri_alpha: GoldilocksQuadExtWire<F>,
    pub fri_betas: Vec<GoldilocksQuadExtWire<F>>,
    pub fri_pow_response: GoldilocksWire<F>,
    pub fri_query_indices: Vec<GoldilocksWire<F>>,
}

pub struct PolynomialCoeffsExtWire<F: ScalarField>(pub Vec<GoldilocksQuadExtWire<F>>);

pub struct FriProofWire<F: ScalarField> {
    pub commit_phase_merkle_caps: Vec<MerkleCapWire<F>>,
    pub query_round_proofs: Vec<FriQueryRoundWire<F>>,
    pub final_poly: PolynomialCoeffsExtWire<F>,
    pub pow_witness: GoldilocksWire<F>,
}

pub struct FriInitialTreeProofWire<F: ScalarField> {
    pub evals_proofs: Vec<(Vec<GoldilocksWire<F>>, MerkleProofWire<F>)>,
}

pub struct FriQueryStepWire<F: ScalarField> {
    pub evals: Vec<GoldilocksQuadExtWire<F>>,
    pub merkle_proof: MerkleProofWire<F>,
}

pub struct FriQueryRoundWire<F: ScalarField> {
    pub initial_trees_proof: FriInitialTreeProofWire<F>,
    pub steps: Vec<FriQueryStepWire<F>>,
}

pub struct FriPrecomputedReducedEvalWire<F: ScalarField> {
    pub precomputed_reduced_evals: PrecomputedReducedOpeningsWire<F>,
    pub precomputed_reduced_evals_hash: HashOutWire<F>,
}

pub struct FriChip<F: ScalarField> {
    extension_chip: GoldilocksQuadExtChip<F>,
    merkle_tree_chip: MerkleTreeChip<F>,
}

impl<F: ScalarField> FriChip<F> {
    pub fn new(
        extension_chip: GoldilocksQuadExtChip<F>,
        merkle_tree_chip: MerkleTreeChip<F>,
    ) -> Self {
        Self {
            extension_chip,
            merkle_tree_chip,
        }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.merkle_tree_chip.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.merkle_tree_chip.range()
    }

    pub fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        self.merkle_tree_chip.goldilocks_chip()
    }

    pub fn poseidon_chip(&self) -> &PoseidonChip<F> {
        &self.merkle_tree_chip.poseidon_chip()
    }

    pub fn extension_chip(&self) -> &GoldilocksQuadExtChip<F> {
        &self.extension_chip
    }

    pub fn merkle_tree_chip(&self) -> &MerkleTreeChip<F> {
        &self.merkle_tree_chip
    }

    fn verify_proof_of_work(
        &self,
        ctx: &mut Context<F>,
        fri_pow_response: GoldilocksWire<F>,
        config: &FriConfig,
    ) {
        let range_chip = self.range();
        // Assert `proof_of_work_bits` leading zeros in `fri_pow_response`
        // i.e. max value of `fri_pow_response` is less than `2^(64 - proof_of_work_bits)`
        range_chip.range_check(
            ctx,
            fri_pow_response.0,
            GoldilocksField::BITS - config.proof_of_work_bits as usize,
        );
    }

    fn verify_initial_proof(
        &self,
        ctx: &mut Context<F>,
        x_index_bits: &[BoolWire<F>],
        proof: &FriInitialTreeProofWire<F>,
        initial_merkle_caps: &[MerkleCapWire<F>],
        cap_index: &GoldilocksWire<F>,
    ) {
        let merkle_tree_chip = self.merkle_tree_chip();
        for ((evals, merkle_proof), cap) in proof.evals_proofs.iter().zip(initial_merkle_caps) {
            merkle_tree_chip.verify_proof_to_cap_with_cap_index(
                ctx,
                evals.as_slice(),
                x_index_bits,
                cap_index,
                cap,
                merkle_proof,
            );
        }
    }

    fn combine_initial(
        &self,
        ctx: &mut Context<F>,
        instance: &FriInstanceInfoWire<F>,
        proof: &FriInitialTreeProofWire<F>,
        alpha: &GoldilocksQuadExtWire<F>,
        subgroup_x: GoldilocksWire<F>,
        precomputed_reduced_evals: &PrecomputedReducedOpeningsWire<F>,
        params: &FriParams,
    ) -> GoldilocksQuadExtWire<F> {
        let extension_chip = self.extension_chip();

        let degree_log = params.degree_bits;
        debug_assert_eq!(
            degree_log,
            params.config.cap_height + proof.evals_proofs[0].1.siblings.len()
                - params.config.rate_bits
        );
        let subgroup_x = extension_chip.from_base(ctx, &subgroup_x);
        let mut sum = extension_chip.load_zero(ctx);

        for (batch, reduced_openings) in instance
            .batches
            .iter()
            .zip(&precomputed_reduced_evals.reduced_openings_at_point)
        {
            let FriBatchInfoWire { point, polynomials } = batch;
            let evals = polynomials
                .iter()
                // TODO: Blinding
                .map(|p| {
                    extension_chip.from_base(
                        ctx,
                        &proof.evals_proofs[p.oracle_index].0[p.polynomial_index],
                    )
                })
                .collect_vec();
            // TODO: Is there a more optimal method?
            let reduced_evals = extension_chip.reduce_with_powers(ctx, &evals, alpha);

            let numerator = extension_chip.sub(ctx, &reduced_evals, reduced_openings);
            let denominator = extension_chip.sub(ctx, &subgroup_x, point);
            let denominator_inv = extension_chip.inv(ctx, &denominator);

            let alpha_shift = extension_chip.exp_u64(ctx, alpha, evals.len() as u64);
            sum = extension_chip.mul(ctx, &alpha_shift, &sum);
            sum = extension_chip.mul_add(ctx, &numerator, &denominator_inv, &sum);
        }

        sum
    }

    fn interpolate_coset(
        &self,
        ctx: &mut Context<F>,
        coset_shift: &GoldilocksWire<F>,
        values: &[GoldilocksQuadExtWire<F>],
        evaluation_point: GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        // The answer is gotten by interpolating {(x*g^i, P(x*g^i))} and evaluating at beta.
        let n = values.len();
        let arity_bits = log2_strict(n);

        let goldilocks_chip = self.goldilocks_chip();
        let extension_chip = self.extension_chip();

        let shifted_evaluation_point =
            extension_chip.scalar_div(ctx, &evaluation_point, &coset_shift);

        let domain = GoldilocksField::two_adic_subgroup(arity_bits)
            .iter()
            .map(|&x| extension_chip.load_constant(ctx, x.into()))
            .collect_vec();

        // wi = \prod_{j \neq i} \frac{1}{x_j - x_i}
        let barycentric_weights = barycentric_weights(
            &GoldilocksField::two_adic_subgroup(arity_bits)
                .into_iter()
                .map(|x| (x, GoldilocksField::ZERO))
                .collect::<Vec<_>>(),
        )
        .iter()
        .map(|&x| goldilocks_chip.load_constant(ctx, x))
        .collect_vec();

        let weighted_values = values
            .iter()
            .zip(barycentric_weights.iter())
            .map(|(value, weight)| extension_chip.scalar_mul(ctx, value, weight))
            .collect_vec();

        let initial_eval = extension_chip.load_zero(ctx);
        let initial_partial_prod =
            extension_chip.load_constant(ctx, QuadraticExtension::<GoldilocksField>::ONE); // TODO: Create helper

        weighted_values
            .iter()
            .zip(domain.iter())
            .fold(
                (initial_eval, initial_partial_prod),
                |(eval, terms_partial_prod), (val, x_i)| {
                    let term = extension_chip.sub(ctx, &shifted_evaluation_point, x_i);
                    let next_terms_partial_prod =
                        extension_chip.mul(ctx, &terms_partial_prod, &term);

                    let tmp1 = extension_chip.mul(ctx, &eval, &term);
                    let tmp2 = extension_chip.mul(ctx, &val, &terms_partial_prod);
                    let next_eval = extension_chip.add(ctx, &tmp1, &tmp2);

                    (next_eval, next_terms_partial_prod)
                },
            )
            .0
    }

    fn compute_evaluation(
        &self,
        ctx: &mut Context<F>,
        x: &GoldilocksWire<F>,
        x_index_within_coset_bits: &[BoolWire<F>],
        arity_bits: usize,
        evals: &[GoldilocksQuadExtWire<F>],
        beta: GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let goldilocks_chip = self.goldilocks_chip();

        let arity = 1 << arity_bits;
        debug_assert_eq!(evals.len(), arity);

        let g = GoldilocksField::primitive_root_of_unity(arity_bits);
        let g_inv = g.exp_u64((arity as u64) - 1);

        // The evaluation vector needs to be reordered first.
        let mut evals = evals.to_vec();
        reverse_index_bits_in_place(&mut evals);
        // Want `g^(arity - rev_x_index_within_coset)` as in the out-of-circuit version. Compute it
        // as `(g^-1)^rev_x_index_within_coset`.
        let start = goldilocks_chip.exp_from_bits_const_base(
            ctx,
            &g_inv,
            // TODO: How to avoid this clone?
            x_index_within_coset_bits
                .iter()
                .rev()
                .cloned()
                .collect_vec()
                .as_slice(),
        );
        let coset_start = goldilocks_chip.mul(ctx, &start, x);

        self.interpolate_coset(ctx, &coset_start, &evals, beta)
    }

    fn eval_scalar(
        &self,
        ctx: &mut Context<F>,
        poly: &PolynomialCoeffsExtWire<F>,
        point: &GoldilocksWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let extension_chip = self.extension_chip();

        let point = extension_chip.from_base(ctx, point);
        extension_chip.reduce_with_powers(ctx, poly.0.as_slice(), &point)
    }

    fn verify_query_round(
        &self,
        ctx: &mut Context<F>,
        instance: &FriInstanceInfoWire<F>,
        challenges: &FriChallengesWire<F>,
        precomputed_reduced_evals: &PrecomputedReducedOpeningsWire<F>,
        initial_merkle_caps: &[MerkleCapWire<F>],
        proof: &FriProofWire<F>,
        x_index: GoldilocksWire<F>,
        n: usize,
        round_proof: &FriQueryRoundWire<F>,
        params: &FriParams,
    ) {
        let n_log = log2_strict(n);

        let goldilocks_chip = self.goldilocks_chip();
        let extension_chip = self.extension_chip();

        // Note that this `low_bits` decomposition permits non-canonical binary encodings. Here we
        // verify that this has a negligible impact on soundness error.
        // TODO
        // Self::assert_noncanonical_indices_ok(&params.config);
        // TODO: Do I need to check if x_index < n?
        let mut x_index_bits = goldilocks_chip.num_to_bits(ctx, &x_index, n_log);

        let cap_index = goldilocks_chip.bits_to_num(
            ctx,
            &x_index_bits[x_index_bits.len() - params.config.cap_height..],
        );
        self.verify_initial_proof(
            ctx,
            &x_index_bits,
            &round_proof.initial_trees_proof,
            initial_merkle_caps,
            &cap_index,
        );

        // `subgroup_x` is `subgroup[x_index]`, i.e., the actual field element in the domain.
        let mut subgroup_x = {
            let g = goldilocks_chip.load_constant(ctx, GoldilocksField::coset_shift());
            let phi = GoldilocksField::primitive_root_of_unity(n_log);
            let phi = goldilocks_chip.exp_from_bits_const_base(
                ctx,
                &phi,
                x_index_bits.iter().copied().rev().collect_vec().as_slice(),
            );
            // subgroup_x = g * phi
            goldilocks_chip.mul(ctx, &g, &phi)
        };

        // old_eval is the last derived evaluation; it will be checked for consistency with its
        // committed "parent" value in the next iteration.
        let mut old_eval = self.combine_initial(
            ctx,
            instance,
            &round_proof.initial_trees_proof,
            &challenges.fri_alpha,
            subgroup_x,
            precomputed_reduced_evals,
            params,
        );

        for (i, &arity_bits) in params.reduction_arity_bits.iter().enumerate() {
            let evals = &round_proof.steps[i].evals;

            // Split x_index into the index of the coset x is in, and the index of x within that coset.
            let coset_index_bits = x_index_bits[arity_bits..].to_vec();
            let x_index_within_coset_bits = &x_index_bits[..arity_bits];
            let x_index_within_coset = goldilocks_chip.bits_to_num(ctx, x_index_within_coset_bits);

            // Check consistency with our old evaluation from the previous round.
            let new_eval = extension_chip.select_from_idx(
                ctx,
                // TODO: Ugly
                evals,
                &x_index_within_coset,
            );
            extension_chip.assert_equal(ctx, &new_eval, &old_eval);

            // Infer P(y) from {P(x)}_{x^arity=y}.
            old_eval = self.compute_evaluation(
                ctx,
                &subgroup_x,
                x_index_within_coset_bits,
                arity_bits,
                evals,
                challenges.fri_betas[i],
            );

            self.merkle_tree_chip.verify_proof_to_cap_with_cap_index(
                ctx,
                &evals.iter().flat_map(|x| x.0).collect_vec(),
                &coset_index_bits,
                &cap_index,
                &proof.commit_phase_merkle_caps[i],
                &round_proof.steps[i].merkle_proof,
            );

            // Update the point x to x^arity.
            subgroup_x = goldilocks_chip.exp_power_of_2(ctx, &subgroup_x, arity_bits);

            x_index_bits = coset_index_bits;
        }

        // Final check of FRI. After all the reductions, we check that the final polynomial is equal
        // to the one sent by the prover.
        let eval = self.eval_scalar(ctx, &proof.final_poly, &subgroup_x);
        extension_chip.assert_equal(ctx, &eval, &old_eval);
    }

    fn verify_fri_proof(
        &self,
        ctx: &mut Context<F>,
        instance: &FriInstanceInfoWire<F>,
        openings: &FriOpeningsWire<F>,
        challenges: &FriChallengesWire<F>,
        initial_merkle_caps: &[MerkleCapWire<F>],
        proof: &FriProofWire<F>,
        params: &FriParams,
    ) {
        // TODO
        // validateFriProofShape(friProof, instance, f.friParams)

        // TODO
        // if let Some(max_arity_bits) = params.max_arity_bits() {
        //     self.check_recursion_config(max_arity_bits);
        // }

        debug_assert_eq!(
            params.final_poly_len(),
            proof.final_poly.0.len(),
            "Final polynomial has wrong degree."
        );

        // Size of the LDE domain.
        let n = params.lde_size();

        self.verify_proof_of_work(ctx, challenges.fri_pow_response, &params.config);

        // Check that parameters are coherent.
        debug_assert_eq!(
            params.config.num_query_rounds,
            proof.query_round_proofs.len(),
            "Number of query rounds does not match config."
        );

        let precomputed_reduced_evals = PrecomputedReducedOpeningsWire::from_os_and_alpha(
            ctx,
            self.extension_chip(),
            openings,
            &challenges.fri_alpha,
        );

        for (i, round_proof) in proof.query_round_proofs.iter().enumerate() {
            self.verify_query_round(
                ctx,
                instance,
                challenges,
                &precomputed_reduced_evals,
                initial_merkle_caps,
                proof,
                challenges.fri_query_indices[i],
                n,
                round_proof,
                params,
            );
        }
    }
}
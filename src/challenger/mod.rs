use halo2_base::utils::BigPrimeField;
use halo2_base::Context;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::fri::FriConfig;
use starky::config::StarkConfig;
use starky::permutation::{PermutationChallenge, PermutationChallengeSet};
use starky::stark::Stark;

use crate::fri::{FriChallengesWire, FriOpeningsWire, FriProofWire, PolynomialCoeffsExtWire};
use crate::goldilocks::extension::GoldilocksQuadExtWire;
use crate::goldilocks::field::GoldilocksWire;
use crate::hash::{HasherChip, PermutationChip};
use crate::merkle::MerkleCapWire;
use crate::stark::{StarkProofChallengesWire, StarkProofWire};

pub struct ChallengerChip<F: BigPrimeField, HC: HasherChip<F>> {
    hasher_chip: HC,
    // TODO: Ugly
    sponge_state: <HC::PermutationChip as PermutationChip<F>>::StateWire,
    input_buffer: Vec<GoldilocksWire<F>>,
    output_buffer: Vec<GoldilocksWire<F>>,
}

impl<F: BigPrimeField, HC: HasherChip<F>> ChallengerChip<F, HC> {
    // TODO: Initialize state as zero.
    pub fn new(
        hasher_chip: HC,
        state: <HC::PermutationChip as PermutationChip<F>>::StateWire,
    ) -> Self {
        Self {
            hasher_chip,
            sponge_state: state,
            input_buffer: vec![],
            output_buffer: vec![],
        }
    }

    pub fn permutation_chip(&self) -> &HC::PermutationChip {
        self.hasher_chip.permutation_chip()
    }

    pub fn observe_element(&mut self, target: &GoldilocksWire<F>) {
        // Any buffered outputs are now invalid, since they wouldn't reflect this input.
        self.output_buffer.clear();

        self.input_buffer.push(*target);
    }

    pub fn observe_elements(&mut self, targets: &[GoldilocksWire<F>]) {
        for target in targets {
            self.observe_element(target);
        }
    }

    // TODO: What if we want to observe a different hash type than the one used by the challenger's hasher chip?
    pub fn observe_hash(&mut self, ctx: &mut Context<F>, hash: &HC::HashWire) {
        self.observe_elements(self.hasher_chip.to_goldilocks_vec(ctx, hash).as_slice())
    }

    pub fn observe_cap(&mut self, ctx: &mut Context<F>, cap: &MerkleCapWire<F, HC::HashWire>) {
        for hash in &cap.0 {
            self.observe_hash(ctx, hash)
        }
    }

    pub fn observe_extension_element(&mut self, element: GoldilocksQuadExtWire<F>) {
        self.observe_elements(&element.0);
    }

    pub fn observe_extension_elements(&mut self, elements: &[GoldilocksQuadExtWire<F>]) {
        for &element in elements {
            self.observe_extension_element(element);
        }
    }

    pub fn observe_openings(&mut self, openings: &FriOpeningsWire<F>) {
        for v in &openings.batches {
            self.observe_extension_elements(&v.values);
        }
    }

    pub fn get_challenge(&mut self, ctx: &mut Context<F>) -> GoldilocksWire<F> {
        self.absorb_buffered_inputs(ctx);

        // TODO: This is some weird error.
        // let permutation_chip = self.permutation_chip();
        let permutation_chip = self.hasher_chip.permutation_chip();
        if self.output_buffer.is_empty() {
            // Evaluate the permutation to produce `r` new outputs.
            self.sponge_state = permutation_chip.permute(ctx, &self.sponge_state);
            self.output_buffer = permutation_chip
                .squeeze_goldilocks(&self.sponge_state)
                .to_vec();
        }

        self.output_buffer
            .pop()
            .expect("Output buffer should be non-empty")
    }

    pub fn get_n_challenges(&mut self, ctx: &mut Context<F>, n: usize) -> Vec<GoldilocksWire<F>> {
        (0..n).map(|_| self.get_challenge(ctx)).collect()
    }

    pub fn get_extension_challenge(&mut self, ctx: &mut Context<F>) -> GoldilocksQuadExtWire<F> {
        // TODO: Remove hardcode
        GoldilocksQuadExtWire(self.get_n_challenges(ctx, 2).try_into().unwrap())
    }

    pub fn get_fri_challenges(
        &mut self,
        ctx: &mut Context<F>,
        commit_phase_merkle_caps: &[MerkleCapWire<F, HC::HashWire>],
        final_poly: &PolynomialCoeffsExtWire<F>,
        pow_witness: &GoldilocksWire<F>,
        inner_fri_config: &FriConfig,
    ) -> FriChallengesWire<F> {
        let num_fri_queries = inner_fri_config.num_query_rounds;
        // Scaling factor to combine polynomials.
        let fri_alpha = self.get_extension_challenge(ctx);

        // Recover the random betas used in the FRI reductions.
        let fri_betas = commit_phase_merkle_caps
            .iter()
            .map(|cap| {
                self.observe_cap(ctx, cap);
                self.get_extension_challenge(ctx)
            })
            .collect();

        self.observe_extension_elements(&final_poly.0);

        self.observe_element(pow_witness);
        let fri_pow_response = self.get_challenge(ctx);

        let fri_query_indices = (0..num_fri_queries)
            .map(|_| self.get_challenge(ctx))
            .collect();

        FriChallengesWire {
            fri_alpha,
            fri_betas,
            fri_pow_response,
            fri_query_indices,
        }
    }

    pub fn get_stark_challenges<S: Stark<GoldilocksField, 2>>(
        &mut self,
        ctx: &mut Context<F>,
        proof: &StarkProofWire<F, HC::HashWire>,
        stark: &S,
        config: &StarkConfig,
    ) -> StarkProofChallengesWire<F> {
        let StarkProofWire {
            trace_cap,
            permutation_zs_cap,
            quotient_polys_cap,
            openings,
            opening_proof:
                FriProofWire {
                    commit_phase_merkle_caps,
                    final_poly,
                    pow_witness,
                    ..
                },
        } = proof;

        let num_challenges = config.num_challenges;

        self.observe_cap(ctx, trace_cap);

        let permutation_challenge_sets = permutation_zs_cap.as_ref().map(|permutation_zs_cap| {
            let tmp = self.get_n_permutation_challenge_sets(
                ctx,
                num_challenges,
                stark.permutation_batch_size(),
            );
            self.observe_cap(ctx, permutation_zs_cap);
            tmp
        });

        let stark_alphas = self.get_n_challenges(ctx, num_challenges);

        self.observe_cap(ctx, quotient_polys_cap);
        let stark_zeta = self.get_extension_challenge(ctx);

        self.observe_openings(&openings.to_fri_openings());

        StarkProofChallengesWire {
            permutation_challenge_sets,
            stark_alphas,
            stark_zeta,
            fri_challenges: self.get_fri_challenges(
                ctx,
                commit_phase_merkle_caps,
                final_poly,
                pow_witness,
                &config.fri_config,
            ),
        }
    }

    fn get_permutation_challenge(
        &mut self,
        ctx: &mut Context<F>,
    ) -> PermutationChallenge<GoldilocksWire<F>> {
        let beta = self.get_challenge(ctx);
        let gamma = self.get_challenge(ctx);
        PermutationChallenge { beta, gamma }
    }

    fn get_permutation_challenge_set(
        &mut self,
        ctx: &mut Context<F>,
        num_challenges: usize,
    ) -> PermutationChallengeSet<GoldilocksWire<F>> {
        let challenges = (0..num_challenges)
            .map(|_| self.get_permutation_challenge(ctx))
            .collect();
        PermutationChallengeSet { challenges }
    }

    fn get_n_permutation_challenge_sets(
        &mut self,
        ctx: &mut Context<F>,
        num_challenges: usize,
        num_sets: usize,
    ) -> Vec<PermutationChallengeSet<GoldilocksWire<F>>> {
        (0..num_sets)
            .map(|_| self.get_permutation_challenge_set(ctx, num_challenges))
            .collect()
    }

    /// Absorb any buffered inputs. After calling this, the input buffer will be empty, and the
    /// output buffer will be full.
    fn absorb_buffered_inputs(&mut self, ctx: &mut Context<F>) {
        // TODO: This is some weird error.
        // let permutation_chip = self.permutation_chip();
        let permutation_chip = self.hasher_chip.permutation_chip();

        if self.input_buffer.is_empty() {
            return;
        }

        self.sponge_state =
            permutation_chip.absorb_goldilocks(ctx, &self.sponge_state, &self.input_buffer);

        // TODO: squeeze -> to_goldilocks_vec
        self.output_buffer = permutation_chip
            .squeeze_goldilocks(&self.sponge_state)
            .to_vec();

        self.input_buffer.clear();
    }
}

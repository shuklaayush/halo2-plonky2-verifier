// #![cfg_attr(not(feature = "std"), no_std)]

mod goldilocks;
mod hash;
mod merkle;

/*
#[cfg(test)]
mod tests {
    use super::*;

    use starky::fibonacci_stark::FibonacciStark;

    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;

    use core::iter::once;
    use itertools::Itertools;
    use plonky2::fri::verifier::verify_fri_proof;
    use starky::config::StarkConfig;
    use starky::proof::StarkProofWithPublicInputs;
    use starky::prover::prove;
    use starky::stark::Stark;
    use starky::verifier::verify_stark_proof;

    fn fibonacci<F: Field>(n: usize, x0: F, x1: F) -> F {
        (0..n).fold((x0, x1), |x, _| (x.1, x.0 + x.1)).1
    }

    use std::fs::File;
    use std::io::{BufReader, BufWriter, Write};

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

        let file = File::create("proof.json")?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &proof_with_pis)?;
        writer.flush()?;

        // verify_stark_proof(stark, proof_with_pis.clone(), &config);

        // let StarkProofWithPublicInputs {
        //     proof,
        //     public_inputs,
        // } = proof_with_pis;

        // let degree_bits = proof_with_pis.proof.recover_degree_bits(&config);
        // let challenges = proof_with_pis.get_challenges(&stark, &config, degree_bits);

        // let merkle_caps = once(proof_with_pis.proof.trace_cap)
        //     .chain(proof_with_pis.proof.permutation_zs_cap)
        //     .chain(once(proof_with_pis.proof.quotient_polys_cap))
        //     .collect_vec();

        // verify_fri_proof::<F, C, D>(
        //     &stark.fri_instance(
        //         challenges.stark_zeta,
        //         F::primitive_root_of_unity(degree_bits),
        //         &config,
        //     ),
        //     &proof_with_pis.proof.openings.to_fri_openings(),
        //     &challenges.fri_challenges,
        //     &merkle_caps,
        //     &proof_with_pis.proof.opening_proof,
        //     &config.fri_params(degree_bits),
        // )?;

        Ok(())
    }

    #[test]
    fn test_deser_proof() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let file = File::open("test_data/keccak_proof.json")?;
        let reader = BufReader::new(file);
        let proof_with_pis: StarkProofWithPublicInputs<F, C, D> = serde_json::from_reader(reader)?;

        let merkle_caps = proof_with_pis.proof.opening_proof.commit_phase_merkle_caps;
        let queries = proof_with_pis.proof.opening_proof.query_round_proofs;

        println!("{:?}", merkle_caps.len());
        println!("{:?}", queries.len());

        let query = queries[0].clone().steps;
        println!("{:?}", query.len());

        // One cap for each FRI round
        // Each cap is number of tree nodes at height
        // Each node is 4 u64 limbs (256 bit)
        let merkle_caps_fp = merkle_caps
            .iter()
            .map(|cap| {
                cap.0
                    .iter()
                    .map(|node| {
                        node.elements
                            .iter()
                            .map(|limb| Fp::from(limb.0))
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        // Total queries used in FRI
        // Each query is number of round steps
        // Each step is arity number of evaluations (16 by default)
        // Each evaluation is an extended field element - 2 u64 limbs (128 bit)
        let queries_evals_fp = queries
            .iter()
            .map(|query| {
                query
                    .steps
                    .iter()
                    .map(|step| {
                        step.evals
                            .iter()
                            .map(|limb_ext| [Fp::from(limb_ext.0[0].0), Fp::from(limb_ext.0[1].0)])
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        let queries_proofs_fp = queries
            .iter()
            .map(|query| {
                query
                    .steps
                    .iter()
                    .map(|step| {
                        step.merkle_proof
                            .siblings
                            .iter()
                            .map(|node| {
                                node.elements
                                    .iter()
                                    .map(|limb| Fp::from(limb.0))
                                    .collect_vec()
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();

        println!("{:?}", queries_evals_fp[0][0][0].len());
        println!("{:?}", queries_proofs_fp[0]);

        Ok(())
    }
}
*/

use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use plonky2::field::extension::Extendable;
use plonky2::field::extension::FieldExtension;
use plonky2::field::types::PrimeField64;

use super::fp::{Fp, FpChip};
use crate::fields::FieldChip;

// TODO: Use const generics for arbitrary extension
#[derive(Debug, Clone)]
pub struct Fp2<F: ScalarField, F64: PrimeField64 + Extendable<2>>([Fp<F, F64>; 2]);

// TODO: Reference and lifetimes? Should Fp2Chip own FpChip?
#[derive(Debug, Clone)]
pub struct Fp2Chip<F: ScalarField, F64: PrimeField64 + Extendable<2>> {
    pub fp_chip: FpChip<F, F64>,
}

impl<F: ScalarField, F64: PrimeField64 + Extendable<2>> Fp2Chip<F, F64> {
    pub fn new(fp_chip: FpChip<F, F64>) -> Self {
        Self { fp_chip }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.fp_chip.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.fp_chip.range()
    }

    pub fn load_constant(&self, ctx: &mut Context<F>, a: F64::Extension) -> Fp2<F, F64> {
        let [a0, a1] = a.to_basefield_array();

        Fp2([
            self.fp_chip.load_constant(ctx, a0),
            self.fp_chip.load_constant(ctx, a1),
        ])
    }

    fn load_constants<const N: usize>(
        &self,
        ctx: &mut Context<F>,
        a: &[F64::Extension; N],
    ) -> [Fp2<F, F64>; N] {
        a.iter()
            .map(|a| self.load_constant(ctx, *a))
            .collect::<Vec<Fp2<F, F64>>>() // TODO: There must be a better way
            .try_into()
            .unwrap()
    }

    pub fn load_witness(&self, ctx: &mut Context<F>, a: F64::Extension) -> Fp2<F, F64> {
        let [a0, a1] = a.to_basefield_array();

        Fp2([
            self.fp_chip.load_witness(ctx, a0),
            self.fp_chip.load_witness(ctx, a1),
        ])
    }

    pub fn add(&self, ctx: &mut Context<F>, a: &Fp2<F, F64>, b: &Fp2<F, F64>) -> Fp2<F, F64> {
        let Fp2([a0, a1]) = a;
        let Fp2([b0, b1]) = b;

        Fp2([
            self.fp_chip.add(ctx, &a0, &b0),
            self.fp_chip.add(ctx, &a1, &b1),
        ])
    }

    pub fn sub(&self, ctx: &mut Context<F>, a: &Fp2<F, F64>, b: &Fp2<F, F64>) -> Fp2<F, F64> {
        let Fp2([a0, a1]) = a;
        let Fp2([b0, b1]) = b;

        Fp2([
            self.fp_chip.sub(ctx, &a0, &b0),
            self.fp_chip.sub(ctx, &a1, &b1),
        ])
    }

    pub fn mul(&self, ctx: &mut Context<F>, a: &Fp2<F, F64>, b: &Fp2<F, F64>) -> Fp2<F, F64> {
        let Fp2([a0, a1]) = a;
        let Fp2([b0, b1]) = b;

        let w = self.fp_chip.load_constant(ctx, F64::W); // TODO: Cache
        let a0b0 = self.fp_chip.mul(ctx, &a0, &b0);
        let a1b1 = self.fp_chip.mul(ctx, &a1, &b1);
        let wa1b1 = self.fp_chip.mul(ctx, &w, &a1b1);
        let c0 = self.fp_chip.add(ctx, &a0b0, &wa1b1);

        let a0b1 = self.fp_chip.mul(ctx, &a0, &b1);
        let a1b0 = self.fp_chip.mul(ctx, &a1, &b0);
        let c1 = self.fp_chip.add(ctx, &a0b1, &a1b0);

        Fp2([c0, c1])
    }

    pub fn mul_add(
        &self,
        ctx: &mut Context<F>,
        a: &Fp2<F, F64>,
        b: &Fp2<F, F64>,
        c: &Fp2<F, F64>,
    ) -> Fp2<F, F64> {
        let ab = self.mul(ctx, a, b);
        self.add(ctx, &ab, c)
    }

    pub fn range_check(&self, ctx: &mut Context<F>, a: &Fp2<F, F64>) {
        let Fp2([a0, a1]) = a;

        self.fp_chip.range_check(ctx, &a0);
        self.fp_chip.range_check(ctx, &a1);
    }

    pub fn assert_equal(&self, ctx: &mut Context<F>, a: &Fp2<F, F64>, b: &Fp2<F, F64>) {
        let Fp2([a0, a1]) = a;
        let Fp2([b0, b1]) = b;

        self.fp_chip.assert_equal(ctx, &a0, &b0);
        self.fp_chip.assert_equal(ctx, &a1, &b1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use plonky2::field::extension::quadratic::QuadraticExtension;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Sample;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_fp2_chip() {
        let mut rng = StdRng::seed_from_u64(0);

        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = RangeCircuitBuilder::default().use_k(k as usize);
        builder.set_lookup_bits(lookup_bits);

        let fp_chip =
            FpChip::<Fr, GoldilocksField>::new(lookup_bits, builder.lookup_manager().clone());
        let fp2_chip = Fp2Chip::new(fp_chip);

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);

        for _ in 0..100 {
            let a = QuadraticExtension::sample(&mut rng);
            let b = QuadraticExtension::sample(&mut rng);

            let c1 = fp2_chip.load_constant(ctx, a * b);

            let a_wire = fp2_chip.load_constant(ctx, a);
            let b_wire = fp2_chip.load_constant(ctx, b);
            let c2 = fp2_chip.mul(ctx, &a_wire, &b_wire);

            fp2_chip.assert_equal(ctx, &c1, &c2);
        }

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }
}

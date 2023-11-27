use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::extension::Extendable;
use plonky2::field::extension::FieldExtension;
use plonky2::field::goldilocks_field::GoldilocksField;

use super::field::{GoldilocksChip, GoldilocksWire};

// TODO: Use const generics for arbitrary GoldilocksExtWire
#[derive(Copy, Clone, Debug)]
pub struct GoldilocksQuadExtWire<F: ScalarField>([GoldilocksWire<F>; 2]);

impl<F: ScalarField> GoldilocksQuadExtWire<F> {
    pub fn value(&self) -> QuadraticExtension<GoldilocksField> {
        let val1 = self.0[0].value();
        let val2 = self.0[1].value();
        QuadraticExtension::from_basefield_array([val1, val2])
    }
}

// TODO: Reference and lifetimes? Should GoldilocksExtensionChip own GoldilocksChip?
#[derive(Debug, Clone)]
pub struct GoldilocksQuadExtChip<F: ScalarField> {
    pub goldilocks_chip: GoldilocksChip<F>,
}

impl<F: ScalarField> GoldilocksQuadExtChip<F> {
    pub fn new(goldilocks_chip: GoldilocksChip<F>) -> Self {
        Self { goldilocks_chip }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.goldilocks_chip.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.goldilocks_chip.range()
    }

    pub fn load_constant(
        &self,
        ctx: &mut Context<F>,
        a: QuadraticExtension<GoldilocksField>,
    ) -> GoldilocksQuadExtWire<F> {
        let [a0, a1] = a.to_basefield_array();

        GoldilocksQuadExtWire([
            self.goldilocks_chip.load_constant(ctx, a0),
            self.goldilocks_chip.load_constant(ctx, a1),
        ])
    }

    fn load_constant_array<const N: usize>(
        &self,
        ctx: &mut Context<F>,
        a: &[QuadraticExtension<GoldilocksField>; N],
    ) -> [GoldilocksQuadExtWire<F>; N] {
        a.iter()
            .map(|a| self.load_constant(ctx, *a))
            .collect::<Vec<GoldilocksQuadExtWire<F>>>() // TODO: There must be a better way
            .try_into()
            .unwrap()
    }

    pub fn load_witness(
        &self,
        ctx: &mut Context<F>,
        a: QuadraticExtension<GoldilocksField>,
    ) -> GoldilocksQuadExtWire<F> {
        let [a0, a1] = a.to_basefield_array();

        GoldilocksQuadExtWire([
            self.goldilocks_chip.load_witness(ctx, a0),
            self.goldilocks_chip.load_witness(ctx, a1),
        ])
    }

    pub fn add(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        GoldilocksQuadExtWire([
            self.goldilocks_chip.add(ctx, &a0, &b0),
            self.goldilocks_chip.add(ctx, &a1, &b1),
        ])
    }

    pub fn sub(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        GoldilocksQuadExtWire([
            self.goldilocks_chip.sub(ctx, &a0, &b0),
            self.goldilocks_chip.sub(ctx, &a1, &b1),
        ])
    }

    // a * b = (a0 * b0 + w * a1 * b1, a0 * b1 + a1 * b0)
    pub fn mul(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        let w = self
            .goldilocks_chip
            .load_constant(ctx, <GoldilocksField as Extendable<2>>::W); // TODO: Cache
        let a0b0 = self.goldilocks_chip.mul(ctx, &a0, &b0);
        let a1b1 = self.goldilocks_chip.mul(ctx, &a1, &b1);
        let wa1b1 = self.goldilocks_chip.mul(ctx, &w, &a1b1);
        let c0 = self.goldilocks_chip.add(ctx, &a0b0, &wa1b1);

        let a0b1 = self.goldilocks_chip.mul(ctx, &a0, &b1);
        let a1b0 = self.goldilocks_chip.mul(ctx, &a1, &b0);
        let c1 = self.goldilocks_chip.add(ctx, &a0b1, &a1b0);

        GoldilocksQuadExtWire([c0, c1])
    }

    pub fn mul_add(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
        c: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let ab = self.mul(ctx, a, b);
        self.add(ctx, &ab, c)
    }

    pub fn range_check(&self, ctx: &mut Context<F>, a: &GoldilocksQuadExtWire<F>) {
        let GoldilocksQuadExtWire([a0, a1]) = a;

        self.goldilocks_chip.range_check(ctx, &a0);
        self.goldilocks_chip.range_check(ctx, &a1);
    }

    pub fn assert_equal(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        self.goldilocks_chip.assert_equal(ctx, &a0, &b0);
        self.goldilocks_chip.assert_equal(ctx, &a1, &b1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    use plonky2::field::extension::quadratic::QuadraticExtension;
    use plonky2::field::types::Sample;

    #[test]
    fn test_goldilocks_extension_chip() {
        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = BaseCircuitBuilder::default().use_k(k as usize);
        builder.set_lookup_bits(lookup_bits);

        let gl_chip = GoldilocksChip::<Fr>::new(lookup_bits, builder.lookup_manager().clone());
        let gle_chip = GoldilocksQuadExtChip::new(gl_chip);

        let ctx = builder.main(0);

        for _ in 0..100 {
            let a = QuadraticExtension::rand();
            let b = QuadraticExtension::rand();

            let a_wire = gle_chip.load_constant(ctx, a);
            let b_wire = gle_chip.load_constant(ctx, b);
            let c_wire = gle_chip.mul(ctx, &a_wire, &b_wire);

            assert_eq!(c_wire.value(), a * b);
        }

        builder.calculate_params(Some(unusable_rows));
        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }
}

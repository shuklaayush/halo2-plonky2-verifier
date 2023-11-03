use goldilocks::Field64;
use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::utils::BigPrimeField;
use halo2_base::virtual_region::lookups::LookupAnyManager;
use halo2_base::{AssignedValue, Context};
use std::marker::PhantomData;

const MAX_PHASE: usize = 3;

pub struct Fp64<F: BigPrimeField, Fp: Field64> {
    pub native: AssignedValue<F>,
    pub value: u64,

    _marker: PhantomData<Fp>,
}

impl<F: BigPrimeField, Fp: Field64> Fp64<F, Fp> {
    pub fn new(native: AssignedValue<F>, value: u64) -> Self {
        Self {
            native,
            value,
            _marker: PhantomData,
        }
    }
}

pub struct Fp64Chip<F: BigPrimeField, Fp: Field64> {
    pub range: RangeChip<F>, // TODO: Change to reference and add lifetime?
    _marker: PhantomData<Fp>,
}

impl<F: BigPrimeField, Fp: Field64> Fp64Chip<F, Fp> {
    pub fn new(lookup_bits: usize, lookup_manager: [LookupAnyManager<F, 1>; MAX_PHASE]) -> Self {
        Self {
            range: RangeChip::<F>::new(lookup_bits, lookup_manager),
            _marker: PhantomData,
        }
    }

    fn gate(&self) -> &GateChip<F> {
        self.range.gate()
    }

    fn range(&self) -> &RangeChip<F> {
        &self.range
    }

    pub fn load_constant(&self, ctx: &mut Context<F>, a: Fp) -> Fp64<F, Fp> {
        let a = a.to_canonical_u64();
        Fp64::new(ctx.load_constant(F::from(a)), a)
    }

    pub fn load_witness(&self, ctx: &mut Context<F>, a: Fp) -> Fp64<F, Fp> {
        let a = a.to_canonical_u64();
        Fp64::new(ctx.load_witness(F::from(a)), a)
    }

    fn add(&self, ctx: &mut Context<F>, a: Fp64<F, Fp>, b: Fp64<F, Fp>) -> Fp64<F, Fp> {
        let one = self.load_constant(ctx, Fp::ONE);
        self.mul_add(ctx, a, one, b)
    }

    fn sub(&self, ctx: &mut Context<F>, a: Fp64<F, Fp>, b: Fp64<F, Fp>) -> Fp64<F, Fp> {
        let minus_one = self.load_constant(ctx, Fp::ZERO - Fp::ONE);
        self.mul_add(ctx, a, minus_one, b)
    }

    fn mul(&self, ctx: &mut Context<F>, a: Fp64<F, Fp>, b: Fp64<F, Fp>) -> Fp64<F, Fp> {
        let zero = self.load_constant(ctx, Fp::ZERO);
        self.mul_add(ctx, a, b, zero)
    }

    fn mul_add(
        &self,
        ctx: &mut Context<F>,
        a: Fp64<F, Fp>,
        b: Fp64<F, Fp>,
        c: Fp64<F, Fp>,
    ) -> Fp64<F, Fp> {
        // 1. Calculate hint
        let product: u128 = (a.value as u128) * (b.value as u128);
        let sum = product + (c.value as u128);
        let quotient = (sum / (Fp::ORDER as u128)) as u64;
        let remainder = (sum % (Fp::ORDER as u128)) as u64;

        // 2. Load witnesses from hint
        let quotient = self.load_witness(ctx, Fp::from(quotient));
        let remainder = self.load_witness(ctx, Fp::from(remainder));

        // 3. Constrain witnesses
        let gate = self.gate();
        let lhs = gate.mul_add(ctx, a.native, b.native, c.native);
        let p = ctx.load_constant(F::from(Fp::ORDER)); // TODO: Cache
        let rhs = gate.mul_add(ctx, p, quotient.native, remainder.native);

        gate.is_equal(ctx, lhs, rhs);

        let range = self.range();
        range.is_less_than_safe(ctx, quotient.native, Fp::ORDER);
        range.is_less_than_safe(ctx, remainder.native, Fp::ORDER);

        // Return
        remainder
    }

    fn range_check(&self, ctx: &mut Context<F>, a: Fp64<F, Fp>) {
        let range = self.range();
        let p = ctx.load_constant(F::from(Fp::ORDER)); // TODO: Cache
        range.check_less_than(ctx, a.native, p, 64);
    }

    fn assert_equal(&self, ctx: &mut Context<F>, a: Fp64<F, Fp>, b: Fp64<F, Fp>) {
        ctx.constrain_equal(&a.native, &b.native);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use goldilocks::fp::Goldilocks as Fp;
    use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;

    #[test]
    fn test_fp_chip() {
        let k = 16;
        let lookup_bits = 8;
        let unusable_rows = 9;

        let mut builder = RangeCircuitBuilder::default().use_k(k as usize);
        builder.set_lookup_bits(lookup_bits);

        let fp_chip = Fp64Chip::<Fr, Fp>::new(lookup_bits, builder.lookup_manager().clone()); // TODO: Why clone?

        // TODO: What is builder.main(0)?
        let ctx = builder.main(0);
        let a = fp_chip.load_constant(ctx, Fp::ZERO - Fp::ONE);
        let b = fp_chip.load_constant(ctx, Fp::ONE);
        let c = fp_chip.add(ctx, a, b);

        let d = fp_chip.load_constant(ctx, Fp::ZERO);

        fp_chip.assert_equal(ctx, c, d);

        builder.calculate_params(Some(unusable_rows));

        MockProver::run(k, &builder, vec![])
            .unwrap()
            .assert_satisfied();
    }
}

use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::plonk::Assigned;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, ScalarField};
use halo2_base::{AssignedValue, Context};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, Field64, PrimeField64};

use super::BoolWire;

// TODO: Use SafeUint64?
//       https://github.com/axiom-crypto/halo2-lib/blob/400122a6cf074783d0e5ee904a711e75ddfff3d4/halo2-base/src/safe_types/mod.rs#L109-L109
#[derive(Copy, Clone, Debug)]
pub struct GoldilocksWire<F: ScalarField>(pub AssignedValue<F>);

// TODO: Is this correct?
impl<F: ScalarField> Default for GoldilocksWire<F> {
    fn default() -> GoldilocksWire<F> {
        Self(AssignedValue {
            value: Assigned::Zero,
            cell: None,
        })
    }
}

impl<F: ScalarField> GoldilocksWire<F> {
    pub fn value_raw(&self) -> &F {
        self.0.value()
    }

    pub fn value(&self) -> GoldilocksField {
        debug_assert!(self.value_raw() < &F::from(GoldilocksField::ORDER));

        GoldilocksField::from_canonical_u64(self.0.value().get_lower_64())
    }
}

// TODO: Use this to simplify code
// impl<F: ScalarField> Into<QuantumCell<F>> for GoldilocksWire<F> {
//     fn into(self) -> QuantumCell<F> {
//         self.0.into()
//     }
// }

// TODO: Reference and lifetimes? Should GoldilocksChip own RangeChip?
//       Add, mul as trait implementations for GoldilocksWire instead of GoldilocksChip?
//       Generic FieldChip trait?
#[derive(Debug, Clone)]
pub struct GoldilocksChip<F: ScalarField> {
    pub range: RangeChip<F>, // TODO: Change to reference and add lifetime?
}

impl<F: ScalarField> GoldilocksChip<F> {
    pub fn new(range: RangeChip<F>) -> Self {
        Self { range }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.range.gate()
    }

    // TODO: Rename to range_chip?
    pub fn range(&self) -> &RangeChip<F> {
        &self.range
    }
}

// TODO: Abstract away as generic FieldChip trait?
//       Change load_* syntax to just *. `load_zero` -> `zero`, `load_constant` -> `constant`
//       Pass values instead of references since they are cheap to copy?
impl<F: ScalarField> GoldilocksChip<F> {
    pub fn load_zero(&self, ctx: &mut Context<F>) -> GoldilocksWire<F> {
        GoldilocksWire(ctx.load_zero())
    }

    pub fn load_one(&self, ctx: &mut Context<F>) -> GoldilocksWire<F> {
        GoldilocksWire(ctx.load_constant(F::ONE))
    }

    pub fn load_neg_one(&self, ctx: &mut Context<F>) -> GoldilocksWire<F> {
        let neg_one = GoldilocksField::NEG_ONE.to_canonical_u64();
        GoldilocksWire(ctx.load_constant(F::from(neg_one)))
    }

    // TODO: Keep a track of constants loaded to avoid loading them multiple times?
    pub fn load_constant(&self, ctx: &mut Context<F>, a: GoldilocksField) -> GoldilocksWire<F> {
        let a = a.to_canonical_u64();
        GoldilocksWire(ctx.load_constant(F::from(a)))
    }

    pub fn load_constant_array<const N: usize>(
        &self,
        ctx: &mut Context<F>,
        a: &[GoldilocksField; N],
    ) -> [GoldilocksWire<F>; N] {
        a.iter()
            .map(|a| self.load_constant(ctx, *a))
            .collect::<Vec<GoldilocksWire<F>>>()
            .try_into() // TODO: There must be a better way than try_into
            .unwrap()
    }

    // TODO: Only vec?
    pub fn load_constant_slice(
        &self,
        ctx: &mut Context<F>,
        a: &[GoldilocksField],
    ) -> Vec<GoldilocksWire<F>> {
        a.iter().map(|a| self.load_constant(ctx, *a)).collect()
    }

    pub fn load_witness(&self, ctx: &mut Context<F>, a: GoldilocksField) -> GoldilocksWire<F> {
        let a = a.to_canonical_u64();
        GoldilocksWire(ctx.load_witness(F::from(a)))
    }

    pub fn select(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        sel: &BoolWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(gate.select(ctx, a.0, b.0, sel.0))
    }

    pub fn select_array<const N: usize>(
        &self,
        ctx: &mut Context<F>,
        a: [GoldilocksWire<F>; N],
        b: [GoldilocksWire<F>; N],
        sel: &BoolWire<F>,
    ) -> [GoldilocksWire<F>; N] {
        let gate = self.gate();

        a.iter()
            .zip(b.iter())
            .map(|(a, b)| GoldilocksWire(gate.select(ctx, a.0, b.0, sel.0)))
            .collect::<Vec<GoldilocksWire<F>>>()
            .try_into() // TODO: There must be a better way than try_into
            .unwrap()
    }

    pub fn select_from_idx(
        &self,
        ctx: &mut Context<F>,
        arr: &[GoldilocksWire<F>],
        idx: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(gate.select_from_idx(
            ctx,
            arr.iter().map(|x| x.0).collect::<Vec<_>>(),
            idx.0,
        ))
    }

    pub fn select_array_from_idx<const N: usize>(
        &self,
        ctx: &mut Context<F>,
        arr: &[[GoldilocksWire<F>; N]],
        idx: &GoldilocksWire<F>,
    ) -> [GoldilocksWire<F>; N] {
        let gate = self.gate();

        let indicator = gate.idx_to_indicator(ctx, idx.0, arr.len());
        let native_arr = gate.select_array_by_indicator(
            ctx,
            arr.iter()
                .map(|inner| inner.iter().map(|x| x.0).collect::<Vec<_>>())
                .collect::<Vec<_>>()
                .as_slice(),
            indicator.as_slice(),
        );

        native_arr
            .iter()
            .map(|&x| GoldilocksWire(x))
            .collect::<Vec<_>>()
            .try_into() // TODO: There must be a better way than try_into
            .unwrap()
    }

    pub fn num_to_bits(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        range_bits: usize,
    ) -> Vec<BoolWire<F>> {
        let gate = self.gate();

        let native_bits = gate.num_to_bits(ctx, a.0, range_bits);
        native_bits.iter().map(|&x| BoolWire(x)).collect::<Vec<_>>()
    }

    pub fn bits_to_num(&self, ctx: &mut Context<F>, bits: &[BoolWire<F>]) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(
            gate.bits_to_num(ctx, bits.iter().map(|x| x.0).collect::<Vec<_>>().as_slice()),
        )
    }

    pub fn neg(&self, ctx: &mut Context<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        let neg_one = self.load_neg_one(ctx);
        self.mul(ctx, a, &neg_one)
    }

    pub fn add(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        // TODO: Cache
        let one = self.load_constant(ctx, GoldilocksField::ONE);
        self.mul_add(ctx, a, &one, b)
    }

    pub fn add_no_reduce(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(gate.add(ctx, a.0, b.0))
    }

    pub fn sub(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let minus_one = self.load_constant(ctx, GoldilocksField::ZERO - GoldilocksField::ONE);
        self.mul_add(ctx, b, &minus_one, a)
    }

    // TODO: What is this even supposed to do?
    pub fn sub_no_reduce(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        let minus_one = self.load_constant(ctx, GoldilocksField::ZERO - GoldilocksField::ONE);
        let minus_b = gate.mul(ctx, b.0, minus_one.0);
        GoldilocksWire(gate.add(ctx, a.0, minus_b))
    }

    pub fn mul(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let zero = self.load_constant(ctx, GoldilocksField::ZERO);
        self.mul_add(ctx, a, b, &zero)
    }

    pub fn mul_no_reduce(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(gate.mul(ctx, a.0, b.0))
    }

    // TODO: Change to div_add?
    pub fn div(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        // TODO: Is this required?
        assert!(b.value() != GoldilocksField::ZERO);

        // 1. Calculate hint
        let res = a.value() / b.value();

        // 2. Load witnesses from hint
        let res = self.load_witness(ctx, res);

        // 3. Constrain witnesses
        let product = self.mul(ctx, b, &res);
        self.assert_equal(ctx, a, &product);

        res
    }

    pub fn square(&self, ctx: &mut Context<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        self.mul(ctx, a, a)
    }

    pub fn mul_add(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        c: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        // 1. Calculate hint
        let product: u128 =
            (a.value().to_canonical_u64() as u128) * (b.value().to_canonical_u64() as u128);
        let sum = product + (c.value().to_canonical_u64() as u128);
        let quotient = (sum / (GoldilocksField::ORDER as u128)) as u64;
        let remainder = (sum % (GoldilocksField::ORDER as u128)) as u64;

        // 2. Load witnesses from hint
        let quotient = self.load_witness(ctx, GoldilocksField::from_canonical_u64(quotient));
        let remainder = self.load_witness(ctx, GoldilocksField::from_canonical_u64(remainder));

        // 3. Constrain witnesses
        let gate = self.gate();
        let lhs = gate.mul_add(ctx, a.0, b.0, c.0);
        let p = ctx.load_constant(F::from(GoldilocksField::ORDER)); // TODO: Cache
        let rhs = gate.mul_add(ctx, p, quotient.0, remainder.0);

        gate.is_equal(ctx, lhs, rhs);

        let range = self.range();
        range.check_less_than_safe(ctx, quotient.0, GoldilocksField::ORDER);
        range.check_less_than_safe(ctx, remainder.0, GoldilocksField::ORDER);

        // Return
        remainder
    }

    pub fn mul_add_no_reduce(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        c: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(gate.mul_add(ctx, a.0, b.0, c.0))
    }

    // TODO: Can I use a custom gate here?
    pub fn mul_sub(
        &self,
        ctx: &mut Context<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        c: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let ab = self.mul(ctx, a, b);
        self.sub(ctx, &ab, c)
    }

    pub fn inv(&self, ctx: &mut Context<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        // 1. Calculate hint
        let inverse = a.value().inverse();

        // 2. Load witnesses from hint
        let inverse = self.load_witness(ctx, inverse);

        // 3. Constrain witnesses
        let product = self.mul(ctx, a, &inverse);
        let one = self.load_constant(ctx, GoldilocksField::ONE);
        self.assert_equal(ctx, &product, &one);

        // Return
        inverse
    }

    pub fn exp_from_bits_const_base(
        &self,
        ctx: &mut Context<F>,
        base: &GoldilocksField,
        exponent_bits: &[BoolWire<F>],
    ) -> GoldilocksWire<F> {
        let mut product = self.load_constant(ctx, GoldilocksField::ONE);
        for (i, bit) in exponent_bits.iter().enumerate() {
            let pow = 1 << i;
            // If the bit is on, we multiply product by base^pow.
            // We can arithmetize this as:
            //     product *= 1 + bit (base^pow - 1)
            //     product = (base^pow - 1) product bit + product
            let base_pow_minus_one =
                self.load_constant(ctx, base.exp_u64(pow as u64) - GoldilocksField::ONE);
            // TODO: Can we condense this into a single mul_add?
            let a = self.mul(ctx, &base_pow_minus_one, &product);
            // TODO: Ugly
            product = self.mul_add(ctx, &a, &(*bit).into(), &product);
        }

        product
    }

    pub fn exp_power_of_2(
        &self,
        ctx: &mut Context<F>,
        base: &GoldilocksWire<F>,
        power_log: usize,
    ) -> GoldilocksWire<F> {
        let mut product = *base;
        for _ in 0..power_log {
            product = self.square(ctx, &product);
        }
        product
    }

    pub fn reduce(&self, ctx: &mut Context<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        // 1. Calculate hint
        let val = fe_to_biguint(a.value_raw());
        let quotient = val.clone() / GoldilocksField::ORDER;
        let remainder = GoldilocksField::from_noncanonical_biguint(val);

        // 2. Load witnesses from hint
        let quotient = ctx.load_witness(biguint_to_fe(&quotient));
        let remainder = self.load_witness(ctx, remainder);

        // 3. Constrain witnesses
        let gate = self.gate();
        let p = ctx.load_constant(F::from(GoldilocksField::ORDER));
        let rhs = gate.mul_add(ctx, quotient, p, remainder.0);

        gate.is_equal(ctx, a.0, rhs);

        let range = self.range();
        // TODO: Dummy
        range.range_check(ctx, quotient, 160);
        range.check_less_than_safe(ctx, remainder.0, GoldilocksField::ORDER);

        // Return
        remainder
    }

    pub fn range_check(&self, ctx: &mut Context<F>, a: &GoldilocksWire<F>) {
        let range = self.range();
        let p = ctx.load_constant(F::from(GoldilocksField::ORDER)); // TODO: Cache
        range.check_less_than(ctx, a.0, p, 64);
    }

    pub fn assert_equal(&self, ctx: &mut Context<F>, a: &GoldilocksWire<F>, b: &GoldilocksWire<F>) {
        ctx.constrain_equal(&a.0, &b.0);
    }
}

// TODO: Add more tests. test_case?
#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use plonky2::field::types::Sample;

    #[test]
    fn test_mul() {
        base_test().k(14).run(|ctx, range| {
            let gl_chip = GoldilocksChip::<Fr>::new(range.clone()); // TODO: Remove clone, store reference

            for _ in 0..100 {
                let a = GoldilocksField::rand();
                let b = GoldilocksField::rand();

                let a_wire = gl_chip.load_constant(ctx, a);
                let b_wire = gl_chip.load_constant(ctx, b);
                let c_wire = gl_chip.mul(ctx, &a_wire, &b_wire);

                assert_eq!(c_wire.value(), a * b);
            }
        })
    }
}

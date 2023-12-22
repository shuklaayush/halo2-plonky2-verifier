use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::plonk::Assigned;
use halo2_base::utils::{fe_to_biguint, BigPrimeField};
use halo2_base::AssignedValue;
use itertools::Itertools;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, Field64, PrimeField64};

use verifier_macro::count;

use crate::util::context_wrapper::ContextWrapper;

use super::BoolWire;

#[derive(Copy, Clone, Debug)]
pub struct GoldilocksWire<F: BigPrimeField>(pub AssignedValue<F>);

// TODO: Is this correct?
impl<F: BigPrimeField> Default for GoldilocksWire<F> {
    fn default() -> GoldilocksWire<F> {
        Self(AssignedValue {
            value: Assigned::Zero,
            cell: None,
        })
    }
}

impl<F: BigPrimeField> GoldilocksWire<F> {
    pub fn value_raw(&self) -> &F {
        self.0.value()
    }

    pub fn value(&self) -> GoldilocksField {
        debug_assert!(self.value_raw() < &F::from(GoldilocksField::ORDER));

        GoldilocksField::from_canonical_u64(self.0.value().get_lower_64())
    }
}

// TODO: Use this to simplify code
// impl<F: BigPrimeField> Into<QuantumCell<F>> for GoldilocksWire<F> {
//     fn into(self) -> QuantumCell<F> {
//         self.0.into()
//     }
// }

// TODO: Reference and lifetimes? Should GoldilocksChip own RangeChip?
//       Add, mul as trait implementations for GoldilocksWire instead of GoldilocksChip?
//       Generic FieldChip trait?
#[derive(Debug, Clone)]
pub struct GoldilocksChip<F: BigPrimeField> {
    pub range: RangeChip<F>, // TODO: Change to reference and add lifetime?
}

// TODO: Abstract away as generic FieldChip trait?
//       Change load_* syntax to just *. `load_zero` -> `zero`, `load_constant` -> `constant`
//       Pass values instead of references since they are cheap to copy?
//       Assert somewhere that F ~ 256 bits
impl<F: BigPrimeField> GoldilocksChip<F> {
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

    // TODO: Keep a track of constants loaded to avoid loading them multiple times?
    //       Maybe do range check
    #[count]
    pub fn load_constant(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: GoldilocksField,
    ) -> GoldilocksWire<F> {
        let a = a.to_canonical_u64();
        GoldilocksWire(ctx.ctx.load_constant(F::from(a)))
    }

    #[count]
    pub fn load_zero(&self, ctx: &mut ContextWrapper<F>) -> GoldilocksWire<F> {
        self.load_constant(ctx, GoldilocksField::ZERO)
    }

    #[count]
    pub fn load_one(&self, ctx: &mut ContextWrapper<F>) -> GoldilocksWire<F> {
        self.load_constant(ctx, GoldilocksField::ONE)
    }

    #[count]
    pub fn load_neg_one(&self, ctx: &mut ContextWrapper<F>) -> GoldilocksWire<F> {
        self.load_constant(ctx, GoldilocksField::NEG_ONE)
    }

    #[count]
    pub fn load_constant_array<const N: usize>(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &[GoldilocksField; N],
    ) -> [GoldilocksWire<F>; N] {
        a.iter()
            .map(|a| self.load_constant(ctx, *a))
            .collect::<Vec<GoldilocksWire<F>>>()
            .try_into() // TODO: There must be a better way than try_into
            .unwrap()
    }

    // TODO: Only vec?
    #[count]
    pub fn load_constant_slice(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &[GoldilocksField],
    ) -> Vec<GoldilocksWire<F>> {
        a.iter().map(|a| self.load_constant(ctx, *a)).collect_vec()
    }

    #[count]
    pub fn load_constant_vec(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &Vec<GoldilocksField>,
    ) -> Vec<GoldilocksWire<F>> {
        a.iter().map(|a| self.load_constant(ctx, *a)).collect_vec()
    }

    #[count]
    pub fn load_witness(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: GoldilocksField,
    ) -> GoldilocksWire<F> {
        let a = a.to_canonical_u64();
        let wire = GoldilocksWire(ctx.ctx.load_witness(F::from(a)));
        // Ensure that the witness is in the Goldilocks field
        self.range_check(ctx, &wire);
        wire
    }

    #[count]
    pub fn select(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        sel: &BoolWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(gate.select(ctx.ctx, a.0, b.0, sel.0))
    }

    #[count]
    pub fn select_array<const N: usize>(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: [GoldilocksWire<F>; N],
        b: [GoldilocksWire<F>; N],
        sel: &BoolWire<F>,
    ) -> [GoldilocksWire<F>; N] {
        let gate = self.gate();

        a.iter()
            .zip(b.iter())
            .map(|(a, b)| GoldilocksWire(gate.select(ctx.ctx, a.0, b.0, sel.0)))
            .collect::<Vec<GoldilocksWire<F>>>()
            .try_into() // TODO: There must be a better way than try_into
            .unwrap()
    }

    // TODO: Barrel shifter? Merkle tree like select?
    pub fn select_from_idx(
        &self,
        ctx: &mut ContextWrapper<F>,
        arr: &[GoldilocksWire<F>],
        idx: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        GoldilocksWire(gate.select_from_idx(
            ctx.ctx,
            arr.iter().map(|x| x.0).collect::<Vec<_>>(),
            idx.0,
        ))
    }

    #[count]
    pub fn select_array_from_idx<const N: usize>(
        &self,
        ctx: &mut ContextWrapper<F>,
        arr: &[[GoldilocksWire<F>; N]],
        idx: &GoldilocksWire<F>,
    ) -> [GoldilocksWire<F>; N] {
        let gate = self.gate();

        let indicator = gate.idx_to_indicator(ctx.ctx, idx.0, arr.len());
        let native_arr = gate.select_array_by_indicator(
            ctx.ctx,
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

    #[count]
    pub fn num_to_bits(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        range_bits: usize,
    ) -> Vec<BoolWire<F>> {
        let gate = self.gate();

        let native_bits = gate.num_to_bits(ctx.ctx, a.0, range_bits);
        native_bits.iter().map(|&x| BoolWire(x)).collect::<Vec<_>>()
    }

    #[count]
    pub fn bits_to_num(
        &self,
        ctx: &mut ContextWrapper<F>,
        bits: &[BoolWire<F>],
    ) -> GoldilocksWire<F> {
        let gate = self.gate();

        // TODO: halo2-lib doesn't use horner's trick so allocates extra 2^i constants
        GoldilocksWire(gate.bits_to_num(
            ctx.ctx,
            bits.iter().map(|x| x.0).collect::<Vec<_>>().as_slice(),
        ))
    }

    #[count]
    pub fn neg(&self, ctx: &mut ContextWrapper<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        let neg_one = self.load_neg_one(ctx);
        self.mul(ctx, a, &neg_one)
    }

    #[count]
    pub fn add_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();
        GoldilocksWire(gate.add(ctx.ctx, a.0, b.0))
    }

    #[count]
    pub fn add(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let sum = self.add_no_reduce(ctx, a, b);
        self.reduce(ctx, &sum)
    }

    #[count]
    pub fn sub_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();
        let neg_one = self.load_neg_one(ctx);
        GoldilocksWire(gate.mul_add(ctx.ctx, b.0, neg_one.0, a.0))
    }

    #[count]
    pub fn sub(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let diff = self.sub_no_reduce(ctx, a, b);
        self.reduce(ctx, &diff)
    }

    #[count]
    pub fn mul_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();
        GoldilocksWire(gate.mul(ctx.ctx, a.0, b.0))
    }

    #[count]
    pub fn mul(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let prod = self.mul_no_reduce(ctx, a, b);
        self.reduce(ctx, &prod)
    }

    #[count]
    pub fn mul_add_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        c: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let gate = self.gate();
        GoldilocksWire(gate.mul_add(ctx.ctx, a.0, b.0, c.0))
    }

    #[count]
    pub fn mul_add(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        c: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let prodadd = self.mul_add_no_reduce(ctx, a, b, c);
        self.reduce(ctx, &prodadd)
    }

    // TODO: Can I use a custom gate here?
    #[count]
    pub fn mul_sub(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
        c: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        let prod = self.mul_no_reduce(ctx, a, b);
        let diff = self.sub_no_reduce(ctx, &prod, c);
        self.reduce(ctx, &diff)
    }

    // TODO: Only supports reduction upto p * (p - 1) i.e. max value of a mul_add
    #[count]
    pub fn reduce(&self, ctx: &mut ContextWrapper<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        // 1. Calculate hint
        let val = fe_to_biguint(a.value_raw());
        let quotient =
            GoldilocksField::from_noncanonical_biguint(val.clone() / GoldilocksField::ORDER);
        let remainder = GoldilocksField::from_noncanonical_biguint(val);

        // 2. Load witnesses from hint
        //    Also ensures that quotient and remainder are in the field
        let quotient = self.load_witness(ctx, quotient);
        let remainder = self.load_witness(ctx, remainder);

        // 3. Constrain witnesses
        let gate = self.gate();
        let p = ctx.ctx.load_constant(F::from(GoldilocksField::ORDER));
        let rhs = gate.mul_add(ctx.ctx, quotient.0, p, remainder.0);

        gate.is_equal(ctx.ctx, a.0, rhs);

        // Return
        remainder
    }

    #[count]
    pub fn inv(&self, ctx: &mut ContextWrapper<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        // 1. Calculate hint
        let inverse = a.value().inverse();

        // 2. Load witnesses from hint
        let inverse = self.load_witness(ctx, inverse);

        // 3. Constrain witnesses
        let product = self.mul(ctx, a, &inverse);
        let one = self.load_one(ctx);
        self.assert_equal(ctx, &product, &one);

        // Return
        inverse
    }

    // TODO: Change to div_add?
    #[count]
    pub fn div(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksWire<F> {
        // TODO: Is this required?
        assert!(b.value() != GoldilocksField::ZERO);

        // 1. Calculate hint
        let res = a.value() / b.value();

        // 2. Load witnesses from hint
        //    Also ensures that res is in the field
        let res = self.load_witness(ctx, res);

        // 3. Constrain witnesses
        let product = self.mul(ctx, b, &res);
        self.assert_equal(ctx, a, &product);

        res
    }

    #[count]
    pub fn square(&self, ctx: &mut ContextWrapper<F>, a: &GoldilocksWire<F>) -> GoldilocksWire<F> {
        self.mul(ctx, a, a)
    }

    // TODO: Lazy reduction?
    #[count]
    pub fn exp_from_bits_const_base(
        &self,
        ctx: &mut ContextWrapper<F>,
        base: &GoldilocksField,
        exponent_bits: &[BoolWire<F>],
    ) -> GoldilocksWire<F> {
        let mut product = self.load_one(ctx);
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

    // TODO: Lazy reduction?
    #[count]
    pub fn exp_power_of_2(
        &self,
        ctx: &mut ContextWrapper<F>,
        base: &GoldilocksWire<F>,
        power_log: usize,
    ) -> GoldilocksWire<F> {
        let mut product = *base;
        for _ in 0..power_log {
            product = self.square(ctx, &product);
        }
        product
    }

    #[count]
    pub fn assert_equal(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
        b: &GoldilocksWire<F>,
    ) {
        ctx.ctx.constrain_equal(&a.0, &b.0);
    }

    #[count]
    pub fn range_check(&self, ctx: &mut ContextWrapper<F>, a: &GoldilocksWire<F>) {
        let range = self.range();
        // let before = ctx.ctx.advice.len();
        range.check_less_than_safe(ctx.ctx, a.0, GoldilocksField::ORDER);
        // range.range_check(ctx.ctx, a.0, GoldilocksField::BITS);
        // println!("Cells added: {}", ctx.ctx.advice.len() - before);
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
            let mut ctx = ContextWrapper::new(ctx);
            let ctx = &mut ctx;

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

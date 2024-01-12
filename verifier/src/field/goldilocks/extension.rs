use halo2_base::utils::BigPrimeField;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::extension::Extendable;
use plonky2::field::extension::FieldExtension;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::util::bits_u64;

use verifier_macro::count;

use crate::util::context_wrapper::ContextWrapper;

use super::base::{GoldilocksChip, GoldilocksWire};

// TODO: Use const generics for arbitrary GoldilocksExtWire
#[derive(Copy, Clone, Debug)]
pub struct GoldilocksQuadExtWire<F: BigPrimeField>(pub [GoldilocksWire<F>; 2]);

impl<F: BigPrimeField> GoldilocksQuadExtWire<F> {
    pub fn value(&self) -> QuadraticExtension<GoldilocksField> {
        let val1 = self.0[0].value();
        let val2 = self.0[1].value();
        QuadraticExtension::from_basefield_array([val1, val2])
    }
}

impl<F: BigPrimeField> Default for GoldilocksQuadExtWire<F> {
    fn default() -> GoldilocksQuadExtWire<F> {
        Self([GoldilocksWire::default(); 2])
    }
}

// impl<F: BigPrimeField> TryFrom<&[GoldilocksWire<F>]> for GoldilocksQuadExtWire<F> {
//     type Error = anyhow::Error;

//     fn try_from(elements: &[GoldilocksWire<F>]) -> Result<Self, Self::Error> {
//         ensure!(elements.len() == 2);
//         Ok(Self(elements.try_into().unwrap()))
//     }
// }

#[derive(Debug, Clone)]
pub struct GoldilocksQuadExtChip<F: BigPrimeField> {
    pub goldilocks_chip: GoldilocksChip<F>,
}

impl<F: BigPrimeField> GoldilocksQuadExtChip<F> {
    pub fn new(goldilocks_chip: GoldilocksChip<F>) -> Self {
        Self { goldilocks_chip }
    }

    #[count]
    pub fn load_constant(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: QuadraticExtension<GoldilocksField>,
    ) -> GoldilocksQuadExtWire<F> {
        let [a0, a1] = a.to_basefield_array();

        GoldilocksQuadExtWire([
            self.goldilocks_chip.load_constant(ctx, a0),
            self.goldilocks_chip.load_constant(ctx, a1),
        ])
    }

    #[count]
    pub fn load_zero(&self, ctx: &mut ContextWrapper<F>) -> GoldilocksQuadExtWire<F> {
        self.load_constant(ctx, QuadraticExtension::<GoldilocksField>::ZERO)
    }

    #[count]
    pub fn load_one(&self, ctx: &mut ContextWrapper<F>) -> GoldilocksQuadExtWire<F> {
        self.load_constant(ctx, QuadraticExtension::<GoldilocksField>::ONE)
    }

    #[count]
    pub fn load_constant_array<const N: usize>(
        &self,
        ctx: &mut ContextWrapper<F>,
        arr: &[QuadraticExtension<GoldilocksField>; N],
    ) -> [GoldilocksQuadExtWire<F>; N] {
        arr.map(|a| self.load_constant(ctx, a))
    }

    #[count]
    pub fn load_witness(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: QuadraticExtension<GoldilocksField>,
    ) -> GoldilocksQuadExtWire<F> {
        let [a0, a1] = a.to_basefield_array();

        GoldilocksQuadExtWire([
            self.goldilocks_chip.load_witness(ctx, a0),
            self.goldilocks_chip.load_witness(ctx, a1),
        ])
    }

    #[count]
    pub fn select_from_idx(
        &self,
        ctx: &mut ContextWrapper<F>,
        arr: &[GoldilocksQuadExtWire<F>],
        // TODO: Should index be a separate type?
        idx: &GoldilocksWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let arr0 = arr.iter().map(|x| x.0[0]).collect::<Vec<_>>();
        let arr1 = arr.iter().map(|x| x.0[1]).collect::<Vec<_>>();

        let arr0i = self
            .goldilocks_chip
            .select_from_idx(ctx, arr0.as_slice(), idx);
        let arrli = self
            .goldilocks_chip
            .select_from_idx(ctx, arr1.as_slice(), idx);

        GoldilocksQuadExtWire([arr0i, arrli])
    }

    #[count]
    pub fn load_base(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let zero = self.goldilocks_chip.load_zero(ctx);
        GoldilocksQuadExtWire([*a, zero])
    }

    #[count]
    pub fn add_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        GoldilocksQuadExtWire([
            self.goldilocks_chip.add_no_reduce(ctx, a0, b0),
            self.goldilocks_chip.add_no_reduce(ctx, a1, b1),
        ])
    }

    #[count]
    pub fn add(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let sum = self.add_no_reduce(ctx, a, b);
        self.reduce(ctx, &sum)
    }

    #[count]
    pub fn sub_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        GoldilocksQuadExtWire([
            self.goldilocks_chip.sub_no_reduce(ctx, a0, b0),
            self.goldilocks_chip.sub_no_reduce(ctx, a1, b1),
        ])
    }

    #[count]
    pub fn sub(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let diff = self.sub_no_reduce(ctx, a, b);
        self.reduce(ctx, &diff)
    }

    // a * b = (a0 * b0 + w * a1 * b1, a0 * b1 + a1 * b0)
    #[count]
    pub fn mul_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        let w = self
            .goldilocks_chip
            .load_constant(ctx, <GoldilocksField as Extendable<2>>::W); // TODO: Cache
        let a0b0 = self.goldilocks_chip.mul_no_reduce(ctx, a0, b0);
        let a1b1 = self.goldilocks_chip.mul_no_reduce(ctx, a1, b1);
        let wa1b1 = self.goldilocks_chip.mul_no_reduce(ctx, &w, &a1b1);
        let c0 = self.goldilocks_chip.add_no_reduce(ctx, &a0b0, &wa1b1);

        let a0b1 = self.goldilocks_chip.mul_no_reduce(ctx, a0, b1);
        let a1b0 = self.goldilocks_chip.mul_no_reduce(ctx, a1, b0);
        let c1 = self.goldilocks_chip.add_no_reduce(ctx, &a0b1, &a1b0);

        GoldilocksQuadExtWire([c0, c1])
    }

    // TODO: Can I use `mul_no_reduce` here? Because c0 is > p*(p-1)
    #[count]
    pub fn mul(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        let w = self
            .goldilocks_chip
            .load_constant(ctx, <GoldilocksField as Extendable<2>>::W); // TODO: Cache
        let a0b0 = self.goldilocks_chip.mul(ctx, a0, b0);
        let a1b1 = self.goldilocks_chip.mul(ctx, a1, b1);
        let wa1b1 = self.goldilocks_chip.mul(ctx, &w, &a1b1);
        let c0 = self.goldilocks_chip.add(ctx, &a0b0, &wa1b1);

        let a0b1 = self.goldilocks_chip.mul(ctx, a0, b1);
        let a1b0 = self.goldilocks_chip.mul(ctx, a1, b0);
        let c1 = self.goldilocks_chip.add(ctx, &a0b1, &a1b0);

        GoldilocksQuadExtWire([c0, c1])
    }

    // TODO: Is there a better way to do this?
    #[count]
    pub fn div(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let binv = self.inv(ctx, b);
        self.mul(ctx, a, &binv)
    }

    #[count]
    pub fn square(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;

        let w = self
            .goldilocks_chip
            .load_constant(ctx, <GoldilocksField as Extendable<2>>::W); // TODO: Cache
        let a0a0 = self.goldilocks_chip.square(ctx, a0);
        let a1a1 = self.goldilocks_chip.square(ctx, a1);
        let wa1a1 = self.goldilocks_chip.mul(ctx, &w, &a1a1);
        let c0 = self.goldilocks_chip.add(ctx, &a0a0, &wa1a1);

        let a0a1 = self.goldilocks_chip.mul(ctx, a0, a1);
        let c1 = self.goldilocks_chip.add(ctx, &a0a1, &a0a1);

        GoldilocksQuadExtWire([c0, c1])
    }

    // TODO: Can I use a custom gate for this?
    #[count]
    pub fn mul_add_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
        c: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let ab = self.mul_no_reduce(ctx, a, b);
        self.add_no_reduce(ctx, &ab, c)
    }

    // TODO: Can I use `mul_no_reduce` here? Because c0 is > p*(p-1)
    #[count]
    pub fn mul_add(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
        c: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let ab = self.mul(ctx, a, b);
        self.add(ctx, &ab, c)
    }

    #[count]
    pub fn mul_sub_no_reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
        c: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let ab = self.mul_no_reduce(ctx, a, b);
        self.sub_no_reduce(ctx, &ab, c)
    }

    #[count]
    pub fn mul_sub(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
        c: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let ab = self.mul(ctx, a, b);
        self.sub(ctx, &ab, c)
    }

    #[count]
    pub fn inv(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        // 1. Calculate hint
        let inverse = a.value().inverse();

        // 2. Load witnesses from hint
        //    Also performs range check
        let inverse = self.load_witness(ctx, inverse);

        // 3. Constrain witnesses
        let product = self.mul(ctx, a, &inverse);
        let one = self.load_one(ctx);
        self.assert_equal(ctx, &product, &one);

        // Return
        inverse
    }

    #[count]
    pub fn scalar_mul(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        GoldilocksQuadExtWire([
            self.goldilocks_chip.mul(ctx, &a.0[0], b),
            self.goldilocks_chip.mul(ctx, &a.0[1], b),
        ])
    }

    #[count]
    pub fn scalar_div(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        GoldilocksQuadExtWire([
            self.goldilocks_chip.div(ctx, &a.0[0], b),
            self.goldilocks_chip.div(ctx, &a.0[1], b),
        ])
    }

    #[count]
    pub fn reduce(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let GoldilocksQuadExtWire([a0, a1]) = a;

        GoldilocksQuadExtWire([
            self.goldilocks_chip.reduce(ctx, a0),
            self.goldilocks_chip.reduce(ctx, a1),
        ])
    }

    #[count]
    pub fn exp_u64(
        &self,
        ctx: &mut ContextWrapper<F>,
        base: &GoldilocksQuadExtWire<F>,
        exponent: u64,
    ) -> GoldilocksQuadExtWire<F> {
        match exponent {
            0 => return self.load_one(ctx),
            1 => return *base,
            2 => return self.mul(ctx, base, base),
            _ => (),
        }
        let mut current = *base;
        let mut product = self.load_one(ctx);

        for j in 0..bits_u64(exponent) {
            if j != 0 {
                current = self.square(ctx, &current);
            }
            if (exponent >> j & 1) != 0 {
                product = self.mul(ctx, &product, &current);
            }
        }
        product
    }

    /// Exponentiate `base` to the power of `2^power_log`.
    #[count]
    pub fn exp_power_of_2(
        &self,
        ctx: &mut ContextWrapper<F>,
        base: &GoldilocksQuadExtWire<F>,
        power_log: usize,
    ) -> GoldilocksQuadExtWire<F> {
        let mut curr = *base;
        for _ in 0..power_log {
            curr = self.square(ctx, &curr);
        }
        curr
    }

    #[count]
    pub fn reduce_with_powers(
        &self,
        ctx: &mut ContextWrapper<F>,
        terms: &[GoldilocksQuadExtWire<F>],
        scalar: &GoldilocksQuadExtWire<F>,
    ) -> GoldilocksQuadExtWire<F> {
        let mut sum = self.load_zero(ctx);
        for term in terms.iter().rev() {
            sum = self.mul(ctx, &sum, scalar);
            sum = self.add(ctx, &sum, term);
        }
        sum
    }

    #[count]
    pub fn range_check(&self, ctx: &mut ContextWrapper<F>, a: &GoldilocksQuadExtWire<F>) {
        let GoldilocksQuadExtWire([a0, a1]) = a;

        self.goldilocks_chip.range_check(ctx, a0);
        self.goldilocks_chip.range_check(ctx, a1);
    }

    #[count]
    pub fn assert_equal(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &GoldilocksQuadExtWire<F>,
        b: &GoldilocksQuadExtWire<F>,
    ) {
        let GoldilocksQuadExtWire([a0, a1]) = a;
        let GoldilocksQuadExtWire([b0, b1]) = b;

        self.goldilocks_chip.assert_equal(ctx, a0, b0);
        self.goldilocks_chip.assert_equal(ctx, a1, b1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;
    use plonky2::field::extension::quadratic::QuadraticExtension;
    use plonky2::field::types::Sample;

    use crate::field::native::NativeChip;

    #[test]
    fn test_goldilocks_extension_chip() {
        base_test().k(14).run(|ctx, range| {
            let ctx = &mut ContextWrapper::new(ctx);

            let native = NativeChip::<Fr>::new(range.clone());
            let gl_chip = GoldilocksChip::new(native);
            let gle_chip = GoldilocksQuadExtChip::new(gl_chip);

            for _ in 0..100 {
                let a = QuadraticExtension::rand();
                let b = QuadraticExtension::rand();

                let a_wire = gle_chip.load_constant(ctx, a);
                let b_wire = gle_chip.load_constant(ctx, b);
                let c_wire = gle_chip.mul(ctx, &a_wire, &b_wire);

                assert_eq!(c_wire.value(), a * b);
            }
        });
    }
}

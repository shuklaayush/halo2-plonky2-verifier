use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::utils::BigPrimeField;
use halo2_base::AssignedValue;

use verifier_macro::count;

use crate::util::context_wrapper::ContextWrapper;

#[derive(Debug, Clone)]
pub struct NativeChip<F: BigPrimeField> {
    range_chip: RangeChip<F>,
}

impl<F: BigPrimeField> NativeChip<F> {
    pub fn new(range_chip: RangeChip<F>) -> Self {
        Self { range_chip }
    }

    pub fn gate_chip(&self) -> &GateChip<F> {
        self.range_chip.gate()
    }

    pub fn range_chip(&self) -> &RangeChip<F> {
        &self.range_chip
    }

    #[count]
    pub fn load_constant(&self, ctx: &mut ContextWrapper<F>, a: F) -> AssignedValue<F> {
        ctx.ctx.load_constant(a)
    }

    #[count]
    pub fn load_zero(&self, ctx: &mut ContextWrapper<F>) -> AssignedValue<F> {
        ctx.ctx.load_zero()
    }

    #[count]
    pub fn load_constants(&self, ctx: &mut ContextWrapper<F>, c: &[F]) -> Vec<AssignedValue<F>> {
        ctx.ctx.load_constants(c)
    }

    #[count]
    pub fn load_witness(&self, ctx: &mut ContextWrapper<F>, a: F) -> AssignedValue<F> {
        ctx.ctx.load_witness(a)
    }

    #[count]
    pub fn add(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: AssignedValue<F>,
        b: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let gate = self.gate_chip();
        gate.add(ctx.ctx, a, b)
    }

    #[count]
    pub fn mul(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: AssignedValue<F>,
        b: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let gate = self.gate_chip();
        gate.mul(ctx.ctx, a, b)
    }

    #[count]
    pub fn mul_add(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: AssignedValue<F>,
        b: AssignedValue<F>,
        c: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let gate = self.gate_chip();
        gate.mul_add(ctx.ctx, a, b, c)
    }

    #[count]
    pub fn select(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: AssignedValue<F>,
        b: AssignedValue<F>,
        sel: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let gate = self.gate_chip();
        gate.select(ctx.ctx, a, b, sel)
    }

    // TODO: Barrel shifter? Merkle tree like select?
    #[count]
    pub fn select_from_idx(
        &self,
        ctx: &mut ContextWrapper<F>,
        arr: &[AssignedValue<F>],
        idx: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let gate = self.gate_chip();
        gate.select_from_idx(ctx.ctx, arr.to_vec(), idx)
    }

    #[count]
    pub fn select_array_by_indicator(
        &self,
        ctx: &mut ContextWrapper<F>,
        array2d: &[Vec<AssignedValue<F>>],
        indicator: &[AssignedValue<F>],
    ) -> Vec<AssignedValue<F>> {
        let gate = self.gate_chip();
        gate.select_array_by_indicator(ctx.ctx, array2d, indicator)
    }

    #[count]
    pub fn idx_to_indicator(
        &self,
        ctx: &mut ContextWrapper<F>,
        idx: AssignedValue<F>,
        len: usize,
    ) -> Vec<AssignedValue<F>> {
        let gate = self.gate_chip();
        gate.idx_to_indicator(ctx.ctx, idx, len)
    }

    #[count]
    pub fn num_to_bits(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: AssignedValue<F>,
        range_bits: usize,
    ) -> Vec<AssignedValue<F>> {
        let gate = self.gate_chip();
        gate.num_to_bits(ctx.ctx, a, range_bits)
    }

    #[count]
    pub fn bits_to_num(
        &self,
        ctx: &mut ContextWrapper<F>,
        bits: &[AssignedValue<F>],
    ) -> AssignedValue<F> {
        let gate = self.gate_chip();
        // TODO: halo2-lib doesn't use horner's trick so allocates extra 2^i constants
        gate.bits_to_num(ctx.ctx, bits)
    }

    #[count]
    pub fn decompose_le(
        &self,
        ctx: &mut ContextWrapper<F>,
        num: AssignedValue<F>,
        limb_bits: usize,
        num_limbs: usize,
    ) -> Vec<AssignedValue<F>> {
        let range = self.range_chip();
        range.decompose_le(ctx.ctx, num, limb_bits, num_limbs)
    }

    #[count]
    pub fn limbs_to_num(
        &self,
        ctx: &mut ContextWrapper<F>,
        limbs: &[AssignedValue<F>],
        limb_bits: usize,
    ) -> AssignedValue<F> {
        let range = self.range_chip();
        range.limbs_to_num(ctx.ctx, limbs, limb_bits)
    }

    #[count]
    pub fn check_less_than_safe(&self, ctx: &mut ContextWrapper<F>, a: AssignedValue<F>, b: u64) {
        let range = self.range_chip();
        range.check_less_than_safe(ctx.ctx, a, b)
    }

    #[count]
    pub fn range_check(&self, ctx: &mut ContextWrapper<F>, a: AssignedValue<F>, range_bits: usize) {
        let range = self.range_chip();
        range.range_check(ctx.ctx, a, range_bits)
    }

    #[count]
    pub fn assert_equal(
        &self,
        ctx: &mut ContextWrapper<F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) {
        ctx.ctx.constrain_equal(a, b);
    }
}

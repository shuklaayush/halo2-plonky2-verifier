use halo2_base::utils::ScalarField;
use halo2_base::Context;
use plonky2::field::types::Field64;

pub mod fp;
pub mod fp2;

pub trait FieldChip<F: ScalarField, F64: Field64, Fp> {
    fn load_constant(&self, ctx: &mut Context<F>, a: F64) -> Fp;

    fn load_constants<const N: usize>(&self, ctx: &mut Context<F>, a: &[F64; N]) -> [Fp; N];

    fn load_witness(&self, ctx: &mut Context<F>, a: F64) -> Fp;

    fn add(&self, ctx: &mut Context<F>, a: &Fp, b: &Fp) -> Fp;

    fn sub(&self, ctx: &mut Context<F>, a: &Fp, b: &Fp) -> Fp;

    fn mul(&self, ctx: &mut Context<F>, a: &Fp, b: &Fp) -> Fp;

    fn mul_add(&self, ctx: &mut Context<F>, a: &Fp, b: &Fp, c: &Fp) -> Fp;

    fn select(&self, ctx: &mut Context<F>, a: &Fp, b: &Fp, sel: &Fp) -> Fp;

    fn select_from_idx(&self, ctx: &mut Context<F>, arr: &[Fp], idx: &Fp) -> Fp;

    fn select_array_from_idx(&self, ctx: &mut Context<F>, arr: &[&[Fp]], idx: &Fp) -> Vec<Fp>;

    // TODO: Should this be a Vec<Fp> or Vec<F>?
    fn num_to_bits(&self, ctx: &mut Context<F>, a: &Fp, range_bits: usize) -> Vec<Fp>;

    // TODO: Should this be a &[F] or &[Fp]?
    fn bits_to_num(&self, ctx: &mut Context<F>, bits: &[Fp]) -> Fp;

    fn range_check(&self, ctx: &mut Context<F>, a: &Fp);

    fn assert_equal(&self, ctx: &mut Context<F>, a: &Fp, b: &Fp);
}

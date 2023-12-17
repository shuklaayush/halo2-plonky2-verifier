pub mod extension;
pub mod field;

use halo2_base::utils::ScalarField;
use halo2_base::AssignedValue;

use field::GoldilocksWire;

#[derive(Copy, Clone, Debug)]
pub struct BoolWire<F: ScalarField>(pub AssignedValue<F>);

// TODO: Maybe create a bool chip?
impl<F: ScalarField> From<GoldilocksWire<F>> for BoolWire<F> {
    fn from(w: GoldilocksWire<F>) -> Self {
        Self(w.0)
    }
}

impl<F: ScalarField> From<BoolWire<F>> for GoldilocksWire<F> {
    fn from(b: BoolWire<F>) -> GoldilocksWire<F> {
        GoldilocksWire(b.0)
    }
}

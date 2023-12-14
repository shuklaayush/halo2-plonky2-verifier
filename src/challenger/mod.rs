use halo2_base::gates::{GateChip, RangeChip};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use plonky2::hash::poseidon::SPONGE_RATE;

use crate::goldilocks::extension::GoldilocksQuadExtWire;
use crate::goldilocks::field::{GoldilocksChip, GoldilocksWire};
use crate::hash::poseidon::permutation::{PoseidonPermutationChip, PoseidonStateWire};
use crate::hash::HashOutWire;
use crate::merkle::MerkleCapWire;

pub struct ChallengerChip<F: ScalarField> {
    permutation_chip: PoseidonPermutationChip<F>,
    sponge_state: PoseidonStateWire<F>,
    input_buffer: Vec<GoldilocksWire<F>>,
    output_buffer: Vec<GoldilocksWire<F>>,
}

impl<F: ScalarField> ChallengerChip<F> {
    pub fn new(permutation_chip: PoseidonPermutationChip<F>, state: PoseidonStateWire<F>) -> Self {
        Self {
            permutation_chip,
            sponge_state: state,
            input_buffer: vec![],
            output_buffer: vec![],
        }
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.permutation_chip.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.permutation_chip.range()
    }

    pub fn goldilocks_chip(&self) -> &GoldilocksChip<F> {
        self.permutation_chip.goldilocks_chip()
    }

    pub fn permutation_chip(&self) -> &PoseidonPermutationChip<F> {
        &self.permutation_chip
    }

    pub fn observe_element(&mut self, target: GoldilocksWire<F>) {
        // Any buffered outputs are now invalid, since they wouldn't reflect this input.
        self.output_buffer.clear();

        self.input_buffer.push(target);
    }

    pub fn observe_elements(&mut self, targets: &[GoldilocksWire<F>]) {
        for &target in targets {
            self.observe_element(target);
        }
    }

    pub fn observe_hash(&mut self, hash: &HashOutWire<F>) {
        self.observe_elements(&hash.elements)
    }

    pub fn observe_cap(&mut self, cap: &MerkleCapWire<F>) {
        for hash in &cap.0 {
            self.observe_hash(hash)
        }
    }

    pub fn observe_extension_element(&mut self, element: GoldilocksQuadExtWire<F>) {
        self.observe_elements(&element.0);
    }

    pub fn observe_extension_elements(&mut self, elements: &[GoldilocksQuadExtWire<F>]) {
        for &element in elements {
            self.observe_extension_element(element);
        }
    }

    pub fn get_challenge(&mut self, ctx: &mut Context<F>) -> GoldilocksWire<F> {
        self.absorb_buffered_inputs(ctx);

        if self.output_buffer.is_empty() {
            // Evaluate the permutation to produce `r` new outputs.
            self.sponge_state = self.permutation_chip.permute(ctx, &self.sponge_state);
            self.output_buffer = self.sponge_state.squeeze().to_vec();
        }

        self.output_buffer
            .pop()
            .expect("Output buffer should be non-empty")
    }

    pub fn get_n_challenges(&mut self, ctx: &mut Context<F>, n: usize) -> Vec<GoldilocksWire<F>> {
        (0..n).map(|_| self.get_challenge(ctx)).collect()
    }

    pub fn get_hash(&mut self, ctx: &mut Context<F>) -> HashOutWire<F> {
        HashOutWire {
            elements: [
                self.get_challenge(ctx),
                self.get_challenge(ctx),
                self.get_challenge(ctx),
                self.get_challenge(ctx),
            ],
        }
    }

    pub fn get_extension_challenge(&mut self, ctx: &mut Context<F>) -> GoldilocksQuadExtWire<F> {
        // TODO: Remove hardcode
        GoldilocksQuadExtWire(self.get_n_challenges(ctx, 2).try_into().unwrap())
    }

    /// Absorb any buffered inputs. After calling this, the input buffer will be empty, and the
    /// output buffer will be full.
    fn absorb_buffered_inputs(&mut self, ctx: &mut Context<F>) {
        if self.input_buffer.is_empty() {
            return;
        }

        for input_chunk in self.input_buffer.chunks(SPONGE_RATE) {
            // Overwrite the first r elements with the inputs. This differs from a standard sponge,
            // where we would xor or add in the inputs. This is a well-known variant, though,
            // sometimes called "overwrite mode".
            self.sponge_state.0.copy_from_slice(input_chunk);
            self.sponge_state = self.permutation_chip.permute(ctx, &self.sponge_state);
        }

        self.output_buffer = self.sponge_state.squeeze().to_vec();

        self.input_buffer.clear();
    }
}

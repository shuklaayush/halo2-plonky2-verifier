# Halo2 plonky2 verifier

This repository contains halo2 gadgets to verify [plonky2/starky](https://github.com/0xpolygonzero/plonky2) proofs. It uses Axiom's [halo2-lib](https://github.com/axiom-crypto/halo2-lib) under the hood.

Currently, the code can verify FRI proofs from plonky2, and full proof verification is still WIP.

TODOs:

- [x] FRI verification
- [ ] STARK vanishing polynomial evaluation
- [ ] PLONK verification
- [ ] Benchmarking

## Test

To run the mock prover for verification of a Fibonacci STARK:

```bash
cargo t -r -- --nocapture test_fibonacci_stark
```

## Acknowledgements

This code is adapted from the original [recursive verifier](https://github.com/0xPolygonZero/plonky2/blob/fdd7ee46fe735186b00a7090ead9ff1ae660f14d/starky/src/recursive_verifier.rs) implementation in plonky2.

Succinct's [gnark-plonky2-verifier](https://github.com/succinctlabs/gnark-plonky2-verifier) was also used as a reference, and the PoseidonBN254 implementation is adapted from there. 

Other references:

- [halo2-fri-gadget](https://github.com/maxgillett/halo2-fri-gadget): Contains gadgets for Winterfell FRI proof verification for proofs generated in a circuit's native field.
- [plonky2-circom](https://github.com/polymerdao/plonky2-circom)

## Disclaimer

These gadgets have **NOT** been formally audited. Therefore, they should not be deployed in production.

#![feature(generic_const_exprs)]
// #![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod challenger;
pub mod field;
pub mod fri;
pub mod hash;
pub mod merkle;
pub mod stark;
pub mod util;
pub mod witness;

#[cfg(test)]
pub mod test_util;

// TODO: Benchmark real proving, criterion, ppfrof, flamegraph, etc.

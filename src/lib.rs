#![feature(generic_const_exprs)]
// #![cfg_attr(not(feature = "std"), no_std)]

pub mod challenger;
pub mod fri;
pub mod goldilocks;
pub mod hash;
pub mod merkle;
pub mod stark;
pub mod util;
pub mod witness;

// TODO: Benchmark real proving, criterion, ppfrof, flamegraph, etc.

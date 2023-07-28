//! ## Open questions & ToDos
//! * Trait vs Ciphersuite
//!   * Define 1 struct per ciphersuite that implements the trait
//!   * Define a ciphersuite that's a function argument to switch between the implementations
//! * What's the high level API?
//! * How to match the code to the spec?
//!   * Do you follow the RFC? If yes, it should be clear where the functions are.
//!   * If not, there should be a good structure that points to the corresponding places in the RFC.
//! * Add x25519 as different implementation (taking it from <https://github.com/hacspec/specs/pull/12>)
//! * If using traits
//!   * Simplify traits
//!   * Clearly separate traits
//! * Comments are all code because of indentation

#![doc = include_str!("../Readme.md")]
// #![warn(missing_docs)]
// #![warn(rustdoc::missing_crate_level_docs)]

mod hacspec_helper;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidEll,
}

mod bls12_381;
pub mod bls12_381_hash;
pub mod expand_message;
pub mod hash_suite;
pub mod hasher;
pub mod p256_hash;
pub mod prime_curve;

#[cfg(test)]
mod test_utils;

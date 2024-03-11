#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate is an executable specification of an MPC engine based on the
//! WRK17 protocol.

/// The computational security parameter, in bytes.
pub const COMPUTATIONAL_SECURITY: usize = 128 / 8;

/// The statistical security parameter, in bytes.
pub const STATISTICAL_SECURITY: usize = 128 / 8;

pub mod circuit;
pub mod messages;
pub mod primitives;

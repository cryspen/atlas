#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate is an executable specification of an MPC engine based on the
//! WRK17 protocol.

use circuit::CircuitError;

#[derive(Debug)]
/// An error type.
pub enum Error {
    /// More random bytes have been asked for than are available.
    InsufficientRandomness,
    /// An error during circuit processing
    Circuit(CircuitError),
    /// Miscellaneous error.
    OtherError,
}

impl From<hacspec_lib::Error> for Error {
    fn from(value: hacspec_lib::Error) -> Self {
        match value {
            hacspec_lib::Error::InsufficientRandomness => Self::InsufficientRandomness,
        }
    }
}

impl From<p256::Error> for Error {
    fn from(value: p256::Error) -> Self {
        match value {
            p256::Error::InvalidAddition
            | p256::Error::DeserializeError
            | p256::Error::PointAtInfinity => Self::OtherError,
            p256::Error::SamplingError => Self::InsufficientRandomness,
        }
    }
}

impl From<hacspec_chacha20poly1305::Error> for Error {
    fn from(value: hacspec_chacha20poly1305::Error) -> Self {
        match value {
            hacspec_chacha20poly1305::Error::InvalidTag => Self::OtherError,
        }
    }
}

/// The computational security parameter, in bytes.
pub const COMPUTATIONAL_SECURITY: usize = 128 / 8;

/// The statistical security parameter, in bytes.
pub const STATISTICAL_SECURITY: usize = 128 / 8;

pub mod circuit;
pub mod messages;
pub mod party;
pub mod primitives;
pub mod utils;

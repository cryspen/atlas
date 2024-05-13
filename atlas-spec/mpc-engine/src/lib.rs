#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate is an executable specification of an MPC engine based on the
//! WRK17 protocol.

use circuit::CircuitError;
use messages::{Message, SubMessage};

#[derive(Debug)]
/// An error type.
pub enum Error {
    /// More random bytes have been asked for than are available.
    InsufficientRandomness,
    /// An error during circuit processing
    Circuit(CircuitError),
    /// A specific subprotocol message was expected but a different one was
    /// received.
    UnexpectedSubprotocolMessage(SubMessage),
    /// A specific top-level message was expected but a different one was
    /// received
    UnexpectedMessage(Message),
    /// Failed to open a commitment
    BadCommitment(Vec<u8>, Vec<u8>),
    /// Error from the curve implementation
    CurveError,
    /// Error from the AEAD
    AEADError,
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
            | p256::Error::PointAtInfinity => Self::CurveError,
            p256::Error::SamplingError => Self::InsufficientRandomness,
        }
    }
}

impl From<hacspec_chacha20poly1305::Error> for Error {
    fn from(value: hacspec_chacha20poly1305::Error) -> Self {
        match value {
            hacspec_chacha20poly1305::Error::InvalidTag => Self::AEADError,
        }
    }
}

/// The computational security parameter, in bytes.
pub const COMPUTATIONAL_SECURITY: usize = 128 / 8;

/// The statistical security parameter, in bytes.
pub const STATISTICAL_SECURITY: usize = 128 / 8;

// NOTE: The `broadcast` module implements a broadcast utility via a trusted
// third-party message relay, in lieu of a secure peer-to-peer broadcast
// sub-protocol.
pub mod broadcast;
pub mod circuit;
pub mod messages;
pub mod party;
pub mod primitives;
pub mod utils;

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate is an executable specification of an MPC engine based on the
//! WRK17 protocol.

use circuit::CircuitError;
use messages::{Message, SubMessage};

#[derive(Debug)]
/// An error type.
///
/// We generally expect to definitely panic in two cases:
/// * Insufficient randomness was provided for a given operation
/// * A channel handle was prematurely dropped (this indicates a bug in the
///   specification)
///
/// In other cases, the errors might be the result of a buggy protocol
/// participant, or a detected attempt at cheating. These cases should be
/// handled by the surrounding application in order to gracefully shut down or,
/// if possible remove the cheater in a secure way, so these errors should be
/// handled there.
pub enum Error {
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

impl From<p256::Error> for Error {
    fn from(_value: p256::Error) -> Self {
        Self::CurveError
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
pub const STATISTICAL_SECURITY: usize = 5; // for 5 * 8 = 40 bits of statistical security

// NOTE: The `broadcast` module implements a broadcast utility via a trusted
// third-party message relay, in lieu of a secure peer-to-peer broadcast
// sub-protocol.
pub mod broadcast;
pub mod circuit;
pub mod messages;
pub mod party;
pub mod primitives;
pub mod utils;

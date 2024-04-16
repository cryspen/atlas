#![doc = include_str!("../Readme.md")]
#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Hash-to-Curve Errors
pub enum Error {
    /// The length requested of the expand_message function leads to an invalid parameter.
    InvalidEll,
    /// Catch-all error for errors in the underlying curver implementation.
    CurveError,
}

impl From<p256::Error> for Error {
    fn from(_value: p256::Error) -> Self {
        Self::CurveError
    }
}

// ========== Suites =============
pub mod p256_hash;

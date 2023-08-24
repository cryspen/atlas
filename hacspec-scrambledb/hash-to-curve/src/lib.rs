#![doc = include_str!("../Readme.md")]
// #![warn(missing_docs)]
// #![warn(rustdoc::missing_crate_level_docs)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidEll,
    InvalidAddition,
    PointAtInfinity,
    UnsupportedCiphersuite,

    CurveError,
}

impl From<p256::Error> for Error {
    fn from(_value: p256::Error) -> Self {
        Self::CurveError
    }
}

// ========== Suites =============
pub mod p256_hash;

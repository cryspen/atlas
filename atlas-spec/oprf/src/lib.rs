#![allow(non_camel_case_types, non_snake_case)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInputError,
    DeriveKeyPairError,
    CurveError,
    HashToCurveError,
    ElgamalError,
    RandomnessError,
}

impl From<p256::Error> for Error {
    fn from(_: p256::Error) -> Self {
        Self::CurveError
    }
}

impl From<hash_to_curve::Error> for Error {
    fn from(_: hash_to_curve::Error) -> Self {
        Self::HashToCurveError
    }
}

impl From<elgamal::Error> for Error {
    fn from(_: elgamal::Error) -> Self {
        Self::ElgamalError
    }
}

impl From<hacspec_lib::Error> for Error {
    fn from(_value: hacspec_lib::Error) -> Self {
        Self::RandomnessError
    }
}

// 3. Protocol
pub mod protocol;

// 4.2 OPRF(P-256, SHA-256)
pub mod p256_sha256;

pub mod coprf;

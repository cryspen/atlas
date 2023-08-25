#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    RandomnessError,
    CorruptedData,
}

impl From<oprf::Error> for Error {
    fn from(value: oprf::Error) -> Self {
        match value {
            oprf::Error::InvalidInputError => Self::CorruptedData,
            oprf::Error::DeriveKeyPairError => Self::RandomnessError,
            oprf::Error::CurveError => Self::CorruptedData,
            oprf::Error::HashToCurveError => Self::CorruptedData,
            oprf::Error::ElgamalError => Self::RandomnessError,
        }
    }
}

impl From<hacspec_lib::Error> for Error {
    fn from(value: hacspec_lib::Error) -> Self {
        match value {
            hacspec_lib::Error::InsufficientRandomness => Self::RandomnessError,
        }
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(_value: std::array::TryFromSliceError) -> Self {
        Self::RandomnessError
    }
}

impl From<p256::Error> for Error {
    fn from(value: p256::Error) -> Self {
        match value {
            p256::Error::InvalidAddition => Self::CorruptedData,
            p256::Error::DeserializeError => Self::CorruptedData,
            p256::Error::PointAtInfinity => Self::CorruptedData,
            p256::Error::SamplingError => Self::RandomnessError,
        }
    }
}

impl From<elgamal::Error> for Error {
    fn from(value: elgamal::Error) -> Self {
        match value {
            elgamal::Error::CurveError => Self::CorruptedData,
            elgamal::Error::SamplingError => Self::RandomnessError,
        }
    }
}
/// security parameter in bytes
const SECPAR_BYTES: usize = 16;

/// OPRF context string used by ScrambleDB sources
const SCRAMBLEDB_SRC_CONTEXT: &[u8] = b"ScrambleDBSourceContext";

/// ID given to finalized joined tables by data processor
const JOIN_ID: &str = "Join-";

pub mod converter;
pub mod lake;
pub mod processor;
pub mod source;
mod table;

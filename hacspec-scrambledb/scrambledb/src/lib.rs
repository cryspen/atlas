#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ConverterSetupError,
    PseudonomizationError,
    JoinError,
}
/// security parameter in bytes
const SECPAR_BYTES: usize = 16;
/// bytes of randomness required to sample scalars
const RANDBYTES_SCALAR: usize = 32;
/// Suite identifier for initializing the coPRF
const COPRF_SUITE_ID: &[u8] = b"coPRF-P256-SHA256";
/// ID given to finalized joined tables by data processor
const JOIN_ID: &[u8] = b"Join-";

pub mod converter;
pub mod lake;
pub mod processor;
pub mod source;
mod table;

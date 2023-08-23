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

pub mod converter;
pub mod lake;
pub mod processor;
pub mod source;
mod table;

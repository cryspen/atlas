#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ConverterSetupError,
    PseudonomizationError,
}

const SECPAR_BYTES: usize = 16; // security parameter in bytes;
const RANDBYTES_SCALAR: usize = 32; // bytes of randomness required to sample scalars

pub mod converter;
pub mod lake;
pub mod processor;
pub mod source;
mod table;

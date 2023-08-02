#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidScalarMult,
    InvalidPointAdd,
    DeserializeError,
    InvalidExpansion
}


/// # 2. Preliminaries
pub mod prime_order_group;
pub mod dlog_eq;

/// # 3. Protocol
/// pub mod oprf;
 
/// # 4. Ciphersuites
pub mod oprf_suite;
mod p256_sha256;


mod util;

#![doc = include_str!("../Readme.md")]
// #![warn(missing_docs)]
// #![warn(rustdoc::missing_crate_level_docs)]

use expand_message::expand_message_xmd;
use hasher::SHA256;

mod hacspec_helper;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidEll,
    InvalidAddition,
    PointAtInfinity,
    UnsupportedCiphersuite,
}

pub mod expand_message;
pub mod hash_suite;
pub mod hasher;
pub mod mappings;

pub mod prime_curve;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_snake_case)]
pub struct Ciphersuite {
    pub ID: &'static str,
    pub K: usize,
    pub L: usize,
    pub M: usize,
}

pub const P256_XMD_SHA256_SSWU_RO: Ciphersuite = Ciphersuite {
    ID: "P256_XMD:SHA-256_SSWU_RO_",
    K: 128,
    L: 48,
    M: 1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandMessageType {
    P256_SHA256,
}

pub fn expand_message(
    expand_message_type: ExpandMessageType,
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, Error> {
    match expand_message_type {
        ExpandMessageType::P256_SHA256 => expand_message_xmd::<SHA256>(msg, dst, len_in_bytes),
    }
}

// ========== Suites =============
pub mod p256_hash;
//pub mod p384_hash;
//pub mod p521_hash;

//pub mod curve25519_hash;
//pub mod edwards25519_hash;

//pub mod curve448_hash;
//pub mod edwards448_hash;

//pub mod secp256k1_hash;

// mod bls12_381;
// pub mod bls12_381_g1_hash;
// pub mod bls12_381_g2_hash;

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn p256_xmd_sha256_sswu_ro_hash_to_field() {
        test_hash_to_field_plain(P256_XMD_SHA256_SSWU_RO)
    }
}

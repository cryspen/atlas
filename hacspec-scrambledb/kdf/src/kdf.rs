#![doc = include_str!("../Readme.md")]
#![allow(non_snake_case, non_camel_case_types)]

#[cfg(feature = "evercrypt")]
use evercrypt_cryptolib::*;
#[cfg(not(feature = "evercrypt"))]
use hacspec_cryptolib::*;
use hacspec_lib::*;

use hpke_errors::*;

type CryptoResult = Result<ByteSeq, CryptoError>;

/// ## Key Derivation Functions (KDFs)
///
/// | Value  | KDF         | Nh  | Reference |
/// | :----- | :---------- | --- | :-------- |
/// | 0x0000 | (reserved)  | N/A | N/A       |
/// | 0x0001 | HKDF-SHA256 | 32  | [RFC5869] |
/// | 0x0002 | HKDF-SHA384 | 48  | [RFC5869] |
/// | 0x0003 | HKDF-SHA512 | 64  | [RFC5869] |
///
/// ### KDF Identifiers
///
/// The "HPKE KDF Identifiers" registry lists identifiers for key derivation
/// functions defined for use with HPKE. These identifiers are two-byte values,
/// so the maximum possible value is 0xFFFF = 65535.
///
/// Template:
///
/// * Value: The two-byte identifier for the algorithm
/// * KDF: The name of the algorithm
/// * Nh: The output size of the Extract function in bytes
/// * Reference: Where this algorithm is defined
///
/// [RFC5869]: https://www.rfc-editor.org/info/rfc5869
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum KDF {
    /// 0x0001
    HKDF_SHA256,
    /// 0x0002
    HKDF_SHA384,
    /// 0x0003
    HKDF_SHA512,
}

// pub type Error = u8;
// pub const UNKNOWN_ALGORITHM: Error = 1u8;
// pub const HKDF_INVALID_OUTPUT_LENGTH: Error = 2u8;
// pub const CRYPTO_ERROR: Error = 3u8;

pub type InputKeyMaterial = ByteSeq;
pub type Info = ByteSeq;

/// Get the numeric value of the `kdf_id`.
///
/// See [`KDF`] for details.
pub fn kdf_value(kdf_id: KDF) -> U16 {
    match kdf_id {
        KDF::HKDF_SHA256 => U16(0x0001u16),
        KDF::HKDF_SHA384 => U16(0x0002u16),
        KDF::HKDF_SHA512 => U16(0x0003u16),
    }
}

/// The output size of the `Extract()` function in bytes.
///
/// See [`KDF`] for details.
pub fn Nh(kdf_id: KDF) -> usize {
    match kdf_id {
        KDF::HKDF_SHA256 => 32,
        KDF::HKDF_SHA384 => 48,
        KDF::HKDF_SHA512 => 64,
    }
}

/// The string literal "HPKE-v1" used in [`LabeledExtract()`] and [`LabeledExpand()`]
/// ensures that any secrets derived in HPKE are bound to the scheme's name
/// and version, even when possibly derived from the same Diffie-Hellman or
/// KEM shared secret as in another scheme or version.
fn hpke_version_label() -> ByteSeq {
    byte_seq!(0x48u8, 0x50u8, 0x4bu8, 0x45u8, 0x2du8, 0x76u8, 0x31u8)
}

fn hash_for_kdf(alg: KDF) -> HashAlgorithm {
    match alg {
        KDF::HKDF_SHA256 => HashAlgorithm::SHA256,
        KDF::HKDF_SHA384 => HashAlgorithm::SHA384,
        KDF::HKDF_SHA512 => HashAlgorithm::SHA512,
    }
}

/// LabeledExtract
///
/// ```text
/// def LabeledExtract(salt, label, ikm):
///   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
///   return Extract(salt, labeled_ikm)
/// ```
pub fn LabeledExtract(
    alg: KDF,
    suite_id: &ByteSeq,
    salt: &ByteSeq,
    label: &ByteSeq,
    ikm: &InputKeyMaterial,
) -> HpkeByteSeqResult {
    match hkdf_extract(
        hash_for_kdf(alg),
        &hpke_version_label()
            .concat(suite_id)
            .concat(label)
            .concat(ikm),
        salt,
    ) {
        CryptoResult::Ok(prk) => HpkeByteSeqResult::Ok(prk),
        CryptoResult::Err(_) => HpkeByteSeqResult::Err(HpkeError::CryptoError),
    }
}

/// KDF: Labeled Expand
///
/// ```text
/// def LabeledExpand(prk, label, info, L):
///   labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
///                         label, info)
///   return Expand(prk, labeled_info, L)
/// ```
pub fn LabeledExpand(
    alg: KDF,
    suite_id: &ByteSeq,
    prk: &ByteSeq,
    label: &ByteSeq,
    info: &Info,
    L: usize,
) -> HpkeByteSeqResult {
    if L > (255 * Nh(alg)) {
        // This check is mentioned explicitly in the spec because because it
        // must be adhered to when exporting secrets.
        // The check comes from HKDF and will be performed there again.
        HpkeByteSeqResult::Err(HpkeError::InvalidParameters)
    } else {
        match hkdf_expand(
            hash_for_kdf(alg),
            prk,
            &U16_to_be_bytes(U16(L as u16))
                .concat(&hpke_version_label())
                .concat(suite_id)
                .concat(label)
                .concat(info),
            L,
        ) {
            CryptoResult::Ok(r) => HpkeByteSeqResult::Ok(r),
            CryptoResult::Err(_) => HpkeByteSeqResult::Err(HpkeError::CryptoError),
        }
    }
}

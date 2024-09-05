//! # ScrambleDB
//!
//! This document describes `ScrambleDB`, a protocol between several
//! parties for the pseudonymization and non-transitive joining of data.
//!
//! ## Overview and Concepts
//! `ScrambleDB` operates on tables of data, where a table is a collection
//! of attribute entries for entities identified by unique keys.
//!
//!
//! `ScrambleDB` offers two sub-protocols for blindly converting between different
//! table types.
//! ### Conversion from plain tables to pseudonymized columns
//! A plain table contains attribute data organized by (possibly
//! sensitive) entity identifiers, e.g. a table might store attribute
//! data for attributes `Address` and `Date of Birth (DoB)` under the
//! entity identifier `Full Name`:
//!
//! | Full Name (Identifier) | Address                            | DoB           |
//! |------------------------|------------------------------------|---------------|
//! | Bilbo Baggins          | 1 Bagshot Row, Hobbiton, the Shire | Sept. 22 1290 |
//! | Frodo Baggins          | 1 Bagshot Row, Hobbiton, the Shire | Sept. 22 1368 |
//!
//! The result of `ScrambleDB` pseudonymization of such a
//! table can be thought of as computed in two steps:
//!
//! 1. Splitting the original table by attributes, resulting in
//!    single-column tables, one per attribute, indexed by the original
//!    identifier.
//!
//! | Full Name (Identifier) | Address                            |
//! |------------------------|------------------------------------|
//! | Bilbo Baggins          | 1 Bagshot Row, Hobbiton, the Shire |
//! | Frodo Baggins          | 1 Bagshot Row, Hobbiton, the Shire |
//!
//! | Full Name (Identifier) | DoB           |
//! |------------------------|---------------|
//! | Bilbo Baggins          | Sept. 22 1290 |
//! | Frodo Baggins          | Sept. 22 1368 |
//!
//! 2. Pseudonymization and shuffling of split columns, such that the original
//!    identifiers are replaced by pseudonyms which are unlinkable between
//!    different columns.
//!
//! | Pseudonym (Identifier) | Address                            |
//! |------------------------|------------------------------------|
//! | _pseudo1_              | 1 Bagshot Row, Hobbiton, the Shire |
//! | _pseudo2_              | 1 Bagshot Row, Hobbiton, the Shire |
//! |                        |                                    |
//!
//! | Pseudonym (Identifier) | DoB           |
//! |------------------------|---------------|
//! | _pseudo3_              | Sept. 22 1368 |
//! | _pseudo4_              | Sept. 22 1290 |
//!
//!
//! Since the result of pseudonymizing a plain table is a set of
//! pseudonymized single-column tables we refer to this operation as a
//! _split conversion_.
//!
//! ### Conversion from pseudonymized columns to non-transitively joined tables
//! Pseudonymized columns may be selectively re-joined such that the
//! original link between data is restored, but under a fresh pseudonymous
//! identifier instead of the original (sensitive) identifier. In the
//! above example, a join of pseudonymized columns `Address` and `DoB`
//! would result in the following pseudonymized joined table.
//!
//!
//! | Join Pseudonym (Identifier) | Address                            | DoB           |
//! |-----------------------------|------------------------------------|---------------|
//! | _pseudo5_                   | 1 Bagshot Row, Hobbiton, the Shire | Sept. 22 1290 |
//! | _pseudo6_                   | 1 Bagshot Row, Hobbiton, the Shire | Sept. 22 1368 |
//!
//! The contained pseudonyms are fresh for each join and are
//! non-transitive, i.e. it is not possible to further join two
//! join-results based on the join pseudonym.
//!
//! Since the result of this conversion is a joined table, we refer to the
//! operation as a _join conversion_.
//!
//! ### Data Sources, Stores and Converter
//! `ScrambleDB` is a multiparty protocol where parties serve different
//! roles as origins or destinations of data.
//!
//! Non-pseudonymized data originates at a **data source**.
//!
//! **Data stores** hold pseudonymized data and come in two forms:
//! - The **data lake** is a designated data store which stores
//!   pseudonymized data columns fed to it by data sources via the
//!   ScrambleDB protocol.
//! - A **data processor** is a data store which acquires pseudonymized
//!   joined tables from a data lake via the ScrambleDB protocol.
//!
//! The **converter** facilitates the protocol in an oblivious fashion by
//! blindly performing the two types of conversion operations.
//!
//!
//! ## Cryptographic Preliminaries
//!
//! ### Rerandomizable Public Key Encryption
//! A rerandomizable public key encryption scheme `RPKE` is parameterized by a
//! set of possible plaintexts `PlainText` as well as a set of ciphertexts
//! `Ciphertext`.
//!
//! It offers the following interface:
//! - Key Generation:
//! ```text
//! fn RPKE.generate_key_pair(randomness) -> (ek, dk)
//!
//! Inputs:
//!     randomness
//!
//! Ouputs:
//!     ek: EncryptionKey
//!     dk: DecryptionKey
//! ```
//! - Encryption:
//! ```text
//! fn RPKE.encrypt(ek, msk, randomness) -> ctxt
//!
//! Inputs:
//!     ek: EncryptionKey
//!     msg: Plaintext
//!     randomness
//!
//! Outputs:
//!     ctxt: Ciphertext
//! ```
//! - Decryption:
//! ``` text
//! fn RPKE.decrypt(dk, ctxt) -> msg'
//!
//! Inputs:
//!     dk: DecryptionKey
//!     ctxt: Ciphertext
//!
//! Output:
//!     msg': Plaintext
//!
//! Failures:
//!     DecryptionFailure
//! ```
//! - Ciphertext rerandomization:
//!
//! ``` text
//! fn RPKE.rerandomize(ek, ctxt, randomness) -> ctxt'
//!
//! Inputs:
//!     ek: EncryptionKey
//!     ctxt: Ciphertext
//!     randomness
//!
//! Output:
//!     ctxt': Ciphertext
//! ```
//!
//! ### Convertible Pseudorandom Function (coPRF)
//! **TODO: Describe coPRF interface**
//!
//! ### Pseudorandom Permutation
//! A pseudorandom permutation is a keyed pseudorandom permutation with
//! the following interface, where `PRPKey` is the set of possible keys
//! for the permutation and `PRPValue` is the both the domain and range of
//! the permutation.
//!
//! - Permutation:
//!
//! ``` text
//! PRP.eval(k, x) -> y
//!
//! Inputs:
//!     k: PRPKey
//!     x: PRPValue
//!
//! Output:
//!     y: PRPValue
//! ```
//!
//! - Inversion:
//!
//! ``` text
//! PRP.inverse(k, x) -> y
//!
//! Inputs:
//!     k: PRPKey
//!     x: PRPValue
//!
//! Output:
//!     y: PRPValue
//! ```
//!
//! We require that for all possible PRP keys `k`, successive application
//! of `PRP.eval`, then `PRP.inverse` or reversed is the identity
//! function, i.e. for any `x` in `PRPValue`:
//!
//! ``` text
//! PRP.eval(k, PRP.inverse(k, x)) = PRP.inverse(k, PRP.eval(k, x)) = x
//! ```

#[cfg(feature = "double-hpke")]
use libcrux::hpke::{aead::AEAD, kdf::KDF, kem::KEM, HPKECiphertext, HPKEConfig, Mode};

/// Security parameter in bytes
const SECPAR_BYTES: usize = 16;

/// The HPKE Configuration used in the implementation of double HPKE
/// encryption using the HPKE single-shot API.
#[cfg(feature = "double-hpke")]
const HPKE_CONF: HPKEConfig = HPKEConfig(
    Mode::mode_base,
    KEM::DHKEM_P256_HKDF_SHA256,
    KDF::HKDF_SHA256,
    AEAD::ChaCha20Poly1305,
);

/// A wrapper type to facilitate (de-)serialization of HPKE
/// ciphertexts to (and from) linear byte vectors.
#[cfg(feature = "double-hpke")]
pub struct SerializedHPKE {
    len_kem_output: u32,
    len_ciphertext: u32,
    bytes: Vec<u8>,
}

#[cfg(feature = "double-hpke")]
impl SerializedHPKE {
    /// Prepare an HPKE ciphertext for serialization by wrapping it in
    /// a `SerializedHPKE`.
    pub fn from_hpke_ct(ct: &HPKECiphertext) -> Self {
        let mut bytes = ct.0.clone();
        bytes.extend_from_slice(&ct.1);

        Self {
            len_kem_output: ct.0.len() as u32,
            len_ciphertext: ct.1.len() as u32,
            bytes,
        }
    }

    /// Reconstruct an HPKE ciphertext from the wrapper type. This
    /// does not perform validation of the reconstructed ciphertext.
    pub fn to_hpke_ct(&self) -> HPKECiphertext {
        HPKECiphertext(
            self.bytes[0..self.len_kem_output as usize].to_vec(),
            self.bytes[self.len_kem_output as usize..self.bytes.len()].to_vec(),
        )
    }

    /// Serialize the wrapper type to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.len_kem_output.to_be_bytes());
        bytes.extend_from_slice(&self.len_ciphertext.to_be_bytes());
        bytes.extend_from_slice(&self.bytes);
        bytes
    }

    /// Deseralize a wrapped HPKE ciphertext from a byte vector. This
    /// does not perform validation of the deserialized ciphertext.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let len_kem_output = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let len_ciphertext = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        Self {
            len_kem_output,
            len_ciphertext,
            bytes: bytes[8..bytes.len()].to_vec(),
        }
    }
}

pub mod table;
pub mod setup;
pub mod split;
pub mod join;
pub mod finalize;
pub mod data_transformations;
pub mod data_types;

pub mod error;

#[cfg(feature = "wasm")]
pub mod wasm_demo;

#[cfg(test)]
mod test_util;

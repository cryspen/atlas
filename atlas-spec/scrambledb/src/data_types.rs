//! This module defines data structures for indvidual pieces of data in
//! ScrambleDB.
//!
//! A value generally consists of a handle and a data value. Handles can be
//! identifiable or pseudonymous and either form can also be blinded. Data
//! values may be in plain text or encrypted and always carry with them the
//! name of the attribute they belong to in plain text.

use oprf::coprf::coprf_online::{BlindInput, BlindOutput};
#[cfg(not(feature = "double-hpke"))]
use p256::P256Point;

/// A type for finalized pseudonyms, i.e. those which have been hardened for
/// storage by applying a PRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(test, derive(Hash))]
pub struct FinalizedPseudonym(pub(crate) [u8; 64]);
/// A type for blinded identifiable handles.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlindedIdentifiableHandle(pub(crate) BlindInput);
/// A type for  blinded pseudonymous handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlindedPseudonymizedHandle(pub(crate) BlindOutput);

/// A plain text data value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DataValue {
    /// A byte string encoding the data value.
    pub(crate) value: Vec<u8>,
    /// The name of the attribute the value belongs to.
    pub(crate) attribute_name: String,
}

/// An encrypted data value.
#[cfg(feature = "double-hpke")]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncryptedDataValue {
    /// A byte string encoding the encrypted data value.
    pub(crate) value: Vec<u8>,
    /// The name of the attribute the value belongs to.
    pub(crate) attribute_name: String,
    /// The encryption level, as understood in terms of [crate::data_transformations::double_hpke].
    pub(crate) encryption_level: u8,
}

/// An encrypted data value.
#[cfg(not(feature = "double-hpke"))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncryptedDataValue {
    /// A vector of ElGamal ciphertexts encoding the encrypted data value.
    pub(crate) value: Vec<(P256Point, P256Point)>,
    /// The name of the attribute the value belongs to.
    pub(crate) attribute_name: String,
}

/// An identifiable piece of data.
///
/// `PartialOrd` derive:
/// When derived on structs, it will produce a lexicographic ordering based on
/// the top-to-bottom declaration order of the struct’s members.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IdentifiableData {
    /// A plain text handle.
    /// Because `PartialOrd` is derived, the order for this struct is
    /// lexicographical on this handle.
    pub(crate) handle: String,
    /// A plain text data value.
    pub(crate) data_value: DataValue,
}

/// The blinded version of an identifiable piece of data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlindedIdentifiableData {
    /// A blinded plain text handle.
    pub(crate) blinded_handle: BlindedIdentifiableHandle,
    /// An encrypted data value.
    pub(crate) encrypted_data_value: EncryptedDataValue,
}

/// The blinded version of a pseudonymized piece of data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlindedPseudonymizedData {
    /// A blinded pseudonymous handle.
    pub(crate) blinded_handle: BlindedPseudonymizedHandle,
    /// An encrypted data value.
    pub(crate) encrypted_data_value: EncryptedDataValue,
}

/// A pseudonymized piece of data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PseudonymizedData {
    /// A pseudonymous handle.
    pub(crate) handle: FinalizedPseudonym,
    /// A plain text data value.
    pub(crate) data_value: DataValue,
}

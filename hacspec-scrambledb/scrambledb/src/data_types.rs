//! This module defines data structures for indvidual pieces of data in
//! ScrambleDB.
//!
//! A value generally consists of a handle and a data value. Handles can be
//! identifiable or pseudonymous and either form can also be blinded. Data
//! values may be in plain text or encrypted and always carry with them the
//! name of the attribute they belong to in plain text.
/// A type for finalized pseudonyms, i.e. those which have been hardened for
/// storage by applying a PRP.
pub struct FinalizedPseudonym(pub(crate) [u8; 64]);
/// A type for blinded identifiable handles.
pub struct BlindedIdentifiableHandle(pub(crate) BlindInput);
/// A type for  blinded pseudonymous handles.
pub struct BlindedPseudonymizedHandle(pub(crate) BlindOutput);

/// A plain text data value.
pub struct DataValue {
    /// A byte string encoding the data value.
    pub(crate) value: Vec<u8>,
    /// The name of the attribute the value belongs to.
    pub(crate) attribute_name: String,
}
/// An encrypted data value.
pub struct EncryptedDataValue {
    /// A byte string encoding the encrypted data value.
    pub(crate) value: Vec<u8>,
    /// The name of the attribute the value belongs to.
    pub(crate) attribute_name: String,
}

/// An identifiable piece of data.
pub struct IdentifiableData {
    /// A plain text handle.
    pub(crate) handle: String,
    /// A plain text data value.
    pub(crate) data_value: DataValue,
}

/// The blinded version of an identifiable piece of data.
pub struct BlindedIdentifiableData {
    /// A blinded plain text handle.
    pub(crate) handle: BlindedIdentifiableHandle,
    /// An encrypted data value.
    pub(crate) data_value: EncryptedDataValue,
}

/// The blinded version of a pseudonymized piece of data.
pub struct BlindedPseudonymizedData {
    /// A blinded pseudonymous handle.
    pub(crate) handle: BlindedPseudonymizedHandle,
    /// An encrypted data value.
    pub(crate) data_value: EncryptedDataValue,
}

/// A pseudonymized piece of data.
pub struct PseudonymizedData {
    /// A pseudonymous handle.
    pub(crate) handle: FinalizedPseudonym,
    /// A plain text data value.
    pub(crate) data_value: DataValue,
}

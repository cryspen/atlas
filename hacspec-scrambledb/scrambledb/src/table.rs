//! ## Tables and Data Types
//! The `ScrambleDB` protocol provides conversions between types of data
//! tables that are differentiated by their structure and contents.

use oprf::coprf::coprf_online::{BlindInput, BlindOutput};

/// A plain entity identifier is a unicode string.
pub type PlainIdentifier = String;

/// A plain data value is a plaintext value of the underlying
/// rerandomizable public key encryption scheme.
pub type PlainValue = elgamal::Plaintext;
pub type EncryptedValue = elgamal::Ciphertext;
pub type BlindIdentifier = BlindInput;
pub type BlindPseudonym = BlindOutput;
pub type Pseudonym = [u8; 64];

pub type PlainTable = MultiColumnTable<PlainIdentifier, PlainValue>;
pub type BlindTable = MultiColumnTable<BlindIdentifier, EncryptedValue>;
pub type ConvertedTable = SingleColumnTable<BlindPseudonym, EncryptedValue>;
pub type PseudonymizedTable = SingleColumnTable<Pseudonym, PlainValue>;

#[derive(Clone)]
pub struct Column<K, V> {
    attribute: String,
    data: Vec<(K, V)>,
}

impl<K, V> Column<K, V> {
    pub fn new(attribute: String, data: Vec<(K, V)>) -> Self {
        Self { attribute, data }
    }

    pub fn attribute(&self) -> String {
        self.attribute.clone()
    }

    pub fn data(&self) -> Vec<(K, V)>
    where
        K: Clone,
        V: Clone,
    {
        self.data.clone()
    }

    pub fn sort(&mut self)
    where
        K: Ord,
        K: Clone,
    {
        self.data.sort_by_key(|(k, _)| k.clone())
    }
}

pub struct MultiColumnTable<K, V> {
    identifier: String,
    columns: Vec<Column<K, V>>,
}

pub struct SingleColumnTable<K, V> {
    identifier: String,
    column: Column<K, V>,
}

impl<K, V> SingleColumnTable<K, V> {
    pub fn new(identifier: String, column: Column<K, V>) -> Self {
        Self { identifier, column }
    }
    pub fn identifier(&self) -> String {
        self.identifier.clone()
    }

    pub fn column(&self) -> Column<K, V>
    where
        K: Clone,
        V: Clone,
    {
        self.column.clone()
    }
}

impl<K, V> MultiColumnTable<K, V> {
    pub fn new(identifier: String, columns: Vec<Column<K, V>>) -> Self {
        Self {
            identifier,
            columns,
        }
    }
    pub fn identifier(&self) -> String {
        self.identifier.clone()
    }

    pub fn columns(&self) -> Vec<Column<K, V>>
    where
        K: Clone,
        V: Clone,
    {
        self.columns.clone()
    }
}

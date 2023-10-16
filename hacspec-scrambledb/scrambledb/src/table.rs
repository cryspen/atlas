//! ## Tables and Data Types
//! The `ScrambleDB` protocol provides conversions between types of data
//! tables that are differentiated by their structure and contents.

use oprf::coprf::coprf_online::{BlindInput, BlindOutput};

/// A plain entity identifier is a unicode string.
pub type PlainIdentifier = String;

/// A plain data value is a plaintext value of the underlying
/// rerandomizable public key encryption scheme.
pub type PlainValue = Vec<u8>;
pub type EncryptedValue = Vec<u8>;
pub type BlindIdentifier = BlindInput;
pub type BlindPseudonym = BlindOutput;
pub type Pseudonym = [u8; 64];

pub type PlainTable = MultiColumnTable<PlainIdentifier, PlainValue>;
pub type BlindTable = MultiColumnTable<BlindIdentifier, EncryptedValue>;
pub type ConvertedTable = SingleColumnTable<BlindPseudonym, EncryptedValue>;
pub type PseudonymizedTable = SingleColumnTable<Pseudonym, PlainValue>;

use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct Column<K, V> {
    attribute: String,
    data: Vec<(K, V)>,
}

impl<K, V> Column<K, V> {
    pub fn new(attribute: String, data: Vec<(K, V)>) -> Self {
        Self { attribute, data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn attribute(&self) -> String {
        self.attribute.clone()
    }

    pub fn keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.data.iter().map(|(k, _v)| k.clone()).collect()
    }

    pub fn values(&self) -> Vec<V>
    where
        K: Clone,
        V: Clone,
    {
        self.data.iter().map(|(_k, v)| v.clone()).collect()
    }

    pub fn get(&self, key: &K) -> Option<V>
    where
        K: PartialEq,
        V: Clone,
    {
        self.data
            .iter()
            .find(|(k, _v)| k == key)
            .map(|(_k, v)| v.clone())
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

#[derive(Clone, Debug)]
pub struct MultiColumnTable<K, V> {
    identifier: String,
    columns: Vec<Column<K, V>>,
}

#[derive(Clone)]
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

    pub fn len(&self) -> usize
    where
        K: Clone,
        V: Clone,
    {
        self.column.data().len()
    }

    pub fn keys(&self) -> Vec<K>
    where
        K: Clone,
        V: Clone,
    {
        self.column.data().iter().map(|(k, _v)| k.clone()).collect()
    }

    pub fn values(&self) -> Vec<V>
    where
        K: Clone,
        V: Clone,
    {
        self.column.data().iter().map(|(_k, v)| v.clone()).collect()
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

    pub fn num_rows(&self) -> usize
    where
        K: Clone,
        V: Clone,
    {
        self.columns()[0].len()
    }

    pub fn columns(&self) -> Vec<Column<K, V>>
    where
        K: Clone,
        V: Clone,
    {
        self.columns.clone()
    }

    pub fn rows(&self) -> Vec<Vec<(K, V)>>
    where
        K: Clone + PartialEq,
        V: Clone,
    {
        let mut rows = Vec::new();
        for i in 0..self.num_rows() {
            let mut row = Vec::new();
            for column in self.columns() {
                row.push(column.data()[i].clone());
            }
            rows.push(row)
        }

        rows
    }
}

use std::collections::HashMap;

use elgamal::Ciphertext;
use oprf::coprf::coprf_online::BlindedElement;

/// Let `T` denote a table with `m` columnds and `n` rows.
/// We define the following functions on `T`:
/// * `attributes(T) -> attr_1,..., attr_m` returns the list of attributes of the columns
/// * `key(T) -> k_1,...,k_n` returns the list of keys of the rows
/// * `id(T) -> id` returns the table identifier
/// * `get(T, i, j) -> value` returns the value at position `i,j` in the table
pub(crate) mod table {
    use oprf::coprf::coprf_online::BlindInput;
    use std::{collections::HashMap, hash::Hash, path::Iter};

    pub type Attribute = Vec<u8>;
    pub type Identifier = Vec<u8>;
    pub type Value = Vec<u8>;
    pub type BlindedPseudonym = oprf::coprf::coprf_online::BlindOutput;
    pub type EncryptedValue = elgamal::Ciphertext;
    pub type Pseudonym = Vec<u8>;

    pub type TableKey = Vec<u8>;
    pub type TableValue = elgamal::Plaintext;

    pub struct SourceInputTable {
        identifier: Identifier,
        inner: HashMap<Attribute, HashMap<TableKey, TableValue>>,
    }

    impl SourceInputTable {
        pub fn attributes(&self) -> impl Iterator<Item = &Attribute> {
            self.inner.keys()
        }

        pub fn size(&self) -> usize {
            self.inner.len() * self.inner.values().len()
        }
        pub fn identifier(&self) -> Vec<u8> {
            self.identifier.clone()
        }

        pub fn get_column(&self, attr: &Attribute) -> Option<&HashMap<TableKey, TableValue>> {
            self.inner.get(attr)
        }
    }

    pub struct SourceOutputTable {
        identifier: Identifier,
        inner: HashMap<Attribute, HashMap<BlindInput, EncryptedValue>>,
    }

    impl SourceOutputTable {
        pub fn new(
            identifier: Identifier,
            inner: HashMap<Attribute, HashMap<BlindInput, EncryptedValue>>,
        ) -> Self {
            Self { identifier, inner }
        }

        pub fn attributes(&self) -> impl Iterator<Item = &Attribute> {
            self.inner.keys()
        }

        pub fn size(&self) -> usize {
            self.inner.len() * self.inner.values().len()
        }
        pub fn identifier(&self) -> Vec<u8> {
            self.identifier.clone()
        }

        pub fn get_column(&self, attr: &Attribute) -> Option<&HashMap<BlindInput, EncryptedValue>> {
            self.inner.get(attr)
        }

        pub fn shuffle(&mut self) {
            todo!()
        }
    }

    pub struct LakeTable {
        identifier: Identifier,
        attr: Attribute,
        inner: HashMap<Pseudonym, Value>,
    }

    pub struct BlindColumn {
        identifier: Identifier,
        attr: Attribute,
        entries: Vec<(BlindedPseudonym, EncryptedValue)>,
    }

    impl BlindColumn {
        pub fn new(
            identifier: &Identifier,
            attr: &Attribute,
            inner: Vec<(BlindedPseudonym, EncryptedValue)>,
        ) -> Self {
            BlindColumn {
                identifier: identifier.clone(),
                attr: attr.clone(),
                entries: inner,
            }
        }

        pub(crate) fn attr(&self) -> &[u8] {
            self.attr.as_ref()
        }

        pub(crate) fn identifier(&self) -> &[u8] {
            self.identifier.as_ref()
        }

        pub(crate) fn entries(&self) -> &[(BlindedPseudonym, EncryptedValue)] {
            self.entries.as_ref()
        }
    }

    pub type LakeInputTable = BlindColumn;
    pub(crate) type LakeOutputTable = BlindColumn;
    pub(crate) type ProcessorInputTable = BlindColumn;

    // pub struct Table {
    //     pub(crate) attributes: Vec<Attribute>,
    //     pub(crate) identifier: Identifier,
    //     pub(crate) keys: Vec<BlindedElement>,
    //     pub(crate) values: Vec<Vec<Value>>,
    // }

    // impl Table {
    //     pub fn attributes(&self) -> &[Attribute] {
    //         &self.attributes
    //     }

    //     pub fn keys(&self) -> &[BlindedElement] {
    //         &self.keys
    //     }

    //     pub fn id(&self) -> &Identifier {
    //         &self.identifier
    //     }

    //     pub fn get(&self, i: usize, j: usize) -> Option<&Value> {
    //         self.values.get(i).map(|e| e.get(j)).flatten()
    //     }

    //     pub fn shuffle(mut self) -> Self {
    //         let old_keys = self.keys.clone();
    //         self.keys.sort();

    //         let mut new_values = self.values.clone();
    //         for (new_index, k) in self.keys.iter().enumerate() {
    //             let index = old_keys.iter().position(|old| old == k).unwrap();
    //             new_values[0][new_index] = self.values[0][index];
    //         }
    //         self.values = new_values;

    //         self
    //     }
    // }
}

pub(crate) type TableKey = oprf::coprf::coprf_online::BlindedElement;
pub(crate) type AttrName = Vec<u8>;
pub(crate) type Value = Vec<u8>;
pub(crate) type TableAttr = (AttrName, Value);
pub(crate) type Table = HashMap<TableKey, Vec<TableAttr>>;

pub(crate) type BlindedTable = HashMap<TableAttr, HashMap<BlindedElement, Ciphertext>>;
pub(crate) type ConvertibleTable = HashMap<BlindedElement, Ciphertext>;

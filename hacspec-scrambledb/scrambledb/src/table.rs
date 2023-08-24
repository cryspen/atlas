//! Let `T` denote a table with `m` columns and `n` rows.
//! We define the following functions on `T`:
//! * `attributes(T) -> attr_1,..., attr_m` returns the list of attributes of the columns
//! * `key(T) -> k_1,...,k_n` returns the list of keys of the rows
//! * `id(T) -> id` returns the table identifier
//! * `get(T, i, j) -> value` returns the value at position `i,j` in the table

use oprf::coprf::coprf_online::BlindInput;
use std::collections::HashMap;

pub type Attribute = Vec<u8>;
pub type Identifier = Vec<u8>;

pub type BlindedPseudonym = oprf::coprf::coprf_online::BlindOutput;
pub type EncryptedValue = elgamal::Ciphertext;

pub enum TableKey {
    Plain(Vec<u8>),
    Pseudonym([u8; 64]),
}
pub type TableValue = elgamal::Plaintext;

impl From<[u8; 64]> for TableKey {
    fn from(value: [u8; 64]) -> Self {
        Self::Pseudonym(value)
    }
}
pub struct ClearTable {
    identifier: Identifier,
    inner: HashMap<Attribute, Vec<(TableKey, TableValue)>>,
}

impl ClearTable {
    pub fn new(
        identifier: Identifier,
        inner: HashMap<Attribute, Vec<(TableKey, TableValue)>>,
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

    pub fn get_column(&self, attr: &Attribute) -> Option<&Vec<(TableKey, TableValue)>> {
        self.inner.get(attr)
    }
}

pub type SourceInputTable = ClearTable;
pub type JoinedTable = ClearTable;

pub struct SourceOutputTable {
    identifier: Identifier,
    inner: HashMap<Attribute, Vec<(BlindInput, EncryptedValue)>>,
}

impl SourceOutputTable {
    pub fn new(
        identifier: Identifier,
        inner: HashMap<Attribute, Vec<(BlindInput, EncryptedValue)>>,
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

    pub fn get_column(&self, attr: &Attribute) -> Option<&Vec<(BlindInput, EncryptedValue)>> {
        self.inner.get(attr)
    }
}

pub struct LakeTable {
    identifier: Identifier,
    attr: Attribute,
    entries: Vec<(TableKey, TableValue)>,
}

impl LakeTable {
    pub fn new(
        identifier: Identifier,
        attr: Attribute,
        entries: Vec<(TableKey, TableValue)>,
    ) -> Self {
        Self {
            identifier,
            attr,
            entries,
        }
    }

    pub fn identifier(&self) -> &[u8] {
        self.identifier.as_ref()
    }

    pub fn attr(&self) -> &[u8] {
        self.attr.as_ref()
    }

    pub fn entries(&self) -> &[(TableKey, TableValue)] {
        self.entries.as_ref()
    }
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

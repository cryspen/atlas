//! This module defines the interface for share authentication.
use super::mac::{Mac, MacKey};

/// A bit held by a party with a given ID.
#[derive(Debug, Clone)]
pub struct Bit {
    pub(crate) id: BitID,
    pub(crate) value: bool,
}
#[derive(Debug, Clone)]
/// A bit identifier.
///
/// This is unique per party, not globally, so if referring bits held by another
/// party, their party ID is also required to disambiguate.
pub struct BitID(pub(crate) usize);

#[derive(Debug, Clone)]
/// A bit authenticated between two parties.
pub struct AuthBit {
    pub(crate) bit: Bit,
    pub(crate) macs: Vec<(usize, Mac)>,
    pub(crate) mac_keys: Vec<BitKey>,
}

/// The key to authenticate a two-party authenticated bit.
#[derive(Debug, Clone)]
pub struct BitKey {
    pub(crate) holder_bit_id: BitID,
    pub(crate) bit_holder: usize,
    pub(crate) mac_key: MacKey,
}

//! This module defines the interface for share authentication.
use crate::{primitives::mac::MAC_LENGTH, Error};

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

impl AuthBit {
    /// Serialize the bit value and all MACs on the bit.
    pub fn serialize_bit_macs(&self) -> Vec<u8> {
        let mut result = vec![0u8; (self.macs.len() + 1) * MAC_LENGTH + 1];
        result[0] = self.bit.value as u8;
        for (key_holder, mac) in self.macs.iter() {
            result[1 + key_holder * MAC_LENGTH..1 + (key_holder + 1) * MAC_LENGTH]
                .copy_from_slice(mac);
        }

        result
    }

    /// Deserialize a bit and MACs on that bit.
    pub fn deserialize_bit_macs(bytes: &[u8]) -> Result<(bool, Vec<[u8; MAC_LENGTH]>), Error> {
        if bytes[0] > 1 {
            return Err(Error::InvalidSerialization);
        }
        let bit_value = bytes[0] != 0;
        let mac_chunks = bytes[1..].chunks_exact(MAC_LENGTH);
        if !mac_chunks.remainder().is_empty() {
            return Err(Error::InvalidSerialization);
        }

        let mut macs: Vec<[u8; MAC_LENGTH]> = Vec::new();
        for mac in mac_chunks {
            macs.push(
                mac.try_into()
                    .expect("chunks should be of the required length"),
            )
        }

        Ok((bit_value, macs))
    }
}

/// The key to authenticate a two-party authenticated bit.
#[derive(Debug, Clone)]
pub struct BitKey {
    pub(crate) holder_bit_id: BitID,
    pub(crate) bit_holder: usize,
    pub(crate) mac_key: MacKey,
}

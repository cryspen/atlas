//! This module defines the interface for share authentication.
use serde::{Deserialize, Serialize};

use crate::{primitives::mac::MAC_LENGTH, Error};

use super::mac::{self, Mac, MacKey};

/// A bit held by a party with a given ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bit {
    pub(crate) id: BitID,
    pub(crate) value: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// A bit identifier.
///
/// This is unique per party, not globally, so if referring bits held by another
/// party, their party ID is also required to disambiguate.
pub struct BitID(pub(crate) usize);

#[derive(Debug, Clone)]
/// A bit authenticated between two parties.
pub struct AuthBit<const NUM_PARTIES: usize> {
    pub(crate) bit: Bit,
    pub(crate) macs: [Mac; NUM_PARTIES],
    pub(crate) mac_keys: [MacKey; NUM_PARTIES],
}

impl<const NUM_PARTIES: usize> AuthBit<NUM_PARTIES> {
    /// Serialize the bit value and all MACs on the bit.
    pub fn serialize_bit_macs(&self) -> Vec<u8> {
        let mut result = vec![0u8; NUM_PARTIES * MAC_LENGTH + 1];
        result[0] = self.bit.value as u8;
        for (key_holder, mac) in self.macs.iter().enumerate() {
            result[1 + key_holder * MAC_LENGTH..1 + (key_holder + 1) * MAC_LENGTH]
                .copy_from_slice(mac);
        }

        result
    }

    /// Deserialize a bit and MACs on that bit.
    pub fn deserialize_bit_macs(bytes: &[u8]) -> Result<(bool, [Mac; NUM_PARTIES]), Error> {
        if bytes[0] > 1 {
            return Err(Error::InvalidSerialization);
        }
        let bit_value = bytes[0] != 0;
        let mac_chunks = bytes[1..].chunks_exact(MAC_LENGTH);
        if !mac_chunks.remainder().is_empty() {
            return Err(Error::InvalidSerialization);
        }

        let mut macs = [mac::zero_mac(); NUM_PARTIES];

        for (party_index, mac) in mac_chunks.enumerate() {
            macs[party_index] = mac
                .try_into()
                .expect("chunks should be of the required length");
        }

        Ok((bit_value, macs))
    }
}

/// The key to authenticate a two-party authenticated bit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitKey {
    pub(crate) holder_bit_id: BitID,
    pub(crate) bit_holder: usize,
    pub(crate) mac_key: MacKey,
}

#[test]
fn serialization() {
    let macs_1 = [
        [1u8; MAC_LENGTH],
        [2; MAC_LENGTH],
        [3; MAC_LENGTH],
        [4; MAC_LENGTH],
    ];
    let macs_2 = [
        [11u8; MAC_LENGTH],
        [22; MAC_LENGTH],
        [33; MAC_LENGTH],
        [44; MAC_LENGTH],
    ];
    let keys = [
        [5u8; MAC_LENGTH],
        [6; MAC_LENGTH],
        [7; MAC_LENGTH],
        [8; MAC_LENGTH],
    ];
    let test_bit_1 = AuthBit {
        bit: Bit {
            id: BitID(0),
            value: true,
        },
        macs: macs_1,
        mac_keys: keys,
    };
    let test_bit_2 = AuthBit {
        bit: Bit {
            id: BitID(1),
            value: false,
        },
        macs: macs_2,
        mac_keys: keys,
    };

    let (bit_1, deserialized_macs_1) =
        AuthBit::<4>::deserialize_bit_macs(&test_bit_1.serialize_bit_macs()).unwrap();

    let (bit_2, deserialized_macs_2) =
        AuthBit::<4>::deserialize_bit_macs(&test_bit_2.serialize_bit_macs()).unwrap();
    assert_eq!(bit_1, true);
    assert_eq!(bit_2, false);
    assert_eq!(deserialized_macs_1, macs_1);
    assert_eq!(deserialized_macs_2, macs_2);
}

//! This module defines the interface for share authentication.
use crate::{
    messages::{Message, MessagePayload},
    party::Party,
    primitives::mac::MAC_LENGTH,
    Error,
};

use super::mac::{self, verify_mac, Mac, MacKey};

#[derive(Debug, Clone)]
/// A bit authenticated between two parties.
pub struct AuthBit<const NUM_PARTIES: usize> {
    pub(crate) bit: bool,
    pub(crate) macs: [Mac; NUM_PARTIES],
    pub(crate) keys: [MacKey; NUM_PARTIES],
}

impl<const NUM_PARTIES: usize> AuthBit<NUM_PARTIES> {
    /// Serialize the bit value and all MACs on the bit.
    pub fn serialize_bit_macs(&self) -> Vec<u8> {
        let mut result = vec![0u8; NUM_PARTIES * MAC_LENGTH + 1];
        result[0] = self.bit as u8;
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

/// Locally compute the XOR of two authenticated bits, which will itself be
/// authenticated already.
pub fn xor<const NUM_PARTIES: usize>(
    a: &AuthBit<NUM_PARTIES>,
    b: &AuthBit<NUM_PARTIES>,
) -> AuthBit<NUM_PARTIES> {
    let mut macs = [mac::zero_mac(); NUM_PARTIES];

    for (maccing_party, mac) in a.macs.iter().enumerate() {
        let mut xored_mac = [0u8; MAC_LENGTH];
        let other_mac = b.macs[maccing_party];

        for byte in 0..MAC_LENGTH {
            xored_mac[byte] = mac[byte] ^ other_mac[byte];
        }
        macs[maccing_party] = xored_mac;
    }

    let mut mac_keys = [mac::zero_key(); NUM_PARTIES];
    for (bit_holder, key) in a.keys.iter().enumerate() {
        let mut xored_key = [0u8; MAC_LENGTH];
        let other_key = b.keys[bit_holder];

        for byte in 0..MAC_LENGTH {
            xored_key[byte] = key[byte] ^ other_key[byte];
        }
        mac_keys[bit_holder] = xored_key;
    }

    AuthBit {
        bit: a.bit ^ b.bit,
        macs,
        keys: mac_keys,
    }
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
        bit: true,
        macs: macs_1,
        keys,
    };
    let test_bit_2 = AuthBit {
        bit: false,
        macs: macs_2,
        keys,
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

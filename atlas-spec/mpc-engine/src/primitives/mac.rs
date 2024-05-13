//! This module defines an information theoretic MAC for authenticating bits.

use hacspec_lib::Randomness;

use crate::{Error, COMPUTATIONAL_SECURITY};

/// The length in bytes of an information theoretic MAC, and of the MAC key.
pub const MAC_LENGTH: usize = COMPUTATIONAL_SECURITY;

/// A MAC on a bit.
pub type Mac = [u8; MAC_LENGTH];
/// A MAC key for authenticating a bit to another party.
pub type MacKey = [u8; MAC_LENGTH];

/// Generate a fresh MAC key.
pub fn generate_mac_key(entropy: &mut Randomness) -> Result<MacKey, Error> {
    let k: [u8; MAC_LENGTH] = entropy
        .bytes(MAC_LENGTH)?
        .try_into()
        .map_err(|_| Error::OtherError)?;
    Ok(k)
}

/// Authenticate a bit using the global MAC key.
pub fn mac(
    bit: &bool,
    global_key: &MacKey,
    entropy: &mut Randomness,
) -> Result<(Mac, MacKey), Error> {
    let key: [u8; MAC_LENGTH] = generate_mac_key(entropy)?;

    let mut mac = [0u8; MAC_LENGTH];
    for idx in 0..mac.len() {
        mac[idx] = key[idx] ^ (if *bit { global_key[idx] } else { 0x00 });
    }

    Ok((mac, key))
}

/// Verify a MAC on a given bit.
pub fn verify_mac(bit: &bool, mac: &Mac, key: &MacKey, global_key: &MacKey) -> bool {
    for idx in 0..mac.len() {
        let recomputed = key[idx] ^ (if *bit { global_key[idx] } else { 0x00 });
        if mac[idx] != recomputed {
            return false;
        }
    }
    true
}

#[test]
fn simple() {
    use rand::thread_rng;
    use rand::RngCore;
    let mut rng = thread_rng();
    let mut random = vec![0; 2 * COMPUTATIONAL_SECURITY + 1];
    rng.fill_bytes(&mut random);
    let mut entropy = Randomness::new(random);

    let b = entropy.bit().unwrap();
    let delta = generate_mac_key(&mut entropy).unwrap();
    let (mac, key) = mac(&b, &delta, &mut entropy).unwrap();
    debug_assert!(verify_mac(&b, &mac, &key, &delta));
    debug_assert!(!verify_mac(&!b, &mac, &key, &delta))
}

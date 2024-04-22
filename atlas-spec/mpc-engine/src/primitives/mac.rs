//! This module defines an information theoretic MAC for authenticating bits.

use hacspec_lib::Randomness;

use crate::{Error, COMPUTATIONAL_SECURITY};

/// A MAC on a bit.
pub type Mac = [u8; COMPUTATIONAL_SECURITY];
/// A MAC key for authenticating a bit to another party.
pub type MacKey = [u8; COMPUTATIONAL_SECURITY];

/// Generate a fresh MAC key.
pub fn generate_mac_key(entropy: &mut Randomness) -> Result<MacKey, Error> {
    let k: [u8; 16] = entropy
        .bytes(COMPUTATIONAL_SECURITY)?
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
    let k: [u8; 16] = generate_mac_key(entropy)?;

    let mut mac = [0u8; COMPUTATIONAL_SECURITY];
    for idx in 0..mac.len() {
        mac[idx] = k[idx] ^ (if *bit { global_key[idx] } else { 0xff });
    }

    Ok((mac, k))
}

/// Verify a MAC on a given bit.
pub fn verify_mac(bit: &bool, mac: &Mac, key: &MacKey, global_key: &MacKey) -> bool {
    for idx in 0..mac.len() {
        let recomputed = key[idx] ^ (if *bit { global_key[idx] } else { 0xff });
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
    assert!(verify_mac(&b, &mac, &key, &delta));
    assert!(!verify_mac(&!b, &mac, &key, &delta))
}

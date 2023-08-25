use hacspec_lib::FunctionalVec;
use sha256::*;

mod hacspec_helper;
use hacspec_helper::*;

/// Hash trait
pub trait Hash {
    const BLOCK_LEN: usize;
    const HASH_LEN: usize;

    fn hash(bytes: &[u8]) -> Vec<u8>;
}

/// SHA 256 struct for the [`Hash`] trait.
pub struct Sha256 {}

impl Hash for Sha256 {
    const BLOCK_LEN: usize = 64;
    const HASH_LEN: usize = 32;

    fn hash(bytes: &[u8]) -> Vec<u8> {
        sha256::sha256(bytes).to_vec()
    }
}

// === HMAC ===

fn o_pad<H: Hash>() -> Vec<u8> {
    vec![0x5c; H::BLOCK_LEN]
}

fn i_pad<H: Hash>() -> Vec<u8> {
    vec![0x36; H::BLOCK_LEN]
}

fn k_block<H: Hash>(k: &[u8]) -> Vec<u8> {
    let k = if k.len() > H::BLOCK_LEN {
        H::hash(k)
    } else {
        k.to_vec()
    };
    let mut block = vec![0u8; H::BLOCK_LEN];
    for i in 0..k.len() {
        block[i] = k[i];
    }
    block
}

// H(K XOR opad, H(K XOR ipad, text))
pub fn hmac<H: Hash>(k: &[u8], txt: &[u8]) -> Vec<u8> {
    // Applications that use keys longer than B bytes will first hash the key
    // using H and then use the resultant L byte string as the actual key to HMAC
    let k_block = k_block::<H>(k);

    let mut h_in = xor_slice(k_block.clone(), &i_pad::<H>());
    h_in.extend_from_slice(txt);
    let h_inner = hash(&h_in);

    let mut h_in = xor_slice(k_block, &o_pad::<H>());
    h_in.extend_from_slice(&h_inner);

    hash(&h_in).to_vec()
}

pub fn hkdf_extract<H: Hash>(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac::<H>(salt, ikm)
}

pub fn hkdf_expand<H: Hash>(prk: &[u8], info: &[u8], l: usize) -> Vec<u8> {
    let n = (l + H::HASH_LEN - 1) / H::HASH_LEN; // N = ceil(L/HashLen)

    let t = hmac::<H>(prk, &info.concat_byte(1u8));
    for i in 1..n {
        let round_input = t[i * H::HASH_LEN..(i + 1) * H::HASH_LEN]
            .to_vec()
            .concat(info)
            .concat_byte((i - 1) as u8);
        let t_i = hmac::<H>(prk, &round_input);
        t.concat(&t_i);
    }
    t[0..l].to_vec()
}

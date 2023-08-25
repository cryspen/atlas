use hacspec_lib::FunctionalVec;
use sha256::*;

mod hacspec_helper;
use hacspec_helper::*;

const BLOCK_LEN: usize = 64;
const HASH_LEN: usize = 32;

fn hash(bytes: &[u8]) -> Vec<u8> {
    sha256::sha256(bytes).to_vec()
}

// === HMAC ===

fn o_pad() -> Vec<u8> {
    vec![0x5c; BLOCK_LEN]
}

fn i_pad() -> Vec<u8> {
    vec![0x36; BLOCK_LEN]
}

fn k_block(k: &[u8]) -> Vec<u8> {
    let k = if k.len() > BLOCK_LEN {
        hash(k)
    } else {
        k.to_vec()
    };
    let mut block = vec![0u8; BLOCK_LEN];
    for i in 0..k.len() {
        block[i] = k[i];
    }
    block
}

// // H(K XOR opad, H(K XOR ipad, text))
pub fn hmac(k: &[u8], txt: &[u8]) -> Vec<u8> {
    // Applications that use keys longer than B bytes will first hash the key
    // using H and then use the resultant L byte string as the actual key to HMAC
    let k_block = k_block(k);

    let mut h_in = xor_slice(k_block.clone(), &i_pad());
    h_in.extend_from_slice(txt);
    let h_inner = hash(&h_in);

    let mut h_in = xor_slice(k_block, &o_pad());
    h_in.extend_from_slice(&h_inner);

    hash(&h_in).to_vec()
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], l: usize) -> Vec<u8> {
    let n = (l + HASH_LEN - 1) / HASH_LEN; // N = ceil(L/HashLen)

    let mut t = hmac(prk, &info.concat_byte(1u8));
    for i in 1..n {
        let round_input = t[i * HASH_LEN..(i + 1) * HASH_LEN]
            .to_vec()
            .concat(info)
            .concat_byte((i - 1) as u8);
        let t_i = hmac(prk, &round_input);
        t.extend_from_slice(&t_i);
    }
    t[0..l].to_vec()
}

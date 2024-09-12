use std::convert::TryInto;

// Import chacha20 and poly1305
use hacspec_chacha20::*;
use hacspec_poly1305::*;

#[derive(Debug)]
pub enum Error {
    InvalidTag,
}

pub type ChaChaPolyKey = ChaChaKey;
pub type ChaChaPolyIV = ChaChaIV;
pub type ByteSeqResult = Result<Vec<u8>, Error>;

pub fn init(key: ChaChaPolyKey, iv: ChaChaPolyIV) -> PolyState {
    let key_block0 = chacha20_key_block0(key, iv);
    let poly_key = key_block0[0..32].try_into().unwrap();
    poly1305_init(poly_key)
}

pub fn poly1305_update_padded(m: &[u8], st: PolyState) -> PolyState {
    let st = poly1305_update_blocks(m, st);
    let mchunks = m.chunks_exact(16);
    let mut last = [0u8; 16];
    let m_last = mchunks.remainder();
    last[0..m_last.len()].copy_from_slice(m_last);
    poly1305_update_last(16, &last.to_vec(), st)
}

pub fn finish(aad_len: usize, cipher_len: usize, st: PolyState) -> Poly1305Tag {
    let mut last_block = [0u8; 16];
    last_block[0..8].copy_from_slice(&(aad_len as u64).to_le_bytes());
    last_block[8..16].copy_from_slice(&(cipher_len as u64).to_le_bytes());
    let st = poly1305_update_block(&last_block, st);
    poly1305_finish(st)
}

pub fn chacha20_poly1305_encrypt(
    key: ChaChaPolyKey,
    iv: ChaChaPolyIV,
    aad: &[u8],
    msg: &[u8],
) -> (Vec<u8>, Poly1305Tag) {
    let cipher_text = chacha20(key, iv, 1u32, msg);
    let mut poly_st = init(key, iv);
    poly_st = poly1305_update_padded(aad, poly_st);
    poly_st = poly1305_update_padded(&cipher_text, poly_st);
    let tag = finish(aad.len(), cipher_text.len(), poly_st);
    (cipher_text, tag)
}

pub fn chacha20_poly1305_decrypt(
    key: ChaChaPolyKey,
    iv: ChaChaPolyIV,
    aad: &[u8],
    cipher_text: &[u8],
    tag: Poly1305Tag,
) -> ByteSeqResult {
    let mut poly_st = init(key, iv);
    poly_st = poly1305_update_padded(aad, poly_st);
    poly_st = poly1305_update_padded(cipher_text, poly_st);
    let my_tag = finish(aad.len(), cipher_text.len(), poly_st);
    if my_tag == tag {
        ByteSeqResult::Ok(chacha20(key, iv, 1u32, cipher_text))
    } else {
        ByteSeqResult::Err(Error::InvalidTag)
    }
}

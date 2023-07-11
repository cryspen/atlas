use crate::p256;
use libcrux::digest::{Algorithm, hash};

const B_IN_BYTES: usize = libcrux::digest::digest_size(Algorithm::Sha256); // output size of H = SHA-256 in bytes
const S_IN_BYTES: usize = 64; // input block size of H = SHA-256
const K: usize = 128; // security level of this suite

// XXX: How to write this more generically?
const L: usize = 48; // ceil((ceil(log2(p)) + k) / 8), where p = 2^256 - 2^224 + 2^192 + 2^96 - 1 and k = 128

pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    unimplemented!()
}

pub fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Vec<p256::Fp> {
    let len_in_bytes = count * p256::M * L;
    let uniform_bytes = expand_message_xmd(msg,dst,len_in_bytes);
    let mut u = Vec::with_capacity(count);
    for i in 0..count {
	// m = 1
	let elm_offset = L * i;
	let tv = &uniform_bytes[elm_offset..L];
	u.push(p256::Fp::from_bytes_be(tv));
    }
    u
}

pub fn map_to_curve(u: &p256::Fp) -> p256::G {
    unimplemented!()
}

pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> p256::G {
    let u = hash_to_field(msg, dst, 2);
    let q0 = map_to_curve(&u[0]);
    let q1 = map_to_curve(&u[1]);
    let r = q0 + q1;
    let p = r.clear_cofactor();
    p
}


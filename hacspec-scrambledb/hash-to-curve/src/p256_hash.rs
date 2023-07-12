use crate::p256;
use libcrux::digest::{hash, Algorithm};

const B_IN_BYTES: usize = libcrux::digest::digest_size(Algorithm::Sha256); // output size of H = SHA-256 in bytes
const S_IN_BYTES: usize = 64; // input block size of H = SHA-256
const K: usize = 128; // security level of this suite

// XXX: How to write this more generically?
const L: usize = 48; // ceil((ceil(log2(p)) + k) / 8), where p = 2^256 - 2^224 + 2^192 + 2^96 - 1 and k = 128

pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    // adapted from hacspec-v1/specs/bls12-
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES; // ceil(len_in_bytes / b_in_bytes)
                                                            // must be that ell <= 255
    let mut dst_prime = Vec::from(dst);
    dst_prime.extend_from_slice(&[dst.len() as u8; 1]);

    let z_pad = [0u8; S_IN_BYTES];

    let mut l_i_b_str = [0u8; 2];
    l_i_b_str[0] = (len_in_bytes / 256) as u8;
    l_i_b_str[1] = len_in_bytes as u8; // I2OSP(len_in_bytes, 2)

    let mut msg_prime = Vec::from(z_pad);
    msg_prime.extend_from_slice(msg);
    msg_prime.extend_from_slice(&l_i_b_str);
    msg_prime.extend_from_slice(&[0u8; 1]);
    msg_prime.extend_from_slice(&dst_prime); // msg_prime = Z_pad || msg || l_i_b_str || 0 || dst_prime

    let b_0 = hash(Algorithm::Sha256, &msg_prime); // H(msg_prime)

    let mut payload_1 = b_0.clone();
    payload_1.extend_from_slice(&[1u8; 1]);
    payload_1.extend_from_slice(&dst_prime);
    let mut b_i = hash(Algorithm::Sha256, &payload_1); // H(b_0 || 1 || dst_prime)

    let mut uniform_bytes = b_i.clone();
    for i in 2..=ell {
        let t: Vec<u8> = b_i.iter().zip(b_0.iter()).map(|(a, b)| a ^ b).collect();
        let mut payload_i = t;
        payload_i.extend_from_slice(&[i as u8; 1]);
        payload_i.extend_from_slice(&dst_prime);
        b_i = hash(Algorithm::Sha256, &payload_i); //H((b_0 ^ b_(i-1)) || 1 || dst_prime)
        uniform_bytes.extend_from_slice(&b_i);
    }
    uniform_bytes.truncate(len_in_bytes);
    uniform_bytes
}

pub fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Vec<p256::Fp> {
    let len_in_bytes = count * p256::M * L;
    let uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes);
    let mut u = Vec::with_capacity(count);
    for i in 0..count {
        // m = 1
        let elm_offset = L * i;
        let tv = &uniform_bytes[elm_offset..L];
        u.push(p256::Fp::from_bytes_be(tv));
    }
    u
}

// Simplified Shallue-van de Woestijne-Ulas method
pub fn map_to_curve(u: &p256::Fp) -> p256::G {
    use num_traits::One;
    use num_traits::Zero;
    let Z = p256::Fp::zero() - p256::Fp::from_literal(10u128);

    let tv1 = (Z.clone() * Z.clone() * u * u * u * u + Z.clone() * u * u).inv0();
    let x1 = if tv1.is_zero() {
        (*p256::B).clone() * (Z.clone() * &(*p256::A)).inv0()
    } else {
        (p256::Fp::one() + tv1.clone()) * (p256::Fp::zero() - &(*p256::B)) * (&(*p256::A)).inv0()
    };

    let gx1 = x1.clone() * x1.clone() * x1.clone() + (*p256::A).clone() * x1.clone() + &(*p256::B);
    let x2 = Z.clone() * u * u * x1.clone();
    let gx2 = x2.clone() * x2.clone() * x2.clone() + (*p256::A).clone() * x2.clone() + &(*p256::B);

    let mut output = if gx1.is_square() {
        p256::G(x1, gx1.sqrt(), false)
    } else {
        p256::G(x2, gx2.sqrt(), false)
    };

    if u.sgn0() != output.1.sgn0() {
        output.1 = p256::Fp::zero() - output.1
    }

    output
}

pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> p256::G {
    let u = hash_to_field(msg, dst, 2);
    let q0 = map_to_curve(&u[0]);
    let q1 = map_to_curve(&u[1]);
    let r = q0 + &q1;
    let p = r.clear_cofactor();
    p
}

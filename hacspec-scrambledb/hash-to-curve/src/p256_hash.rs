// TODO: Add comments about what this is and where the spec is.

// use crate::hacspec_helper::*;
use libcrux::digest::{hash, Algorithm};
use p256::{NatMod, *};

const B_IN_BYTES: usize = libcrux::digest::digest_size(Algorithm::Sha256); // output size of H = SHA-256 in bytes
const S_IN_BYTES: usize = 64; // input block size of H = SHA-256
#[allow(unused)]
const K: usize = 128; // security level of this suite

// XXX: How to write this more generically?
const L: usize = 48; // ceil((ceil(log2(p)) + k) / 8), where p = 2^256 - 2^224 + 2^192 + 2^96 - 1 and k = 128

// TODO: Add the pseudoc code and description as doc comments form the RFC to the functions.
fn msg_prime(msg: &[u8], dst_prime: &[u8], len_in_bytes: usize) -> Vec<u8> {
    let z_pad = [0u8; S_IN_BYTES];

    let mut l_i_b_str = [0u8; 2];
    l_i_b_str[0] = (len_in_bytes / 256) as u8;
    l_i_b_str[1] = len_in_bytes as u8;

    let mut out = Vec::from(z_pad);
    out.extend_from_slice(msg);
    out.extend_from_slice(&l_i_b_str);
    out.extend_from_slice(&[0u8; 1]);
    out.extend_from_slice(&dst_prime); // msg_prime = Z_pad || msg || l_i_b_str || 0 || dst_prime

    out
}

fn dst_prime(dst: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(dst);
    out.extend_from_slice(&[dst.len() as u8; 1]);

    out
}

pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    // adapted from hacspec-v1/specs/bls12-
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES; // ceil(len_in_bytes / b_in_bytes)
                                                            // must be that ell <= 255
    let dst_prime = dst_prime(dst);

    let msg_prime = msg_prime(msg, &dst_prime, len_in_bytes);

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

pub fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Vec<P256FieldElement> {
    // m = 1 for P-256
    let len_in_bytes = count * L;
    let uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes);
    let mut u = Vec::with_capacity(count);
    for i in 0..count {
        // m = 1
        let elm_offset = L * i;
        let tv = &uniform_bytes[elm_offset..L * (i + 1)];
	let tv = P256FieldElement::from_be_bytes(&tv);
	u.push(tv);
    }
    u
}

/// This function returns `true` whenever the value `x` is a square in the field F. By Euler's criterion, this function can be calculated in constant time as
///
/// ```text
/// is_square(x) := { True, if x^((q - 1) / 2) is 0 or 1 in F;
/// 	            { False, otherwise.
/// ```
fn is_square(x: P256FieldElement) -> bool {
    let exp = P256FieldElement::zero() - P256FieldElement::from_u128(1) * P256FieldElement::from_u128(2).inv();
    let test = x.pow_felem(&exp);
    test == P256FieldElement::zero() || test == P256FieldElement::from_u128(1)
}

/// Input: x, an element of F.
/// Output: z, an element of F such that (z^2) == x, if x is square in F.
///
/// For P-256, we have q = p = 3 (mod 4). Therefore we compute the square as follows:
///
/// 1. c1 = (q + 1) / 4
/// 2. return x^c1
fn sqrt(x: P256FieldElement) -> P256FieldElement {
    let c1 = P256FieldElement::from_u128(1) * P256FieldElement::from_u128(4).inv();
    x.pow_felem(&c1)
}

fn sgn0(x: P256FieldElement) -> bool {
    x.bit(0)
}

// Simplified Shallue-van de Woestijne-Ulas method
pub fn map_to_curve(u: &P256FieldElement) -> P256Point {
    let a = P256FieldElement::from_u128(3u128).neg();
    let b = P256FieldElement::from_hex(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    );
    let z = P256FieldElement::from_u128(10u128).neg();

    let tv1 = (z.pow(2) * u.pow(4) + z * u.pow(2)).inv0();
    let x1 = if tv1 == P256FieldElement::zero() {
        b * (z * a).inv()
    } else {
        (b.neg() * a.inv()) * (tv1 + P256FieldElement::from_u128(1u128))
    };

    let gx1 = x1.pow(3) + a * x1 + b;
    let x2 = z * u.pow(2) * x1;
    let gx2 = x2.pow(3) + a * x2 + b;

    let mut output = if is_square(gx1) {
        (x1, sqrt(gx1))
    } else {
        (x2, sqrt(gx2))
    };

    if sgn0(*u) != sgn0(output.1) {
        output.1 = output.1.neg();
    }

    output
}

fn p256_clear_cofactor(p: P256Point) -> P256Point {
    // no-op for P-256
    p
}

pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> P256Point {
    let u = hash_to_field(msg, dst, 2);
    let q0 = map_to_curve(&u[0]);
    let q1 = map_to_curve(&u[1]);
    let r = point_add(q0, q1).unwrap();
    let p = p256_clear_cofactor(r);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use serde_json::Value;

    fn load_vectors(path: &str) -> Value {
        use std::fs;
        serde_json::from_str(&fs::read_to_string(path).expect("File not found.")).unwrap()
    }

    lazy_static! {
        static ref VECTORS_EXPAND_MESSAGE_XMD_SHA256_38: serde_json::Value =
            load_vectors("expand_message_xmd_SHA256_38.json");
        static ref VECTORS_P256_XMD_SHA256_SSWU_RO: serde_json::Value =
            load_vectors("P256_XMD_SHA-256_SSWU_RO_.json");
    }

    #[test]
    fn test_dst_prime() {
        let dst = VECTORS_EXPAND_MESSAGE_XMD_SHA256_38["DST"]
            .as_str()
            .unwrap();
        let dst = dst.as_bytes();

        let mut test_cases = VECTORS_EXPAND_MESSAGE_XMD_SHA256_38["tests"]
            .as_array()
            .unwrap()
            .clone();
        let test_case = test_cases.pop().unwrap();

        let dst_prime_expected = test_case["DST_prime"].as_str().unwrap();
        let dst_prime_expected = hex::decode(dst_prime_expected).unwrap();
        assert_eq!(dst_prime_expected, dst_prime(&dst));
    }

    #[test]
    fn test_msg_prime() {
        let test_cases = VECTORS_EXPAND_MESSAGE_XMD_SHA256_38["tests"]
            .as_array()
            .unwrap()
            .clone();
        for test_case in test_cases.iter() {
            let msg = test_case["msg"].as_str().unwrap();
            let msg = msg.as_bytes();

            let msg_prime_expected = test_case["msg_prime"].as_str().unwrap();
            let msg_prime_expected = hex::decode(msg_prime_expected).unwrap();

            let dst_prime = test_case["DST_prime"].as_str().unwrap();
            let dst_prime = hex::decode(dst_prime).unwrap();

            let len_in_bytes = test_case["len_in_bytes"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x");
            let len_in_bytes = usize::from_str_radix(len_in_bytes, 16).unwrap();

            assert_eq!(msg_prime_expected, msg_prime(msg, &dst_prime, len_in_bytes));
        }
    }

    #[test]
    fn test_expand_message_xmd() {
        let dst = VECTORS_EXPAND_MESSAGE_XMD_SHA256_38["DST"]
            .as_str()
            .unwrap();
        let dst = dst.as_bytes();

        let test_cases = VECTORS_EXPAND_MESSAGE_XMD_SHA256_38["tests"]
            .as_array()
            .unwrap()
            .clone();
        for test_case in test_cases.iter() {
            let msg = test_case["msg"].as_str().unwrap();
            let msg = msg.as_bytes();

            let len_in_bytes = test_case["len_in_bytes"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x");
            let len_in_bytes = usize::from_str_radix(len_in_bytes, 16).unwrap();

            let uniform_bytes_expected = test_case["uniform_bytes"].as_str().unwrap();
            let uniform_bytes_expected = hex::decode(uniform_bytes_expected).unwrap();

            assert_eq!(
                uniform_bytes_expected,
                expand_message_xmd(msg, &dst, len_in_bytes)
            );
        }
    }

    #[test]
    fn test_hash_to_field() {
        let dst = VECTORS_P256_XMD_SHA256_SSWU_RO["dst"].as_str().unwrap();
        let dst = dst.as_bytes();

        let test_cases = VECTORS_P256_XMD_SHA256_SSWU_RO["vectors"]
            .as_array()
            .unwrap()
            .clone();

        for test_case in test_cases.iter() {
            let msg_str = test_case["msg"].as_str().unwrap();

            let msg = msg_str.as_bytes();

            let u = test_case["u"].as_array().unwrap();
            let u0_expected = u[0].as_str().unwrap().trim_start_matches("0x");
            let u0_expected = P256FieldElement::from_be_bytes(&hex::decode(u0_expected).unwrap());
            let u1_expected = u[1].as_str().unwrap().trim_start_matches("0x");
            let u1_expected = P256FieldElement::from_be_bytes(&hex::decode(u1_expected).unwrap());

            let u_real = hash_to_field(msg, dst, 2);
            assert_eq!(u_real.len(), 2);
            assert_eq!(
                u0_expected.as_ref(),
                u_real[0].as_ref(),
                "u0 did not match for {msg_str}"
            );
            assert_eq!(
                u1_expected.as_ref(),
                u_real[1].as_ref(),
                "u1 did not match for {msg_str}"
            );
        }
    }

    #[test]
    fn test_map_to_curve() {
        let test_cases = VECTORS_P256_XMD_SHA256_SSWU_RO["vectors"]
            .as_array()
            .unwrap()
            .clone();

        for test_case in test_cases.iter() {
            let u = test_case["u"].as_array().unwrap();
            let u0 = u[0].as_str().unwrap().trim_start_matches("0x");
            let u0 = P256FieldElement::from_be_bytes(&hex::decode(u0).unwrap());
            let u1 = u[1].as_str().unwrap().trim_start_matches("0x");
            let u1 = P256FieldElement::from_be_bytes(&hex::decode(u1).unwrap());

            let (q0_x, q0_y) = map_to_curve(&u0);
            let (q1_x, q1_y) = map_to_curve(&u1);

            let q0_expected = &test_case["Q0"];
            let q0_x_expected = q0_expected["x"].as_str().unwrap().trim_start_matches("0x");
            let q0_x_expected =
                P256FieldElement::from_be_bytes(&hex::decode(q0_x_expected).unwrap());
            let q0_y_expected = q0_expected["y"].as_str().unwrap().trim_start_matches("0x");
            let q0_y_expected =
                P256FieldElement::from_be_bytes(&hex::decode(q0_y_expected).unwrap());

            let q1_expected = &test_case["Q1"];
            let q1_x_expected = q1_expected["x"].as_str().unwrap().trim_start_matches("0x");
            let q1_x_expected =
                P256FieldElement::from_be_bytes(&hex::decode(q1_x_expected).unwrap());
            let q1_y_expected = q1_expected["y"].as_str().unwrap().trim_start_matches("0x");
            let q1_y_expected =
                P256FieldElement::from_be_bytes(&hex::decode(q1_y_expected).unwrap());

            // assert_eq!(inf0, false, "Q0 should not be infinite");
            // assert_eq!(inf1, false, "Q1 should not be infinite");
            assert_eq!(q0_x_expected.as_ref(), q0_x.as_ref(), "x0 incorrect");
            assert_eq!(q0_y_expected.as_ref(), q0_y.as_ref(), "y0 incorrect");
            assert_eq!(q1_x_expected.as_ref(), q1_x.as_ref(), "x1 incorrect");
            assert_eq!(q1_y_expected.as_ref(), q1_y.as_ref(), "y1 incorrect");
        }
    }

    #[test]
    fn test_hash_to_curve() {
        let dst = VECTORS_P256_XMD_SHA256_SSWU_RO["dst"].as_str().unwrap();
        let dst = dst.as_bytes();
        let test_cases = VECTORS_P256_XMD_SHA256_SSWU_RO["vectors"]
            .as_array()
            .unwrap()
            .clone();

        for test_case in test_cases.iter() {
            let msg = test_case["msg"].as_str().unwrap();
            let msg = msg.as_bytes();

            let p_expected = &test_case["P"];
            let p_x_expected = p_expected["x"].as_str().unwrap().trim_start_matches("0x");
            let p_x_expected = P256FieldElement::from_be_bytes(&hex::decode(p_x_expected).unwrap());
            let p_y_expected = p_expected["y"].as_str().unwrap().trim_start_matches("0x");
            let p_y_expected = P256FieldElement::from_be_bytes(&hex::decode(p_y_expected).unwrap());

            let (x, y) = hash_to_curve(msg, dst);

            // assert!(!inf, "Point should not be infinite");
            assert_eq!(p_x_expected.as_ref(), x.as_ref(), "x-coordinate incorrect");
            assert_eq!(p_y_expected.as_ref(), y.as_ref(), "y-coordinate incorrect");
        }
    }
}

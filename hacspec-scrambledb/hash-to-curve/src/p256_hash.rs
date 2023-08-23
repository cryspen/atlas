use crate::hacspec_helper::FunctionalVec;
use crate::Error;
use libcrux::digest::hash;
use libcrux::digest::Algorithm::Sha256;
use p256::{is_square, sgn0, sqrt, NatMod, P256FieldElement, P256Point, P256Scalar};

/// # 8.2 Suites for NIST P-256
///
/// `P256_XMD:SHA-256_SSWU_RO_`
///
/// [`P256_XMD:SHA-256_SSWU_NU_`](P256_XMD_SHA256_SSWU_NU) is identical to `P256_XMD:SHA-256_SSWU_RO_`,
/// except that the encoding type is encode_to_curve (Section 3).
#[allow(non_camel_case_types)]
pub struct P256_XMD_SHA256_SSWU_RO {}
const ID: &str = "P256_XMD:SHA-256_SSWU_RO_";
const K: usize = 128;
const L: usize = 48;

const B_IN_BYTES: usize = libcrux::digest::digest_size(Sha256); // output size of H = SHA-256 in bytes
const S_IN_BYTES: usize = 64; // input block size of H = SHA-256

#[allow(non_snake_case)]
fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, Error> {
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES;
    if ell > 255 || len_in_bytes > 65535 || dst.len() > 255 {
        return Err(Error::InvalidEll);
    }

    let dst_prime = dst.concat_byte(dst.len() as u8);
    let z_pad = vec![0u8; S_IN_BYTES];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    // msg_prime = Z_pad || msg || l_i_b_str || 0 || dst_prime
    let msg_prime = z_pad
        .concat(msg)
        .concat(&l_i_b_str)
        .concat(&[0u8; 1])
        .concat(&dst_prime);

    let b_0 = hash(Sha256, &msg_prime); // H(msg_prime)

    let payload_1 = b_0.concat_byte(1).concat(&dst_prime);
    let mut b_i = hash(Sha256, &payload_1); // H(b_0 || 1 || dst_prime)

    let mut uniform_bytes = b_i.clone();
    for i in 2..=ell {
        // i < 256 is checked before
        let payload_i = strxor(&b_0, &b_i).concat_byte(i as u8).concat(&dst_prime);
        //H((b_0 ^ b_(i-1)) || 1 || dst_prime)
        b_i = hash(Sha256, &payload_i);
        uniform_bytes.extend_from_slice(&b_i);
    }
    uniform_bytes.truncate(len_in_bytes);
    Ok(uniform_bytes)
}

fn strxor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

pub fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<P256FieldElement>, Error> {
    let len_in_bytes = count * L;
    let uniform_bytes = expand_message(msg, dst, len_in_bytes)?;
    let mut u = Vec::with_capacity(count);
    for i in 0..count {
        let elm_offset = L * i;
        let tv = &uniform_bytes[elm_offset..L * (i + 1)];
        let tv = P256FieldElement::from_be_bytes(tv);
        u.push(tv);
    }
    Ok(u)
}

pub fn hash_to_scalar(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<P256Scalar>, Error> {
    let len_in_bytes = count * L;
    let uniform_bytes = expand_message(msg, dst, len_in_bytes)?;
    let mut u = Vec::with_capacity(count);
    for i in 0..count {
        let elm_offset = L * i;
        let tv = &uniform_bytes[elm_offset..L * (i + 1)];
        let tv = P256Scalar::from_be_bytes(tv);
        u.push(tv);
    }
    Ok(u)
}

fn sswu(
    u: &P256FieldElement,
    a: &P256FieldElement,
    b: &P256FieldElement,
    z: P256FieldElement,
) -> (P256FieldElement, P256FieldElement) {
    let tv1 = (z.pow(2) * u.pow(4) + z * u.pow(2)).inv0();
    let x1 = if tv1 == P256FieldElement::zero() {
        *b * (z * *a).inv()
    } else {
        (b.neg() * a.inv()) * (tv1 + P256FieldElement::from_u128(1u128))
    };

    let gx1 = x1.pow(3) + (*a) * x1 + (*b);
    let x2 = z * u.pow(2) * x1;
    let gx2 = x2.pow(3) + *a * x2 + *b;

    let mut output = if is_square(&gx1) {
        (x1, sqrt(&gx1))
    } else {
        (x2, sqrt(&gx2))
    };

    if sgn0(u) != sgn0(&output.1) {
        output.1 = output.1.neg();
    }

    output
}

fn map_to_curve(u: P256FieldElement) -> P256Point {
    sswu(
        &u,
        &P256FieldElement::from_u128(3u128).neg(),
        &P256FieldElement::from_hex(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        ),
        P256FieldElement::from_u128(10u128).neg(),
    )
    .into()
}

pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<P256Point, Error> {
    let u: Vec<P256FieldElement> = hash_to_field(msg, dst, 2)?;
    let q0 = map_to_curve(u[0]);
    let q1 = map_to_curve(u[1]);
    let r = p256::point_add(q0, q1)?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::read_to_string;

    use serde_json::Value;

    pub fn load_vectors(path: &std::path::Path) -> Value {
        serde_json::from_str(&read_to_string(path).expect("File not found.")).unwrap()
    }

    #[test]
    fn p256_xmd_sha256_sswu_ro_hash_to_field() {
        let mut vector_path = std::path::Path::new("vectors").join(ID);
        vector_path.set_extension("json");
        eprintln!(" Reading {}", vector_path.display());

        let tests = load_vectors(vector_path.as_path());
        let dst = tests["dst"].as_str().unwrap().as_bytes();

        assert_eq!(tests["ciphersuite"].as_str().unwrap(), ID);

        for test_case in tests["vectors"].as_array().unwrap().iter() {
            let msg_str = test_case["msg"].as_str().unwrap();
            let msg = msg_str.as_bytes();

            let u_expected: Vec<_> = test_case["u"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u_i| {
                    let u_i = u_i.as_str().unwrap();
                    let u0_expected = u_i.trim_start_matches("0x");
                    P256FieldElement::from_be_bytes(&hex::decode(u0_expected).unwrap())
                })
                .collect();

            let u_real = hash_to_field(msg, dst, 2).unwrap();
            assert_eq!(u_real.len(), u_expected.len());
            for (u_real, u_expected) in u_real.iter().zip(u_expected.iter()) {
                assert_eq!(
                    u_expected.as_ref(),
                    u_real.as_ref(),
                    "u0 did not match for {msg_str}",
                );
            }
        }
    }
    #[test]
    fn p256_xmd_sha256_sswu_ro_map_to_curve() {
        let mut vector_path = std::path::Path::new("vectors").join(ID);
        vector_path.set_extension("json");
        let vectors = load_vectors(vector_path.as_path());

        let test_cases = vectors["vectors"].as_array().unwrap().clone();

        for test_case in test_cases.iter() {
            let u = test_case["u"].as_array().unwrap();
            let u0 = u[0].as_str().unwrap().trim_start_matches("0x");
            let u0 = P256FieldElement::from_be_bytes(&hex::decode(u0).unwrap());
            let u1 = u[1].as_str().unwrap().trim_start_matches("0x");
            let u1 = P256FieldElement::from_be_bytes(&hex::decode(u1).unwrap());

            let (q0_x, q0_y) = map_to_curve(u0).into();
            let (q1_x, q1_y) = map_to_curve(u1).into();

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

            assert_eq!(q0_x_expected, q0_x, "x0 incorrect");
            assert_eq!(q0_y_expected, q0_y, "y0 incorrect");

            assert_eq!(q1_x_expected, q1_x, "x1 incorrect");
            assert_eq!(q1_y_expected, q1_y, "y1 incorrect");
        }
    }

    #[test]
    fn p256_xmd_sha256_sswu_ro_hash_to_curve() {
        let mut vector_path = std::path::Path::new("vectors").join(ID);
        vector_path.set_extension("json");
        let vectors = load_vectors(vector_path.as_path());

        let dst = vectors["dst"].as_str().unwrap();
        let dst = dst.as_bytes();
        let test_cases = vectors["vectors"].as_array().unwrap().clone();

        for test_case in test_cases.iter() {
            let msg = test_case["msg"].as_str().unwrap();
            let msg = msg.as_bytes();

            let p_expected = &test_case["P"];
            let p_x_expected = p_expected["x"].as_str().unwrap().trim_start_matches("0x");
            let p_x_expected = P256FieldElement::from_be_bytes(&hex::decode(p_x_expected).unwrap());
            let p_y_expected = p_expected["y"].as_str().unwrap().trim_start_matches("0x");
            let p_y_expected = P256FieldElement::from_be_bytes(&hex::decode(p_y_expected).unwrap());

            let (x, y) = hash_to_curve(msg, dst).unwrap().into();

            // assert!(!inf, "Point should not be infinite");
            assert_eq!(p_x_expected.as_ref(), x.as_ref(), "x-coordinate incorrect");
            assert_eq!(p_y_expected.as_ref(), y.as_ref(), "y-coordinate incorrect");
        }
    }
}

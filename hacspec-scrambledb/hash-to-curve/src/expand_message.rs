
// TODO: Add the pseudoc code and description as doc comments form the RFC to the functions.
#[allow(non_snake_case)]
fn msg_prime(msg: &[u8], dst_prime: &[u8], len_in_bytes: usize, S_IN_BYTES: usize) -> Vec<u8> {
    let z_pad = vec![0u8; S_IN_BYTES];

    let mut l_i_b_str = [0u8; 2];
    l_i_b_str[0] = (len_in_bytes / 256) as u8;
    l_i_b_str[1] = len_in_bytes as u8;

    let mut out = z_pad;
    out.extend_from_slice(msg);
    out.extend_from_slice(&l_i_b_str);
    out.extend_from_slice(&[0u8; 1]);
    out.extend_from_slice(dst_prime); // msg_prime = Z_pad || msg || l_i_b_str || 0 || dst_prime

    out
}

fn dst_prime(dst: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(dst);
    out.extend_from_slice(&[dst.len() as u8; 1]);

    out
}

#[allow(non_snake_case, unused)]
pub fn expand_message_xof(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
    B_IN_BYTES: usize,
    S_IN_BYTES: usize,
    hash: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    unimplemented!()
}

#[allow(non_snake_case)]
pub fn expand_message_xmd(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
    B_IN_BYTES: usize,
    S_IN_BYTES: usize,
    hash: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    // adapted from hacspec-v1/specs/bls12-
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES; // ceil(len_in_bytes / b_in_bytes)
                                                            // must be that ell <= 255
    let dst_prime = dst_prime(dst);

    let msg_prime = msg_prime(msg, &dst_prime, len_in_bytes, S_IN_BYTES);

    let b_0 = hash(&msg_prime); // H(msg_prime)

    let mut payload_1 = b_0.clone();
    payload_1.extend_from_slice(&[1u8; 1]);
    payload_1.extend_from_slice(&dst_prime);
    let mut b_i = hash(&payload_1); // H(b_0 || 1 || dst_prime)

    let mut uniform_bytes = b_i.clone();
    for i in 2..=ell {
        let t: Vec<u8> = b_i.iter().zip(b_0.iter()).map(|(a, b)| a ^ b).collect();
        let mut payload_i = t;
        payload_i.extend_from_slice(&[i as u8; 1]);
        payload_i.extend_from_slice(&dst_prime);
        b_i = hash(&payload_i); //H((b_0 ^ b_(i-1)) || 1 || dst_prime)
        uniform_bytes.extend_from_slice(&b_i);
    }
    uniform_bytes.truncate(len_in_bytes);
    uniform_bytes
}

#[cfg(test)]
mod tests{
    use super::*;
    use lazy_static::lazy_static;
    use serde_json::Value;
    use crate::hasher::{HashAlgorithm, SHA256};

    pub fn load_vectors(path: &str) -> Value {
        use std::fs;
        serde_json::from_str(&fs::read_to_string(path).expect("File not found.")).unwrap()
    }

    lazy_static! {
        pub static ref VECTORS_EXPAND_MESSAGE_XMD_SHA256_38: serde_json::Value =
            load_vectors("expand_message_xmd_SHA256_38.json");
        pub static ref VECTORS_P256_XMD_SHA256_SSWU_RO: serde_json::Value =
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

            assert_eq!(
                msg_prime_expected,
                msg_prime(msg, &dst_prime, len_in_bytes, SHA256::S_IN_BYTES)
            );
        }
    }

    #[test]
    fn test_expand_message_xmd() {
	use crate::hash_suite::HashToCurveSuite;
	use crate::p256_hash::P256_XMD_SHA256_SSWU_RO_;

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
                P256_XMD_SHA256_SSWU_RO_::expand_message(msg, &dst, len_in_bytes)
            );
        }
    }
}

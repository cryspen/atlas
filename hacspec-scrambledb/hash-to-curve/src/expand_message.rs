//! `expand_message` is a function that generates a uniformly random byte
//! string.  It takes three arguments:
//!
//! 1.  `msg`, a byte string containing the message to hash,
//!
//! 2.  `DST`, a byte string that acts as a domain separation tag, and
//!
//! 3.  `len_in_bytes`, the number of bytes to be generated.
//!
//! This document defines the following two variants of expand_message:
//!
//! *  [expand_message_xmd] is appropriate for use with a
//!    wide range of hash functions, including SHA-2 [FIPS180-4], SHA-3
//!    [FIPS202], BLAKE2 [RFC7693], and others.
//!
//! *  [expand_message_xof]  appropriate for use with
//!    extendable-output functions (XOFs) including functions in the
//!    SHAKE [FIPS202] or BLAKE2X [BLAKE2X] families.
//!
//! These variants should suffice for the vast majority of use cases, but
//! other variants are possible.
//!
//! ### Defining other expand_message variants
//!
//! When defining a new `expand_message` variant, the most important
//! consideration is that `hash_to_field` models `expand_message` as a random
//! oracle.  Thus, implementors SHOULD prove indifferentiability from a
//! random oracle under an appropriate assumption about the underlying
//! cryptographic primitives; see Section 10.5 for more information.
//!
//! In addition, `expand_message` variants:
//!
//! *  MUST give collision resistance commensurate with the security
//!    level of the target elliptic curve.
//!
//! *  MUST be built on primitives designed for use in applications
//!    requiring cryptographic randomness.  As examples, a secure stream
//!    cipher is an appropriate primitive, whereas a Mersenne twister
//!    pseudorandom number generator [MT98] is not.
//!
//! *  MUST NOT use rejection sampling.
//!
//! *  MUST give independent values for distinct (`msg`, `DST`, `length`)
//!    inputs.  Meeting this requirement is subtle.  As a simplified
//!    example, hashing `msg || DST` does not work, because in this case
//!    distinct `(msg, DST)` pairs whose concatenations are equal will
//!    return the same output (e.g., `("AB", "CDEF")` and `("ABC", "DEF")`).
//!    The variants defined in this document use a suffix-free encoding
//!    of `DST` to avoid this issue.
//!
//! *  MUST use the domain separation tag `DST` to ensure that invocations
//!    of cryptographic primitives inside of `expand_message` are domain
//!    separated from invocations outside of `expand_message`.  For
//!    example, if the `expand_message` variant uses a hash function H, an
//!    encoding of `DST` MUST be added either as a prefix or a suffix of
//!    the input to each invocation of `H`.  Adding `DST` as a suffix is the
//!    RECOMMENDED approach.
//!
//! *  SHOULD read `msg` exactly once, for efficiency when `msg` is long.
//!
//! In addition, each `expand_message` variant MUST specify a unique
//! `EXP_TAG` that identifies that variant in a Suite ID.  See Section 8.10
//! for more
//!
//! ### Using DSTs longer than 255 bytes
//!
//! The `expand_message` variants defined in this section accept domain
//! separation tags of at most 255 bytes.  If applications require a
//! domain separation tag longer than 255 bytes, e.g., because of
//! requirements imposed by an invoking protocol, implementors MUST
//! compute a short domain separation tag by hashing, as follows:
//!
//! *  For expand_message_xmd using hash function H, DST is computed as
//!
//!
//! ``` text
//! DST = H("H2C-OVERSIZE-DST-" || a_very_long_DST)
//! ```
//!
//! *  For expand_message_xof using extendable-output function H, DST is
//!    computed as
//!
//! ``` text
//! DST = H("H2C-OVERSIZE-DST-" || a_very_long_DST, ceil(2 * k / 8))
//! ```
//!
//! Here, a_very_long_DST is the DST whose length is greater than 255
//! bytes, "H2C-OVERSIZE-DST-" is a 17-byte ASCII string literal, and k
//! is the target security level in bits.

use crate::{hacspec_helper::FunctionalVec, hasher::HashAlgorithm, Error};

/// The `expand_message_xof` function produces a uniformly random byte
/// string using an extendable-output function (XOF) H.  For security, H
/// MUST meet the following criteria:
///
/// *  The collision resistance of H MUST be at least k bits.
///
/// *  H MUST be an XOF that has been proved indifferentiable from a
///    random oracle under a reasonable cryptographic assumption.
///
/// The SHAKE [FIPS202] XOF family is a typical and RECOMMENDED choice.
/// As an example, for 128-bit security, SHAKE128 would be an appropriate
/// choice.
///
/// The following procedure implements `expand_message_xof`.
///
/// ```text
/// expand_message_xof(msg, DST, len_in_bytes)
///
/// Parameters:
/// - H(m, d), an extendable-output function that processes
///   input message m and returns d bytes.
///
/// Input:
/// - msg, a byte string.
/// - DST, a byte string of at most 255 bytes.
///   See below for information on using longer DSTs.
/// - len_in_bytes, the length of the requested output in bytes.
///
/// Output:
/// - uniform_bytes, a byte string.
///
/// Steps:
/// 1. ABORT if len_in_bytes > 65535 or len(DST) > 255
/// 2. DST_prime = DST || I2OSP(len(DST), 1)
/// 3. msg_prime = msg || I2OSP(len_in_bytes, 2) || DST_prime
/// 4. uniform_bytes = H(msg_prime, len_in_bytes)
/// 5. return uniform_bytes
/// ```
#[allow(non_snake_case, unused)]
pub fn expand_message_xof(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
    B_IN_BYTES: usize,
    S_IN_BYTES: usize,
    hash: fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    todo!()
}


/// The `expand_message_xmd` function produces a uniformly random byte
/// string using a cryptographic hash function H that outputs b bits.
/// For security, H MUST meet the following requirements:
///
/// *  The number of bits output by H MUST be b >= 2 * k, for k the
///    target security level in bits, and b MUST be divisible by 8.  The
///    first requirement ensures k-bit collision resistance; the second
///    ensures uniformity of `expand_message_xmd`'s output.
///
/// *  H MAY be a Merkle-Damgaard hash function like SHA-2.  In this
///    case, security holds when the underlying compression function is
///    modeled as a random oracle [CDMP05].  (See Section 10.6 for
///    discussion.)
///
/// *  H MAY be a sponge-based hash function like SHA-3 or BLAKE2.  In
///    this case, security holds when the inner function is modeled as a
///    random transformation or as a random permutation [BDPV08].
///
/// *  Otherwise, H MUST be a hash function that has been proved
///    indifferentiable from a random oracle [MRH04] under a reasonable
///    cryptographic assumption.
///
/// SHA-2 [FIPS180-4] and SHA-3 [FIPS202] are typical and RECOMMENDED
/// choices.  As an example, for the 128-bit security level, b >= 256
/// bits and either SHA-256 or SHA3-256 would be an appropriate choice.
///
/// The hash function H is assumed to work by repeatedly ingesting fixed-
/// length blocks of data.  The length in bits of these blocks is called
/// the input block size (s).  As examples, s = 1024 for SHA-512
/// [FIPS180-4] and s = 576 for SHA3-512 [FIPS202].  For correctness, H
/// requires b <= s.
///
/// The following procedure implements `expand_message_xmd`.
/// ```text
/// expand_message_xmd(msg, DST, len_in_bytes)
///
/// Parameters:
/// - H, a hash function (see requirements above).
/// - b_in_bytes, b / 8 for b the output size of H in bits.
///   For example, for b = 256, b_in_bytes = 32.
/// - s_in_bytes, the input block size of H, measured in bytes (see
///   discussion above). For example, for SHA-256, s_in_bytes = 64.
///
/// Input:
/// - msg, a byte string.
/// - DST, a byte string of at most 255 bytes.
///   See below for information on using longer DSTs.
/// - len_in_bytes, the length of the requested output in bytes,
///   not greater than the lesser of (255 * b_in_bytes) or 2^16-1.
///
/// Output:
/// - uniform_bytes, a byte string.
///
/// Steps:
/// 1.  ell = ceil(len_in_bytes / b_in_bytes)
/// 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
/// 3.  DST_prime = DST || I2OSP(len(DST), 1)
/// 4.  Z_pad = I2OSP(0, s_in_bytes)
/// 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
///    6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
///    7.  b_0 = H(msg_prime)
///    8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
///    9.  for i in (2, ..., ell):
///    10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
///    11. uniform_bytes = b_1 || ... || b_ell
///    12. return substr(uniform_bytes, 0, len_in_bytes)
/// ```
/// Note that the string Z_pad (step 6) is prefixed to msg before
/// computing b_0 (step 7).  This is necessary for security when H is a
/// Merkle-Damgaard hash, e.g., SHA-2 (see Section 10.6).  Hashing this
/// additional data means that the cost of computing b_0 is higher than
/// the cost of simply computing H(msg).  In most settings this overhead
/// is negligible, because the cost of evaluating H is much less than the
/// other costs involved in hashing to a curve.
///
/// It is possible, however, to entirely avoid this overhead by taking
/// advantage of the fact that Z_pad depends only on H, and not on the
/// arguments to `expand_message_xmd`.  To do so, first precompute and save
/// the internal state of H after ingesting Z_pad.  Then, when computing
/// b_0, initialize H using the saved state.  Further details are
/// implementation dependent, and beyond the scope of this document.

#[allow(non_snake_case)]
pub fn expand_message_xmd<H: HashAlgorithm>(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let ell = (len_in_bytes + H::B_IN_BYTES - 1) / H::B_IN_BYTES;
    if ell > 255 || len_in_bytes > 65535 || dst.len() > 255 {
        return Err(Error::InvalidEll);
    }

    let dst_prime = dst.concat_byte(dst.len() as u8);
    let z_pad = vec![0u8; H::S_IN_BYTES];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    // msg_prime = Z_pad || msg || l_i_b_str || 0 || dst_prime
    let msg_prime = z_pad
        .concat(msg)
        .concat(&l_i_b_str)
        .concat(&[0u8; 1])
        .concat(&dst_prime);

    let b_0 = H::hash(&msg_prime); // H(msg_prime)

    let payload_1 = b_0.concat_byte(1).concat(&dst_prime);
    let mut b_i = H::hash(&payload_1); // H(b_0 || 1 || dst_prime)

    let mut uniform_bytes = b_i.clone();
    for i in 2..=ell {
        // i < 256 is checked before
        let payload_i = strxor(&b_0, &b_i).concat_byte(i as u8).concat(&dst_prime);
        //H((b_0 ^ b_(i-1)) || 1 || dst_prime)
        b_i = H::hash(&payload_i);
        uniform_bytes.extend_from_slice(&b_i);
    }
    uniform_bytes.truncate(len_in_bytes);
    Ok(uniform_bytes)
}

fn strxor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{HashAlgorithm, SHA256};
    use serde_json::Value;

    pub fn load_vectors(path: &str) -> Value {
        use std::fs;
        serde_json::from_str(&fs::read_to_string(path).expect("File not found.")).unwrap()
    }

    /// Helper function to assemble `msg_prime`.
    #[allow(non_snake_case)]
    fn msg_prime(msg: &[u8], dst_prime: &[u8], len_in_bytes: usize, S_IN_BYTES: usize) -> Vec<u8> {
        let z_pad = vec![0u8; S_IN_BYTES];
        let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

        // msg_prime = Z_pad || msg || l_i_b_str || 0 || dst_prime
        let msg_prime = z_pad
            .concat(msg)
            .concat(&l_i_b_str)
            .concat(&[0u8; 1])
            .concat(&dst_prime);

        msg_prime
    }

    /// Helper function to assemble `dst_prime`.
    fn dst_prime(dst: &[u8]) -> Vec<u8> {
        let mut out = Vec::from(dst);
        Vec::<u8>::extend_from_slice(&mut out, &[dst.len() as u8; 1]);

        out
    }

    #[test]
    fn test_dst_prime() {
        let vectors_expand_message_xmd_sha256_38 =
            load_vectors("expand_message_xmd_SHA256_38.json");

        let dst = vectors_expand_message_xmd_sha256_38["DST"]
            .as_str()
            .unwrap();
        let dst = dst.as_bytes();

        let mut test_cases = vectors_expand_message_xmd_sha256_38["tests"]
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
        let vectors_expand_message_xmd_sha256_38 =
            load_vectors("expand_message_xmd_SHA256_38.json");

        let test_cases = vectors_expand_message_xmd_sha256_38["tests"]
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
        let vectors_expand_message_xmd_sha256_38 =
            load_vectors("expand_message_xmd_SHA256_38.json");

        let dst = vectors_expand_message_xmd_sha256_38["DST"]
            .as_str()
            .unwrap();
        let dst = dst.as_bytes();

        let test_cases = vectors_expand_message_xmd_sha256_38["tests"]
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
                expand_message_xmd::<SHA256>(msg, &dst, len_in_bytes).unwrap()
            );
        }
    }
}

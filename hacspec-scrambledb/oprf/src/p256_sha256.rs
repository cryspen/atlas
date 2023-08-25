//! ## 4.3.  OPRF(P-256, SHA-256)
//!
//! This ciphersuite uses P-256 [NISTCurves] for the Group and SHA-256
//! for the Hash function.  The value of the ciphersuite identifier is
//! "P256-SHA256".
//!

use crate::Error;

use p256::{P256Point, P256Scalar};

#[allow(non_upper_case_globals, unused)]
const identifier: &[u8] = b"P256-SHA256";

pub type P256SerializedPoint = [u8; 33];

/// SerializeElement(A): Implemented using the compressed Elliptic-
///     Curve-Point-to-Octet-String method according to [SEC1]; Ne =
///     33.
///
pub fn serialize_element(p: &P256Point) -> P256SerializedPoint {
    p256::serialize_point(p)
}

#[allow(unused)]
pub fn deserialize_element(pm: P256SerializedPoint) -> Result<P256Point, Error> {
    p256::deserialize_point(pm).map_err(|e| e.into())
}

pub fn identity() -> P256Point {
    P256Point::AtInfinity
}

pub fn scalar_inverse(s: P256Scalar) -> P256Scalar {
    use p256::NatMod;
    s.inv()
}

/// HashToScalar(): Use hash_to_field from [I-D.irtf-cfrg-hash-to-curve] using L = 48, expand_message_xmd with SHA-256, DST = "HashToScalar-" || contextString, and prime modulus equal to Group.Order().
pub fn hash_to_scalar(bytes: &[u8], context_string: &[u8]) -> Result<P256Scalar, Error> {
    let mut dst: Vec<u8> = "HashToScalar-".into(); // DST = "HashToScalar-" || contextString
    dst.extend_from_slice(context_string);
    hash_to_scalar_dst(bytes, &dst, context_string)
}

pub fn hash_to_scalar_dst(
    bytes: &[u8],
    dst: &[u8],
    context_string: &[u8],
) -> Result<P256Scalar, Error> {
    let mut dst = dst.to_vec();
    dst.extend_from_slice(context_string);

    hash_to_curve::p256_hash::hash_to_scalar(bytes, &dst, 1)
        .map(|v| v[0])
        .map_err(|e| e.into())
}

/// HashToGroup(): Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO_ [I-D.irtf-cfrg-hash-to-curve] and DST = "HashToGroup-" || contextString.
pub fn hash_to_group(bytes: &[u8], context_string: &[u8]) -> Result<P256Point, Error> {
    let mut dst: Vec<u8> = b"HashToGroup-".to_vec();
    dst.extend_from_slice(context_string);

    hash_to_curve::p256_hash::hash_to_curve(bytes, &dst).map_err(|e| e.into())
}

#[test]
fn serialize_deserialize() {
    use hacspec_lib::Randomness;
    let p: P256Point = p256::p256_point_mul_base(
        p256::random_scalar(&mut Randomness::new(vec![0xab; 32])).unwrap(),
    )
    .unwrap();

    assert_eq!(p, deserialize_element(serialize_element(&p)).unwrap());
}

//! ## 4.3.  OPRF(P-256, SHA-256)
//!
//! This ciphersuite uses P-256 [NISTCurves] for the Group and SHA-256
//! for the Hash function.  The value of the ciphersuite identifier is
//! "P256-SHA256".
//!

use crate::Error;
use hash_to_curve::ExpandMessageType;
use p256::{P256Point, P256Scalar};

#[allow(non_upper_case_globals)]
const identifier: &'static [u8] = b"P256-SHA256";

pub fn hash(payload: &[u8]) -> Vec<u8> {
    use libcrux::digest::{hash, Algorithm};
    hash(Algorithm::Sha256, payload)
}

pub type P256SerializedPoint = [u8; 33];

/// SerializeElement(A): Implemented using the compressed Elliptic-
///     Curve-Point-to-Octet-String method according to [SEC1]; Ne =
///     33.
///
pub fn serialize_element(p: &P256Point) -> P256SerializedPoint {
    use p256::NatMod;
    let (x, y) = p256::Affine::from(*p);

    let x_serialized = x.to_be_bytes();

    let mut out = [0u8; 33];
    for (to, from) in out.iter_mut().zip(x_serialized.iter()) {
        *to = *from
    }
    out[32] = if y.bit(0) { 2 } else { 3 };

    out
}

pub fn identity() -> P256Point {
    // XXX: For P-256, this is the point at infinity, which our implementation does not expose.
    P256Point::AtInfinity
}

pub fn scalar_inverse(s: P256Scalar) -> P256Scalar {
    use p256::NatMod;
    s.inv()
}

/// HashToScalar(): Use hash_to_field from [I-D.irtf-cfrg-hash-to-curve] using L = 48, expand_message_xmd with SHA-256, DST = "HashToScalar-" || contextString, and prime modulus equal to Group.Order().
pub fn hash_to_scalar(bytes: &[u8], context_string: &[u8]) -> P256Scalar {
    let mut dst: Vec<u8> = "HashToScalar-".into(); // DST = "HashToScalar-" || contextString
    dst.extend_from_slice(context_string);
    hash_to_scalar_dst(bytes, &dst, context_string)
}

pub fn hash_to_scalar_dst(bytes: &[u8], dst: &[u8], context_string: &[u8]) -> P256Scalar {
    use hash_to_curve::hash_suite::hash_to_field;

    let mut dst = dst.to_vec();
    dst.extend_from_slice(context_string);

    hash_to_field::<32, P256Scalar>(ExpandMessageType::P256_SHA256, bytes, &dst, 1, 48, 1).unwrap()
        [0][0]
}

/// HashToGroup(): Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO_ [I-D.irtf-cfrg-hash-to-curve] and DST = "HashToGroup-" || contextString.
pub fn hash_to_group(bytes: &[u8], context_string: &[u8]) -> Result<P256Point, Error> {
    use hash_to_curve::hash_suite::HashToCurve;
    use hash_to_curve::p256_hash::P256_XMD_SHA256_SSWU_RO;

    let mut dst: Vec<u8> = b"HashToGroup-".to_vec();
    dst.extend_from_slice(context_string);

    P256_XMD_SHA256_SSWU_RO::hash_to_curve(bytes, &dst)
        .map_err(|e| e.into())
        .map(|r| r.into())
}

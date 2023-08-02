//! ## 4.3.  OPRF(P-256, SHA-256)
//!
//! This ciphersuite uses P-256 [NISTCurves] for the Group and SHA-256
//! for the Hash function.  The value of the ciphersuite identifier is
//! "P256-SHA256".
//!

use crate::oprf_suite::Ciphersuite;
use crate::prime_order_group::PrimeOrderGroup;
use crate::Error;
use p256::{P256Point, P256Scalar};

#[allow(non_camel_case_types)]
pub struct P256_SHA256 {}

impl Ciphersuite<P256Point> for P256_SHA256 {
    #[allow(non_upper_case_globals)]
    const identifier: &'static [u8] = b"P256-SHA256";
    fn hash(payload: &[u8]) -> Vec<u8> {
        use libcrux::digest::{hash, Algorithm};
        hash(Algorithm::Sha256, payload)
    }
}

#[allow(unused)]
impl PrimeOrderGroup for P256Point {
    //! *  Group: P-256 (secp256r1) [NISTCurves]
    //!
    type Scalar = P256Scalar;

    fn order() {
        //!    -  Order(): Return 0xffffffff00000000ffffffffffffffffbce6faada7179
        //! 	  e84f3b9cac2fc632551.  
        todo!()
    }

    fn identity() -> Self {
        //!    -  Identity(): As defined in [NISTCurves].
        todo!()
    }

    fn generator() -> Self {
        //!    -  Generator(): As defined in [NISTCurves].
        todo!()
    }

    fn hash_to_group(bytes: &[u8]) -> Self {
        //!    -  HashToGroup(): Use hash_to_curve with suite P256_XMD:SHA-
        //! 	  256_SSWU_RO_ [I-D.irtf-cfrg-hash-to-curve] and DST =
        //! 	  "HashToGroup-" || contextString.
        todo!()
    }

    fn hash_to_scalar(bytes: &[u8]) -> Self::Scalar {
        //!    -  HashToScalar(): Use hash_to_field from
        //! 	  [I-D.irtf-cfrg-hash-to-curve] using L = 48, expand_message_xmd
        //! 	  with SHA-256, DST = "HashToScalar-" || contextString, and prime
        //! 	  modulus equal to Group.Order().
        // use hash_to_curve::hash_suite::hash_to_field;
        fn scalar_expand_message_xmd(
            msg: &[u8],
            dst: &[u8],
            len_in_bytes: usize,
        ) -> Result<Vec<u8>, Error> {
            use hash_to_curve::expand_message::expand_message_xmd;
            use hash_to_curve::hasher::SHA256;
            // TODO: Error conversion!
            expand_message_xmd::<SHA256>(msg, dst, len_in_bytes).map_err(|e| Error::InvalidExpansion)
        }
        // hash_to_field::<32, P256Scalar, P256Scalar>(
        //     bytes,`
        //     b"HashToScalar",
        //     1,
        //     48,
        //     1,
        //     scalar_expand_message_xmd,
        // ).unwrap()[0]
        todo!()
    }

    fn random_scalar() -> Self::Scalar {
        //!    -  RandomScalar(): Implemented by returning a uniformly random
        //! 	  Scalar in the range [0, G.Order() - 1].  Refer to Section 4.7
        //! 	  for implementation guidance.
        todo!()
    }

    fn scalar_inverse(scalar: Self::Scalar) -> Self::Scalar {
        //!    -  ScalarInverse(s): Returns the multiplicative inverse of input
        //! 	  Scalar s mod Group.Order().
        todo!()
    }

    fn serialize_element(self) -> Vec<u8> {
        //!    -  SerializeElement(A): Implemented using the compressed Elliptic-
        //! 	  Curve-Point-to-Octet-String method according to [SEC1]; Ne =
        //! 	  33.
        todo!()
    }

    fn deserialize_element(bytes: &[u8]) -> Result<Self, crate::Error>
    where
        Self: Sized,
    {
        //!    -  DeserializeElement(buf): Implemented by attempting to
        //! 	  deserialize a 33 byte input string to a public key using the
        //! 	  compressed Octet-String-to-Elliptic-Curve-Point method
        //! 	  according to [SEC1], and then performs partial public-key
        //! 	  validation as defined in section 5.6.2.3.4 of [KEYAGREEMENT].
        //! 	  This includes checking that the coordinates of the resulting
        //! 	  point are in the correct range, that the point is on the curve,
        //! 	  and that the point is not the group identity element.  If these
        //! 	  checks fail, deserialization returns an InputValidationError
        //! 	  error.
        todo!()
    }

    fn serialize_scalar(scalar: Self::Scalar) -> Vec<u8> {
        //!    -  SerializeScalar(s): Implemented using the Field-Element-to-
        //! 	  Octet-String conversion according to [SEC1]; Ns = 32.
        todo!()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Result<Self::Scalar, crate::Error> {
        //!    -  DeserializeScalar(buf): Implemented by attempting to
        //! 	  deserialize a Scalar from a 32-byte string using Octet-String-
        //! 	  to-Field-Element from [SEC1].  This function can fail if the
        //! 	  input does not represent a Scalar in the range [0, G.Order() -
        //! 	  1].
        todo!()
    }
}

pub type P256SerializedPoint = [u8; 33];

/// SerializeElement(A): Implemented using the compressed Elliptic-
///     Curve-Point-to-Octet-String method according to [SEC1]; Ne =
///     33.
///
pub fn serialize_element(p: &P256Point) -> P256SerializedPoint {
    use p256::NatMod;
    let (x, y) = p;

    let x_serialized = x.to_be_bytes();

    let mut out = [0u8; 33];
    for (to, from) in out.iter_mut().zip(x_serialized.iter()) {
        *to = *from
    }
    out[32] = if y.bit(0) { 2 } else { 3 };

    out
}

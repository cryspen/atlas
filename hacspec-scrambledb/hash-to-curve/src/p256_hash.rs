// TODO: Add comments about what this is and where the spec is.

use crate::hash_suite::{EncodeToCurve, HashToCurve, HashToField};
use crate::hasher::SHA256;
use crate::prime_curve::{MapToCurve, PrimeField, PrimeCurve, Constructor};
use crate::Error;
use crate::{expand_message::expand_message_xmd, hash_suite::Ciphersuite};
use p256::{NatMod, P256FieldElement, P256Point};

/// # 8.2 Suites for NIST P-256
///
/// `P256_XMD:SHA-256_SSWU_RO_`
///
/// [`P256_XMD:SHA-256_SSWU_NU_`](P256_XMD_SHA256_SSWU_NU) is identical to `P256_XMD:SHA-256_SSWU_RO_`,
/// except that the encoding type is encode_to_curve (Section 3).
#[allow(non_camel_case_types)]
pub struct P256_XMD_SHA256_SSWU_RO {}

impl Ciphersuite for P256_XMD_SHA256_SSWU_RO {
    const ID: &'static str = "P256_XMD:SHA-256_SSWU_RO_";
    const K: usize = 128;
    const L: usize = 48;
    const M: usize = 1;

    type BaseField = P256FieldElement;
    type OutputCurve = P256Point;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, Error> {
        expand_message_xmd::<SHA256>(msg, dst, len_in_bytes)
    }
}

impl Constructor<32, P256FieldElement> for P256FieldElement {
    fn from_coeffs(v: Vec<P256FieldElement>) -> Self {
	assert_eq!(v.len(), 1);
	v[0]
    }
}

impl HashToField for P256_XMD_SHA256_SSWU_RO {
    fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<P256FieldElement>, Error> {
	 crate::hash_suite::hash_to_field::<32, P256FieldElement, P256FieldElement>(msg, dst, count, Self::L, Self::M, Self::expand_message)

    }
}

impl HashToCurve for P256_XMD_SHA256_SSWU_RO {
    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<(Self::BaseField, Self::BaseField), Error> {
        let u = Self::hash_to_field(msg, dst, 2)?;
        let q0 = u[0].map_to_curve();
        let q1 = u[1].map_to_curve();
        let r = Self::OutputCurve::point_add(q0, q1)?;
        Ok(Self::OutputCurve::clear_cofactor(r))
    }
}

#[allow(non_camel_case_types)]
pub struct P256_XMD_SHA256_SSWU_NU {}

impl Ciphersuite for P256_XMD_SHA256_SSWU_NU {
    const ID: &'static str = "P256_XMD:SHA-256_SSWU_NU_";
    const K: usize = 128;
    const L: usize = 48;
    const M: usize = 1;

    type BaseField = P256FieldElement;
    type OutputCurve = P256Point;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, Error> {
        expand_message_xmd::<SHA256>(msg, dst, len_in_bytes)
    }
}

impl HashToField for P256_XMD_SHA256_SSWU_NU {
    fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<P256FieldElement>, Error> {
	crate::hash_suite::hash_to_field::<32, P256FieldElement, P256FieldElement>(msg, dst, count, Self::L, Self::M, Self::expand_message)
    }
}

impl EncodeToCurve for P256_XMD_SHA256_SSWU_NU {
    fn encode_to_curve(msg: &[u8], dst: &[u8]) -> Result<Self::OutputCurve, Error> {
        let u = Self::hash_to_field(msg, dst, 1)?;
        let q = u[0].map_to_curve();
        Ok(P256Point::clear_cofactor(q))
    }
}

impl PrimeField<32> for P256FieldElement {
    fn is_square(&self) -> bool {
        crate::prime_curve::is_square_m_eq_1(self)
    }

    fn sqrt(self) -> P256FieldElement {
        crate::prime_curve::sqrt_3mod4_m_eq_1(&self)
    }

    fn sgn0(self) -> bool {
        crate::prime_curve::sgn0_m_eq_1(self)
    }
}

impl PrimeCurve for P256Point {
    type BaseField = P256FieldElement;

    fn clear_cofactor(self) -> Self {
	self
    }

    fn point_add(lhs: Self, rhs: Self) -> Result<(Self::BaseField, Self::BaseField), Error> {
	p256::point_add(lhs, rhs).map_err(|_e| Error::InvalidAddition)
    }
}

impl MapToCurve for P256FieldElement {
    type TargetCurve = P256Point;

    fn map_to_curve(self) -> Self::TargetCurve{
        crate::mappings::sswu_m_eq_1(
            &self,
            &P256FieldElement::from_u128(3u128).neg(),
            &P256FieldElement::from_hex(
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            ),
            P256FieldElement::from_u128(10u128).neg(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn p256_xmd_sha256_sswu_ro_hash_to_field() {
	test_hash_to_field::<32, P256_XMD_SHA256_SSWU_RO>()
    }

    #[test]
    fn p256_xmd_sha256_sswu_ro_map_to_curve() {
	test_map_to_curve::<32, P256_XMD_SHA256_SSWU_RO>();
    }

    #[test]
    fn p256_xmd_sha256_sswu_ro_hash_to_curve() {
	test_hash_to_curve::<32, P256_XMD_SHA256_SSWU_RO>( );
    }

    #[test]
    fn p256_xmd_sha256_sswu_nu_encode_to_curve() {
	test_encode_to_curve::<32, P256_XMD_SHA256_SSWU_NU>();
    }
}

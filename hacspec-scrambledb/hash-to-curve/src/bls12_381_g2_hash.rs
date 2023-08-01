use crate::bls12_381::*;
use crate::expand_message::expand_message_xmd;
use crate::hash_suite::{Ciphersuite, HashToCurve, HashToField};
use crate::hasher::SHA256;
use crate::prime_curve::{MapToCurve, PrimeCurve, Constructor};
use crate::Error;
use p256::NatMod; // XXX: move to hacspec lib

#[allow(non_camel_case_types)]
pub struct BLS12381G2_XMD_SHA_256_SSWU_RO {}

impl Ciphersuite for BLS12381G2_XMD_SHA_256_SSWU_RO {
    const ID: &'static str = "BLS12381G2_XMD:SHA-256_SSWU_RO_";
    const K: usize = 128;
    const L: usize = 64;
    const M: usize = 2;

    type BaseField = Fp2;
    type OutputCurve = BLS12_G2;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, Error> {
        expand_message_xmd::<SHA256>(msg, dst, len_in_bytes)
    }
}


impl Constructor<48, BLS12FieldElement> for Fp2 {
    fn from_coeffs(v: Vec<BLS12FieldElement>) -> Self {
       assert_eq!(v.len(), 2);
            (v[0], v[1])
    }
}
impl HashToField for BLS12381G2_XMD_SHA_256_SSWU_RO {
    fn hash_to_field(
        msg: &[u8],
        dst: &[u8],
        count: usize,
    ) -> Result<Vec<Self::BaseField>, crate::Error> {
        crate::hash_suite::hash_to_field::<48, BLS12FieldElement, Fp2>(
            msg,
            dst,
            count,
            Self::L,
            Self::M,
            Self::expand_message,
        )
    }
}

impl HashToCurve for BLS12381G2_XMD_SHA_256_SSWU_RO {
    fn hash_to_curve(
        msg: &[u8],
        dst: &[u8],
    ) -> Result<(Self::BaseField, Self::BaseField), crate::Error> {
        let u = Self::hash_to_field(msg, dst, 2)?;
        let (x0, y0) = u[0].map_to_curve();
        let (x1, y1) = u[1].map_to_curve();
        let r = g2add((x0, y0, false), (x1, y1, false));
        Ok(BLS12_G2::clear_cofactor(r))
    }
}

impl MapToCurve for Fp2 {
    type TargetCurve = (Fp2, Fp2);

    fn map_to_curve(self) -> Self::TargetCurve {
        todo!()
    }
}

impl PrimeCurve for BLS12_G2 {
    type BaseField = Fp2;

    fn clear_cofactor(self) -> (Self::BaseField, Self::BaseField) {
        todo!()
    }

    fn point_add(_lhs: Self, _rhs: Self) -> Result<(Self::BaseField, Self::BaseField), Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn bls12381g2_xmd_sha256_sswu_ro_hash_to_field() {
        let mut vector_path =
            std::path::Path::new("vectors").join(BLS12381G2_XMD_SHA_256_SSWU_RO::ID);
        vector_path.set_extension("json");
        let vectors = load_vectors(vector_path.as_path());

        let dst = vectors["dst"].as_str().unwrap();
        let dst = dst.as_bytes();

        let test_cases = vectors["vectors"].as_array().unwrap().clone();

        for test_case in test_cases.iter() {
            let msg_str = test_case["msg"].as_str().unwrap();

            let msg = msg_str.as_bytes();

            let u = test_case["u"].as_array().unwrap();
            let u0: Vec<&str> = u[0].as_str().unwrap().split(',').collect();
            let u0_0_expected = u0[0].trim_start_matches("0x");
            let u0_0_expected =
                BLS12FieldElement::from_be_bytes(&hex::decode(u0_0_expected).unwrap());
            let u0_1_expected = u0[1].trim_start_matches("0x");
            let u0_1_expected =
                BLS12FieldElement::from_be_bytes(&hex::decode(u0_1_expected).unwrap());

            let u1: Vec<&str> = u[1].as_str().unwrap().split(',').collect();
            let u1_0_expected = u1[0].trim_start_matches("0x");
            let u1_0_expected =
                BLS12FieldElement::from_be_bytes(&hex::decode(u1_0_expected).unwrap());
            let u1_1_expected = u1[1].trim_start_matches("0x");
            let u1_1_expected =
                BLS12FieldElement::from_be_bytes(&hex::decode(u1_1_expected).unwrap());

            let u_real = BLS12381G2_XMD_SHA_256_SSWU_RO::hash_to_field(msg, dst, 2).unwrap();
            assert_eq!(u_real.len(), 2);
            assert_eq!(
                u0_0_expected.as_ref(),
                u_real[0].0.as_ref(),
                "u0_0 did not match for {msg_str}"
            );
            assert_eq!(
                u0_1_expected.as_ref(),
                u_real[0].1.as_ref(),
                "u0_1 did not match for {msg_str}"
            );
            assert_eq!(
                u1_0_expected.as_ref(),
                u_real[1].0.as_ref(),
                "u1_0 did not match for {msg_str}"
            );
            assert_eq!(
                u1_1_expected.as_ref(),
                u_real[1].1.as_ref(),
                "u1_1 did not match for {msg_str}"
            );
        }
    }

    #[test]
    fn bls12381g2_xmd_sha256_sswu_ro_map_to_curve() {
        todo!()
    }

    #[test]
    fn bls12381g2_xmd_sha256_sswu_ro_hash_to_curve() {
        todo!()
    }

    #[test]
    fn bls12381g2_xmd_sha256_sswu_nu_encode_to_curve() {
        todo!()
    }
}

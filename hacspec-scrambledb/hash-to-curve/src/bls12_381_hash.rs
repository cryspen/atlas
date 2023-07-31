//! # 8.8. Suites for BLS12-381
//! This section defines ciphersuites for groups G1 and G2 of the BLS12-381
//! elliptic curve [BLS12-381]. The curve parameters in this section match the
//! ones listed in [I-D.irtf-cfrg-pairing-friendly-curves], Appendix C.

use crate::bls12_381::*;
use crate::hash_suite::{Ciphersuite, HashToCurve, HashToField};
use crate::prime_curve::{MapToCurve, MapToCurveIsogeny, PrimeField};
use p256::NatMod; // XXX: move to hacspec lib

/// # 8.8.1. BLS12-381 G1
///
/// `BLS12381G1_XMD:SHA-256_SSWU_RO_`
///
/// BLS12381G1_XMD:SHA-256_SSWU_NU_ is identical to BLS12381G1_XMD:SHA-256_SSWU_RO_,
/// except that the encoding type is encode_to_curve (Section 3).
///
/// Note that the h_eff values for these suites are chosen for compatibility with
/// the fast cofactor clearing method described by Scott ([WB19] Section 5).
///
/// An optimized example implementation of the Simplified SWU mapping to the
/// curve E' isogenous to BLS12-381 G1 is given in Appendix F.2.
#[allow(non_camel_case_types)]
pub struct BLS12381G1_XMD_SHA_256_SSWU_RO {}

impl Ciphersuite for BLS12381G1_XMD_SHA_256_SSWU_RO {
    const ID: &'static str = "BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const K: usize = 128;
    const L: usize = 64;

    type BaseField = BLS12FieldElement;
    type OutputCurve = BLS12_G1;
}

impl HashToCurve for BLS12381G1_XMD_SHA_256_SSWU_RO {
    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Self::OutputCurve, crate::Error> {
        let u = Self::hash_to_field(msg, dst, 2)?;
        let q0 = BLS12_G1::map_to_curve(&u[0]);
        let q1 = BLS12_G1::map_to_curve(&u[1]);
        let r = g1add(q0, q1);
        Ok(BLS12_G1::clear_cofactor(r))
    }
}

impl PrimeField for BLS12FieldElement {
    fn is_square(&self) -> bool {
        let exp = BLS12FieldElement::from_u128(1).neg() * BLS12FieldElement::from_u128(2).inv();
        let test = self.pow_felem(&exp);
        test == BLS12FieldElement::zero() || test == BLS12FieldElement::one()
    }

    /// Input: x, an element of F.
    /// Output: z, an element of F such that (z^2) == x, if x is square in F.
    ///
    /// For BLS12-381, we have q = p = 3 (mod 4). Therefore we compute the square as follows:
    ///
    /// 1. c1 = (q + 1) / 4
    /// 2. return x^c1
    fn sqrt(self) -> BLS12FieldElement {
        let c1 = BLS12FieldElement::one() * BLS12FieldElement::from_u128(4).inv();
        self.pow_felem(&c1)
    }

    // In BLS12-381, the base field of G1 has m = 1.
    fn sgn0(self) -> bool {
        self.bit(0)
    }

    fn hash_to_field_prime_order(count: usize, l: usize, uniform_bytes: Vec<u8>) -> Vec<Self> {
        let mut u = Vec::with_capacity(count);
        for i in 0..count {
            // m = 1
            let elm_offset = l * i;
            let tv = &uniform_bytes[elm_offset..l * (i + 1)];
            let tv = Self::from_be_bytes(tv);
            u.push(tv);
        }
        u
    }
}



impl MapToCurve for BLS12_G1 {
    type BaseField = BLS12FieldElement;

    fn map_to_curve(fe: &Self::BaseField) -> Self {
        let (x_prime, y_prime) = BLS12_G1::iso_sswu(fe);

    }

    fn clear_cofactor(self) -> Self {
        let h_eff = crate::bls12_381::Scalar::from_hex("d201000000010001");
        g1mul(h_eff, self)
    }
}

impl MapToCurveIsogeny for BLS12_G1 {
    fn iso_map(
        x_iso: Self::BaseField,
        y_iso: Self::BaseField,
    ) -> (Self::BaseField, Self::BaseField) {
        todo!()
    }

    fn isogeny_a() -> Self::BaseField {
        Self::BaseField::from_hex("144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d")
    }

    fn isogeny_b() -> Self::BaseField {
        Self::BaseField::from_hex("12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0")
    }

    fn iso_sswu_z() -> Self::BaseField {
        Self::BaseField::from_u128(11)
    }

    fn iso_sswu(fe: &Self::BaseField) -> Self {
        let a = Self::isogeny_a();
        let b = Self::isogeny_b();
        let z = Self::iso_sswu_z();

        let tv1 = (z.pow(2) * u.pow(4) + z * u.pow(2)).inv0();
        let x1 = if tv1 == P256FieldElement::zero() {
            b * (z * a).inv()
        } else {
            (b.neg() * a.inv()) * (tv1 + P256FieldElement::from_u128(1u128))
        };

        let gx1 = x1.pow(3) + a * x1 + b;
        let x2 = z * u.pow(2) * x1;
        let gx2 = x2.pow(3) + a * x2 + b;

        let mut output = if gx1.is_square() {
            (x1, gx1.sqrt())
        } else {
            (x2, gx2.sqrt())
        };

        if u.sgn0() != output.1.sgn0() {
            output.1 = output.1.neg();
        }

        output
    }
}

impl HashToField for BLS12381G1_XMD_SHA_256_SSWU_RO {
    fn hash_to_field(
        msg: &[u8],
        dst: &[u8],
        count: usize,
    ) -> Result<Vec<Self::BaseField>, crate::Error> {
        todo!()
    }
}

/// # 8.8.2
///
/// `BLS12381G2_XMD:SHA-256_SSWU_RO_`
///
/// `BLS12381G2_XMD:SHA-256_SSWU_NU_` is identical to BLS12381G2_XMD:SHA-256_SSWU_RO_,
/// except that the encoding type is encode_to_curve (Section 3).
///
/// Note that the h_eff values for these suites are chosen for compatibility with
/// the fast cofactor clearing method described by Budroni and Pintore ([BP17], Section 4.1),
/// and summarized in Appendix G.3.
///
/// An optimized example implementation of the Simplified SWU mapping to the
/// curve E' isogenous to BLS12-381 G2 is given in Appendix F.2.
#[allow(non_camel_case_types)]
pub struct BLS12381G2_XMD_SHA_256_SSWU_RO {}

impl Ciphersuite for BLS12381G2_XMD_SHA_256_SSWU_RO {
    const ID: &'static str = "BLS12381G2_XMD:SHA-256_SSWU_RO_";
    const K: usize = 128;
    const L: usize = 64;

    type BaseField = BLS12FieldElement;
    type OutputCurve = BLS12_G2;
}

impl HashToField for BLS12381G2_XMD_SHA_256_SSWU_RO {
    fn hash_to_field(
        msg: &[u8],
        dst: &[u8],
        count: usize,
    ) -> Result<Vec<Self::BaseField>, crate::Error> {
        todo!()
    }
}

impl HashToCurve for BLS12381G2_XMD_SHA_256_SSWU_RO {
    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Self::OutputCurve, crate::Error> {
        todo!()
    }
}

impl PrimeField for BLS12381G2_XMD_SHA_256_SSWU_RO {
    fn is_square(&self) -> bool {
        todo!()
    }

    fn sqrt(self) -> Self {
        todo!()
    }

    fn sgn0(self) -> bool {
        todo!()
    }

    fn hash_to_field_prime_order(count: usize, l: usize, uniform_bytes: Vec<u8>) -> Vec<Self> {
        todo!()
    }
}

impl MapToCurve for BLS12_G2 {
    type BaseField = BLS12FieldElement;

    fn map_to_curve(fe: &Self::BaseField) -> Self {
        todo!()
    }

    fn clear_cofactor(self) -> Self {
        todo!()
    }
}

impl MapToCurveIsogeny for BLS12_G2 {
    fn iso_map(
        x_iso: Self::BaseField,
        y_iso: Self::BaseField,
    ) -> (Self::BaseField, Self::BaseField) {
        todo!()
    }

    fn isogeny_a() -> Self::BaseField {
        todo!()
    }

    fn isogeny_b() -> Self::BaseField {
        todo!()
    }

    fn iso_sswu_z() -> Self::BaseField {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use p256::NatMod;

    use super::*;
    use crate::test_utils::load_vectors;

    #[test]
    fn p256_xmd_sha256_sswu_ro_hash_to_field() {
        let vectors_bls12381g1_xmd_sha256_sswu_ro =
            load_vectors("vectors/BLS12381G1_XMD:SHA-256_SSWU_RO_.json");

        let dst = vectors_bls12381g1_xmd_sha256_sswu_ro["dst"]
            .as_str()
            .unwrap();
        let dst = dst.as_bytes();

        let test_cases = vectors_bls12381g1_xmd_sha256_sswu_ro["vectors"]
            .as_array()
            .unwrap()
            .clone();

        for test_case in test_cases.iter() {
            let msg_str = test_case["msg"].as_str().unwrap();

            let msg = msg_str.as_bytes();

            let u = test_case["u"].as_array().unwrap();
            let u0_expected = u[0].as_str().unwrap().trim_start_matches("0x");
            let u0_expected = BLS12FieldElement::from_be_bytes(&hex::decode(u0_expected).unwrap());
            let u1_expected = u[1].as_str().unwrap().trim_start_matches("0x");
            let u1_expected = BLS12FieldElement::from_be_bytes(&hex::decode(u1_expected).unwrap());

            let u_real = BLS12381G1_XMD_SHA_256_SSWU_RO::hash_to_field(msg, dst, 2).unwrap();
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
}

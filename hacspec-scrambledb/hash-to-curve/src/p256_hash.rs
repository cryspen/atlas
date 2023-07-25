// TODO: Add comments about what this is and where the spec is.

use p256::{NatMod, *};
use crate::hash_suite::HashToCurveSuite;
use crate::hasher::{HashAlgorithm, SHA256};
use crate::expand_message::expand_message_xmd;
use crate::prime_field::{PrimeField, hash_to_field_prime_order};

#[allow(non_camel_case_types)]
pub struct P256_XMD_SHA256_SSWU_RO_ {}

impl HashToCurveSuite for P256_XMD_SHA256_SSWU_RO_ {
    const ID: &'static str = "P256_XMD:SHA-256_SSWU_RO_";
    const K: usize = 128;
    const L: usize = 48;

    type BaseField = P256FieldElement;
    type OutputCurve = P256Point;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        expand_message_xmd(
            msg,
            dst,
            len_in_bytes,
            SHA256::B_IN_BYTES,
            SHA256::S_IN_BYTES,
            SHA256::hash,
        )
    }

    fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Vec<P256FieldElement> {
        hash_to_field_prime_order::<P256FieldElement,32>(msg, dst, count, Self::L, Self::expand_message)
    }

    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Self::OutputCurve {
        let u = Self::hash_to_field(msg, dst, 2);
        let q0 = P256Point::map_to_curve(&u[0]);
        let q1 = P256Point::map_to_curve(&u[1]);
        let r = point_add(q0, q1).unwrap();
        P256Point::clear_cofactor(r)
    }
}

#[allow(non_camel_case_types)]
pub struct P256_XMD_SHA256_SSWU_NU_ {}

impl HashToCurveSuite for P256_XMD_SHA256_SSWU_NU_ {
    const ID: &'static str = "P256_XMD:SHA-256_SSWU_NU_";
    const K: usize = 128;
    const L: usize = 48;

    type BaseField = P256FieldElement;
    type OutputCurve = P256Point;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        expand_message_xmd(
            msg,
            dst,
            len_in_bytes,
            SHA256::B_IN_BYTES,
            SHA256::S_IN_BYTES,
            SHA256::hash,
        )
    }

    fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Vec<P256FieldElement> {
        hash_to_field_prime_order::<P256FieldElement,32>(msg, dst, count, Self::L, Self::expand_message)
    }

    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Self::OutputCurve {
        let u = Self::hash_to_field(msg, dst, 1);
        let q = P256Point::map_to_curve(&u[0]);
        P256Point::clear_cofactor(q)
    }
}

impl PrimeField<p256::P256FieldElement, 32> for P256FieldElement {
    /// This function returns `true` whenever the value `x` is a square in the field F. By Euler's criterion, this function can be calculated in constant time as
    ///
    /// ```text
    /// is_square(x) := { True, if x^((q - 1) / 2) is 0 or 1 in F;
    ///                 { False, otherwise.
    /// ```
    fn is_sqare(&self) -> bool {
        let exp = P256FieldElement::from_u128(1).neg() * P256FieldElement::from_u128(2).inv();
        let test = self.pow_felem(&exp);
        test == P256FieldElement::zero() || test == P256FieldElement::from_u128(1)
    }

    /// Input: x, an element of F.
    /// Output: z, an element of F such that (z^2) == x, if x is square in F.
    ///
    /// For P-256, we have q = p = 3 (mod 4). Therefore we compute the square as follows:
    ///
    /// 1. c1 = (q + 1) / 4
    /// 2. return x^c1
    fn sqrt(self) -> P256FieldElement {
        let c1 = P256FieldElement::from_u128(1) * P256FieldElement::from_u128(4).inv();
        self.pow_felem(&c1)
    }

    fn sgn0(self) -> bool {
        self.bit(0)
    }
}



trait PrimeCurveWeierstrass<T: NatMod<LEN>, const LEN: usize> {
    type BaseField: PrimeField<T, LEN>;

    fn map_to_curve(fe: &Self::BaseField) -> Self;
    fn clear_cofactor(self) -> Self;

    fn weierstrass_a() -> Self::BaseField;
    fn weierstrass_b() -> Self::BaseField;
    fn sswu_z() -> Self::BaseField;
}

impl PrimeCurveWeierstrass<p256::P256FieldElement, 32> for P256Point {
    type BaseField = P256FieldElement;

    fn weierstrass_a() -> Self::BaseField {
        P256FieldElement::from_u128(3u128).neg()
    }

    fn weierstrass_b() -> Self::BaseField {
        P256FieldElement::from_hex(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        )
    }

    fn sswu_z() -> Self::BaseField {
        P256FieldElement::from_u128(10u128).neg()
    }

    // Simplified Shallue-van de Woestijne-Ulas method
    // TODO: Can I implement this generically?
    fn map_to_curve(u: &Self::BaseField) -> Self {
        let a = Self::weierstrass_a();
        let b = Self::weierstrass_b();
        let z = Self::sswu_z();

        let tv1 = (z.pow(2) * u.pow(4) + z * u.pow(2)).inv0();
        let x1 = if tv1 == P256FieldElement::zero() {
            b * (z * a).inv()
        } else {
            (b.neg() * a.inv()) * (tv1 + P256FieldElement::from_u128(1u128))
        };

        let gx1 = x1.pow(3) + a * x1 + b;
        let x2 = z * u.pow(2) * x1;
        let gx2 = x2.pow(3) + a * x2 + b;

        let mut output = if gx1.is_sqare() {
            (x1, gx1.sqrt())
        } else {
            (x2, gx2.sqrt())
        };

        if u.sgn0() != output.1.sgn0() {
            output.1 = output.1.neg();
        }

        output
    }
    fn clear_cofactor(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use serde_json::Value;

    pub fn load_vectors(path: &str) -> Value {
        use std::fs;
        serde_json::from_str(&fs::read_to_string(path).expect("File not found.")).unwrap()
    }

    lazy_static! {
        pub static ref VECTORS_EXPAND_MESSAGE_XMD_SHA256_38: serde_json::Value =
            load_vectors("vectors/expand_message_xmd_SHA256_38.json");
        pub static ref VECTORS_P256_XMD_SHA256_SSWU_RO: serde_json::Value =
            load_vectors("vectors/P256_XMD:SHA-256_SSWU_RO_.json");
	pub static ref VECTORS_P256_XMD_SHA256_SSWU_NU: serde_json::Value =
            load_vectors("vectors/P256_XMD:SHA-256_SSWU_NU_.json");

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
                P256_XMD_SHA256_SSWU_RO_::expand_message(msg, &dst, len_in_bytes)
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

            let u_real = P256_XMD_SHA256_SSWU_RO_::hash_to_field(msg, dst, 2);
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

            let (q0_x, q0_y) = P256Point::map_to_curve(&u0);
            let (q1_x, q1_y) = P256Point::map_to_curve(&u1);

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
    fn test_hash_to_curve_uniform() {
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

            let (x, y) = P256_XMD_SHA256_SSWU_RO_::hash_to_curve(msg, dst);

            // assert!(!inf, "Point should not be infinite");
            assert_eq!(p_x_expected.as_ref(), x.as_ref(), "x-coordinate incorrect");
            assert_eq!(p_y_expected.as_ref(), y.as_ref(), "y-coordinate incorrect");
        }
    }

        #[test]
    fn test_hash_to_curve_nonuniform() {
        let dst = VECTORS_P256_XMD_SHA256_SSWU_NU["dst"].as_str().unwrap();
        let dst = dst.as_bytes();
        let test_cases = VECTORS_P256_XMD_SHA256_SSWU_NU["vectors"]
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

            let (x, y) = P256_XMD_SHA256_SSWU_NU_::hash_to_curve(msg, dst);

            // assert!(!inf, "Point should not be infinite");
            assert_eq!(p_x_expected.as_ref(), x.as_ref(), "x-coordinate incorrect");
            assert_eq!(p_y_expected.as_ref(), y.as_ref(), "y-coordinate incorrect");
        }
    }
}

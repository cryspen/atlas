use natmod::nat_mod;

mod hacspec_helper;
pub use hacspec_helper::*;

#[derive(Debug)]
pub enum Error {
    InvalidAddition,
}

const BITS: u128 = 256;

#[nat_mod("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 32)]
pub struct P256FieldElement {}

#[nat_mod("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 32)]
pub struct P256Scalar {}

pub type Affine = (P256FieldElement, P256FieldElement);
pub type AffineResult = Result<Affine, Error>;
type P256Jacobian = (P256FieldElement, P256FieldElement, P256FieldElement);
type JacobianResult = Result<P256Jacobian, Error>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum P256Point {
    NonInf(Affine),
    AtInfinity,
}

impl From<P256Point> for Affine {
    fn from(value: P256Point) -> Self {
        match value {
            P256Point::AtInfinity => panic!("No affine representation of Point at Infinity."),
            P256Point::NonInf(affine) => affine,
        }
    }
}

impl From<Affine> for P256Point {
    fn from(value: Affine) -> Self {
        P256Point::NonInf(value)
    }
}

pub fn jacobian_to_affine(p: P256Jacobian) -> Affine {
    let (x, y, z) = p;
    let z2 = z.pow(2);
    let z2i = z2.inv();
    let z3 = z * z2;
    let z3i = z3.inv();
    let x = x * z2i;
    let y = y * z3i;
    (x, y)
}

impl std::ops::Neg for P256FieldElement {
    type Output = P256FieldElement;

    fn neg(self) -> Self::Output {
        hacspec_helper::NatMod::neg(self)
    }
}

impl std::ops::Neg for P256Point {
    type Output = P256Point;
    fn neg(self) -> Self::Output {
        match self {
            P256Point::AtInfinity => self,
            P256Point::NonInf((x, y)) => (x, hacspec_helper::NatMod::neg(y)).into(),
        }
    }
}

pub fn affine_to_jacobian(p: Affine) -> P256Jacobian {
    let (x, y) = p;
    (x, y, P256FieldElement::from_u128(1))
}

fn point_double(p: P256Jacobian) -> P256Jacobian {
    let (x1, y1, z1) = p;
    let delta = z1.pow(2);
    let gamma = y1.pow(2);

    let beta = x1 * gamma;

    let alpha_1 = x1 - delta;
    let alpha_2 = x1 + delta;
    let alpha = P256FieldElement::from_u128(3) * (alpha_1 * alpha_2);

    let x3 = alpha.pow(2) - (P256FieldElement::from_u128(8) * beta);

    let z3_ = (y1 + z1).pow(2);
    let z3 = z3_ - (gamma + delta);

    let y3_1 = (P256FieldElement::from_u128(4) * beta) - x3;
    let y3_2 = P256FieldElement::from_u128(8) * (gamma * gamma);
    let y3 = (alpha * y3_1) - y3_2;
    (x3, y3, z3)
}

fn is_point_at_infinity(p: P256Jacobian) -> bool {
    let (_x, _y, z) = p;
    z == P256FieldElement::from_u128(0)
}

fn s1_equal_s2(s1: P256FieldElement, s2: P256FieldElement) -> JacobianResult {
    if s1 == s2 {
        JacobianResult::Err(Error::InvalidAddition)
    } else {
        Ok((
            P256FieldElement::from_u128(0),
            P256FieldElement::from_u128(1),
            P256FieldElement::from_u128(0),
        ))
    }
}

pub fn point_add_jacob(p: P256Jacobian, q: P256Jacobian) -> JacobianResult {
    let mut result = Ok(q);
    if !is_point_at_infinity(p) {
        if is_point_at_infinity(q) {
            result = Ok(p);
        } else {
            let (x1, y1, z1) = p;
            let (x2, y2, z2) = q;
            let z1z1 = z1.pow(2);
            let z2z2 = z2.pow(2);
            let u1 = x1 * z2z2;
            let u2 = x2 * z1z1;
            let s1 = (y1 * z2) * z2z2;
            let s2 = (y2 * z1) * z1z1;

            if u1 == u2 {
                result = s1_equal_s2(s1, s2);
            } else {
                let h = u2 - u1;
                let i = (P256FieldElement::from_u128(2) * h).pow(2);
                let j = h * i;
                let r = P256FieldElement::from_u128(2) * (s2 - s1);
                let v = u1 * i;

                let x3_1 = P256FieldElement::from_u128(2) * v;
                let x3_2 = r.pow(2) - j;
                let x3 = x3_2 - x3_1;

                let y3_1 = (P256FieldElement::from_u128(2) * s1) * j;
                let y3_2 = r * (v - x3);
                let y3 = y3_2 - y3_1;

                let z3_ = (z1 + z2).pow(2);
                let z3 = (z3_ - (z1z1 + z2z2)) * h;
                result = Ok((x3, y3, z3));
            }
        }
    };
    result
}

fn ltr_mul(k: P256Scalar, p: P256Jacobian) -> JacobianResult {
    let mut q = (
        P256FieldElement::from_u128(0),
        P256FieldElement::from_u128(1),
        P256FieldElement::from_u128(0),
    );
    for i in 0..BITS {
        q = point_double(q);
        if k.bit(BITS - 1 - i) {
            q = point_add_jacob(q, p)?;
        }
    }
    Ok(q)
}

pub fn p256_point_mul(k: P256Scalar, p: Affine) -> AffineResult {
    let jac = ltr_mul(k, affine_to_jacobian(p))?;
    Ok(jacobian_to_affine(jac))
}

pub fn p256_point_mul_base(k: P256Scalar) -> AffineResult {
    let base_point = (
        P256FieldElement::from_be_bytes(&[
            0x6Bu8, 0x17u8, 0xD1u8, 0xF2u8, 0xE1u8, 0x2Cu8, 0x42u8, 0x47u8, 0xF8u8, 0xBCu8, 0xE6u8,
            0xE5u8, 0x63u8, 0xA4u8, 0x40u8, 0xF2u8, 0x77u8, 0x03u8, 0x7Du8, 0x81u8, 0x2Du8, 0xEBu8,
            0x33u8, 0xA0u8, 0xF4u8, 0xA1u8, 0x39u8, 0x45u8, 0xD8u8, 0x98u8, 0xC2u8, 0x96u8,
        ]),
        P256FieldElement::from_be_bytes(&[
            0x4Fu8, 0xE3u8, 0x42u8, 0xE2u8, 0xFEu8, 0x1Au8, 0x7Fu8, 0x9Bu8, 0x8Eu8, 0xE7u8, 0xEBu8,
            0x4Au8, 0x7Cu8, 0x0Fu8, 0x9Eu8, 0x16u8, 0x2Bu8, 0xCEu8, 0x33u8, 0x57u8, 0x6Bu8, 0x31u8,
            0x5Eu8, 0xCEu8, 0xCBu8, 0xB6u8, 0x40u8, 0x68u8, 0x37u8, 0xBFu8, 0x51u8, 0xF5u8,
        ]),
    );
    p256_point_mul(k, base_point)
}

fn point_add_distinct(p: Affine, q: Affine) -> AffineResult {
    let r = point_add_jacob(affine_to_jacobian(p), affine_to_jacobian(q))?;
    Ok(jacobian_to_affine(r))
}

pub fn point_add(p: P256Point, q: P256Point) -> Result<P256Point, Error> {
    match p {
        P256Point::AtInfinity => Ok(q),
        P256Point::NonInf(p) => match q {
            P256Point::AtInfinity => Ok(P256Point::AtInfinity),
            P256Point::NonInf(q) => point_add_noninf(p, q).map(|res| P256Point::NonInf(res)),
        },
    }
}

pub fn point_add_noninf(p: Affine, q: Affine) -> AffineResult {
    if p != q {
        point_add_distinct(p, q)
    } else {
        Ok(jacobian_to_affine(point_double(affine_to_jacobian(p))))
    }
}

/// Verify that k != 0 && k < ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
pub fn p256_validate_private_key(k: &[u8]) -> bool {
    let mut valid = true;
    // XXX: This should fail.
    let k_element = P256Scalar::from_be_bytes(k);
    let k_element_bytes = k_element.to_be_bytes();
    let mut all_zero = true;
    for i in 0..k.len() {
        if !k[i] == U8(0u8) {
            all_zero = false;
        }
        if !k_element_bytes[i] == k[i] {
            valid = false;
        }
    }
    valid && !all_zero
}

/// Verify that the point `p` is a valid public key.
pub fn p256_validate_public_key(p: Affine) -> bool {
    let b = P256FieldElement::from_be_bytes(&[
        0x5au8, 0xc6u8, 0x35u8, 0xd8u8, 0xaau8, 0x3au8, 0x93u8, 0xe7u8, 0xb3u8, 0xebu8, 0xbdu8,
        0x55u8, 0x76u8, 0x98u8, 0x86u8, 0xbcu8, 0x65u8, 0x1du8, 0x06u8, 0xb0u8, 0xccu8, 0x53u8,
        0xb0u8, 0xf6u8, 0x3bu8, 0xceu8, 0x3cu8, 0x3eu8, 0x27u8, 0xd2u8, 0x60u8, 0x4bu8,
    ]);
    let point_at_infinity = is_point_at_infinity(affine_to_jacobian(p));
    let (x, y) = p;
    let on_curve = y * y == x * x * x - P256FieldElement::from_u128(3) * x + b;

    !point_at_infinity && on_curve
}

// Calculate w, which is -y or +y, from x. See RFC 6090, Appendix C.
pub fn p256_calculate_w(x: P256FieldElement) -> P256FieldElement {
    let b = P256FieldElement::from_be_bytes(&[
        0x5au8, 0xc6u8, 0x35u8, 0xd8u8, 0xaau8, 0x3au8, 0x93u8, 0xe7u8, 0xb3u8, 0xebu8, 0xbdu8,
        0x55u8, 0x76u8, 0x98u8, 0x86u8, 0xbcu8, 0x65u8, 0x1du8, 0x06u8, 0xb0u8, 0xccu8, 0x53u8,
        0xb0u8, 0xf6u8, 0x3bu8, 0xceu8, 0x3cu8, 0x3eu8, 0x27u8, 0xd2u8, 0x60u8, 0x4bu8,
    ]);
    // (p+1)/4 calculated offline
    let pow = P256FieldElement::from_be_bytes(&[
        0x3fu8, 0xffu8, 0xffu8, 0xffu8, 0xc0u8, 0x00u8, 0x00u8, 0x00u8, 0x40u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x40u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
    ]);
    // w = (x^3 + a*x + b)^((p+1)/4) (mod p). [RFC6090, Appendix C]
    let z = x * x * x - P256FieldElement::from_u128(3) * x + b;
    // z to power of pow
    let w = z.pow_felem(&pow);
    w
}

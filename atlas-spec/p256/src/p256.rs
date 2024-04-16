use hacspec_lib::{hacspec_helper::*, i2osp, Randomness};
use hmac::{hkdf_expand, hkdf_extract};

#[derive(Debug)]
pub enum Error {
    InvalidAddition,
    DeserializeError,
    PointAtInfinity,
    SamplingError,
}

impl From<hacspec_lib::Error> for Error {
    fn from(_value: hacspec_lib::Error) -> Self {
        Self::SamplingError
    }
}

const BITS: u128 = 256;

#[derive(Hash, PartialOrd, Ord)]
#[nat_mod("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 32)]
pub struct P256FieldElement {}

#[nat_mod("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 32)]
pub struct P256Scalar {}

/// Generate a random P256 scalar using rejection sampling.
///
/// Inputs:
/// - `randomness`: Random bytes
/// - `dst`: Domain separation tag
///
/// Outputs:
/// - A random P256 scalar
///
/// Raises:
/// - `SamplingError`: If no valid scalar can be found within 256 sampling attempts
///
/// Panics:
/// - If the provided random bytes are insufficient
pub fn random_scalar(randomness: &mut Randomness, dst: &[u8]) -> Result<P256Scalar, Error> {
    let dkp_prk = hkdf_extract(dst, randomness.bytes(32).unwrap());

    let mut sk = P256Scalar::zero();

    for counter in 0..255 {
        let mut bytes = hkdf_expand(&dkp_prk, &i2osp(counter, 1), 32);

        bytes[0] &= 0xffu8;
        if p256_validate_private_key(&bytes) {
            sk = P256Scalar::from_be_bytes(&bytes);
        }
    }
    if sk == P256Scalar::zero() {
        Err(Error::SamplingError)
    } else {
        Ok(sk)
    }
}

pub type Affine = (P256FieldElement, P256FieldElement);
pub type AffineResult = Result<Affine, Error>;
type P256Jacobian = (P256FieldElement, P256FieldElement, P256FieldElement);
type JacobianResult = Result<P256Jacobian, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
        NatMod::neg(self)
    }
}

pub fn is_square(x: &P256FieldElement) -> bool {
    let exp = P256FieldElement::from_u128(1).neg() * P256FieldElement::from_u128(2).inv();
    let test = x.pow_felem(&exp);
    test == P256FieldElement::zero() || test == P256FieldElement::one()
}

pub fn sgn0(x: &P256FieldElement) -> bool {
    x.bit(0)
}

pub fn sqrt(x: &P256FieldElement) -> P256FieldElement {
    let c1 = P256FieldElement::one() * P256FieldElement::from_u128(4).inv();
    x.pow_felem(&c1)
}

impl std::ops::Neg for P256Point {
    type Output = P256Point;
    fn neg(self) -> Self::Output {
        match self {
            P256Point::AtInfinity => self,
            P256Point::NonInf((x, y)) => (x, NatMod::neg(y)).into(),
        }
    }
}

fn affine_to_jacobian(p: Affine) -> P256Jacobian {
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

fn point_add_jacob(p: P256Jacobian, q: P256Jacobian) -> JacobianResult {
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

pub type P256SerializedPoint = [u8; 33];

/// SerializeElement(A): Implemented using the compressed Elliptic-
///     Curve-Point-to-Octet-String method according to [SEC1]; Ne =
///     33.
///
pub fn serialize_point(p: &P256Point) -> P256SerializedPoint {
    let mut out = [0u8; 33];
    match p {
        P256Point::AtInfinity => out,
        P256Point::NonInf((x, y)) => {
            let x_serialized = x.to_be_bytes();

            for (to, from) in out.iter_mut().skip(1).zip(x_serialized.iter()) {
                *to = *from
            }
            out[0] = if y.bit(0) { 3 } else { 2 };

            out
        }
    }
}
impl P256Point {
    pub fn raw_bytes(&self) -> [u8; 64] {
        match self {
            P256Point::NonInf((x, y)) => {
                let mut out = [0u8; 64];
                out[0..32].copy_from_slice(&x.to_be_bytes());
                out[32..64].copy_from_slice(&y.to_be_bytes());
                out
            }
            P256Point::AtInfinity => panic!("Tried to serialize point at infitiy"),
        }
    }

    pub fn from_raw_bytes(bytes: [u8; 64]) -> Result<P256Point, Error> {
        let x = P256FieldElement::from_be_bytes(&bytes[0..32]);
        let y = P256FieldElement::from_be_bytes(&bytes[32..64]);
        let candidate = P256Point::NonInf((x, y));
        if p256_validate_public_key(candidate) {
            Ok(candidate)
        } else {
            Err(Error::DeserializeError)
        }
    }

    pub fn x(&self) -> Result<P256FieldElement, Error> {
        match self {
            P256Point::NonInf((x, _)) => Ok(*x),
            P256Point::AtInfinity => Err(Error::PointAtInfinity),
        }
    }
    pub fn y(&self) -> Result<P256FieldElement, Error> {
        match self {
            P256Point::NonInf((_, y)) => Ok(*y),
            P256Point::AtInfinity => Err(Error::PointAtInfinity),
        }
    }
}

#[allow(unused)]
pub fn deserialize_point(pm: P256SerializedPoint) -> Result<P256Point, Error> {
    if pm == [0u8; 33] {
        return Err(Error::DeserializeError);
    }

    let x = P256FieldElement::from_be_bytes(&pm[1..33]);

    let ym = pm[0];
    let yp_sign: bool = match ym {
        0x02 => false,
        0x03 => true,
        _ => return Err(Error::DeserializeError),
    };

    let a = P256FieldElement::from_u128(3u128).neg();
    let b = P256FieldElement::from_hex(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    );

    let alpha = x.pow(3) + a * x + b;
    let beta = sqrt(&alpha);

    let y: P256FieldElement = if beta.bit(0) == yp_sign {
        beta
    } else {
        beta.neg()
    };

    Ok((x, y).into())
}

pub fn p256_point_mul(k: P256Scalar, p: P256Point) -> Result<P256Point, Error> {
    let jac = ltr_mul(k, affine_to_jacobian(p.into()))?;
    Ok(jacobian_to_affine(jac).into())
}

pub fn p256_point_mul_base(k: P256Scalar) -> Result<P256Point, Error> {
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
    )
        .into();
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
            P256Point::NonInf(q) => point_add_noninf(p, q).map(P256Point::NonInf),
        },
    }
}

fn point_add_noninf(p: Affine, q: Affine) -> AffineResult {
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
pub fn p256_validate_public_key(p: P256Point) -> bool {
    let b = P256FieldElement::from_be_bytes(&[
        0x5au8, 0xc6u8, 0x35u8, 0xd8u8, 0xaau8, 0x3au8, 0x93u8, 0xe7u8, 0xb3u8, 0xebu8, 0xbdu8,
        0x55u8, 0x76u8, 0x98u8, 0x86u8, 0xbcu8, 0x65u8, 0x1du8, 0x06u8, 0xb0u8, 0xccu8, 0x53u8,
        0xb0u8, 0xf6u8, 0x3bu8, 0xceu8, 0x3cu8, 0x3eu8, 0x27u8, 0xd2u8, 0x60u8, 0x4bu8,
    ]);
    let point_at_infinity = is_point_at_infinity(affine_to_jacobian(p.into()));
    let (x, y) = p.into();
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
    z.pow_felem(&pow)
}

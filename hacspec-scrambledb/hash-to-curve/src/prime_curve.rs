use crate::Error;
use p256::NatMod;

pub trait FieldArithmetic {
    fn is_square(&self) -> bool;
    fn sqrt(self) -> Self;
    fn sgn0(self) -> bool;
    fn inv(self) -> Self;
    fn inv0(self) -> Self;
    fn pow(self, rhs: u128) -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u128(x: u128) -> Self;
}

pub trait PrimeField<const LEN: usize>: NatMod<{ LEN }> {
    fn is_square(&self) -> bool;
    fn sqrt(self) -> Self;

    // TODO: Also include other cases
    /// When m == 1, sgn0 can be significantly simplified:
    ///
    ///```text
    /// sgn0_m_eq_1(x)
    ///
    /// Input: x, an element of GF(p).
    /// Output: 0 or 1.
    ///
    /// Steps:
    /// 1. return x mod 2
    /// ```
    fn sgn0(self) -> bool;
    // fn hash_to_field_prime_order(count: usize, l: usize, uniform_bytes: Vec<u8>) -> Vec<Self>
    // where
    //     Self: Sized;
}

pub trait PrimeCurve: Sized {
    type BaseField;

    fn clear_cofactor(self) -> (Self::BaseField, Self::BaseField);
    fn point_add(lhs: Self, rhs: Self) -> Result<(Self::BaseField, Self::BaseField), Error>;
}

pub trait Constructor<const LEN: usize, Fp: PrimeField<{ LEN }>> {
    fn from_coeffs(v: Vec<Fp>) -> Self;
}

// I^2 + 1 = 0 in F
/// ## I.5. is_square for F = GF(p^2)
///
/// The following `is_square` method applies to any field F = GF(p^2) with
/// basis (1, I) represented as described in Section 2.1, i.e., an element
/// x = (x_1, x_2) = x_1 + x_2 * I.  Other optimizations of this type are
/// possible in other extension fields; see, e.g., [AR13] for more
/// information.
///
/// ``` text
/// is_square(x)
///
/// Parameters:
/// - F, an extension field of characteristic p and order q = p^2
///   with basis (1, I).
///
/// Input: x, an element of F.
/// Output: True if x is square in F, and False otherwise.
///
/// Constants:
/// 1. c1 = (p - 1) / 2         # Integer arithmetic
///
/// Procedure:
/// 1. tv1 = x_1^2
/// 2. tv2 = I * x_2
/// 3. tv2 = tv2^2
/// 4. tv1 = tv1 - tv2
/// 5. tv1 = tv1^c1
/// 6.  e1 = tv1 != -1          # Note: -1 in F
/// 7. return e1
/// ```
#[allow(non_snake_case)]
pub fn is_square_m_eq_2<T: NatMod<{ LEN }>, const LEN: usize>(x: &(T, T), I: &T) -> bool
where
    T: PartialEq<T> + std::ops::Mul<T, Output = T> + std::ops::Sub<T, Output = T> + Copy,
{
    let (x_1, x_2) = x;
    let c1 = T::from_u128(1).neg() * T::from_u128(2).inv();

    let tv1 = x_1.pow(2);
    let tv2 = *x_2 * *I;
    let tv2 = tv2.pow(2);
    let tv1 = tv1 - tv2;
    let tv1 = tv1.pow_felem(&c1);
    tv1 != T::one().inv()
}

pub fn is_square_m_eq_1<T: NatMod<{ LEN }>, const LEN: usize>(x: &T) -> bool
where
    T: PartialEq<T> + std::ops::Mul<T, Output = T> + Copy,
{
    let exp = T::from_u128(1).neg() * T::from_u128(2).inv();
    let test = x.pow_felem(&exp);
    test == T::zero() || test == T::one()
}

/// Input: x, an element of F.
/// Output: z, an element of F such that (z^2) == x, if x is square in F.
///
///
/// 1. c1 = (q + 1) / 4
/// 2. return x^c1
pub fn sqrt_3mod4_m_eq_1<T: NatMod<{ LEN }>, const LEN: usize>(x: &T) -> T
where
    T: PartialEq<T> + std::ops::Mul<T, Output = T> + Copy,
{
    let c1 = T::one() * T::from_u128(4).inv();
    x.pow_felem(&c1)
}

// TODO!
pub fn sqrt_3mod4_m_eq_2<T: NatMod<{ LEN }>, const LEN: usize>(_x: &(T, T)) -> (T, T) {
    unimplemented!()
}

// XXX: The proposed suites only have the case q = 3 mod 4 and m = 1 for everything except BLS12-381 G2 where m = 2.
pub fn sqrt_3mod4_generic<T: NatMod<{ LEN }>, const LEN: usize>(_x: Vec<T>, _m: usize) -> Vec<T> {
    unimplemented!()
}
pub fn sqrt_5mod8_generic<T: NatMod<{ LEN }>, const LEN: usize>(_x: Vec<T>, _m: usize) -> Vec<T> {
    unimplemented!()
}
pub fn sqrt_9mod16_generic<T: NatMod<{ LEN }>, const LEN: usize>(_x: Vec<T>, _m: usize) -> Vec<T> {
    unimplemented!()
}

///  I.4. Constant-time Tonelli-Shanks algorithm
///
/// This algorithm is a constant-time version of the classic Tonelli-Shanks algorithm
/// ([C93], Algorithm 1.5.1) due to Sean Bowe, Jack Grigg, and Eirik Ogilvie-Wigley
/// [jubjub-fq], adapted and optimized by Michael Scott.
/// This algorithm applies to GF(p) for any p. Note, however, that the
/// special-purpose algorithms given in the prior sections are faster, when they
/// apply.
pub fn sqrt_ts_ct<T: NatMod<{ LEN }>, const LEN: usize>(_x: Vec<T>, _m: usize) -> Vec<T> {
    todo!()
}

// XXX: All the spec ever does with this function's output is
// comparisons, yet it gives the output range as {0,1}. Stick to spec
// here or output a bool instead?
/// # 4.1.  The sgn0 function
///
/// This section defines a generic sgn0 implementation that applies to
/// any field F = GF(p^m).  It also gives simplified implementations for
/// the cases F = GF(p) and F = GF(p^2).
///
/// The definition of the sgn0 function for extension fields relies on
/// the polynomial basis or vector representation of field elements, and
/// iterates over the entire vector representation of the input element.
/// As a result, sgn0 depends on the primitive polynomial used to define
/// the polynomial basis; see Section 8 for more information about this
/// basis, and see Section 2.1 for a discussion of representing elements
/// of extension fields as vectors.
///
/// ``` text
/// sgn0(x)
///
/// Parameters:
/// - F, a finite field of characteristic p and order q = p^m.
/// - p, the characteristic of F (see immediately above).
/// - m, the extension degree of F, m >= 1 (see immediately above).
///
/// Input: x, an element of F.
/// Output: 0 or 1.
///
/// Steps:
/// 1. sign = 0
/// 2. zero = 1
/// 3. for i in (1, 2, ..., m):
/// 4.   sign_i = x_i mod 2
/// 5.   zero_i = x_i == 0
/// 6.   sign = sign OR (zero AND sign_i) # Avoid short-circuit logic ops
/// 7.   zero = zero AND zero_i
/// 8. return sign
/// ```
pub fn sgn0_generic<T: NatMod<{ LEN }> + PartialEq, const LEN: usize>(x: Vec<T>, m: usize) -> bool {
    let mut sign = false;
    let mut zero = true;
    for i in 1..=m {
        let x_i = x.get(i - 1).unwrap();
        let sign_i = x_i.bit(0);
        let zero_i = *x_i == T::zero();
        sign = sign || (zero && sign_i); // TODO: Avoid short-circuit logic ops
        zero = zero && zero_i;
    }
    sign
}

/// When m == 1, sgn0 can be significantly simplified:
///
/// ``` text
/// sgn0_m_eq_1(x)
///
/// Input: x, an element of GF(p).
/// Output: 0 or 1.
///
/// Steps:
/// 1. return x mod 2
/// ```
pub fn sgn0_m_eq_1<T: NatMod<{ LEN }>, const LEN: usize>(x: T) -> bool {
    x.bit(0)
}

/// The case m == 2 is only slightly more complicated:
///
/// ``` text
/// sgn0_m_eq_2(x)
///
/// Input: x, an element of GF(p^2).
/// Output: 0 or 1.
///
/// Steps:
/// 1. sign_0 = x_0 mod 2
/// 2. zero_0 = x_0 == 0
/// 3. sign_1 = x_1 mod 2
/// 4. s = sign_0 OR (zero_0 AND sign_1) # Avoid short-circuit logic ops
/// 5. return s
/// ```
pub fn sgn0_m_eq_2<T: NatMod<{ LEN }> + PartialEq, const LEN: usize>(x: &(T, T)) -> bool {
    let (x_0, x_1) = x;
    let sign_0 = x_0.bit(0);
    let zero_0 = *x_0 == T::zero();
    let sign_1 = x_1.bit(0);
    sign_0 || (zero_0 && sign_1) // TODO: Avoid short-circuit logic ops
}

// pub trait MapToCurve<const LEN: usize> {
//     type BaseField: PrimeField<{ LEN }>;

//     fn map_to_curve(fe: &Self::BaseField) -> Self;
// }

pub trait MapToCurve {
    type TargetCurve;

    fn map_to_curve(self) -> Self::TargetCurve;
}

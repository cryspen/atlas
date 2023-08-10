use p256::NatMod;

use crate::expand_message;

use crate::prime_curve::PrimeField;
use crate::Error;

pub trait Ciphersuite {
    /// The SuiteID.
    const ID: &'static str;

    /// The target security level of the suite in bits.
    const K: usize;

    /// The length parameter for [hash_to_field](HashToCurveSuite::hash_to_field).
    const L: usize;

    /// The extension degree of the base field.
    const M: usize;

    /// A point type for an elliptic curve over the [base field](HashToCurveSuite::BaseField).
    type OutputCurve;

    /// A field of prime characteristic p ≠ 2.
    type BaseField;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, Error>;
}

/// encode_to_curve is a nonuniform encoding from byte strings to points in G. That is, the distribution of its output is not uniformly random in G: the set of possible outputs of encode_to_curve is only a fraction of the points in G, and some points in this set are more likely to be output than others. Section 10.4 gives a more precise definition of encode_to_curve's output distribution.
pub trait EncodeToCurve: Ciphersuite {
    fn encode_to_curve(msg: &[u8], dst: &[u8])
        -> Result<(Self::BaseField, Self::BaseField), Error>;
}

/// # 5.  Hashing to a finite field
///
/// The hash_to_field function hashes a byte string msg of arbitrary
/// length into one or more elements of a field F.  This function works
/// in two steps: it first hashes the input byte string to produce a
/// uniformly random byte string, and then interprets this byte string as
/// one or more elements of F.
///
/// For the first step, hash_to_field calls an auxiliary function
/// expand_message.  This document defines two variants of
/// expand_message: one appropriate for hash functions like SHA-2
/// [FIPS180-4] or SHA-3 [FIPS202], and another appropriate for
/// extendable-output functions such as SHAKE128 [FIPS202].  Security
/// considerations for each expand_message variant are discussed below
/// (Section 5.3.1, Section 5.3.2).
///
/// Implementors MUST NOT use rejection sampling to generate a uniformly
/// random element of F, to ensure that the hash_to_field function is
/// amenable to constant-time implementation.  The reason is that
/// rejection sampling procedures are difficult to implement in constant
/// time, and later well-meaning "optimizations" may silently render an
/// implementation non-constant-time.  This means that any hash_to_field
/// function based on rejection sampling would be incompatible with
/// constant-time implementation.
///
/// The hash_to_field function is also suitable for securely hashing to
/// scalars.  For example, when hashing to the scalar field for an
/// elliptic curve (sub)group with prime order r, it suffices to
/// instantiate hash_to_field with target field GF(r).
///
/// The hash_to_field function is designed to be indifferentiable from a
/// random oracle [MRH04] when expand_message (Section 5.3) is modeled as
/// a random oracle (see Section 10.5 for details about its
/// indifferentiability).  Ensuring indifferentiability requires care; to
/// see why, consider a prime p that is close to 3/4 * 2^256.  Reducing a
/// random 256-bit integer modulo this p yields a value that is in the
/// range [0, p / 3] with probability roughly 1/2, meaning that this
/// value is statistically far from uniform in [0, p - 1].
///
/// To control bias, hash_to_field instead uses random integers whose
/// length is at least ceil(log2(p)) + k bits, where k is the target
/// security level for the suite in bits.  Reducing such integers mod p
/// gives bias at most 2^-k for any p; this bias is appropriate when
/// targeting k-bit security.  For each such integer, hash_to_field uses
/// expand_message to obtain L uniform bytes, where
///
/// L = ceil((ceil(log2(p)) + k) / 8)
///
/// These uniform bytes are then interpreted as an integer via OS2IP.
/// For example, for a 255-bit prime p, and k = 128-bit security, L =
/// ceil((255 + 128) / 8) = 48 bytes.
///
/// Note that k is an upper bound on the security level for the
/// corresponding curve.  See Section 10.8 for more details, and
/// Section 8.9 for guidelines on choosing k for a given curve.
///
/// ## 5.1.  Efficiency considerations in extension fields
///
/// The hash_to_field function described in this section is inefficient
/// for certain extension fields.  Specifically, when hashing to an
/// element of the extension field GF(p^m), hash_to_field requires
/// expanding msg into m * L bytes (for L as defined above).  For
/// extension fields where log2(p) is significantly smaller than the
/// security level k, this approach is inefficient: it requires
/// expand_message to output roughly m * log2(p) + m * k bits, whereas m
/// * log2(p) + k bytes suffices to generate an element of GF(p^m) with
/// bias at most 2^-k.  In such cases, applications MAY use an
/// alternative hash_to_field function, provided it meets the following
/// security requirements:
///
/// *  The function MUST output field element(s) that are uniformly
///    random except with bias at most 2^-k.
///
/// *  The function MUST NOT use rejection sampling.
///
/// *  The function SHOULD be amenable to straight line implementations.
///
/// For example, Pornin [P20] describes a method for hashing to
/// GF(9767^19) that meets these requirements while using fewer output
/// bits from expand_message than hash_to_field would for that field.
///
pub trait HashToField: Ciphersuite {
    fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<Self::BaseField>, Error>;
}

/// A trait collecting information about a given `hash-to-curve`
/// suite.
///
/// NOTE: At the moment, the following restrictions apply:
///
/// * Curve must be over a prime order field.
/// * Suite must specify uniform output encoding.
///
pub trait HashToCurve: Ciphersuite {
    /// `hash_to_curve` is a uniform encoding from byte strings to points in
    /// G.  That is, the distribution of its output is statistically close
    /// to uniform in G.
    ///
    /// This function is suitable for most applications requiring a random
    /// oracle returning points in G, when instantiated with any of the
    /// map_to_curve functions described in Section 6.  See Section 10.1
    /// for further discussion.
    ///
    /// ``` text
    ///       hash_to_curve(msg)
    ///
    ///       Input: msg, an arbitrary-length byte string.
    ///       Output: P, a point in G.
    /// ```
    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<(Self::BaseField, Self::BaseField), Error>;
}

// trait Curve{
//     fn hash_to_field();
//     fn map_to_curve();
//     fn clear_cofactor();
// }
// struct Point{}

// fn map_to_curve(fe: &P256Point) -> _ {
//     crate::mappings::map_to_curve_simple_swu(
//         &fe,
//         &<P256FieldElement as FieldArithmetic>::from_u128(3u128).neg(),
//         &P256FieldElement::from_hex(
//             "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
//         ),
//         <P256FieldElement as FieldArithmetic>::from_u128(10u128).neg(),
//     )
// }

// /// hash_to_curve(msg)
// ///
// /// Input: msg, an arbitrary-length byte string.
// /// Output: P, a point in G.
// ///
// /// Steps:
// /// 1. u = hash_to_field(msg, 2)
// /// 2. Q0 = map_to_curve(u[0])
// /// 3. Q1 = map_to_curve(u[1])
// /// 4. R = Q0 + Q1              # Point addition
// /// 5. P = clear_cofactor(R)
// /// 6. return P
// fn p256_sha256_hash_to_curve(
//     msg: &[u8],
//     dst: &[u8],
// ) -> Result<P256Point, Error> {
//     let u = hash_to_field(
//         ExpandMessageType::P256_SHA256,
//         msg,
//         dst,
//         2,
//         48,
//         1,
//     )?;
//     let q0 = u[0].map_to_curve();
//     let q1 = u[1].map_to_curve();
//     let r = p256::point_add(q0, q1)?;
//     Ok(r)
// }

/// ## 5.2.  hash_to_field implementation
///
/// The following procedure implements hash_to_field.
///
/// The expand_message parameter to this function MUST conform to the
/// requirements given in Section 5.3.  Section 3.1 discusses the
/// REQUIRED method for constructing DST, the domain separation tag.
/// Note that hash_to_field may fail (abort) if expand_message fails.
///
/// hash_to_field(msg, count)
///
/// Parameters:
/// - DST, a domain separation tag (see Section 3.1).
/// - F, a finite field of characteristic p and order q = p^m.
/// - p, the characteristic of F (see immediately above).
/// - m, the extension degree of F, m >= 1 (see immediately above).
/// - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
///   parameter of the suite (e.g., k = 128).
/// - expand_message, a function that expands a byte string and
///   domain separation tag into a uniformly random byte string
///   (see Section 5.3).
///
/// ```text
/// Inputs:
/// - msg, a byte string containing the message to hash.
/// - count, the number of elements of F to output.
///
/// Outputs:
/// - (u_0, ..., u_(count - 1)), a list of field elements.
///
/// Steps:
/// 1. len_in_bytes = count * m * L
/// 2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
/// 3. for i in (0, ..., count - 1):
/// 4.   for j in (0, ..., m - 1):
/// 5.     elm_offset = L * (j + i * m)
/// 6.     tv = substr(uniform_bytes, elm_offset, L)
/// 7.     e_j = OS2IP(tv) mod p
/// 8.   u_i = (e_0, ..., e_(m - 1))
/// 9. return (u_0, ..., u_(count - 1))
///```
pub fn hash_to_field<const LEN: usize, Fp: NatMod<{ LEN }>>(
    expand_message_type: crate::ExpandMessageType,
    msg: &[u8],
    dst: &[u8],
    count: usize,
    l: usize,
    m: usize,
) -> Result<Vec<Vec<Fp>>, Error> {
    let len_in_bytes = count * m * l;
    let uniform_bytes = expand_message(expand_message_type, msg, dst, len_in_bytes)?;
    let mut u_i = Vec::new();
    for i in 0..count {
        let mut e_j = Vec::new();
        for j in 0..m {
            let elm_offset = l * (j + i * m);
            let tv = &uniform_bytes[elm_offset..elm_offset + l];
            e_j.push(Fp::from_be_bytes(tv))
        }
        u_i.push(e_j)
    }
    Ok(u_i)
}

// // XXX: This is a specialization of the generic function given in the draft.
pub fn hash_to_field_m_eq_1<const LEN: usize, Fp: PrimeField<{ LEN }>>(
    msg: &[u8],
    dst: &[u8],
    count: usize,
    l: usize,
    expand_message: fn(&[u8], &[u8], usize) -> Result<Vec<u8>, Error>,
) -> Result<Vec<Fp>, Error> {
    let len_in_bytes = count * l;
    let uniform_bytes = expand_message(msg, dst, len_in_bytes)?;
    let mut u = Vec::with_capacity(count);
    for i in 0..count {
        // m = 1
        let elm_offset = l * i;
        let tv = &uniform_bytes[elm_offset..l * (i + 1)];
        let tv = Fp::from_be_bytes(tv);
        u.push(tv);
    }
    Ok(u)
}

// XXX: This is a specialization of the generic function given in the draft.
pub fn hash_to_field_m_eq_2<const LEN: usize, Fp: PrimeField<{ LEN }>>(
    msg: &[u8],
    dst: &[u8],
    count: usize,
    l: usize,
    expand_message: fn(&[u8], &[u8], usize) -> Result<Vec<u8>, Error>,
) -> Result<Vec<(Fp, Fp)>, Error> {
    let len_in_bytes = count * l * 2;
    let uniform_bytes = expand_message(msg, dst, len_in_bytes)?;
    let mut u = Vec::with_capacity(count);
    for i in 0..count {
        // unrolled two loop over j in {0,1}
        let elm_offset0 = l * i * 2;
        let tv0 = &uniform_bytes[elm_offset0..elm_offset0 + l];
        let e0 = Fp::from_be_bytes(tv0);

        let elm_offset1 = l + l * i * 2;
        let tv1 = &uniform_bytes[elm_offset1..elm_offset1 + l];
        let e1 = Fp::from_be_bytes(tv1);

        u.push((e0, e1));
    }
    Ok(u)
}

//! ## 2.1.  Prime-Order Group
//!
//! In this document, we assume the construction of an additive, prime-
//! order group Group for performing all mathematical operations.  In
//! prime-order groups, any element (other than the identity) can
//! generate the other elements of the group.  Usually, one element is
//! fixed and defined as the group generator.  Such groups are uniquely
//! determined by the choice of the prime p that defines the order of the
//! group.  (There may, however, exist different representations of the
//! group for a single p.  Section 4 lists specific groups which indicate
//! both order and representation.)
//!
//! The fundamental group operation is addition + with identity element
//! I.  For any elements A and B of the group, A + B = B + A is also a
//! member of the group.  Also, for any A in the group, there exists an
//! element -A such that A + (-A) = (-A) + A = I.  Scalar multiplication
//! by r is equivalent to the repeated application of the group operation
//! on an element A with itself r-1 times, this is denoted as r*A = A +
//! ... + A.  For any element A, p*A=I.  The case when the scalar
//! multiplication is performed on the group generator is denoted as
//! ScalarMultGen(r).  Given two elements A and B, the discrete logarithm
//! problem is to find an integer k such that B = k*A.  Thus, k is the
//! discrete logarithm of B with respect to the base A.  The set of
//! scalars corresponds to GF(p), a prime field of order p, and are
//! represented as the set of integers defined by {0, 1, ..., p-1}. This
//! document uses types Element and Scalar to denote elements of the
//! group and its set of scalars, respectively.

use crate::Error;

/// We now detail a number of member functions that can be invoked on a
/// prime-order group.
///
/// Section 4 contains details for the implementation of this interface
/// for different prime-order groups instantiated over elliptic curves.
/// In particular, for some choices of elliptic curves, e.g., those
/// detailed in [RFC7748], which require accounting for cofactors,
/// Section 4 describes required steps necessary to ensure the resulting
/// group is of prime order.
pub trait PrimeOrderGroup {
    type Scalar;

     /// *  Order(): Outputs the order of the group (i.e. p).
    fn order();


    /// *  Identity(): Outputs the identity element of the group (i.e.  I).
    fn identity() -> Self;

    /// *  Generator(): Outputs the generator element of the group.
    fn generator() -> Self;

    /// *  HashToGroup(x): Deterministically maps an array of bytes x to an
    ///    element of Group.  The map must ensure that, for any adversary
    ///    receiving R = HashToGroup(x), it is computationally difficult to
    ///    reverse the mapping.  This function is optionally parameterized by
    ///    a domain separation tag (DST); see Section 4.  Security properties
    ///    of this function are described in [I-D.irtf-cfrg-hash-to-curve].
    fn hash_to_group(bytes: &[u8]) -> Self;

    /// *  HashToScalar(x): Deterministically maps an array of bytes x to an
    ///    element in GF(p).  This function is optionally parameterized by a
    ///    DST; see Section 4.  Security properties of this function are
    ///    described in [I-D.irtf-cfrg-hash-to-curve], Section 10.5.
    fn hash_to_scalar(bytes: &[u8]) -> Self::Scalar;

    /// *  RandomScalar(): Chooses at random a non-zero element in GF(p).
    fn random_scalar() -> Self::Scalar;

    /// *  ScalarInverse(s): Returns the inverse of input Scalar s on GF(p).
    fn scalar_inverse(scalar: Self::Scalar) -> Self::Scalar;

    /// *  SerializeElement(A): Maps an Element A to a canonical byte array
    ///    buf of fixed length Ne.
    fn serialize_element(self) -> Vec<u8>;

    /// *  DeserializeElement(buf): Attempts to map a byte array buf to an
    ///    Element A, and fails if the input is not the valid canonical byte
    ///    representation of an element of the group.  This function can
    ///    raise a DeserializeError if deserialization fails or A is the
    ///    identity element of the group; see Section 4 for group-specific
    ///    input validation steps.
    fn deserialize_element(bytes: &[u8]) -> Result<Self, Error>
	where Self: Sized;

    /// *  SerializeScalar(s): Maps a Scalar s to a canonical byte array buf
    ///    of fixed length Ns.
    fn serialize_scalar(scalar: Self::Scalar) -> Vec<u8>;

    /// *  DeserializeScalar(buf): Attempts to map a byte array buf to a
    ///    Scalar s.  This function can raise a DeserializeError if
    ///    deserialization fails; see Section 4 for group-specific input
    ///    valid``ation steps.
    fn deserialize_scalar(bytes: &[u8]) -> Result<Self::Scalar, Error>;
}

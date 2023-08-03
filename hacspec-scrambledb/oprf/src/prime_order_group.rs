//! # 2. Preliminaries
//!
//! The protocols in this document have two primary dependencies:
//! * Group: A prime-order group implementing the API described below in
//!   Section 2.1. See Section 4 for specific instances of groups.
//! * Hash: A cryptographic hash function whose output length is Nh bytes.
//!   Section 4 specifies ciphersuites as combinations of Group and Hash.
//!
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
//! We now detail a number of member functions that can be invoked on a
//! prime-order group.
//!
//! Section 4 contains details for the implementation of this interface
//! for different prime-order groups instantiated over elliptic curves.
//! In particular, for some choices of elliptic curves, e.g., those
//! detailed in [RFC7748], which require accounting for cofactors,
//! Section 4 describes required steps necessary to ensure the resulting
//! group is of prime order.

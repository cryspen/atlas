//! # 6. Deterministic mappings
//!
//! The mappings in this section are suitable for implementing either
//! nonuniform or uniform encodings using the constructions in
//! Section 3. Certain mappings restrict the form of the curve or its
//! parameters. For each mapping presented, this document lists the
//! relevant restrictions.  Note that mappings in this section are not
//! interchangeable: different mappings will almost certainly output
//! different points when evaluated on the same input.  6.1. Choosing a
//! mapping function
//!
//! This section gives brief guidelines on choosing a mapping function for
//! a given elliptic curve. Note that the suites given in Section 8 are
//! recommended mappings for the respective curves.  If the target
//! elliptic curve is a Montgomery curve (Section 6.7), the Elligator 2
//! method (Section 6.7.1) is recommended. Similarly, if the target
//! elliptic curve is a twisted Edwards curve (Section 6.8), the twisted
//! Edwards Elligator 2 method (Section 6.8.2) is recommended.The
//! remaining cases are Weierstrass curves. For curves supported by the
//! Simplified SWU method (Section 6.6.2), that mapping is the recommended
//! one. Otherwise, the Simplified SWU method for AB == 0 (Section 6.6.3)
//! is recommended if the goal is best performance, while the Shallue-van
//! de Woestijne method (Section 6.6.1) is recommended if the goal is
//! simplicity of implementation. (The reason for this distinction is that
//! the Simplified SWU method for AB == 0 requires implementing an isogeny
//! map in addition to the mapping function, while the Shallue-van de
//! Woestijne method does not.)The Shallue-van de Woestijne method
//! (Section 6.6.1) works with any curve, and may be used in cases where a
//! generic mapping is required. Note, however, that this mapping is
//! almost always more computationally expensive than the curve-specific
//! recommendations above.  6.2. Interface
//!
//! The generic interface shared by all mappings in this section is as
//! follows:
//!
//! ``` text
//! (x, y) = map_to_curve(u)
//! ```
//!
//! The input u and outputs x and y are elements of the field F. The
//! affine coordinates (x, y) specify a point on an elliptic curve defined
//! over F. Note, however, that the point (x, y) is not a uniformly random
//! point.  6.3. Notation
//!
//! As a rough guide, the following conventions are used in pseudocode:
//! All arithmetic operations are performed over a field F, unless
//! explicitly stated otherwise.  u: the input to the mapping
//! function. This is an element of F produced by the hash_to_field
//! function.(x, y), (s, t), (v, w): the affine coordinates of the point
//! output by the mapping. Indexed variables (e.g., x1, y2, ...) are used
//! for candidate values.tv1, tv2, ...: reusable temporary variables.c1,
//! c2, ...: constant values, which can be computed in advance.  6.4. Sign
//! of the resulting point
//!
//! In general, elliptic curves have equations of the form y^2 = g(x). The
//! mappings in this section first identify an x such that g(x) is square,
//! then take a square root to find y. Since there are two square roots
//! when g(x) != 0, this may result in an ambiguity regarding the sign of
//! y.  When necessary, the mappings in this section resolve this
//! ambiguity by specifying the sign of the y-coordinate in terms of the
//! input to the mapping function. Two main reasons support this approach:
//! first, this covers elliptic curves over any field in a uniform way,
//! and second, it gives implementors leeway in optimizing square-root
//! implementations.  6.5. Exceptional cases
//!
//! Mappings may have exceptional cases, i.e., inputs u on which the
//! mapping is undefined. These cases must be handled carefully,
//! especially for constant-time implementations.  For each mapping in
//! this section, we discuss the exceptional cases and show how to handle
//! them in constant time. Note that all implementations SHOULD use inv0
//! (Section 4) to compute multiplicative inverses, to avoid exceptional
//! cases that result from attempting to compute the inverse of 0.

use crate::prime_curve::PrimeField;

/// 6.6. Mappings for Weierstrass curves
///
/// The mappings in this section apply to a target curve E defined by the
/// equation
///
/// ``` text
/// y^2 = g(x) = x^3 + A * x + B
/// ```
///
/// where 4 * A^3 + 27 * B^2 != 0.

pub fn sw_m_eq_1() {
    unimplemented!()
}

/// ### 6.6.2. Simplified Shallue-van de Woestijne-Ulas method
///
/// The function map_to_curve_simple_swu(u) implements a simplification of
/// the Shallue-van de Woestijne-Ulas mapping [U07] described by Brier et
/// al. [BCIMRT10], which they call the "simplified SWU" map. Wahby and
/// Boneh [WB19] generalize and optimize this mapping.  Preconditions: A
/// Weierstrass curve y^2 = x^3 + A * x + B where A != 0 and B != 0.
///
/// Constants:
/// * A and B, the parameters of the Weierstrass curve.
///
/// * Z, an element of F meeting the below criteria. Appendix H.2 gives a
///   Sage [SAGE] script that outputs the RECOMMENDED Z. The criteria are:
///   * Z is non-square in F,
///   * Z != -1 in F
///   * the polynomial g(x) - Z is irreducible over F, and
///   * g(B / (Z * A)) is square in F.
///
/// Sign of y: Inputs u and -u give the same x-coordinate. Thus, we set
/// sgn0(y) == sgn0(u).
///
/// Exceptions: The exceptional cases are values of u
/// such that Z^2 * u^4 + Z * u^2 == 0. This includes u == 0, and may
/// include other values depending on Z. Implementations must detect this
/// case and set x1 = B / (Z * A), which guarantees that g(x1) is square
/// by the condition on Z given above.
///
/// Operations:
///
/// 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
/// 2.  x1 = (-B / A) * (1 + tv1)
/// 3.  If tv1 == 0, set x1 = B / (Z * A)
/// 4. gx1 = x1^3 + A * x1 + B
/// 5.  x2 = Z * u^2 * x1
/// 6. gx2 = x2^3 + A * x2 + B
/// 7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
/// 8.  Else set x = x2 and y = sqrt(gx2)
/// 9.  If sgn0(u) != sgn0(y), set y = -y
/// 10. return (x, y)
///
/// Appendix F.2 gives a general and optimized straight-line
/// implementation of this mapping. For more information on optimizing
/// this mapping, see [WB19] Section 4 or the example code found at
/// [hash2curve-repo].
pub fn sswu_m_eq_1<const LEN: usize, Fp: PrimeField<{ LEN }>>(
    u: &Fp,
    a: &Fp,
    b: &Fp,
    z: Fp,
) -> (Fp, Fp)
where
    Fp: std::ops::Mul<Fp, Output = Fp> + std::ops::Add<Fp, Output = Fp> + PartialEq + Copy,
{
    let tv1 = (z.pow(2) * u.pow(4) + z * u.pow(2)).inv0();
    let x1 = if tv1 == Fp::zero() {
        *b * (z * *a).inv()
    } else {
        (b.neg() * a.inv()) * (tv1 + Fp::from_u128(1u128))
    };

    let gx1 = x1.pow(3) + (*a) * x1 + (*b);
    let x2 = z * u.pow(2) * x1;
    let gx2 = x2.pow(3) + *a * x2 + *b;

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

#[allow(unused)]
pub fn sswu_m_eq_2<const LEN: usize, Fp: PrimeField<{ LEN }>>(
    u: &(Fp, Fp),
    a: &(Fp, Fp),
    b: &(Fp, Fp),
    z: (Fp, Fp),
) -> ((Fp, Fp), (Fp, Fp))
where
    Fp: std::ops::Mul<Fp, Output = Fp> + std::ops::Add<Fp, Output = Fp> + PartialEq + Copy,
{
    unimplemented!()
}

/// ### 6.6.3. Simplified SWU for AB == 0
///
/// Wahby and Boneh [WB19] show how to adapt the simplified SWU mapping to
/// Weierstrass curves having A == 0 or B == 0, which the mapping of
/// Section 6.6.2 does not support. (The case A == B == 0 is excluded
/// because y^2 = x^3 is not an elliptic curve.)
///
/// This method applies to curves like secp256k1 [SEC2] and to
/// pairing-friendly curves in the Barreto-Lynn-Scott [BLS03],
/// Barreto-Naehrig [BN05], and other families.
///
/// This method requires finding another elliptic curve E' given by the
/// equation
///
/// ``` text
/// y'^2 = g'(x') = x'^3 + A' * x' + B'
/// ```
///
/// that is isogenous to E and has A' != 0 and B' != 0. (See [WB19],
/// Appendix A, for one way of finding E' using [SAGE].) This isogeny
/// defines a map iso_map(x', y') given by a pair of rational
/// functions. iso_map takes as input a point on E' and produces as output
/// a point on E.
///
/// Once E' and iso_map are identified, this mapping works as follows: on
/// input u, first apply the simplified SWU mapping to get a point on E',
/// then apply the isogeny map to that point to get a point on E.
///
/// Note that iso_map is a group homomorphism, meaning that point addition
/// commutes with iso_map. Thus, when using this mapping in the
/// hash_to_curve construction of Section 3, one can effect a small
/// optimization by first mapping u0 and u1 to E', adding the resulting
/// points on E', and then applying iso_map to the sum. This gives the
/// same result while requiring only one evaluation of iso_map.
///
/// Preconditions: An elliptic curve E' with A' != 0 and B' != 0 that is
/// isogenous to the target curve E with isogeny map iso_map from E' to E.
///
/// Helper functions:
/// * map_to_curve_simple_swu is the mapping of Section 6.6.2 to E'
/// * iso_map is the isogeny map from E' to E
///
/// Sign of y: for this map, the sign is determined by
/// map_to_curve_simple_swu. No further sign adjustments are necessary.
///
/// Exceptions: map_to_curve_simple_swu handles its exceptional
/// cases. Exceptional cases of iso_map are inputs that cause the
/// denominator of either rational function to evaluate to zero; such
/// cases MUST return the identity point on E.
///
/// Operations:
///
/// 1. (x', y') = map_to_curve_simple_swu(u)    # (x', y') is on E'
/// 2.   (x, y) = iso_map(x', y')               # (x, y) is on E
/// 3. return (x, y)
///
/// See [hash2curve-repo] or [WB19] Section 4.3 for details on
/// implementing the isogeny map.
pub fn sswu_ainvb_eq_1<const LEN: usize, Field: PrimeField<{ LEN }>>(
    u: &Field,
    isogeny_a: &Field,
    isogeny_b: &Field,
    isogeny_z: Field,
    isogeny_map: fn(Field, Field) -> (Field, Field),
) -> (Field, Field)
where
    Field: std::ops::Mul<Field, Output = Field>
        + std::ops::Add<Field, Output = Field>
        + PartialEq
        + Copy,
{
    let (x_prime, y_prime) = sswu_m_eq_1(u, isogeny_a, isogeny_b, isogeny_z);
    isogeny_map(x_prime, y_prime)
}

pub fn sswu_ainvb_eq_2<const LEN: usize, Field: PrimeField<{ LEN }>>(
    u: &(Field, Field),
    isogeny_a: &(Field, Field),
    isogeny_b: &(Field, Field),
    isogeny_z: (Field, Field),
    isogeny_map: fn((Field, Field), (Field, Field)) -> ((Field, Field), (Field, Field)),
) -> ((Field, Field), (Field, Field))
where
    Field: std::ops::Mul<Field, Output = Field>
        + std::ops::Add<Field, Output = Field>
        + PartialEq
        + Copy,
{
    let (x_prime, y_prime) = sswu_m_eq_2(u, isogeny_a, isogeny_b, isogeny_z);
    isogeny_map(x_prime, y_prime)
}

/// # 6.7 Mappings for Montgomery curves
/// The mapping defined in this section applies to a target curve M defined by the equation
///
/// ``` text
/// K * t^2 = s^3 + J * s^2 + s
/// ```

pub fn elligator2_m_eq1() {
    unimplemented!()
}

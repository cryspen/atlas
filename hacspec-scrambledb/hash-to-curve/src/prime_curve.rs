use p256::NatMod;
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
    fn hash_to_field_prime_order(count: usize, l: usize, uniform_bytes: Vec<u8>) -> Vec<Self>
    where
        Self: Sized;
}

pub trait MapToCurve<const LEN: usize> {
    type BaseField: PrimeField<{LEN}>;

    fn map_to_curve(fe: &Self::BaseField) -> Self;
    fn clear_cofactor(self) -> Self;
}
// For instance P256
pub trait MapToCurveWeierstrass<const LEN: usize>: MapToCurve<{LEN}> {
    fn weierstrass_a() -> Self::BaseField;
    fn weierstrass_b() -> Self::BaseField;
    fn sswu_z() -> Self::BaseField;

    fn sswu(fe: &Self::BaseField) -> Self;
}

// For instance secp256k1, BLS curves, BN curves
pub trait MapToCurveIsogeny<const LEN: usize>: MapToCurve<{LEN}> {
    fn iso_map(
        x_iso: Self::BaseField,
        y_iso: Self::BaseField,
    ) -> (Self::BaseField, Self::BaseField);

    fn isogeny_a() -> Self::BaseField;
    fn isogeny_b() -> Self::BaseField;
    fn iso_sswu_z() -> Self::BaseField;

    fn iso_sswu(fe: &Self::BaseField) -> Self;
}

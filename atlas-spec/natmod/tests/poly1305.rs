use natmod::nat_mod;

/// This has to come from the lib.

pub trait NatMod<const LEN: usize> {
    const MODULUS: [u8; LEN];
    const MODULUS_STR: &'static str;
    const ZERO: [u8; LEN];

    fn new(value: [u8; LEN]) -> Self;
    fn value(&self) -> &[u8];

    fn fsub(self, _rhs: Self) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    /// Add self with `rhs` and return the result `self + rhs % MODULUS`.
    fn fadd(self, rhs: Self) -> Self
    where
        Self: Sized,
    {
        let lhs = num_bigint::BigUint::from_bytes_be(self.value());
        let rhs = num_bigint::BigUint::from_bytes_be(rhs.value());
        let modulus = num_bigint::BigUint::from_bytes_be(&Self::MODULUS);
        let res = (lhs + rhs) % modulus;
        let res = res.to_bytes_be();
        assert!(res.len() <= LEN);
        let mut value = Self::ZERO;
        let offset = LEN - res.len();
        for i in 0..res.len() {
            value[offset + i] = res[i];
        }
        Self::new(value)
    }

    /// Multiply self with `rhs` and return the result `self * rhs % MODULUS`.
    fn fmul(self, rhs: Self) -> Self
    where
        Self: Sized,
    {
        let lhs = num_bigint::BigUint::from_bytes_be(self.value());
        let rhs = num_bigint::BigUint::from_bytes_be(rhs.value());
        let modulus = num_bigint::BigUint::from_bytes_be(&Self::MODULUS);
        let res = (lhs * rhs) % modulus;
        let res = res.to_bytes_be();
        assert!(res.len() <= LEN);
        let mut value = Self::ZERO;
        let offset = LEN - res.len();
        for i in 0..res.len() {
            value[offset + i] = res[i];
        }
        Self::new(value)
    }

    /// Returns 2 to the power of the argument
    fn pow2(x: usize) -> Self
    where
        Self: Sized,
    {
        let res = num_bigint::BigUint::from(1u32) << x;
        Self::from_bigint(res)
    }

    /// Create a new [`#ident`] from a `u128` literal.
    fn from_u128(literal: u128) -> Self
    where
        Self: Sized,
    {
        Self::from_bigint(num_bigint::BigUint::from(literal))
    }

    /// Create a new [`#ident`] from a little endian byte slice.
    fn from_le_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized,
    {
        Self::from_bigint(num_bigint::BigUint::from_bytes_le(bytes))
    }

    /// Create a new [`#ident`] from a little endian byte slice.
    fn from_be_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized,
    {
        Self::from_bigint(num_bigint::BigUint::from_bytes_be(bytes))
    }

    fn to_le_bytes(self) -> [u8; LEN]
    where
        Self: Sized,
    {
        Self::pad(&num_bigint::BigUint::from_bytes_be(self.value()).to_bytes_le())
    }

    /// Get hex string representation of this.
    fn to_hex(&self) -> String {
        let strs: Vec<String> = self.value().iter().map(|b| format!("{:02x}", b)).collect();
        strs.join("")
    }

    /// New from hex string
    fn from_hex(hex: &str) -> Self
    where
        Self: Sized,
    {
        assert!(hex.len() % 2 == 0);
        let l = hex.len() / 2;
        assert!(l <= LEN);
        let mut value = [0u8; LEN];
        let skip = LEN - l;
        for i in 0..l {
            value[skip + i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .expect("An unexpected error occurred.");
        }
        Self::new(value)
    }

    fn pad(bytes: &[u8]) -> [u8; LEN] {
        let mut value = [0u8; LEN];
        let upper = value.len();
        let lower = upper - bytes.len();
        value[lower..upper].copy_from_slice(&bytes);
        value
    }

    fn from_bigint(x: num_bigint::BigUint) -> Self
    where
        Self: Sized,
    {
        let max_value = Self::MODULUS;
        assert!(
            x <= num_bigint::BigUint::from_bytes_be(&max_value),
            "{} is too large for type {}!",
            x,
            stringify!($ident)
        );
        let repr = x.to_bytes_be();
        if repr.len() > LEN {
            panic!("{} is too large for this type", x)
        }

        Self::new(Self::pad(&repr))
    }
}

#[nat_mod("03fffffffffffffffffffffffffffffffb", 17)]
struct FieldElement {}

#[test]
fn add() {
    let x = FieldElement::from_hex("03fffffffffffffffffffffffffffffffa");
    let y = FieldElement::from_hex("01");
    let z = x + y;
    assert_eq!(FieldElement::ZERO.as_ref(), z.as_ref());

    let x = FieldElement::from_hex("03fffffffffffffffffffffffffffffffa");
    let y = FieldElement::from_hex("02");
    let z = x + y;
    assert_eq!(FieldElement::from_hex("01").as_ref(), z.as_ref());
}

#[test]
fn mul() {
    let x = FieldElement::from_hex("03fffffffffffffffffffffffffffffffa");
    let y = FieldElement::from_hex("01");
    let z = x * y;
    assert_eq!(x.as_ref(), z.as_ref());

    let x = FieldElement::from_hex("03fffffffffffffffffffffffffffffffa");
    let y = FieldElement::from_hex("02");
    let z = x * y;
    assert_eq!(
        FieldElement::from_hex("03fffffffffffffffffffffffffffffff9").as_ref(),
        z.as_ref()
    );
}

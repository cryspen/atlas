/// This has to come from the lib.
pub use natmod::nat_mod;

pub trait NatMod<const LEN: usize> {
    const MODULUS: [u8; LEN];
    const MODULUS_STR: &'static str;
    const ZERO: [u8; LEN];

    fn new(value: [u8; LEN]) -> Self;
    fn value(&self) -> &[u8];

    /// Sub self with `rhs` and return the result `self - rhs % MODULUS`.
    fn fsub(self, rhs: Self) -> Self
    where
        Self: Sized,
    {
        let lhs = num_bigint::BigUint::from_bytes_be(self.value());
        let rhs = num_bigint::BigUint::from_bytes_be(rhs.value());
        let modulus = num_bigint::BigUint::from_bytes_be(&Self::MODULUS);
        let res = if lhs < rhs {
            modulus.clone() + lhs - rhs
        } else {
            lhs - rhs
        };
        let res = res % modulus;
        Self::from_bigint(res)
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
        Self::from_bigint(res)
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
        Self::from_bigint(res)
    }

    /// `self ^ rhs % MODULUS`.
    fn pow(self, rhs: u128) -> Self
    where
        Self: Sized,
    {
        let lhs = num_bigint::BigUint::from_bytes_be(self.value());
        let rhs = num_bigint::BigUint::from(rhs);
        let modulus = num_bigint::BigUint::from_bytes_be(&Self::MODULUS);
        let res = lhs.modpow(&rhs, &modulus);
        Self::from_bigint(res)
    }

    /// Invert self and return the result `self ^ -1 % MODULUS`.
    fn inv(self) -> Self
    where
        Self: Sized,
    {
        let val = num_bigint::BigUint::from_bytes_be(self.value());
        let modulus = num_bigint::BigUint::from_bytes_be(&Self::MODULUS);
        let m = &modulus - num_bigint::BigUint::from(2u32);
        Self::from_bigint(val.modpow(&m, &modulus))
    }

    /// Zero element
    fn zero() -> Self
    where
        Self: Sized,
    {
        Self::new(Self::ZERO)
    }

    fn bit(&self, bit: u128) -> bool {
        let val = num_bigint::BigUint::from_bytes_be(self.value());
        let tmp = val >> bit;
        (tmp & num_bigint::BigUint::from(1u128)).to_bytes_le()[0] == 1
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

// === Secret Integers

pub type U8 = u8;
pub fn U8(x: u8) -> u8 {
    x
}

use std::convert::TryInto;

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

    /// `self ^ rhs % MODULUS`.
    fn pow_felem(self, rhs: &Self) -> Self
    where
        Self: Sized,
    {
        let lhs = num_bigint::BigUint::from_bytes_be(self.value());
        let rhs = num_bigint::BigUint::from_bytes_be(rhs.value());
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

    fn inv0(self) -> Self
    where
        Self: Sized,
    {
        if self.value() == Self::zero().value() {
            Self::zero()
        } else {
            self.inv()
        }
    }

    /// Zero element
    fn zero() -> Self
    where
        Self: Sized,
    {
        Self::new(Self::ZERO)
    }

    /// One element
    fn one() -> Self
    where
        Self: Sized,
    {
        let out = Self::new(Self::ZERO);
        out.fadd(Self::from_u128(1))
    }

    /// One element
    fn two() -> Self
    where
        Self: Sized,
    {
        let out = Self::new(Self::ZERO);
        out.fadd(Self::from_u128(2))
    }

    fn bit(&self, bit: u128) -> bool {
        let val = num_bigint::BigUint::from_bytes_be(self.value());
        val.bit(bit.try_into().unwrap())
    }

    /// Returns 2 to the power of the argument
    fn pow2(x: usize) -> Self
    where
        Self: Sized,
    {
        let res = num_bigint::BigUint::from(1u32) << x;
        Self::from_bigint(res)
    }

    fn neg(self) -> Self
    where
        Self: Sized,
    {
        Self::zero().fsub(self)
    }

    /// Create a new [`#ident`] from a `u128` literal.
    fn from_u128(literal: u128) -> Self
    where
        Self: Sized,
    {
        Self::from_bigint(num_bigint::BigUint::from(literal))
    }

    /// Create a new [`#ident`] from a little endian byte slice.
    ///
    /// This computes bytes % MODULUS
    fn from_le_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized,
    {
        let value = num_bigint::BigUint::from_bytes_le(bytes);
        let modulus = num_bigint::BigUint::from_bytes_be(&Self::MODULUS);
        Self::from_bigint(value % modulus)
    }

    /// Create a new [`#ident`] from a little endian byte slice.
    ///
    /// This computes bytes % MODULUS
    fn from_be_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized,
    {
        let value = num_bigint::BigUint::from_bytes_be(bytes);
        let modulus = num_bigint::BigUint::from_bytes_be(&Self::MODULUS);
        Self::from_bigint(value % modulus)
    }

    fn to_le_bytes(self) -> [u8; LEN]
    where
        Self: Sized,
    {
        Self::pad(&num_bigint::BigUint::from_bytes_be(self.value()).to_bytes_le())
    }

    fn to_be_bytes(self) -> [u8; LEN]
    where
        Self: Sized,
    {
        self.value().try_into().unwrap()
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
        let mut value = vec![0u8; l];
        for i in 0..l {
            value[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .expect("An unexpected error occurred.");
        }

        Self::from_be_bytes(&value)
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
#[allow(dead_code, non_snake_case)]
pub fn U8(x: u8) -> u8 {
    x
}

// === Test vector helpers
pub use std::io::Write;
#[macro_export]
macro_rules! create_test_vectors {
    ($struct_name: ident, $($element: ident: $ty: ty),+) => {
        #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
        #[allow(non_snake_case)]
        struct $struct_name { $($element: $ty),+ }
        impl $struct_name {
            #[cfg_attr(feature="use_attributes", not_hacspec)]
            pub fn from_file<T: serde::de::DeserializeOwned>(file: &'static str) -> T {
                let file = match std::fs::File::open(file) {
                    Ok(f) => f,
                    Err(_) => panic!("Couldn't open file {}.", file),
                };
                let reader = std::io::BufReader::new(file);
                match serde_json::from_reader(reader) {
                    Ok(r) => r,
                    Err(e) => {
                        println!("{:?}", e);
                        panic!("Error reading file.")
                    },
                }
            }
            #[cfg_attr(feature="use_attributes", not_hacspec)]
            pub fn write_file(&self, file: &'static str) {
                let mut file = match std::fs::File::create(file) {
                    Ok(f) => f,
                    Err(_) => panic!("Couldn't open file {}.", file),
                };
                let json = match serde_json::to_string_pretty(&self) {
                    Ok(j) => j,
                    Err(_) => panic!("Couldn't serialize this object."),
                };
                match file.write_all(&json.into_bytes()) {
                    Ok(_) => (),
                    Err(_) => panic!("Error writing to file."),
                }
            }
            #[cfg_attr(feature="use_attributes", not_hacspec)]
            pub fn new_array(file: &'static str) -> Vec<Self> {
                let file = match std::fs::File::open(file) {
                    Ok(f) => f,
                    Err(_) => panic!("Couldn't open file."),
                };
                let reader = std::io::BufReader::new(file);
                match serde_json::from_reader(reader) {
                    Ok(r) => r,
                    Err(e) => {
                        println!("{:?}", e);
                        panic!("Error reading file.")
                    },
                }
            }
        }
    };
}

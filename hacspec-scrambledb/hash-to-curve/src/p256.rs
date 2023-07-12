use lazy_static::lazy_static;
use num_bigint::BigUint;

use core::ops::{Add, Mul, Sub};

use num_traits::identities::{One, Zero};

lazy_static! {
    static ref P: BigUint = BigUint::from_bytes_be(
        hex::decode("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
            .unwrap()
            .as_slice()
    );
    static ref Q: BigUint = P.clone();
    static ref C1: BigUint = (&(*Q) + BigUint::from(1u8)) / BigUint::from(4u8);
    pub static ref A: Fp = Fp::zero() - Fp::from_literal(3u128);
    pub static ref B: Fp = Fp(BigUint::from_bytes_be(
        hex::decode("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
            .unwrap()
            .as_slice()
    ));
}

pub const M: usize = 1; // The extension degree of P-256; including this so other code can be written more generically

#[derive(PartialEq)]
pub struct Fp(BigUint);

impl Add<&Fp> for Fp {
    type Output = Self;

    fn add(self, other: &Fp) -> Self::Output {
        Fp((self.0 + &other.0) % &(*P))
    }
}

impl Add<Fp> for Fp {
    type Output = Self;

    fn add(self, other: Fp) -> Self::Output {
        Fp((self.0 + other.0) % &(*P))
    }
}

impl Mul<Fp> for Fp {
    type Output = Self;

    fn mul(self, other: Fp) -> Self::Output {
        Fp((self.0 * other.0) % &(*P))
    }
}

impl Mul<&Fp> for Fp {
    type Output = Self;

    fn mul(self, other: &Fp) -> Self::Output {
        Fp((self.0 * &other.0) % &(*P))
    }
}

impl Sub<Fp> for Fp {
    type Output = Self;

    fn sub(self, other: Fp) -> Self::Output {
        Fp((self.0 - other.0) % &(*P))
    }
}

impl Sub<&Fp> for Fp {
    type Output = Self;

    fn sub(self, other: &Fp) -> Self::Output {
        Fp((self.0 - &other.0) % &(*P))
    }
}

impl One for Fp {
    fn one() -> Self {
        Fp(BigUint::one())
    }

    fn set_one(&mut self) {
        *self = Fp(BigUint::one())
    }

    fn is_one(&self) -> bool {
        self.0.is_one()
    }
}

impl Zero for Fp {
    fn zero() -> Self {
        Fp(BigUint::zero())
    }
    fn set_zero(&mut self) {
        *self = Fp(BigUint::zero())
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Fp {
    #[allow(dead_code)]
    pub fn from_literal(x: u128) -> Self {
        Fp(BigUint::from(x))
    }

    #[allow(dead_code)]
    pub fn inv0(&self) -> Self {
        if self.is_zero() {
            Self::zero()
        } else {
            Fp(self.0.modpow(&(&(*P) - BigUint::from(2u32)), &(*P)))
        }
    }

    #[allow(dead_code)]
    pub fn sgn0(&self) -> u8 {
        if (&self.0 % BigUint::from(2u32)).is_zero() {
            0
        } else {
            1
        }
    }
    
    #[allow(dead_code)]
    pub fn is_square(&self) -> bool {
	let exp = (&(*P) - BigUint::from(1u8)) / BigUint::from(2u8);
	let res = self.0.modpow(&exp, &(*P));
	res.is_zero() || res.is_one()
    }

    
    #[allow(dead_code)]
    pub fn sqrt(&self) -> Self {
	// p = 3 (mod 4)
	Fp(self.0.modpow(&(*C1), &(*P)))
    }

    #[allow(dead_code)]
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
	Fp(BigUint::from_bytes_be(bytes) % &(*P))
    }
}

// bool signifies point at infinity
pub struct G(pub Fp, pub Fp, pub bool);

impl Add<G> for G {
    type Output = G;

    fn add(self, other: G) -> Self {
	unimplemented!()
    }
}

impl G {
    pub fn clear_cofactor(self) -> Self {
	unimplemented!()
    }
}

//! # Elgamal Public Key Encryption
//!
//! This document represents an executable specification of the Elgamal Public Key Encryption scheme.
//!
//! At the basis of the encryption scheme is a prime order group $`\mathbb{G}`$.

use p256::{p256_point_mul, p256_point_mul_base, point_add, NatMod, P256Point, P256Scalar};
use scrambledb_util::random_scalar;

/// An Elgamal encryption of a message `M` under public key `PK` is a pair of group elements `(c0, c1)` where
/// * `c0` is the group generator multiplied by a randomizer `r`
/// * `c1` is the result of multiplying the  target public encryption key the same randomizer `r` and adding the result to the message `M` that is to be encrypted.
pub type Ciphertext = (P256Point, P256Point);

#[derive(Debug)]
pub enum Error {
    DecryptionError,
    CurveError,
}

impl From<p256::Error> for Error {
    fn from(_value: p256::Error) -> Self {
        Self::CurveError
    }
}

pub type DecryptionKey = P256Scalar;
pub type EncryptionKey = P256Point;

/// An Elgamal private decryption key is a scalar $`sk`$ in the base group $`\mathcal{G}`$.
/// The corresponding public encryption is calculated by multiplication of the group generator `G` with the private key.
pub fn ek_from_dk(dk: DecryptionKey) -> Result<EncryptionKey, Error> {
    let ek = p256_point_mul_base(dk)?.into();

    Ok(ek)
}

pub fn generate_keys() -> Result<(DecryptionKey, EncryptionKey), Error> {
    let dk = random_scalar();
    let ek = ek_from_dk(dk)?;

    Ok((dk, ek))
}

/// Encrypts a message `msg` for the public encryption key `ek` using the specified `randomizer`.
/// This algorithm can fail if the given arguments result in invalid group operations.
pub fn encrypt(ek: P256Point, msg: P256Point, randomizer: P256Scalar) -> Result<Ciphertext, Error> {
    let c0 = p256::p256_point_mul_base(randomizer)?.into();
    let c1 = p256::point_add(msg, p256::p256_point_mul(randomizer, ek.into())?.into())?;

    Ok((c0, c1))
}

fn neg(p: P256Point) -> P256Point {
    match p {
        P256Point::AtInfinity => p,
        P256Point::NonInf((x, y)) => (x, y.neg()).into(),
    }
}

/// To decrypt an Elgamal ciphertext...
pub fn decrypt(dk: P256Scalar, ctx: Ciphertext) -> Result<P256Point, Error> {
    let (c0, c1) = ctx;

    let c0_inv = p256::p256_point_mul(dk, c0.into())?.into();

    let msg = p256::point_add(c1, neg(c0_inv))?;

    Ok(msg)
}

/// Given the correct public encryption key, it is possible to rerandomize Elgamal ciphertexts without changing the message that is encrypted.
pub fn rerandomize(
    ek: P256Point,
    ctx: Ciphertext,
    randomizer: P256Scalar,
) -> Result<Ciphertext, Error> {
    let (c0, c1) = ctx;

    let c0prime = point_add(p256_point_mul_base(randomizer)?.into(), c0)?;

    let ekr = p256_point_mul(randomizer, ek.into())?.into();
    let c1prime = point_add(ekr, c1)?;

    Ok((c0prime, c1prime))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_correctness() {
        let msg = random_element().unwrap();
        let randomizer = random_scalar();
        let (dk, ek) = generate_keys().unwrap();

        let ctx = encrypt(ek, msg, randomizer).unwrap();
        let decryption = decrypt(dk, ctx).unwrap();

        assert_eq!(msg, decryption);
    }

    #[test]
    fn test_rerandomize() {
        let msg = random_element().unwrap();
        let randomizer_enc = random_scalar();
        let randomizer_rerand = random_scalar();
        if randomizer_rerand == P256Scalar::one() {
            panic!("Trivial randomizer");
        }
        let (dk, ek) = generate_keys().unwrap();

        let ctx = encrypt(ek, msg, randomizer_enc).unwrap();
        let rctx = rerandomize(ek, ctx, randomizer_rerand).unwrap();
        let decryption = decrypt(dk, rctx).unwrap();

        assert_eq!(msg, decryption);
        assert_ne!(ctx, rctx);
    }

    fn random_element() -> Result<P256Point, Error> {
        let rand = random_scalar();
        let res = p256_point_mul_base(rand)?.into();

        Ok(res)
    }
}

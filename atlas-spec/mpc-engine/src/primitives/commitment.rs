//! This module implements a commitment scheme in the random oracle model.
//!
//! Assume `H` is a hash function modeled as a random oracle. To commit to value
//! `v`, sample a random string `r` from `{0,1}^\rho` and compute the
//! commitment as `c <- H(v || r)`, the opening being `r`. To verify the
//! commitment given `(v', c, r')` compute `c' <- H(v' || r')` and check that `c
//! == c'`.

use hacspec_lib::Randomness;
use hmac::hkdf_extract;

use crate::{Error, STATISTICAL_SECURITY};

/// A Commitment to some value.
#[derive(Debug)]
pub struct Commitment {
    com: Vec<u8>,
    dst: Vec<u8>,
}

/// The opening information for a commitment.
#[derive(Debug)]
pub struct Opening([u8; STATISTICAL_SECURITY]);

impl Commitment {
    /// Commit to a value.
    pub fn new(
        value: &[u8],
        dst: &[u8],
        entropy: &mut Randomness,
    ) -> Result<(Self, Opening), Error> {
        let mut r = [0u8; STATISTICAL_SECURITY];
        r.copy_from_slice(entropy.bytes(STATISTICAL_SECURITY)?);

        let mut ikm = Vec::from(value);
        ikm.extend_from_slice(&r);

        let com = hkdf_extract(dst, &ikm);
        Ok((
            Commitment {
                com,
                dst: dst.to_vec(),
            },
            Opening(r),
        ))
    }

    /// Verify that the commitment opens to some value.
    pub fn open(&self, value: &[u8], opening: &Opening) -> Result<(), Error> {
        let mut ikm = Vec::from(value);
        ikm.extend_from_slice(&opening.0);
        let com = hkdf_extract(&self.dst, &ikm);
        if self.com != com {
            return Err(Error::OtherError);
        }
        Ok(())
    }
}

#[test]
fn simple() {
    use rand::{thread_rng, RngCore};

    let mut rng = thread_rng();
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    let mut entropy = Randomness::new(entropy.to_vec());
    let value = b"Hello";
    let dst = b"Test";
    let (commitment, opening) = Commitment::new(value, dst, &mut entropy).unwrap();
    assert!(commitment.open(value, &opening).is_ok());
    assert!(commitment.open(b"Wrong Value", &opening).is_err());
}

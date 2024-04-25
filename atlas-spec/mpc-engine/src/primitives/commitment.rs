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
#[derive(Debug, Clone)]
pub struct Commitment {
    commitment: Vec<u8>,
    domain_separator: Vec<u8>,
}

/// The opening information for a commitment.
#[derive(Debug, Clone)]
pub struct Opening {
    value: Vec<u8>,
    opening: [u8; STATISTICAL_SECURITY],
}

impl Commitment {
    /// Commit to a value.
    ///
    /// Given input value `value`, samples a random bitstring `r` of length
    /// `STATISTICAL_SECURITY` and returns a domain separated commitment
    /// `H(value||r)` as well as the corresponding opening.
    pub fn new(
        value: &[u8],
        domain_separator: &[u8],
        entropy: &mut Randomness,
    ) -> Result<(Self, Opening), Error> {
        let mut opening = [0u8; STATISTICAL_SECURITY];
        opening.copy_from_slice(entropy.bytes(STATISTICAL_SECURITY)?);

        let mut ikm = Vec::from(value);
        ikm.extend_from_slice(&opening);

        let commitment = hkdf_extract(domain_separator, &ikm);
        Ok((
            Commitment {
                commitment,
                domain_separator: domain_separator.to_vec(),
            },
            Opening {
                value: value.to_vec(),
                opening,
            },
        ))
    }

    /// Open the commitment, returning the committed value, if successful.
    pub fn open(&self, opening: &Opening) -> Result<Vec<u8>, Error> {
        let mut ikm = vec![0u8; opening.value.len()];
        ikm.copy_from_slice(&opening.value);
        ikm.extend_from_slice(&opening.opening);
        let reconstructed_commitment = hkdf_extract(&self.domain_separator, &ikm);
        if self.commitment != reconstructed_commitment {
            return Err(Error::BadCommitment(
                self.commitment.clone(),
                reconstructed_commitment,
            ));
        }
        Ok(opening.value.to_vec())
    }
}

#[test]
fn simple() {
    use rand::{thread_rng, RngCore};

    let mut rng = thread_rng();
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);
    let mut entropy = Randomness::new(entropy.to_vec());
    let value = b"Hello";
    let another_value = b"Heya";
    let dst = b"Test";
    let (commitment, opening) = Commitment::new(value, dst, &mut entropy).unwrap();
    let (_another_commitment, another_opening) =
        Commitment::new(another_value, dst, &mut entropy).unwrap();
    assert!(commitment.open(&opening).is_ok());
    assert!(commitment.open(&another_opening).is_err());
}

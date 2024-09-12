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

/// The length of a commitment value, derived from the output of a HKDF
/// extraction using SHA-256.
pub const COMMITMENT_LENGTH: usize = 32;

/// A Commitment to some value.
#[derive(Debug, Clone)]
pub struct Commitment {
    commitment: [u8; COMMITMENT_LENGTH],
    domain_separator: Vec<u8>,
}

/// The opening information for a commitment.
#[derive(Debug, Clone)]
pub struct Opening {
    value: Vec<u8>,
    opening: [u8; STATISTICAL_SECURITY],
}

impl Opening {
    /// Serialize an opening to a byte vector.
    ///
    /// The serialization format is
    /// `opening || value`
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.opening);
        result.extend_from_slice(&self.value);

        result
    }

    /// Deserialize an opening from a serialization created using [Opening::as_bytes].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < STATISTICAL_SECURITY + 1 {
            return Err(Error::InvalidSerialization);
        }
        let opening: [u8; STATISTICAL_SECURITY] = Vec::from(&bytes[0..STATISTICAL_SECURITY])
            .try_into()
            .map_err(|_| Error::InvalidSerialization)?;
        let value = Vec::from(&bytes[STATISTICAL_SECURITY..]);
        Ok(Self { value, opening })
    }
}

impl Commitment {
    /// Commit to a value.
    ///
    /// Given input value `value`, samples a random bitstring `r` of length
    /// `STATISTICAL_SECURITY` and returns a domain separated commitment
    /// `H(value||r)` as well as the corresponding opening.
    pub fn new(value: &[u8], domain_separator: &[u8], entropy: &mut Randomness) -> (Self, Opening) {
        let mut opening = [0u8; STATISTICAL_SECURITY];
        opening.copy_from_slice(
            entropy
                .bytes(STATISTICAL_SECURITY)
                .expect("sufficient randomness should have been provided externally"),
        );

        let mut ikm = Vec::from(value);
        ikm.extend_from_slice(&opening);

        let commitment = hkdf_extract(domain_separator, &ikm)
            .try_into()
            .expect("should use HKDF with SHA-256 for correct output length");
        (
            Commitment {
                commitment,
                domain_separator: domain_separator.to_vec(),
            },
            Opening {
                value: value.to_vec(),
                opening,
            },
        )
    }

    /// Open the commitment, returning the committed value, if successful.
    pub fn open(&self, opening: &Opening) -> Result<Vec<u8>, Error> {
        let mut ikm = vec![0u8; opening.value.len()];
        ikm.copy_from_slice(&opening.value);
        ikm.extend_from_slice(&opening.opening);
        let reconstructed_commitment: [u8; COMMITMENT_LENGTH] =
            hkdf_extract(&self.domain_separator, &ikm)
                .try_into()
                .expect("should use HKDF with SHA-256 for correct output length");
        if self.commitment != reconstructed_commitment {
            return Err(Error::BadCommitment(
                self.commitment,
                reconstructed_commitment,
            ));
        }
        Ok(opening.value.to_vec())
    }

    /// Serialize a commitment to a byte vector.
    ///
    /// The serialization format is `commitment ||
    /// len(dst) || dst_bytes`, where the length is represented as big-endian
    /// byte arrays.
    pub fn as_bytes(&self) -> Vec<u8> {
        let dst_len = self.domain_separator.len();
        let mut result = Vec::new();
        result.extend_from_slice(&self.commitment);
        result.extend_from_slice(&dst_len.to_be_bytes());
        result.extend_from_slice(&self.domain_separator);
        result
    }

    /// Deserialize a commitment from a serialization created using [Commitment::as_bytes].
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        if bytes.len() < COMMITMENT_LENGTH + std::mem::size_of::<usize>() {
            return Err(Error::InvalidSerialization);
        }
        let (commitment_bytes, rest) = bytes.split_at(COMMITMENT_LENGTH);
        let commitment = commitment_bytes.try_into().unwrap();

        let (dst_len_bytes, rest) = rest.split_at(std::mem::size_of::<usize>());
        let dst_len = usize::from_be_bytes(dst_len_bytes.try_into().unwrap());
        let (dst_bytes, rest) = rest.split_at(dst_len);
        let domain_separator = Vec::from(dst_bytes);

        Ok((
            Self {
                commitment,
                domain_separator,
            },
            rest.to_vec(),
        ))
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
    let (commitment, opening) = Commitment::new(value, dst, &mut entropy);
    let (_another_commitment, another_opening) = Commitment::new(another_value, dst, &mut entropy);
    debug_assert!(commitment.open(&opening).is_ok());
    debug_assert!(commitment.open(&another_opening).is_err());
}

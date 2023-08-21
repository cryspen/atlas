use libcrux::hpke::kdf::{LabeledExpand, LabeledExtract, KDF};
use p256::{NatMod, P256Scalar};

#[derive(Debug)]
pub enum Error {
    SamplingError,
}

impl From<libcrux::hpke::errors::HpkeError> for Error {
    fn from(_value: libcrux::hpke::errors::HpkeError) -> Self {
        Error::SamplingError
    }
}

// TODO: Pass in context for strings etc
pub fn random_scalar(ikm: &[u8]) -> Result<P256Scalar, Error> {
    let suite_id = b"coPRF-P256-SHA256".to_vec();
    let label = b"dkp_prk".to_vec();
    let candidate_label = b"candidate".to_vec();

    let dkp_prk = LabeledExtract(KDF::HKDF_SHA256, suite_id.clone(), b"", label, &ikm)?;

    let mut sk = P256Scalar::zero();

    for counter in 0..255 {
        let mut bytes = LabeledExpand(
            KDF::HKDF_SHA256,
            suite_id.clone(),
            &dkp_prk,
            candidate_label.clone(),
            &i2osp(counter, 1),
            32,
        )?;
        bytes[0] = bytes[0] & 0xffu8;
        if p256::p256_validate_private_key(&bytes) {
            sk = P256Scalar::from_be_bytes(&bytes);
        }
    }
    if sk == P256Scalar::zero() {
        Err(Error::SamplingError)
    } else {
        Ok(sk)
    }
}

/// From [RFC8017]:
///
/// I2OSP converts a nonnegative integer to an octet string of a
/// specified length.
///
/// ```text
///    I2OSP (x, xLen)
///
///    Input:
///
///       x        nonnegative integer to be converted
///
///       xLen     intended length of the resulting octet string
///
///    Output:
///
///          X corresponding octet string of length xLen
/// ```
pub fn i2osp(x: usize, x_len: usize) -> Vec<u8> {
    assert!(x_len <= 8);
    Vec::from(&x.to_be_bytes()[(8 - x_len)..8])
}

pub fn get_subbytes(bytes: &[u8], offset: usize, count: usize) -> &[u8] {
    &bytes[offset..offset + count]
}

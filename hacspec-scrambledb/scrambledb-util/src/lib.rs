use p256::{NatMod, P256Scalar};

pub fn random_scalar() -> P256Scalar {
    use rand::RngCore;
    let mut bytes = [0u8; 48];
    rand::thread_rng().fill_bytes(&mut bytes);

    P256Scalar::from_be_bytes(&bytes)
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

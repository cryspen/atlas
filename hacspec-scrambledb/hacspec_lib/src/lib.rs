mod bytes;
pub use bytes::*;

mod rng;
pub use rng::*;

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
pub fn i2osp(value: usize, len: usize) -> Vec<u8> {
    match len {
        1 => (value as u8).to_be_bytes().to_vec(),
        2 => (value as u16).to_be_bytes().to_vec(),
        4 => (value as u32).to_be_bytes().to_vec(),
        8 => (value as u64).to_be_bytes().to_vec(),
        _ => panic!("unsupported len {len}"),
    }
}

pub fn subbytes(bytes: &[u8], offset: usize, count: usize) -> &[u8] {
    &bytes[offset..offset + count]
}

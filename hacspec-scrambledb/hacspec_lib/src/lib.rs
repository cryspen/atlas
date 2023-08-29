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

pub fn xor_slice(mut this: Vec<u8>, other: &[u8]) -> Vec<u8> {
    assert!(this.len() == other.len());

    // error[CE0008]: (Diagnostics.Context.Phase (Reject ArbitraryLhs)): ExplicitRejection { reason: "unknown reason" }
    //  --> hmac-rust/src/hacspec_helper.rs:5:9
    //   |
    // 5 |         *x = *x ^ *o;
    //   |
    // for (x, o) in this.iter_mut().zip(other.iter()) {
    //     *x = *x ^ *o;
    // }
    for i in 0..this.len() {
        this[i] = this[i] ^ other[i];
    }
    this
}

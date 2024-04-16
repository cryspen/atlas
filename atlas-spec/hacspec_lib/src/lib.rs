mod bytes;
pub use bytes::*;

mod rng;
pub use rng::*;
pub mod hacspec_helper;

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
        this[i] ^= other[i];
    }
    this
}

macro_rules! to_le_u32s_impl {
    ($name:ident,$l:literal) => {
        pub fn $name(bytes: &[u8]) -> [u32; $l] {
            assert_eq!($l, bytes.len() / 4);
            let mut out = [0; $l];
            for i in 0..$l {
                out[i] = u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
            }
            out
        }
    };
}
to_le_u32s_impl!(to_le_u32s_3, 3);
to_le_u32s_impl!(to_le_u32s_8, 8);
to_le_u32s_impl!(to_le_u32s_16, 16);

pub fn u32s_to_le_bytes(state: &[u32; 16]) -> [u8; 64] {
    let mut out = [0; 64];
    for i in 0..state.len() {
        let tmp = state[i].to_le_bytes();
        for j in 0..4 {
            out[i * 4 + j] = tmp[j];
        }
    }
    out
}

pub fn xor_state(mut state: [u32; 16], other: [u32; 16]) -> [u32; 16] {
    for i in 0..16 {
        state[i] ^= other[i];
    }
    state
}

pub fn add_state(mut state: [u32; 16], other: [u32; 16]) -> [u32; 16] {
    for i in 0..16 {
        state[i] = state[i].wrapping_add(other[i]);
    }
    state
}

pub fn update_array(mut array: [u8; 64], val: &[u8]) -> [u8; 64] {
    assert!(64 >= val.len());
    array[..val.len()].copy_from_slice(val);
    array
}

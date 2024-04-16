use std::convert::TryInto;

// WARNING:
// This spec does not provide secret independence, and treats all keys as public.
// Consequently, it should only be used as a FORMAL SPEC, NOT as a reference implementation.
use hacspec_lib::hacspec_helper::*;

// Type definitions for use in poly1305.
pub type PolyKey = [u8; 32];

const BLOCKSIZE: usize = 16;

// These are type aliases for convenience
pub type PolyBlock = [u8; 16];

// These are actual types; fixed-length arrays.
pub type Poly1305Tag = [u8; 16];

// A byte sequence of length <= BLOCKSIZE
pub type SubBlock = Vec<u8>;

// A length <= BLOCKSIZE
pub type BlockIndex = usize;

// This defines the field for modulo 2^130-5.
// In particular `FieldElement` and `FieldCanvas` are defined.
// The `FieldCanvas` is an integer type with 131-bit (to hold 2*(2^130-5)).
// The `FieldElement` is a natural integer modulo 2^130-5.

// public_nat_mod!(
//     type_name: FieldElement,
//     type_of_canvas: FieldCanvas,
//     bit_size_of_field: 131, // This amounts to 17 bytes
//     modulo_value: "03fffffffffffffffffffffffffffffffb"
// );

#[nat_mod("03fffffffffffffffffffffffffffffffb", 17)]
pub struct FieldElement {}

// Internal Poly1305 State
pub type PolyState = (FieldElement, FieldElement, PolyKey); //(accumulator,r,key)

pub fn poly1305_encode_r(b: &PolyBlock) -> FieldElement {
    let mut n = u128::from_le_bytes(*b);
    n &= 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffffu128;
    FieldElement::from_u128(n)
}

pub fn poly1305_encode_block(b: &PolyBlock) -> FieldElement {
    let n = u128::from_le_bytes(*b);
    let f = FieldElement::from_u128(n);
    f + FieldElement::pow2(128)
}

// In Poly1305 as used in this spec, pad_len is always the length of b, i.e. there is no padding
// In Chacha20Poly1305, pad_len is set to BLOCKSIZE
pub fn poly1305_encode_last(pad_len: BlockIndex, b: &SubBlock) -> FieldElement {
    let mut bytes = [0u8; 16];
    bytes[0..b.len()].copy_from_slice(b);
    let n = u128::from_le_bytes(bytes);
    let f = FieldElement::from_u128(n);
    f + FieldElement::pow2(8 * pad_len)
}

pub fn poly1305_init(k: PolyKey) -> PolyState {
    let r = poly1305_encode_r(&k[0..16].try_into().unwrap());
    (FieldElement::zero(), r, k)
}

pub fn poly1305_update_block(b: &PolyBlock, st: PolyState) -> PolyState {
    let (acc, r, k) = st;
    ((poly1305_encode_block(b) + acc) * r, r, k)
}

pub fn poly1305_update_blocks(m: &[u8], st: PolyState) -> PolyState {
    let mut st = st;
    for block in m.chunks_exact(BLOCKSIZE) {
        st = poly1305_update_block(block.try_into().unwrap(), st);
    }
    st
}

pub fn poly1305_update_last(pad_len: usize, b: &SubBlock, st: PolyState) -> PolyState {
    let mut st = st;
    if !b.is_empty() {
        let (acc, r, k) = st;
        st = ((poly1305_encode_last(pad_len, b) + acc) * r, r, k);
    }
    st
}

pub fn poly1305_update(m: &[u8], st: PolyState) -> PolyState {
    let st = poly1305_update_blocks(m, st);
    let mchunks = m.chunks_exact(BLOCKSIZE);
    let last = mchunks.remainder();
    poly1305_update_last(last.len(), &last.to_vec(), st)
}

pub fn poly1305_finish(st: PolyState) -> Poly1305Tag {
    let (acc, _, k) = st;
    let n = u128::from_le_bytes(k[16..32].try_into().unwrap());
    let aby = acc.to_le_bytes();
    // We can't use from_seq here because the accumulator is larger than 16 bytes.
    let a = u128::from_le_bytes(aby[0..16].try_into().unwrap());
    a.wrapping_add(n).to_le_bytes()
}

pub fn poly1305(m: &[u8], key: PolyKey) -> Poly1305Tag {
    let mut st = poly1305_init(key);
    st = poly1305_update(m, st);
    poly1305_finish(st)
}

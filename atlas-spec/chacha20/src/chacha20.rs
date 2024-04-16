use std::convert::TryInto;

use hacspec_lib::{bytes_to_le_u32s, Conversions};

type State = [u32; 16];
type StateIdx = usize;

type Constants = [u32; 4];

type Block = Vec<u8>;
pub type ChaChaIV = [u8; 12];
pub type ChaChaKey = [u8; 32];

fn chacha20_line(a: StateIdx, b: StateIdx, d: StateIdx, s: usize, m: State) -> State {
    let mut state = m;
    // TODO: we can't write += or ^= here right now :(
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = state[d] ^ state[a];
    state[d] = state[d].rotate_left(s as u32);
    state
}

pub fn chacha20_quarter_round(
    a: StateIdx,
    b: StateIdx,
    c: StateIdx,
    d: StateIdx,
    state: State,
) -> State {
    let state = chacha20_line(a, b, d, 16, state);
    let state = chacha20_line(c, d, b, 12, state);
    let state = chacha20_line(a, b, d, 8, state);
    chacha20_line(c, d, b, 7, state)
}

fn chacha20_double_round(state: State) -> State {
    let state = chacha20_quarter_round(0, 4, 8, 12, state);
    let state = chacha20_quarter_round(1, 5, 9, 13, state);
    let state = chacha20_quarter_round(2, 6, 10, 14, state);
    let state = chacha20_quarter_round(3, 7, 11, 15, state);

    let state = chacha20_quarter_round(0, 5, 10, 15, state);
    let state = chacha20_quarter_round(1, 6, 11, 12, state);
    let state = chacha20_quarter_round(2, 7, 8, 13, state);
    chacha20_quarter_round(3, 4, 9, 14, state)
}

pub fn chacha20_rounds(state: State) -> State {
    let mut st = state;
    for _i in 0..10 {
        st = chacha20_double_round(st);
    }
    st
}

pub fn chacha20_core(ctr: u32, st0: State) -> State {
    let mut state = st0;
    state[12] = state[12] + ctr;
    let k = chacha20_rounds(state);
    for i in 0..16 {
        state[i] = state[i].wrapping_add(k[i]);
    }
    state
}

pub fn chacha20_constants_init() -> Constants {
    let mut constants = [0u32; 4];
    constants[0] = 0x6170_7865u32;
    constants[1] = 0x3320_646eu32;
    constants[2] = 0x7962_2d32u32;
    constants[3] = 0x6b20_6574u32;
    constants
}

pub fn chacha20_init(key: ChaChaKey, iv: ChaChaIV, ctr: u32) -> State {
    let mut st = [0u32; 16];
    st[0..4].copy_from_slice(&chacha20_constants_init());
    st[4..12].copy_from_slice(&bytes_to_le_u32s(&key));
    st[12] = ctr;
    st[13..16].copy_from_slice(&bytes_to_le_u32s(&iv));

    st
}

pub fn chacha20_key_block(state: State) -> Block {
    let state = chacha20_core(0u32, state);

    state.to_le_bytes()
}

pub fn chacha20_key_block0(key: ChaChaKey, iv: ChaChaIV) -> Block {
    let state = chacha20_init(key, iv, 0u32);
    chacha20_key_block(state)
}

pub fn chacha20_encrypt_block(st0: State, ctr: u32, plain: &[u8]) -> Block {
    let st = chacha20_core(ctr, st0);
    let pl: State = bytes_to_le_u32s(&plain).try_into().unwrap();
    let mut st_new = [0u32; 16];
    for i in 0..16 {
        st_new[i] = st[i] ^ pl[i];
    }
    let st = st_new;
    st.to_le_bytes()
}

pub fn chacha20_encrypt_last(st0: State, ctr: u32, plain: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 64];
    b[0..plain.len()].copy_from_slice(&plain);
    b = chacha20_encrypt_block(st0, ctr, &b).try_into().unwrap();
    b[0..plain.len()].to_owned()
}

pub fn chacha20_update(st0: State, m: &[u8]) -> Vec<u8> {
    let mut blocks_out = Vec::new();
    let n_blocks = m.len() / 64;
    let mchunks = m.chunks_exact(64);
    let last_block = mchunks.remainder();
    for (i, msg_block) in mchunks.enumerate() {
        let b = chacha20_encrypt_block(st0, i as u32, msg_block);
        blocks_out.extend_from_slice(&b);
    }
    if last_block.len() != 0 {
        let b = chacha20_encrypt_last(st0, n_blocks as u32, &last_block);
        blocks_out.extend_from_slice(&b);
    }
    blocks_out
}

pub fn chacha20(key: ChaChaKey, iv: ChaChaIV, ctr: u32, m: &[u8]) -> Vec<u8> {
    let state = chacha20_init(key, iv, ctr);
    chacha20_update(state, m)
}

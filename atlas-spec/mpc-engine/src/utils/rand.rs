//! This module provides utilities for providing randomness to protocol
//! participants.

use crate::Error;

/// A utility struct for providing random bytes and bits.
pub struct Randomness {
    pub(crate) bytes: Vec<u8>,
    pub(crate) pointer: usize,
}

impl Randomness {
    /// Initialize the randomness provider.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pointer: 0 }
    }

    /// Output a random bytes, or error, if more bytes are requested than are
    /// available.
    pub fn bytes(&mut self, len: usize) -> Result<&[u8], Error> {
        if self.pointer + len > self.bytes.len() {
            return Err(Error::InsufficientRandomness);
        }

        let out = &self.bytes[self.pointer..self.pointer + len];
        self.pointer += len;
        Ok(out)
    }

    /// Output a random boolean, consuming one byte internally, or error if  no
    /// random byte is available.
    pub fn bit(&mut self) -> Result<bool, Error> {
        if self.pointer + 1 > self.bytes.len() {
            return Err(Error::InsufficientRandomness);
        }

        let out = &self.bytes[self.pointer];
        self.pointer += 1;
        Ok(out & 0x1 == 0x1)
    }
}

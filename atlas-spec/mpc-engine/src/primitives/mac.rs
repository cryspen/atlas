//! This module defines an information theoretic MAC for authenticating bits.

use crate::COMPUTATIONAL_SECURITY;

/// A MAC on a bit.
pub type Mac = [u8; COMPUTATIONAL_SECURITY];
/// A MAC key for authenticating a bit to another party.
pub type MacKey = [u8; COMPUTATIONAL_SECURITY];

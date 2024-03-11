//! This module defines the interface for share authentication.
use super::mac::{Mac, MacKey};

/// An authenticated share of a bit.
#[allow(dead_code)] // TODO: Remove this later.
pub struct AuthShare {
    /// Party i's share of the bit
    pub(crate) share: bool,
    /// MACs on the shared bit provided by the other parties
    pub(crate) macs: Vec<(usize, Mac)>,
    /// Keys for authenticating the other parties' shares of the bit
    pub(crate) keys: Vec<(usize, MacKey)>,
}

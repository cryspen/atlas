//! This module defines message types for the MPC protocol and its sub-protocols.
use crate::{
    circuit::WireIndex,
    primitives::{
        auth_share::AuthShare,
        mac::{Mac, MacKey},
    },
    COMPUTATIONAL_SECURITY,
};

/// Messages that must be handled by the preprocessing subprotocol, or ideal functionality.
pub enum FPreRequest {
    /// A party initialization request. from the indicated party.
    Init {
        /// The requesting party.
        from: usize,
    },
    /// A request for a random authenticated share.
    Random {
        /// The requesting party.
        from: usize,
    },
    /// A request for the AND of two shares.
    And {
        /// The requesting party.
        from: usize,
        /// The first AND input share.
        lhs: AuthShare,
        /// The second AND input share.
        rhs: AuthShare,
    },
}

/// Messages that are the outcome of the FPre subprotocol.
pub enum FPreResponse {
    /// The response to an `Init` request.
    Init {
        /// The receiver of the message.
        to: usize,
        /// A fresh global MAC key.
        global_mac_key: MacKey,
    },
    /// The response to a `Random` request.
    Random {
        /// The receiver of the message.
        to: usize,
        /// A fresh random authenticated bit share.
        share: AuthShare,
    },
    /// The response to an `And` request.
    And {
        /// The receiver of the message.
        to: usize,
        /// A fresh random authenticated bit share of the AND of the requested shares.
        and_share: AuthShare,
    },
}

/// An overall message type for all messages between parties.
///
/// It includes:
/// - top-level protocol messages
/// - suprotocol messages (incomplete)
///   - messages for the FPre subprotocol
///   - (not currently) messages for the remaining sub-protocols the implement
///     FPre
pub enum MPCMessage {
    /// A garbled AND gate, to be sent to the evaluator
    GarbledAnd(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    /// A MAC on a wire mask share
    WireMac(usize, bool, Mac),
    /// Masked input wire value
    MaskedInput(bool),
    /// A wire label, to be sent to the evaluator
    WireLabel {
        /// The originator of the label
        from: usize,
        /// The wire the label belongs to
        wire: WireIndex,
        /// The wire label
        label: [u8; COMPUTATIONAL_SECURITY],
    },
    /// A message to the FPre subprotocol
    FPreRequest(FPreRequest),
    /// The FPre subprotocol response
    FPreResponse(FPreResponse),
}

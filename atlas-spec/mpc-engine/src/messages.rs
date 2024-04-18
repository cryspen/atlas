//! This module defines message types for the MPC protocol and its sub-protocols.
use std::sync::mpsc::{Receiver, Sender};

use crate::{
    circuit::WireIndex,
    primitives::{
        commitment::{Commitment, Opening},
        mac::Mac,
        ot::{OTReceiverSelect, OTSenderInit, OTSenderSend},
    },
    COMPUTATIONAL_SECURITY,
};

/// An overall message type for all messages between parties.
///
/// It includes:
/// - top-level protocol messages
/// - suprotocol messages (incomplete)
///   - messages for the FPre subprotocol
///   - (not currently) messages for the remaining sub-protocols which implement
///     FPre
#[derive(Debug)]
pub struct Message {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) payload: MessagePayload,
}

/// Messages that are actually sent between parties in the top-level MPC
/// protocol.
#[derive(Debug)]
pub enum MessagePayload {
    /// A subchannel for running an 2-party subprotocol.
    SubChannel(Sender<SubMessage>, Receiver<SubMessage>),
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
}

#[derive(Debug)]
/// Message communicated on an subprotocol channel
pub enum SubMessage {
    /// An OT sender commitment
    OTCommit(OTSenderInit),
    /// An OT receiver selection
    OTSelect(OTReceiverSelect),
    /// An OT sender final message
    OTSend(OTSenderSend),
    /// An EQ initiator commitment
    EQCommit(Commitment),
    /// An EQ responder message
    EQResponse(Vec<u8>),
    /// An EQ initiator opening
    EQOpening(Vec<u8>, Opening),
}

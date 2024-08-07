//! Utility functions for the MPC specification.

use crate::broadcast::BroadcastRelay;
use crate::messages::Message;
use crate::party::ChannelConfig;
use std::sync::mpsc::{channel, Receiver, Sender};

/// Set up channel configurations for parties. Returns a vector of Channel Configurations.
pub fn set_up_channels(n: usize) -> (BroadcastRelay, Vec<ChannelConfig>) {
    let party_channels = (0..n)
        .map(|id| (id, channel()))
        .collect::<Vec<(usize, (Sender<Message>, Receiver<Message>))>>();

    let parties_tx: Vec<Sender<Message>> = party_channels
        .iter()
        .map(|(_, (tx, _))| tx.clone())
        .collect();

    let evaluator = party_channels[0].1 .0.clone();
    let (broadcast_sender, broadcast_receiver) = channel::<Message>();

    let channel_configs: Vec<ChannelConfig> = party_channels
        .into_iter()
        .map(|(id, (_tx, rx))| ChannelConfig {
            id,
            listen: rx,
            parties: parties_tx.clone(),
            evaluator: evaluator.clone(),
            broadcast: broadcast_sender.clone(),
        })
        .collect();

    let broadcast_channels = BroadcastRelay::new(broadcast_receiver, parties_tx.clone());

    (broadcast_channels, channel_configs)
}

pub(crate) fn ith_bit(i: usize, bytes: &[u8]) -> bool {
    let byte_index = i / 8;
    let bit_index = 7 - i % 8;
    ((bytes[byte_index] >> bit_index) & 1u8) == 1u8
}

/// Pack slice of `bool`s into a byte vector.
///
/// We assume that `bits.len()` is a multiple of 8.
pub(crate) fn pack_bits(bits: &[bool]) -> Vec<u8> {
    
    let mut result = Vec::new();
    let full_blocks = bits.len() / 8;
    let remainder = bits.len() % 8;

    debug_assert_eq!(remainder, 0);
    
    for i in 0..full_blocks {
        let mut current_byte = 0u8;
        for bit in 0..8 {
            current_byte += (bits[i * 8 + bit] as u8) << (7 - bit);
        }
        result.push(current_byte);
    }

    result
}

pub(crate) fn xor_slices(left: &[u8], right: &[u8]) -> Vec<u8> {
    debug_assert_eq!(left.len(), right.len());
    let mut result = Vec::with_capacity(left.len());
    for i in 0..left.len() {
        result.push(left[i] ^ right[i])
    }
    result
}

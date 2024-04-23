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
    let bit_index = i % 8;
    let bit_value = ((bytes[byte_index] >> bit_index) & 1u8) == 1u8;
    bit_value
}

/// Compute the XOR of the componentwise product of two bit vectors
pub fn prod_component_xor(left: &[u8], right: &[u8]) -> bool {
    assert_eq!(left.len(), right.len());
    let mut xor_chunk = 0u8;
    for i in 0..left.len() {
        let and_chunk = left[i] & right[i];
        xor_chunk ^= and_chunk;
    }
    let mut result = false;
    for i in 0..8 {
        result ^= (xor_chunk >> i & 1u8) == 1u8;
    }
    result
}

#[test]
fn cross_product() {
    let a = [0xffu8, 0xffu8];
    let b = [0x0, 0xffu8];
    let c = [0x01, 0x0];
    let d = [0xff, 0x1];
    assert_eq!(false, prod_component_xor(&a, &a));
    assert_eq!(false, prod_component_xor(&a, &b));
    assert_eq!(true, prod_component_xor(&c, &a));
    assert_eq!(false, prod_component_xor(&c, &b));
    assert_eq!(true, prod_component_xor(&d, &b));
    assert_eq!(true, prod_component_xor(&d, &c));
}

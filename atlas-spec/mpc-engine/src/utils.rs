//! Utility functions for the MPC specification.

use crate::messages::Message;
use crate::party::ChannelConfig;
use std::sync::mpsc::{channel, Receiver, Sender};

/// Set up channel configurations for parties. Returns a vector of Channel Configurations.
pub fn set_up_channels(n: usize) -> Vec<ChannelConfig> {
    let party_channels = (0..n)
        .map(|id| (id, channel()))
        .collect::<Vec<(usize, (Sender<Message>, Receiver<Message>))>>();

    let parties_tx: Vec<Sender<Message>> = party_channels
        .iter()
        .map(|(_, (tx, _))| tx.clone())
        .collect();

    let evaluator = party_channels[0].1 .0.clone();

    let channel_configs: Vec<ChannelConfig> = party_channels
        .into_iter()
        .map(|(id, (_tx, rx))| ChannelConfig {
            id,
            listen: rx,
            parties: parties_tx.clone(),
            evaluator: evaluator.clone(),
        })
        .collect();

    channel_configs
}

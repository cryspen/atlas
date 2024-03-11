//! Utility functions for the MPC specification.

use crate::party::ChannelConfig;
use std::sync::mpsc::{channel, Receiver, Sender};

use crate::messages::MPCMessage;
pub mod rand;

/// Set up channel configurations for parties. Returns a vector of Channel Configurations.
pub fn set_up_channels(n: usize) -> Vec<ChannelConfig> {
    let party_channels = (0..n)
        .map(|id| (id, channel()))
        .collect::<Vec<(usize, (Sender<MPCMessage>, Receiver<MPCMessage>))>>();

    let parties_tx: Vec<Sender<MPCMessage>> = party_channels
        .iter()
        .map(|(_, (tx, _))| tx.clone())
        .collect();

    let evaluator = party_channels[0].1 .0.clone();

    let party_configs: Vec<ChannelConfig> = party_channels
        .into_iter()
        .map(|(id, (tx, rx))| ChannelConfig {
            id,
            listen: rx,
            subprotocol: tx,
            parties: parties_tx.clone(),
            evaluator: evaluator.clone(),
        })
        .collect();

    party_configs
}

/// A channel configuration for the ideal FPre functionality.
#[allow(dead_code)] // TODO: Remove this later.
pub struct IdealFPreChannelConfig {
    self_recv: Receiver<MPCMessage>,
    self_send: Sender<MPCMessage>,
    parties_send: Vec<Sender<MPCMessage>>,
}

/// Set up party channels, as well as an ideal functionality.
pub fn set_up_channels_ideal(n: usize) -> (IdealFPreChannelConfig, Vec<ChannelConfig>) {
    let (self_send, self_recv) = channel();
    let mut channel_configs = set_up_channels(n);

    let parties_send = channel_configs[0].parties.clone();

    for config in channel_configs.iter_mut() {
        config.subprotocol = self_send.clone();
    }

    (
        IdealFPreChannelConfig {
            self_recv,
            self_send,
            parties_send,
        },
        channel_configs,
    )
}

pub mod ideal_fpre;

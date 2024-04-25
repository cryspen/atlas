//! This module implements a trusted broadcast relay.
//!
//! It must be stressed that this acts as a trusted third party in the protocol
//! and does not implement secure point-to-point broadcast among the parties.

use std::sync::mpsc::{Receiver, Sender};

use crate::messages::{Message, MessagePayload};

/// A broadcast relay functionality.
///
/// Accepts openings to broadcasted committed values and faithfully relays them to all
/// parties.
pub struct BroadcastRelay {
    num_parties: usize,
    pub(crate) listen: Receiver<Message>,
    pub(crate) parties: Vec<Sender<Message>>,
}

impl BroadcastRelay {
    /// Create a new broadcast relay.
    pub fn new(listen: Receiver<Message>, parties: Vec<Sender<Message>>) -> Self {
        Self {
            num_parties: parties.len(),
            listen,
            parties,
        }
    }

    /// Continuously await broadcast communication rounds.
    ///
    /// A broadcast round starts with all parties sending commitment opening
    /// information to the broadcast relay. Once openings have been received by
    /// all parties, the relay starts distributing openings to all parties,
    /// sending every opening to every party, except the party where the opening
    /// came from.
    ///
    /// If the receiving channel errors this must mean that all parties have
    /// shut down and dropped their copies of the sender. In this case the
    /// broadcast relay also shuts down.
    pub fn run(&self) {
        'outer: loop {
            let mut openings = Vec::new();
            for _i in 0..self.num_parties {
                let opening_msg = self.listen.recv();
                if let Ok(Message {
                    from,
                    to,
                    payload: MessagePayload::BroadcastOpening(_),
                }) = opening_msg
                {
                    if from != to {
                        panic!("Malformed broadcast opening")
                    }
                    openings.push(opening_msg.expect("already confirmed it's ok"))
                } else {
                    // One of the parties was dropped, time to shut down.
                    break 'outer;
                }
            }

            for opening in openings {
                for i in 0..self.num_parties {
                    if i == opening.from {
                        continue;
                    }

                    if let MessagePayload::BroadcastOpening(ref inner_opening) = opening.payload {
                        let franked_opening = Message {
                            from: opening.from,
                            to: i,
                            payload: MessagePayload::BroadcastOpening(inner_opening.clone()),
                        };
                        self.parties[i].send(franked_opening).unwrap();
                    }
                }
            }
        }
    }
}

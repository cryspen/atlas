//! This module implements a stateless broadcast relay.

use std::sync::mpsc::{Receiver, Sender};

use crate::messages::{Message, MessagePayload};

/// A stateless broadcast relay functionality.
///
/// Accepts openings to broadcasted committed values and relays them to all
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

//! This module defines the behaviour of protocol parties in the different
//! phases of the protocol.

use hacspec_lib::Randomness;

use crate::{
    circuit::Circuit, messages::MPCMessage, primitives::mac::MacKey, Error,
};
use std::sync::mpsc::{Receiver, Sender};

#[derive(Debug)]
/// A type for tracking the current protocol phase.
pub enum ProtocolPhase {
    /// Before the protocol has begun
    PreInit,
    /// Function-independent pre-processing
    Init,
}

/// Collects all party communication channels.
///
/// It includes
/// - `listen`: The parties on message receiver handle
/// - `evaluator`: The sender handle for the designated evaluator party
/// - `subprotocol`: The sender handle for the parties' subprotocol functionality
/// - `parties`: All other parties' sender handles, ordered by their `id`s
/// - `id`: The owning parties `id`
#[allow(dead_code)] // TODO: Remove this later.
pub struct ChannelConfig {
    pub(crate) listen: Receiver<MPCMessage>,
    pub(crate) evaluator: Sender<MPCMessage>,
    pub(crate) subprotocol: Sender<MPCMessage>,
    pub(crate) parties: Vec<Sender<MPCMessage>>,
    pub(crate) id: usize,
}

/// A struct defining protocol party state during a protocol execution.
#[allow(dead_code)] // TODO: Remove this later.
pub struct Party {
    /// The parties numeric identifier
    id: usize,
    /// The channel configuration for communicating to other protocol parties
    channels: ChannelConfig,
    /// The global MAC key for authenticating bit shares
    global_mac_key: Option<MacKey>,
    /// The circuit to be evaluated during the multi-party computation
    circuit: Circuit,
    /// A source of random bytes and bits local to the party
    entropy: Randomness,
    /// Tracks the current phase of protocol execution
    current_phase: ProtocolPhase,
}

#[allow(dead_code)] // TODO: Remove this later.
impl Party {
    /// Initialize an MPC party.
    pub fn new(channels: ChannelConfig, circuit: &Circuit, entropy: Randomness) -> Self {
        Self {
            id: channels.id,
            channels,
            global_mac_key: None,
            circuit: circuit.clone(),
            entropy,
            current_phase: ProtocolPhase::PreInit,
        }
    }

    /// Return `true`, if the party is the designated circuit evaluator.
    fn is_evaluator(&self) -> bool {
        self.id == 0
    }

    /// Send a message to the subprotocol channel.
    fn subprotocol(&mut self, message: MPCMessage) {
        self.channels.subprotocol.send(message).unwrap();
        let msg = self.channels.listen.recv().unwrap();
        self.process_message(msg);
    }

    /// Send a message to the evaluator.
    fn send_to_evaluator(&mut self, message: MPCMessage) {
        self.channels.evaluator.send(message).unwrap();
    }

    /// Participate in a full communication round between all parties.
    ///
    /// Communication turn-order is determined by the parties `id`, i.e. earlier
    /// `id`s send before later `id`s.
    fn full_round(&mut self, round_function: fn(usize, usize) -> MPCMessage) {
        let num_parties = self.channels.parties.len();

        // Expect earlier parties' messages.
        for _i in 0..self.id {
            let msg = self.channels.listen.recv().unwrap();
            self.process_message(msg);
        }

        // All earlier messages have been received, so it is the parties' turn
        // to send messages to everyone, except itself.
        for i in 0..num_parties {
            if i == self.id {
                continue;
            }

            self.channels.parties[i]
                .send(round_function(self.id, i))
                .unwrap();
        }

        // Wait for the messages sent by later parties.
        for _i in self.id + 1..num_parties {
            let msg = self.channels.listen.recv().unwrap();
            self.process_message(msg);
        }
    }

    /// Process an incoming message.
    fn process_message(&mut self, msg: MPCMessage) {
        match msg {
            _ => todo!(),
        }
    }

    /// Run the function independent pre-processing phase of the protocol.
    pub fn function_independent(&mut self) {
        todo!("the function-independent pre-processing phase is not yet implemented (cf. GitHub issue #51")
    }

    /// Run the function-dependent pre-processing phase of the protocol.
    pub fn function_dependent(&mut self) {
        todo!("the function-dependent pre-processing phase is not yet implemented (cf. GitHub issue #51")
    }

    /// Run the input-processing phase of the protocol.
    pub fn input_processing(&mut self) {
        todo!("the input processing phase is not yet implemented (cf. GitHub issue #52")
    }

    /// Run the circuit evaluation phase of the protocol.
    pub fn evaluate_circuit(&mut self) {
        todo!("the circuit evaluation phase is not yet implemented (cf. GitHub issue #54")
    }

    /// Run the output processing phase of the protocol
    pub fn output_processing(&mut self) {
        todo!("the output processing phase is not yet implemented (cf. GitHub issue #53")
    }

    /// Run the MPC protocol, returning the parties output, if any.
    pub fn run(&mut self) -> Result<Option<Vec<bool>>, Error> {
        self.log("Nothing to do, yet!");
        Ok(None)
    }

    /// Utility function to provide debug output during the protocol run.
    fn log(&self, message: &str) {
        eprintln!(
            "Party {} in phase {:?}: {}",
            self.id, self.current_phase, message
        );
    }
}

//! This module implements the preprocessing phase as an ideal functionality.
use super::rand::Randomness;
use super::IdealFPreChannelConfig;
use crate::party::ProtocolPhase;
use crate::primitives::mac::MacKey;
use crate::Error;

/// An ideal functionality implementation of the preprocessing subprotocol.
#[allow(dead_code)] // TODO: Remove this later.
pub struct FPre {
    pub(crate) channels: IdealFPreChannelConfig,
    pub(crate) entropy: Randomness,
    pub(crate) global_mac_keys: Vec<Option<MacKey>>,
    pub(crate) current_phase: ProtocolPhase,
}

impl FPre {
    /// Initialize the ideal functionality.
    pub fn new(channels: IdealFPreChannelConfig, entropy: Randomness) -> Self {
        let num_parties = channels.parties_send.len();
        Self {
            channels,
            entropy,
            global_mac_keys: { vec![None; num_parties] },
            current_phase: ProtocolPhase::PreInit,
        }
    }
    /// Run the FPre functionality in the MPC protocol.
    pub fn run(&mut self) -> Result<Option<Vec<bool>>, Error> {
        self.log("Nothing to do, yet!");
        Ok(None)
    }

    /// Handle party initialization.
    pub fn init_parties(&mut self) -> Result<(), Error> {
        todo!("Ideal functionality not yet implemented")
    }

    /// Utility function to provide debug output during the protocol run.
    pub(crate) fn log(&self, message: &str) {
        eprintln!(
            "Ideal Functionality FPre in phase {:?}: {}",
            self.current_phase, message
        );
    }
}

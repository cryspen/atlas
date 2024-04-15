//! This module implements "The Simplest Oblivious Transfer" due to Orlandi and Chou.

use hacspec_lib::Randomness;

use crate::Error;

/// The OT sender's first message.
pub enum OTSender_first {
    /// The sender's first message.
    s(p256::P256Point),
}

/// The OT receiver's first message.
pub enum OTReceiver_first {
    /// An elliptic curve point.
    r(p256::P256Point),
}

/// The OT sender's second message.
pub enum OTSender_second {
    /// Encryption of the left OT input.
    e_left, // encryption
    /// Encryption of the right OT input.
    e_right, // encryption
}

/// Generate the first sender message.
pub fn sender_first(
    entropy: &mut Randomness,
    left: u8,
    right: u8,
) -> Result<OTSender_first, Error> {
    let dst = b"test";
    let y = p256::random_scalar(entropy, dst)?;

    todo!()
}

/// Generate the first receiver message.
pub fn receiver_first(sender_message: OTSender_first, choose_left: bool) -> OTReceiver_first {
    todo!()
}

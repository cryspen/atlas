//! The KOS OT extension

use std::sync::mpsc::{Receiver, Sender};

use hacspec_lib::Randomness;

use crate::messages::SubMessage;

use super::mac::Mac;

#[derive(Debug)]
/// An Error in the KOS OT extension
pub enum Error {}

#[allow(unreachable_code)]
pub(crate) fn kos_receive(
    selection: &[bool],
    sender_address: Sender<SubMessage>,
    my_inbox: Receiver<SubMessage>,
    receiver_id: usize,
    sender_id: usize,
    entropy: &mut Randomness,
) -> Result<Vec<Mac>, Error> {
    todo!()
}

fn kos_dst(sender_id: usize, receiver_id: usize) -> String {
    format!("KOS-Base-OT-{}-{}", sender_id, receiver_id)
}

pub(crate) fn kos_send(
    receiver_address: Sender<SubMessage>,
    my_inbox: Receiver<SubMessage>,
    receiver_id: usize,
    sender_id: usize,
    inputs: &[(Mac, Mac)],
    entropy: &mut Randomness,
) -> Result<(), Error> {
    todo!()
}

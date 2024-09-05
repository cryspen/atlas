//! The KOS OT extension
//!
//! Computational security parameter is fixed to 128.

#![allow(non_snake_case)]
use std::sync::mpsc::{Receiver, Sender};

use hacspec_lib::Randomness;
use hmac::{hkdf_expand, hkdf_extract};

use crate::{
    messages::SubMessage,
    primitives::{kos_base, mac::zero_mac},
    utils::{ith_bit, pack_bits, xor_slices},
};

use super::{
    kos_base::{BaseOTReceiver, BaseOTSender, ReceiverChoose, ReceiverResponse, SenderTransfer},
    mac::{xor_mac_width, Mac, MAC_LENGTH},
};

const BASE_OT_LEN: usize = 128;

#[derive(Debug)]
/// An Error in the KOS OT extension
pub enum Error {
    /// An Error that occurred in the BaseOT.
    BaseOTError,
    /// A consistency check has failed.
    Consistency,
}

impl From<crate::primitives::kos_base::Error> for Error {
    fn from(_value: crate::primitives::kos_base::Error) -> Self {
        Self::BaseOTError
    }
}

/// Implements a tweakable correlation robust hash function.
///
/// Note: This could also be implemented as
///
///   H(sid|tweak|input) = pi(pi(sid|input) xor tweak) xor pi(sid|input)
///
/// where pi is an ideal permutation, fixed-key AES in practice.
fn CRF(sid: &[u8], input: &Mac, tweak: usize) -> Mac {
    let mut ikm = sid.to_vec();
    ikm.extend_from_slice(&[tweak as u8]);
    ikm.extend_from_slice(input);
    let prk = hkdf_extract(b"", &ikm);
    let result = hkdf_expand(&prk, sid, MAC_LENGTH)
        .try_into()
        .expect("should have received exactly `MAC_LENGTH` bytes");
    result
}

fn PRG(sid: &[u8], k: &[u8], len: usize) -> Vec<u8> {
    let mut ikm = sid.to_vec();
    ikm.extend_from_slice(k);
    let prk = hkdf_extract(b"", &ikm);
    let result = hkdf_expand(&prk, sid, len);

    result
}

fn FRO2(sid: &[u8], matrix: &[Vec<u8>; 128]) -> Vec<u128> {
    let mut ikm = sid.to_vec();
    let out_len = matrix[0].len();
    for column in matrix {
        ikm.extend_from_slice(column)
    }
    let prk = hkdf_extract(b"", &ikm);
    let result_bytes = hkdf_expand(&prk, sid, out_len * 8 * 16);
    let result = result_bytes
        .chunks_exact(16)
        .map(|chunk| {
            u128::from_be_bytes(
                chunk
                    .try_into()
                    .expect("should be given exactly 16 byte chunks"),
            )
        })
        .collect();
    result
}

/// This implements Xor_{j in [m+k]} (Chi_j * M_j).
/// `selection_matrix` is the whole matrix given as a vector of columns.
fn challenge_selection(challenge: &[u128], selection_matrix: &[Vec<u8>; 128]) -> u128 {
    let mut result = 0u128;
    for i in 0..challenge.len() {
        result ^= challenge[i] & packed_row(selection_matrix, i);
    }
    result
}

/// Pack all the bits in a row into a `u128`.
/// `matrix` is the whole matrix given as a vector of columns.
fn packed_row(matrix: &[Vec<u8>; 128], row_index: usize) -> u128 {
    let mut result = 0u128;
    for column in 0..128 {
        let b = ith_bit(row_index, &matrix[column]);
        if b {
            result |= 1 << (127 - column);
        }
    }
    result
}

fn kos_dst(sender_id: usize, receiver_id: usize) -> Vec<u8> {
    format!("KOS-Base-OT-{}-{}", sender_id, receiver_id)
        .as_bytes()
        .to_vec()
}

/// The message sent by the KOS15 Receiver in phase I of the protocol.
#[derive(Debug)]
pub struct KOSReceiverPhaseI {
    base_ot_transfer: SenderTransfer<BASE_OT_LEN>,
    D: [Vec<u8>; 128],
    u: u128,
    v: u128,
}

/// The KOS Receiver state.
pub struct KOSReceiver {
    selection_bits: Vec<bool>,
    base_sender: BaseOTSender<BASE_OT_LEN>,
    M_columns: [Vec<u8>; 128],
    sid: Vec<u8>,
    requested_len: usize,
}

impl KOSReceiver {
    /// `selection.len` must  be a multiple of 8
    pub(crate) fn phase_i(
        selection: &[bool],
        sender_phase_i: KOSSenderPhaseI,
        sid: &[u8],
        entropy: &mut Randomness,
    ) -> Result<(Self, KOSReceiverPhaseI), Error> {
        let requested_len = selection.len();
        // Extend selection lenght to next multiple of 8.
        let mut selection_padded = vec![false; padded_len(selection.len())];
        selection_padded[0..selection.len()].copy_from_slice(&selection);
        let selection = selection_padded.as_slice();
        let (base_sender, base_sender_transfer) = kos_base::BaseOTSender::<BASE_OT_LEN>::transfer(
            entropy,
            &sid,
            sender_phase_i.base_ot_choice,
        );
        match base_sender.inputs {
            Some(base_sender_inputs) => {
                let tau = entropy.bytes(128 / 8).unwrap();
                let mut r_prime = crate::utils::pack_bits(selection);
                r_prime.extend_from_slice(&tau);

                let M_columns: [Vec<u8>; 128] = std::array::from_fn(|i| {
                    PRG(&sid, &base_sender_inputs[i].0, 16 + selection.len() / 8)
                });

                               let R_columns: [Vec<u8>; 128] = std::array::from_fn(|_i| r_prime.clone());
                let D_columns: [Vec<u8>; 128] = std::array::from_fn(|i| {
                    let prg_result = PRG(&sid, &base_sender_inputs[i].1, 16 + selection.len() / 8);
                    let temp_result = crate::utils::xor_slices(&M_columns[i], &prg_result);
                    crate::utils::xor_slices(&temp_result, &R_columns[i])
                });

                let Chi = FRO2(&sid, &D_columns);

                let u = challenge_selection(&Chi, &M_columns);
                let v = challenge_selection(&Chi, &R_columns);

                Ok((
                    Self {
                        selection_bits: selection.to_owned(),
                        base_sender,
                        M_columns,
                        sid: sid.to_owned(),
                        requested_len,
                    },
                    KOSReceiverPhaseI {
                        base_ot_transfer: base_sender_transfer,
                        D: D_columns,
                        u,
                        v,
                    },
                ))
            }
            None => Err(Error::BaseOTError),
        }
    }

    fn phase_ii(self, sender_phase_ii: KOSSenderPhaseII) -> Result<Vec<[u8; 16]>, Error> {
        let mut results = Vec::new();
        self.base_sender.verify(sender_phase_ii.base_ot_response)?;
        for (index, selection_bit) in self.selection_bits.iter().enumerate() {
            let crf_input = packed_row(&self.M_columns, index).to_be_bytes();

            let crf = CRF(&self.sid, &crf_input, index);
            let y = if *selection_bit {
                sender_phase_ii.ys[index].1
            } else {
                sender_phase_ii.ys[index].0
            };
            let a = xor_mac_width(&y, &crf);
            results.push(a)
        }
        results.truncate(self.requested_len);
        Ok(results)
    }
}

pub(crate) struct KOSSender {
    base_receiver: BaseOTReceiver<BASE_OT_LEN>,
    sid: Vec<u8>,
}

/// The message sent by the KOS15 Sender in phase I of the protocol.
#[derive(Debug)]
pub struct KOSSenderPhaseI {
    base_ot_choice: ReceiverChoose<BASE_OT_LEN>,
}

/// The message sent by the KOS15 Sender in phase II of the protocol.
#[derive(Debug)]
pub struct KOSSenderPhaseII {
    ys: Vec<(Mac, Mac)>,
    base_ot_response: ReceiverResponse,
}

fn padded_len(len: usize) -> usize {
    if len % 8 == 0 {
        len
    } else {
        len + 8 - len % 8
    }
}

impl KOSSender {
    pub(crate) fn phase_i(sid: &[u8], entropy: &mut Randomness) -> (Self, KOSSenderPhaseI) {
        let (base_receiver, base_ot_choice) =
            crate::primitives::kos_base::BaseOTReceiver::<BASE_OT_LEN>::choose(entropy, &sid);

        (
            Self {
                sid: sid.to_owned(),
                base_receiver,
            },
            KOSSenderPhaseI { base_ot_choice },
        )
    }

    fn check_uvw(u: u128, v: u128, w: u128, s: u128) -> Result<(), Error> {
        if w == u ^ (s & v) {
            Ok(())
        } else {
            Err(Error::Consistency)
        }
    }

    /// `inputs.len()` must be a multiple of 8.
    fn phase_ii(
        &mut self,
        inputs: &[(Mac, Mac)],
        receiver_phase_i: KOSReceiverPhaseI,
    ) -> Result<KOSSenderPhaseII, Error> {
        let mut inputs_padded = vec![(zero_mac(), zero_mac()); padded_len(inputs.len())];
        inputs_padded[0..inputs.len()].copy_from_slice(inputs);
        let inputs = inputs_padded.as_slice();
        
        let (base_receiver_output, base_ot_response) = self
            .base_receiver
            .response(receiver_phase_i.base_ot_transfer)
            .unwrap();


        match self.base_receiver.selection_bits {
            Some(base_selection_bits) => {
                let Q_columns: [Vec<u8>; 128] = std::array::from_fn(|i| {
                    let mut result =
                        PRG(&self.sid, &base_receiver_output[i], 16 + inputs.len() / 8);
                    // the following is obviously secret-dependent timing
                    if base_selection_bits[i] {
                        result = crate::utils::xor_slices(&result, &receiver_phase_i.D[i]);
                    }

                    result
                });

                let Chi = FRO2(&self.sid, &receiver_phase_i.D);

                let w = challenge_selection(&Chi, &Q_columns);

                let s = pack_bits(&base_selection_bits);

                let mut s_array = [0u8; 16];
                s_array.copy_from_slice(&s[..16]);

                Self::check_uvw(
                    receiver_phase_i.u,
                    receiver_phase_i.v,
                    w,
                    u128::from_be_bytes(s_array),
                )?;

                let mut ys = Vec::new();
                for (index, (a_0, a_1)) in inputs.iter().enumerate() {
                    let crf_input_0 = packed_row(&Q_columns, index).to_be_bytes();
                    let crf_input_1 = xor_slices(&packed_row(&Q_columns, index).to_be_bytes(), &s);

                    let crf_0 = CRF(&self.sid, &crf_input_0, index);
                    let crf_1 = CRF(&self.sid, &crf_input_1.try_into().unwrap(), index);

                    let y_0 = xor_mac_width(a_0, &crf_0);
                    let y_1 = xor_mac_width(a_1, &crf_1);
                    ys.push((y_0, y_1))
                }

                Ok(KOSSenderPhaseII {
                    ys,
                    base_ot_response,
                })
            }
            None => Err(Error::BaseOTError),
        }
    }
}

/// Run the KOS15 protocol in the role of the receiver.
///
/// Uses the given Channels to communicate the KOS messages from the
/// perspective of the receiver. The input `selection` determines
/// which of the senders inputs get obliviously transfered to the
/// receiver.
pub(crate) fn kos_receive(
    selection: &[bool],
    sender_address: Sender<SubMessage>,
    my_inbox: Receiver<SubMessage>,
    receiver_id: usize,
    sender_id: usize,
    entropy: &mut Randomness,
) -> Result<Vec<Mac>, crate::Error> {
    let sid = kos_dst(receiver_id, sender_id);

    let sender_phase_i_msg = my_inbox.recv().unwrap();
    if let SubMessage::KOSSenderPhaseI(sender_phase_i) = sender_phase_i_msg {
        let (receiver, phase_i) =
            KOSReceiver::phase_i(selection, sender_phase_i, &sid, entropy).unwrap();
        sender_address
            .send(SubMessage::KOSReceiverPhaseI(phase_i))
            .unwrap();
        let sender_phase_ii_msg = my_inbox.recv().unwrap();
        if let SubMessage::KOSSenderPhaseII(sender_phase_ii) = sender_phase_ii_msg {
            let outputs = receiver.phase_ii(sender_phase_ii).unwrap();

            Ok(outputs)
        } else {
            Err(crate::Error::UnexpectedSubprotocolMessage(
                sender_phase_ii_msg,
            ))
        }
    } else {
        Err(crate::Error::UnexpectedSubprotocolMessage(
            sender_phase_i_msg,
        ))
    }
}

/// Run the KOS15 protocol in the role of the sender.
///
/// Uses the given Channels to communicate the KOS messages from the
/// perspective of the sender. The receiver's input `selection`
/// determines which of the senders inputs get obliviously transfered
/// to the receiver.
pub(crate) fn kos_send(
    inputs: &[(Mac, Mac)],
    receiver_address: Sender<SubMessage>,
    my_inbox: Receiver<SubMessage>,
    receiver_id: usize,
    sender_id: usize,
    entropy: &mut Randomness,
) -> Result<(), crate::Error> {
    let sid = kos_dst(sender_id, receiver_id);

    let (mut kos_sender, phase_i) = KOSSender::phase_i(&sid, entropy);
    receiver_address
        .send(SubMessage::KOSSenderPhaseI(phase_i))
        .unwrap();
    let receiver_phase_i_message = my_inbox.recv().unwrap();
    if let SubMessage::KOSReceiverPhaseI(receiver_phase_i) = receiver_phase_i_message {
        let phase_ii = kos_sender.phase_ii(inputs, receiver_phase_i).unwrap();
        receiver_address
            .send(SubMessage::KOSSenderPhaseII(phase_ii))
            .unwrap();
        Ok(())
    } else {
        Err(crate::Error::UnexpectedSubprotocolMessage(
            receiver_phase_i_message,
        ))
    }
}

#[test]
fn kos_simple() {
    // pre-requisites
    use rand::{thread_rng, RngCore};
    let sid = b"test";
    let mut rng = thread_rng();
    let mut entropy = [0u8; 100000];
    rng.fill_bytes(&mut entropy);
    let mut entropy = Randomness::new(entropy.to_vec());

    let selection = [true, false, true, false, true, false, true];
    let inputs = [
        ([2u8; 16], [1u8; 16]),
        ([2u8; 16], [1u8; 16]),
        ([2u8; 16], [1u8; 16]),
        ([2u8; 16], [1u8; 16]),
        ([2u8; 16], [1u8; 16]),
        ([2u8; 16], [1u8; 16]),
        ([2u8; 16], [1u8; 16]),
    ];

    let (mut sender, sender_phase_i) = KOSSender::phase_i(sid, &mut entropy);
    eprintln!("Sender Phase I complete");

    let (receiver, receiver_phase_i) =
        KOSReceiver::phase_i(&selection, sender_phase_i, sid, &mut entropy).unwrap();
    eprintln!("Receiver Phase I complete");

    let sender_phase_ii = sender.phase_ii(&inputs, receiver_phase_i).unwrap();
    eprintln!("Sender Phase II complete");

    let receiver_outputs = receiver.phase_ii(sender_phase_ii).unwrap();
    eprintln!("Receiver Phase II complete");

    assert_eq!(receiver_outputs[0], [1u8; 16]);
    assert_eq!(receiver_outputs[1], [2u8; 16]);
    assert_eq!(receiver_outputs[2], [1u8; 16]);
    assert_eq!(receiver_outputs[3], [2u8; 16]);
    assert_eq!(receiver_outputs[4], [1u8; 16]);
    assert_eq!(receiver_outputs[5], [2u8; 16]);
    assert_eq!(receiver_outputs[6], [1u8; 16]);

}

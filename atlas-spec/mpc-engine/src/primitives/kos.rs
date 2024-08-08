//! The KOS OT extension
//!
//! Computational security parameter is fixed to 128.

#![allow(non_snake_case)]
use std::sync::mpsc::{Receiver, Sender};

use hacspec_lib::Randomness;
use hmac::{hkdf_expand, hkdf_extract};

use crate::{
    messages::SubMessage,
    primitives::kos_base,
    utils::{ith_bit, pack_bits},
};

use super::{
    kos_base::{BaseOTReceiver, BaseOTSender, ReceiverChoose, ReceiverResponse, SenderTransfer},
    mac::{xor_mac_width, Mac, MAC_LENGTH},
};

// For light testing
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
fn challenge_selection(challenge: &[u128], selection_matrix: &[Vec<u8>; 128]) -> u128 {
    let mut result = 0u128;
    for i in 0..challenge.len() {
        result = result.wrapping_add(challenge[i].wrapping_mul(packed_row(selection_matrix, i)))
    }
    result
}

fn packed_row(matrix: &[Vec<u8>; 128], index: usize) -> u128 {
    let mut result = 0u128;
    for i in 0..128 {
        let b = ith_bit(index, &matrix[i]);
        if b {
            result += 1 << (i as u128);
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
}

impl KOSReceiver {
    /// `selection.len` must  be a multiple of 8
    pub(crate) fn phase_i(
        selection: &[bool],
        sender_phase_i: KOSSenderPhaseI,
        sid: &[u8],
        entropy: &mut Randomness,
    ) -> (Self, KOSReceiverPhaseI) {
        let (base_sender, base_sender_transfer) = kos_base::BaseOTSender::<BASE_OT_LEN>::transfer(
            entropy,
            &sid,
            sender_phase_i.base_ot_choice,
        );

        let tau = entropy.bytes(128 / 8).unwrap();
        let mut r_prime = crate::utils::pack_bits(selection);
        r_prime.extend_from_slice(&tau);
        let M_columns: [Vec<u8>; 128] =
            std::array::from_fn(|i| PRG(&sid, &base_sender.inputs[i].0, 16 + selection.len() / 8));
        let R_columns: [Vec<u8>; 128] = std::array::from_fn(|_i| r_prime.clone());
        let D_columns: [Vec<u8>; 128] = std::array::from_fn(|i| {
            let prg_result = PRG(&sid, &base_sender.inputs[i].1, 16 + selection.len() / 8);
            let temp_result = crate::utils::xor_slices(&M_columns[i], &prg_result);
            crate::utils::xor_slices(&temp_result, &R_columns[i])
        });

        debug_assert_eq!(M_columns[0].len(), R_columns[0].len());
        debug_assert_eq!(D_columns[0].len(), R_columns[0].len());

        let Chi = FRO2(&sid, &D_columns);

        let u = challenge_selection(&Chi, &M_columns);
        let v = challenge_selection(&Chi, &R_columns);

        (
            Self {
                selection_bits: selection.to_owned(),
                base_sender,
                M_columns,
                sid: sid.to_owned(),
            },
            KOSReceiverPhaseI {
                base_ot_transfer: base_sender_transfer,
                D: D_columns,
                u,
                v,
            },
        )
    }

    fn phase_ii(self, sender_phase_ii: KOSSenderPhaseII) -> Result<Vec<[u8; 16]>, Error> {
        let mut results = Vec::new();
        self.base_sender.verify(sender_phase_ii.base_ot_response)?;
        for (index, selection_bit) in self.selection_bits.iter().enumerate() {
            let crf = CRF(
                &self.sid,
                &packed_row(&self.M_columns, index).to_be_bytes(),
                index,
            );
            let y = if *selection_bit {
                sender_phase_ii.ys[index].1
            } else {
                sender_phase_ii.ys[index].0
            };
            let a = xor_mac_width(&y, &crf);
            results.push(a)
        }
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
        if w == u.wrapping_add(s.wrapping_mul(v)) {
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
        let (base_receiver_output, base_ot_response) = self
            .base_receiver
            .response(receiver_phase_i.base_ot_transfer)?;

        let Q_columns: [Vec<u8>; 128] = std::array::from_fn(|i| {
            let mut result = PRG(&self.sid, &base_receiver_output[i], 16 + inputs.len() / 8);
            // the following is obviously secret-dependent timing
            if self.base_receiver.selection_bits[i] {
                result = crate::utils::xor_slices(&result, &receiver_phase_i.D[i]);
            }
            result
        });

        let Chi = FRO2(&self.sid, &receiver_phase_i.D);

        let w = challenge_selection(&Chi, &Q_columns);
        let s = pack_bits(&self.base_receiver.selection_bits);
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
            let crf_0 = CRF(
                &self.sid,
                &packed_row(&Q_columns, index).to_be_bytes(),
                index,
            );
            let crf_1 = CRF(
                &self.sid,
                &xor_mac_width(&packed_row(&Q_columns, index).to_be_bytes(), &s_array),
                index,
            );
            let y_0 = xor_mac_width(a_0, &crf_0);
            let y_1 = xor_mac_width(a_1, &crf_1);
            ys.push((y_0, y_1))
        }

        Ok(KOSSenderPhaseII {
            ys,
            base_ot_response,
        })
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
    let sid = kos_dst(sender_id, receiver_id);

    let sender_phase_i_msg = my_inbox.recv().unwrap();
    if let SubMessage::KOSSenderPhaseI(sender_phase_i) = sender_phase_i_msg {
        let (receiver, phase_i) = KOSReceiver::phase_i(selection, sender_phase_i, &sid, entropy);
        sender_address
            .send(SubMessage::KOSReceiverPhaseI(phase_i))
            .unwrap();
        let sender_phase_ii_msg = my_inbox.recv().unwrap();
        if let SubMessage::KOSSenderPhaseII(sender_phase_ii) = sender_phase_ii_msg {
            let outputs = receiver
                .phase_ii(sender_phase_ii)
                .map_err(|_| crate::Error::SubprotocolError)?;
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
        let phase_ii = kos_sender
            .phase_ii(inputs, receiver_phase_i)
            .map_err(|_| crate::Error::SubprotocolError)?;
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

    let selection = [true, false, true, false, true, false, true, false];
    let inputs = [
        ([0u8; 16], [1u8; 16]),
        ([0u8; 16], [1u8; 16]),
        ([0u8; 16], [1u8; 16]),
        ([0u8; 16], [1u8; 16]),
        ([0u8; 16], [1u8; 16]),
        ([0u8; 16], [1u8; 16]),
        ([0u8; 16], [1u8; 16]),
        ([0u8; 16], [1u8; 16]),
    ];

    let (mut sender, sender_phase_i) = KOSSender::phase_i(sid, &mut entropy);
    eprintln!("Sender Phase I");

    let (receiver, receiver_phase_i) =
        KOSReceiver::phase_i(&selection, sender_phase_i, sid, &mut entropy);
    eprintln!("Receiver Phase I");

    let sender_phase_ii = sender.phase_ii(&inputs, receiver_phase_i).unwrap();
    eprintln!("Sender Phase II");

    let receiver_outputs = receiver.phase_ii(sender_phase_ii).unwrap();
    eprintln!("Receiver Phase II");

    assert_eq!(receiver_outputs[0], [1u8; 16]);
    assert_eq!(receiver_outputs[1], [0u8; 16]);
    assert_eq!(receiver_outputs[2], [1u8; 16]);
    assert_eq!(receiver_outputs[3], [0u8; 16]);
    assert_eq!(receiver_outputs[4], [1u8; 16]);
    assert_eq!(receiver_outputs[5], [0u8; 16]);
    assert_eq!(receiver_outputs[6], [1u8; 16]);
    assert_eq!(receiver_outputs[7], [0u8; 16]);
}

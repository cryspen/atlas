//! This module implements a base OT for the maliciously secure KOS15 OT extension.
//!
//! BaseOT taken from https://eprint.iacr.org/2020/110.pdf.
#![allow(non_snake_case)]
use std::ops::Neg;

use crate::COMPUTATIONAL_SECURITY;
use hacspec_lib::{hacspec_helper::NatMod, Randomness};
use hash_to_curve::p256_hash::hash_to_curve;
use hmac::{hkdf_expand, hkdf_extract};
use p256::{p256_point_mul, random_scalar, P256Point, P256Scalar};

use super::mac::MAC_LENGTH;
type BaseOTSeed = [u8; COMPUTATIONAL_SECURITY];

#[derive(Debug)]
pub enum Error {
    ReceiverAbort,
    SenderCheatDetected,
}

fn FRO1(seed: &[u8], dst: &[u8]) -> P256Point {
    let mut dst = dst.to_vec();
    dst.extend_from_slice(b"F1");
    hash_to_curve(seed, &dst).unwrap()
}

fn FRO2(point: &P256Point, dst: &[u8]) -> [u8; MAC_LENGTH] {
    let mut dst = dst.to_vec();
    dst.extend_from_slice(b"F2");
    let prk = hkdf_extract(b"", &point.raw_bytes());
    let result = hkdf_expand(&prk, &dst, COMPUTATIONAL_SECURITY);
    let mut result_array = [0u8; COMPUTATIONAL_SECURITY];
    result_array.copy_from_slice(&result);
    result_array
}

fn FRO3(sender_message: &[u8], dst: &[u8]) -> [u8; COMPUTATIONAL_SECURITY] {
    let mut dst = dst.to_vec();
    dst.extend_from_slice(b"F3");
    let prk = hkdf_extract(b"", sender_message);
    let result = hkdf_expand(&prk, &dst, COMPUTATIONAL_SECURITY);
    let mut result_array = [0u8; COMPUTATIONAL_SECURITY];
    result_array.copy_from_slice(&result);
    result_array
}

fn FRO4<const L: usize>(
    hashes: &[[u8; COMPUTATIONAL_SECURITY]; L],
    dst: &[u8],
) -> [u8; COMPUTATIONAL_SECURITY] {
    let mut dst = dst.to_vec();
    dst.extend_from_slice(b"F4");
    let mut input = Vec::new();
    for i in 0..L {
        input.extend_from_slice(&hashes[i]);
    }
    let prk = hkdf_extract(b"", &input);
    let result = hkdf_expand(&prk, &dst, COMPUTATIONAL_SECURITY);
    let mut result_array = [0u8; COMPUTATIONAL_SECURITY];
    result_array.copy_from_slice(&result);
    result_array
}

pub(crate) struct BaseOTReceiver<const L: usize> {
    sid: Vec<u8>,
    T: P256Point,
    pub selection_bits: Option<[bool; L]>,
    alphas: [P256Scalar; L],
}

pub(crate) struct BaseOTSender<const L: usize> {
    sid: Vec<u8>,
    r: P256Scalar,
    pub inputs: Option<[([u8; 16], [u8; 16]); L]>,
    expected_answer: [u8; 16],
    negTr: P256Point,
    chall_hashes: [[u8; COMPUTATIONAL_SECURITY]; L],
}

#[derive(Debug)]
pub(crate) struct ReceiverChoose<const L: usize> {
    seed: BaseOTSeed,
    messages: [P256Point; L],
}

#[derive(Debug)]
pub(crate) struct ReceiverResponse {
    response: [u8; 16],
}

#[derive(Debug)]
pub(crate) struct SenderTransfer<const L: usize> {
    seed: P256Point,
    challenge: [[u8; 16]; L],
    gamma: [u8; 16],
}

impl<const L: usize> BaseOTReceiver<L> {
    pub(crate) fn choose(entropy: &mut Randomness, sid: &[u8]) -> (Self, ReceiverChoose<L>) {
        let (mut receiver, seed) = Self::parameters(entropy, sid);
        let (bits, messages) = receiver.messages(entropy);
        receiver.selection_bits = Some(bits);
        (receiver, ReceiverChoose { seed, messages })
    }

    pub(crate) fn response(
        &self,
        transfer: SenderTransfer<L>,
    ) -> Result<([[u8; 16]; L], ReceiverResponse), Error> {
        let messages = self.decrypt(transfer.seed);

        match &self.selection_bits {
            Some(selection_bits) => {
                let response = self.responses(selection_bits, &messages, &transfer.challenge);
                self.challenge_verification(&response, &transfer.gamma)?;
                Ok((messages, ReceiverResponse { response }))
            }
            None => Err(Error::ReceiverAbort),
        }
    }

    fn parameters(entropy: &mut Randomness, sid: &[u8]) -> (Self, BaseOTSeed) {
        let mut seed_array = [0u8; COMPUTATIONAL_SECURITY];
        let seed = entropy.bytes(COMPUTATIONAL_SECURITY).unwrap().to_owned();
        seed_array.copy_from_slice(&seed);
        let alphas = [P256Scalar::zero(); L];

        let T = FRO1(&seed_array, sid);
        (
            Self {
                sid: sid.to_owned(),
                T,
                selection_bits: None,
                alphas,
            },
            seed_array,
        )
    }

    fn messages(&mut self, entropy: &mut Randomness) -> ([bool; L], [P256Point; L]) {
        let mut messages = [P256Point::AtInfinity; L];
        let bits: [bool; L] = std::array::from_fn(|_| entropy.bit().unwrap());
        for i in 0..L {
            self.alphas[i] = random_scalar(entropy, &self.sid).unwrap();
            messages[i] = p256::p256_point_mul_base(self.alphas[i]).unwrap();
            if bits[i] {
                messages[i] = p256::point_add(messages[i], self.T).unwrap();
            }
        }
        (bits, messages)
    }

    fn decrypt(&self, z: P256Point) -> [[u8; COMPUTATIONAL_SECURITY]; L] {
        let mut messages = [[0u8; COMPUTATIONAL_SECURITY]; L];
        for i in 0..L {
            let input = p256::p256_point_mul(self.alphas[i], z).unwrap();
            messages[i] = FRO2(&input, &self.sid);
        }
        messages
    }

    fn responses(
        &self,
        bits: &[bool; L],
        messages: &[[u8; MAC_LENGTH]; L],
        challenges: &[[u8; COMPUTATIONAL_SECURITY]; L],
    ) -> [u8; COMPUTATIONAL_SECURITY] {
        let mut responses = [[0u8; COMPUTATIONAL_SECURITY]; L];
        for i in 0..L {
            responses[i] = FRO3(&messages[i], &self.sid);
            if bits[i] {
                responses[i] = xor_arrays(&responses[i], &challenges[i]);
            }
        }
        FRO4(&responses, &self.sid)
    }

    fn challenge_verification(
        &self,
        Ans: &[u8; COMPUTATIONAL_SECURITY],
        gamma: &[u8; COMPUTATIONAL_SECURITY],
    ) -> Result<(), Error> {
        let gamma_prime = FRO3(Ans, &self.sid);
        if gamma_prime != *gamma {
            eprintln!("challenge verification failed");
            return Err(Error::ReceiverAbort);
        }
        Ok(())
    }
}

impl<const L: usize> BaseOTSender<L> {
    pub(crate) fn transfer(
        entropy: &mut Randomness,
        sid: &[u8],
        choice: ReceiverChoose<L>,
    ) -> (Self, SenderTransfer<L>) {
        let (mut sender, seed) = Self::parameters(entropy, sid, &choice.seed);
        let inputs = sender.generate_inputs(choice.messages);
        let challenge = sender.challenges(&inputs);
        sender.inputs = Some(inputs);
        let (expected_answer, gamma) = sender.proof();
        sender.expected_answer = expected_answer;
        (
            sender,
            SenderTransfer {
                seed,
                challenge,
                gamma,
            },
        )
    }

    pub(crate) fn verify(&self, response: ReceiverResponse) -> Result<(), Error> {
        if response.response != self.expected_answer {
            Err(Error::SenderCheatDetected)
        } else {
            Ok(())
        }
    }

    fn parameters(entropy: &mut Randomness, sid: &[u8], seed: &BaseOTSeed) -> (Self, P256Point) {
        let T = FRO1(seed, sid);
        let r = random_scalar(entropy, sid).unwrap();
        let negTr = p256::p256_point_mul(r, T).unwrap().neg();
        let chall_hashes = [[0u8; COMPUTATIONAL_SECURITY]; L];
        let z = p256::p256_point_mul_base(r).unwrap();
        (
            Self {
                sid: sid.to_owned().into(),
                chall_hashes,
                r,
                negTr,
                inputs: None,
                expected_answer: [0u8; 16],
            },
            z,
        )
    }

    fn generate_inputs(
        &self,
        receiver_messages: [P256Point; L],
    ) -> [([u8; MAC_LENGTH], [u8; MAC_LENGTH]); L] {
        let mut messages = [([0u8; MAC_LENGTH], [0u8; MAC_LENGTH]); L];
        for i in 0..L {
            let preimg_0 = p256_point_mul(self.r, receiver_messages[i]).unwrap();
            let preimg_1 = p256::point_add(self.negTr, preimg_0).unwrap();
            let pi_0 = FRO2(&preimg_0, &self.sid);
            let pi_1 = FRO2(&preimg_1, &self.sid);
            messages[i] = (pi_0, pi_1);
        }

        messages
    }

    fn challenges(
        &mut self,
        messages: &[([u8; MAC_LENGTH], [u8; MAC_LENGTH]); L],
    ) -> [[u8; COMPUTATIONAL_SECURITY]; L] {
        let mut challenges = [[0u8; COMPUTATIONAL_SECURITY]; L];
        for i in 0..L {
            let chall_hash_0 = FRO3(&messages[i].0, &self.sid);
            let chall_hash_1 = FRO3(&messages[i].1, &self.sid);
            self.chall_hashes[i] = chall_hash_0;
            challenges[i] = xor_arrays(&chall_hash_0, &chall_hash_1);
        }
        challenges
    }

    fn proof(&self) -> ([u8; COMPUTATIONAL_SECURITY], [u8; COMPUTATIONAL_SECURITY]) {
        let expected_answer = FRO4(&self.chall_hashes, &self.sid);
        let gamma = FRO3(&expected_answer, &self.sid);
        (expected_answer, gamma)
    }
}

fn xor_arrays<const L: usize>(a: &[u8; L], b: &[u8; L]) -> [u8; L] {
    let mut result = [0u8; L];
    for i in 0..L {
        result[i] = a[i] ^ b[i];
    }
    result
}

#[test]
fn kos_base_simple() {
    // pre-requisites
    use rand::{thread_rng, RngCore};
    let sid = b"test";
    let mut rng = thread_rng();
    let mut entropy = [0u8; 100000];
    rng.fill_bytes(&mut entropy);
    let mut entropy = Randomness::new(entropy.to_vec());

    let (receiver, choice_message) = BaseOTReceiver::<5>::choose(&mut entropy, sid);

    let (sender, transfer_message) = BaseOTSender::<5>::transfer(&mut entropy, sid, choice_message);

    let (receiver_outputs, response) = receiver.response(transfer_message).unwrap();

    sender.verify(response).unwrap();

    let selection_bits = receiver.selection_bits.unwrap();

    for (i, selection_bit) in selection_bits.iter().enumerate() {
        eprintln! {"{i}:\n\tInput 0: {:?}\n\tInput 1: {:?}\n\tSelection bit: {:?}\n\tOutput: {:?}", sender.inputs.unwrap()[i].0, sender.inputs.unwrap()[i].1, selection_bit, receiver_outputs[i]};
        assert_eq!(
            receiver_outputs[i],
            if *selection_bit {
                sender.inputs.unwrap()[i].1
            } else {
                sender.inputs.unwrap()[i].0
            }
        )
    }
}

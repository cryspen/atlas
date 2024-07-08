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
enum Error {
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
    bits: [bool; L],
    alphas: [P256Scalar; L],
}

pub(crate) struct BaseOTSender<const L: usize> {
    sid: Vec<u8>,
    r: P256Scalar,
    negTr: P256Point,
    chall_hashes: [[u8; COMPUTATIONAL_SECURITY]; L],
}

impl<const L: usize> BaseOTReceiver<L> {
    pub(crate) fn init(entropy: &mut Randomness, sid: &[u8]) -> (Self, BaseOTSeed) {
        let mut seed_array = [0u8; COMPUTATIONAL_SECURITY];
        let seed = entropy.bytes(COMPUTATIONAL_SECURITY).unwrap().to_owned();
        seed_array.copy_from_slice(&seed);
        let bits = [false; L];
        let alphas = [P256Scalar::zero(); L];

        let T = FRO1(&seed_array, sid);
        (
            Self {
                sid: sid.to_owned(),
                T,
                bits,
                alphas,
            },
            seed_array,
        )
    }

    pub(crate) fn messages(&mut self, entropy: &mut Randomness) -> [P256Point; L] {
        let mut messages = [P256Point::AtInfinity; L];
        for i in 0..L {
            self.bits[i] = entropy.bit().unwrap();
            self.alphas[i] = random_scalar(entropy, &self.sid).unwrap();
            messages[i] = p256::p256_point_mul_base(self.alphas[i]).unwrap();
            if self.bits[i] {
                messages[i] = p256::point_add(messages[i], self.T).unwrap();
            }
        }
        messages
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
        messages: &[[u8; MAC_LENGTH]; L],
        challenges: &[[u8; COMPUTATIONAL_SECURITY]; L],
    ) -> [u8; COMPUTATIONAL_SECURITY] {
        let mut responses = [[0u8; COMPUTATIONAL_SECURITY]; L];
        for i in 0..L {
            responses[i] = FRO3(&messages[i], &self.sid);
            if self.bits[i] {
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
            return Err(Error::ReceiverAbort);
        }
        Ok(())
    }
}

impl<const L: usize> BaseOTSender<L> {
    pub(crate) fn init(
        entropy: &mut Randomness,
        sid: &[u8],
        seed: &BaseOTSeed,
    ) -> (Self, P256Point) {
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
            },
            z,
        )
    }

    pub(crate) fn messages(
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
        let Ans = FRO4(&self.chall_hashes, &self.sid);
        let gamma = FRO3(&Ans, &self.sid);
        (Ans, gamma)
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
fn simple() {
    use rand::{thread_rng, RngCore};
    let sid = b"test";
    let mut rng = thread_rng();
    let mut entropy = [0u8; 100000];
    rng.fill_bytes(&mut entropy);
    let mut entropy = Randomness::new(entropy.to_vec());
    let (mut receiver, seed) = BaseOTReceiver::<5>::init(&mut entropy, sid);
    let receiver_messages = receiver.messages(&mut entropy);

    let (mut sender, sender_parameter) = BaseOTSender::<5>::init(&mut entropy, sid, &seed);
    let sender_messages = sender.messages(receiver_messages);
    let challenges = sender.challenges(&sender_messages);
    let (Ans_sender, gamma) = sender.proof();

    let decryptions = receiver.decrypt(sender_parameter);
    let Ans_receiver = receiver.responses(&decryptions, &challenges);
    receiver
        .challenge_verification(&Ans_receiver, &gamma)
        .unwrap();
    assert_eq!(Ans_receiver, Ans_sender)
}

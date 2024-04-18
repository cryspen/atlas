//! This module implements "The Simplest Protocol for Oblivious Transfer" due to
//! Orlandi and Chou.
//! (cf. https://eprint.iacr.org/archive/2015/267/1527602042.pdf)
//!
//! The protocol works as follows in an elliptic curve group G with base point `B` and scalars `Scalars`
//!
//! ```text
//! Sender(l, r)            Receiver(c)
//! y <-$ Scalars
//! S := yB
//! T := yS    -- S -->     x <-$ Scalars
//!                         R := cS + xB
//!            <-- R --
//! k_l                     k = H(S, R, xS)
//!  = H(S, R, yR)       
//! k_r
//!  = H(S, R, yR - T)
//!
//! c_l = E(k_l, l)
//! c_r = E(k_r, r)
//!
//!          -- c_l -->
//!          -- c_r -->     output = D(k, c_l) if decryption successful
//!                         otherwise output = D(k, c_r)
//! ```
//! We instantiate the primitives as follows:
//!     - H: HKDF(SHA-256)
//!     - group G: P256
//!     - Encryption scheme: Chacha20Poly1305

use hacspec_chacha20poly1305::{ChaChaPolyIV, ChaChaPolyKey};
use hacspec_lib::Randomness;
use p256::{p256_point_mul, p256_point_mul_base, P256Point};

use crate::Error;

/// The state of the sender
pub struct OTSender {
    y: p256::P256Scalar,
    s: p256::P256Point,
    t: p256::P256Point,
    dst: Vec<u8>,
}

/// The state of the receiver
pub struct OTReceiver {
    x: p256::P256Scalar,
    r: p256::P256Point,
    s: P256Point,
    dst: Vec<u8>,
}

/// The OT sender's first message.
#[derive(Debug)]
pub struct OTSenderInit(p256::P256Point);

/// The OT receiver's first message.
#[derive(Debug)]
pub struct OTReceiverSelect(p256::P256Point);

/// The encryption of an OT input.
#[derive(Debug)]
pub struct OTCiphertext {
    iv: ChaChaPolyIV,
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}
/// The OT sender's second message.
#[derive(Debug)]
pub struct OTSenderSend {
    left: OTCiphertext,
    right: OTCiphertext,
}

impl OTSender {
    /// Generate the first sender message.
    pub fn init(entropy: &mut Randomness, dst: &[u8]) -> Result<(Self, OTSenderInit), Error> {
        let y = p256::random_scalar(entropy, dst)?;

        let s = p256::p256_point_mul_base(y)?;
        let t = p256_point_mul(y, s)?;

        Ok((
            OTSender {
                y,
                s,
                t,
                dst: dst.to_vec(),
            },
            OTSenderInit(s),
        ))
    }

    /// Generate the second sender message based on the receiver's selection.
    pub fn send(
        &self,
        left_input: &[u8],
        right_input: &[u8],
        selection: &OTReceiverSelect,
        entropy: &mut Randomness,
    ) -> Result<OTSenderSend, Error> {
        assert_eq!(
            left_input.len(),
            right_input.len(),
            "Left and right inputs to the OT must be of the same length."
        );
        let OTReceiverSelect(r) = selection;

        let (left_key, right_key) = self.derive_keys(r)?;

        let (left, right) = encrypt_inputs(entropy, left_key, left_input, right_key, right_input)?;

        Ok(OTSenderSend { left, right })
    }

    fn derive_keys(
        &self,
        receiver_selection: &p256::P256Point,
    ) -> Result<(ChaChaPolyKey, ChaChaPolyKey), Error> {
        let (salt, ikm) = derive_prk(&self.s, receiver_selection);

        let input_right = p256_point_mul(self.y, *receiver_selection)?;

        let input_left = p256::point_add(input_right, -self.t)?;

        let input_left_serialized = p256::serialize_point(&input_left);
        let input_right_serialized = p256::serialize_point(&input_right);

        let mut ikm_left = ikm.clone();
        let mut ikm_right = ikm;

        ikm_left.extend_from_slice(&input_left_serialized);
        ikm_right.extend_from_slice(&input_right_serialized);

        let prk_left = hmac::hkdf_extract(&salt, &ikm_left);
        let prk_right = hmac::hkdf_extract(&salt, &ikm_right);
        Ok((
            hmac::hkdf_expand(&prk_left, &self.dst, 32)
                .try_into()
                .unwrap(),
            hmac::hkdf_expand(&prk_right, &self.dst, 32)
                .try_into()
                .unwrap(),
        ))
    }
}

fn derive_prk(
    sender_commitment: &p256::P256Point,
    receiver_selection: &p256::P256Point,
) -> (Vec<u8>, Vec<u8>) {
    let serialized_s = p256::serialize_point(sender_commitment);
    let serialized_r = p256::serialize_point(receiver_selection);
    let salt = b"no-salt";
    let mut ikm = Vec::from(serialized_s);
    ikm.extend_from_slice(&serialized_r);
    (salt.to_vec(), ikm)
}

fn encrypt_inputs(
    entropy: &mut Randomness,
    left_key: [u8; 32],
    left_input: &[u8],
    right_key: [u8; 32],
    right_input: &[u8],
) -> Result<(OTCiphertext, OTCiphertext), Error> {
    let left_iv = entropy
        .bytes(12)?
        .try_into()
        .expect("should have received 12 bytes of randomness");
    let right_iv = entropy
        .bytes(12)?
        .try_into()
        .expect("should have received 12 bytes of randomness");
    let (left_enc, left_tag) =
        hacspec_chacha20poly1305::chacha20_poly1305_encrypt(left_key, left_iv, &[], left_input);
    let (right_enc, right_tag) =
        hacspec_chacha20poly1305::chacha20_poly1305_encrypt(right_key, right_iv, &[], right_input);
    Ok((
        OTCiphertext {
            iv: left_iv,
            ciphertext: left_enc,
            tag: left_tag,
        },
        OTCiphertext {
            iv: right_iv,
            ciphertext: right_enc,
            tag: right_tag,
        },
    ))
}

impl OTReceiver {
    /// Generate the first receiver message.
    pub fn select(
        entropy: &mut Randomness,
        dst: &[u8],
        sender_message: OTSenderInit,
        choose_left: bool,
    ) -> Result<(Self, OTReceiverSelect), Error> {
        let x = p256::random_scalar(entropy, dst)?;
        let OTSenderInit(s) = sender_message;

        let mut res = p256_point_mul_base(x)?;
        let r = if choose_left {
            res = p256::point_add(res, s)?;
            res
        } else {
            res
        };

        Ok((
            OTReceiver {
                x,
                r,
                s,
                dst: dst.to_vec(),
            },
            OTReceiverSelect(r),
        ))
    }

    /// Receive the selected input from the sender.
    pub fn receive(&self, sender_message: OTSenderSend) -> Result<Vec<u8>, Error> {
        let key = self.derive_key()?;

        let dec = hacspec_chacha20poly1305::chacha20_poly1305_decrypt(
            key,
            sender_message.left.iv,
            &[],
            &sender_message.left.ciphertext,
            sender_message.left.tag,
        )
        .or_else(|_| {
            hacspec_chacha20poly1305::chacha20_poly1305_decrypt(
                key,
                sender_message.right.iv,
                &[],
                &sender_message.right.ciphertext,
                sender_message.right.tag,
            )
        });

        dec.map_err(|e| e.into())
    }

    fn derive_key(&self) -> Result<ChaChaPolyKey, Error> {
        let (salt, mut ikm) = derive_prk(&self.s, &self.r);

        let input = p256_point_mul(self.x, self.s)?;
        let input_serialized = p256::serialize_point(&input);

        ikm.extend_from_slice(&input_serialized);

        let prk = hmac::hkdf_extract(&salt, &ikm);

        Ok(hmac::hkdf_expand(&prk, &self.dst, 32).try_into().unwrap())
    }
}

#[test]
fn simple() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut entropy = [0u8; 88];
    rng.fill_bytes(&mut entropy);
    let mut entropy = Randomness::new(entropy.to_vec());

    let dst = b"test-context";
    let left_input = b"lefto";
    let right_input = b"right";
    let (sender, commitment) = OTSender::init(&mut entropy, dst).unwrap();
    let (receiver, selection) = OTReceiver::select(&mut entropy, dst, commitment, false).unwrap();

    let send_message = sender
        .send(left_input, right_input, &selection, &mut entropy)
        .unwrap();

    let receiver_output = receiver.receive(send_message).unwrap();
    assert_eq!(right_input.to_vec(), receiver_output);
}

#![warn(missing_docs)]
//! ## E.1. CoPRF Setup
//!
//! CoPRFs are defined in a multi-key setting, such that CoPRF evaluation
//! keys are derived from a master secret.

use libcrux::hpke::kdf::{LabeledExpand, LabeledExtract, KDF};
use p256::{p256_validate_private_key, NatMod, P256Scalar};
use scrambledb_util::i2osp;
use std::collections::HashMap;

use crate::protocol::configuration::{create_context_string, ModeID};
use crate::Error;

/// As blinding is performed by Elgamal encryption, the blinding public key is an Elgamal encryption key.
pub type BlindingPublicKey = elgamal::EncryptionKey;
/// As unblinding is performed by Elgamal decryption, the unblinding private key is an Elgamal decryption key.
pub type BlindingPrivateKey = elgamal::DecryptionKey;

/// The master secret for generating coPRF keys. It is fixed to a
/// length 32 bytes since that is the number of bytes necessary as an
/// input for HPKE-style key derivation when targeting scalars in
/// P256.  Per the HPKE RFC [RFC9180] it is crucial that a minimum of
/// `Nsk` bytes of entropy is provided to the key derivation
/// algorithm, where `Nsk` is the number of bytes to represent a valid
/// private key, i.e. a P256 scalar in our case.
pub type CoPRFMasterSecret = [u8; 32];

/// A coPRF evaluation key is identified by a bytestring of arbitrary length.
pub type CoPRFKeyID = Vec<u8>;
/// A coPRF evaluation key is a scalar for the base group of the scheme, in our case P256.
pub type CoPRFKey = P256Scalar;

/// The coPRF requester requires the blinding public key of the intended receiver of the PRF output.
#[allow(unused)]
pub struct CoPRFRequesterContext {
    pub context_string: Vec<u8>,
    pub bpk: BlindingPublicKey,
}

/// The coPRF evaluator holds the coPRF master secret, as well as any evaluation keys derived from it.
#[allow(unused)]
pub struct CoPRFEvaluatorContext {
    pub context_string: Vec<u8>,
    pub msk: CoPRFMasterSecret,
    pub keys: HashMap<CoPRFKeyID, CoPRFKey>,
}

/// The coPRF receiver needs an unblinding private key in order to obtain the final coPRF output from the blinded evaluation result.
#[allow(unused)]
pub struct CoPRFReceiverContext {
    context_string: Vec<u8>,
    bpk: BlindingPublicKey,
    bsk: BlindingPrivateKey,
}

/// ### E.1.1. Requester Setup
/// The requesting party requires the blinding public key of the receiving
/// party on whose behalf PRF evaluation queries should be carried out.
pub fn setup_coprf_requester(identifier: &[u8], bpk: BlindingPublicKey) -> CoPRFRequesterContext {
    CoPRFRequesterContext {
        context_string: create_context_string(ModeID::modecoPRF, identifier),
        bpk,
    }
}

/// ### E.1.2. Evaluator Setup
/// The coPRF evaluator holds the master secret as well as any PRF evaluation keys derived from it.
pub fn setup_coprf_evaluator(identifier: &[u8], msk: CoPRFMasterSecret) -> CoPRFEvaluatorContext {
    CoPRFEvaluatorContext {
        context_string: create_context_string(ModeID::modecoPRF, identifier),
        msk,
        keys: HashMap::new(),
    }
}

/// ### E.1.3. Receiver Setup
/// The coPRF receiver holds a pair of corresponding blinding and unblinding keys.
pub fn setup_coprf_receiver(
    identifier: &[u8],
    bpk: BlindingPublicKey,
    bsk: BlindingPrivateKey,
) -> CoPRFReceiverContext {
    CoPRFReceiverContext {
        context_string: create_context_string(ModeID::modecoPRF, identifier),
        bpk,
        bsk,
    }
}

/// ### E.1.4. Blinding Key Generation
/// Following the instantiation presented by [Lehmann], blinding is
/// implemented using a rerandomizable homomorphic encryption scheme, in
/// this case the Elgamal public key encryption scheme.
///
/// In this intance, blinding and unblinding correspond to encryption and
/// decryption using the encryption scheme, hence blinding key generation
/// is the key generation procedure for the encryption scheme.
///
pub fn generate_blinding_key_pair(
    uniform_bytes: &[u8],
) -> Result<(BlindingPrivateKey, BlindingPublicKey), Error> {
    let (bsk, bpk) = elgamal::generate_keys(uniform_bytes)?;
    Ok((bsk, bpk))
}

/// ### E.1.5. Evaluation Key Derivation
/// [Lehman] recommends a key derivation procedure using an underlying PRF
/// which maps from bitstrings to a finite field, such that the field is
/// compatible with the homomorphism afforded by the encryption scheme.
///
/// Concretely in our case, PRF evaluation keys should be scalars in
/// P256. To achieve this, we use the rejection sampling method outlined in [RFC9180].
pub fn derive_key(msk: CoPRFMasterSecret, key_id: &[u8]) -> Result<CoPRFKey, Error> {
    let mut key_material = msk.to_vec();
    key_material.extend_from_slice(key_id);
    let suite_id = b"coPRF-P256-SHA256".to_vec();
    let label = b"dkp_prk".to_vec();
    let candidate_label = b"candidate".to_vec();

    let dkp_prk = LabeledExtract(
        KDF::HKDF_SHA256,
        suite_id.clone(),
        b"",
        label,
        &key_material,
    )?;

    let mut sk = P256Scalar::zero();

    for counter in 0..255 {
        let mut bytes = LabeledExpand(
            KDF::HKDF_SHA256,
            suite_id.clone(),
            &dkp_prk,
            candidate_label.clone(),
            &i2osp(counter, 1),
            32,
        )?;
        bytes[0] = bytes[0] & 0xffu8;
        if p256_validate_private_key(&bytes) {
            sk = P256Scalar::from_be_bytes(&bytes);
        }
    }
    if sk == P256Scalar::zero() {
        Err(Error::DeriveKeyPairError)
    } else {
        Ok(sk)
    }
}

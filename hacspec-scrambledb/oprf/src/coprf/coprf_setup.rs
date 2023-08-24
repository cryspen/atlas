#![warn(missing_docs)]
//! ## E.1. CoPRF Setup
//!
//! CoPRFs are defined in a multi-key setting, such that CoPRF evaluation
//! keys are derived from a master secret.

use hacspec_lib::Randomness;
use p256::P256Scalar;

use crate::{
    protocol::configuration::{create_context_string, ModeID},
    Error,
};

/// As blinding is performed by Elgamal encryption, the blinding public
/// key is an Elgamal encryption key.
pub type BlindingPublicKey = elgamal::EncryptionKey;
/// As unblinding is performed by Elgamal decryption, the unblinding
/// private key is an Elgamal decryption key.
pub type BlindingPrivateKey = elgamal::DecryptionKey;

/// The master secret for generating coPRF keys. It is fixed to a
/// length 32 bytes since that is the number of bytes necessary as an
/// input for HPKE-style key derivation when targeting scalars in
/// P256.  Per the HPKE RFC [RFC9180] it is crucial that a minimum of
/// `Nsk` bytes of entropy is provided to the key derivation
/// algorithm, where `Nsk` is the number of bytes to represent a valid
/// private key, i.e. a P256 scalar in our case.
pub type CoPRFMasterSecret = [u8; 32];

/// A coPRF evaluation key is identified by a bytestring of arbitrary
/// length.
pub type CoPRFKeyID = Vec<u8>;
/// A coPRF evaluation key is a scalar for the base group of the scheme,
/// in our case P256.
pub type CoPRFKey = P256Scalar;

/// The coPRF requester requires the blinding public key of the intended
/// receiver of the PRF output.
pub struct CoPRFRequesterContext {
    pub(crate) string: Vec<u8>,
    pub(crate) bpk: BlindingPublicKey,
}

/// The coPRF evaluator holds the coPRF master secret.
pub struct CoPRFEvaluatorContext {
    pub(crate) msk: CoPRFMasterSecret,
}

/// The coPRF receiver needs an unblinding private key in order to obtain
/// the final coPRF output from the blinded evaluation result.
pub struct CoPRFReceiverContext {
    pub(crate) bsk: BlindingPrivateKey,
    pub(crate) bpk: BlindingPublicKey,
}

impl CoPRFReceiverContext {
    /// Retrieves the receivers blinding public key. This is needed by the requester to perform initial blinding and by the Evaluator to rerandomize to evaluation result.
    pub fn get_bpk(&self) -> BlindingPublicKey {
        self.bpk
    }
}
impl CoPRFRequesterContext {
    /// ### E.1.1. Requester Setup
    /// The requesting party requires the blinding public key of the receiving
    /// party on whose behalf PRF evaluation queries should be carried out.
    pub fn new(identifier: &[u8], bpk: BlindingPublicKey) -> Self {
        CoPRFRequesterContext {
            string: create_context_string(ModeID::modecoPRF, identifier),
            bpk,
        }
    }
}

impl CoPRFEvaluatorContext {
    /// ### E.1.2. Evaluator Setup
    /// The coPRF evaluator holds the master secret as well as any PRF
    /// evaluation keys derived from it.
    pub fn new(msk: CoPRFMasterSecret) -> Self {
        CoPRFEvaluatorContext { msk }
    }
}

impl CoPRFReceiverContext {
    /// ### E.1.3. Receiver Setup
    /// The coPRF receiver holds a pair of corresponding blinding and unblinding keys.
    pub fn new(randomness: &mut Randomness) -> Self {
        let (bsk, bpk) = generate_blinding_key_pair(randomness).unwrap();
        CoPRFReceiverContext { bsk, bpk }
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
fn generate_blinding_key_pair(
    uniform_bytes: &mut Randomness,
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
pub fn derive_key(context: &CoPRFEvaluatorContext, key_id: &[u8]) -> Result<CoPRFKey, Error> {
    let mut key_material = context.msk.to_vec();
    key_material.extend_from_slice(key_id);

    scrambledb_util::random_scalar(&mut Randomness::new(key_material)).map_err(|e| e.into())
}

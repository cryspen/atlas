//! ## E.1. CoPRF Setup
//!
//! This part of the document describes an extension to the OPRF protocol
//! called convertible PRF (coPRF) introduced in [Lehmann].
//!
//! A coPRF is a protocol for blind evaluation of a PRF between three
//! parties, as opposed to the two parties in the regular OPRF setting.  A
//! **requester** wishes the PRF to be evaluated blindly under the key
//! held by the **evaluator**. Unlike in the two-party OPRF setting, the
//! blinded evaluation result is not returned to the requester, but to a
//! third party, the **receiver**. Only the receiver can unblind the
//! evaluation result and thus receive the PRF output.
//!
//! CoPRFs further provide the possiblity of converting PRF outputs, both
//! in blinded and unblinded form, from one PRF key to another.
//!
//! CoPRFs are defined in a multi-key setting, such that CoPRF evaluation
//! keys are derived from a master secret.

use libcrux::hmac::hmac;
use p256::{NatMod, P256Scalar};
use std::collections::HashMap;

use crate::protocol::configuration::{create_context_string, ModeID};
use crate::Error;

pub type BlindingPublicKey = elgamal::EncryptionKey;
pub type BlindingPrivateKey = elgamal::DecryptionKey;

pub type CoPRFMasterSecret = [u8; 64]; // FIXME: What is the right size here?
pub type CoPRFKeyID = Vec<u8>;
pub type CoPRFKey = P256Scalar;

#[allow(unused)]
pub struct CoPRFRequesterContext {
    context_string: Vec<u8>,
    bpk: BlindingPublicKey,
}

#[allow(unused)]
pub struct CoPRFEvaluatorContext {
    context_string: Vec<u8>,
    msk: CoPRFMasterSecret,
    keys: HashMap<CoPRFKeyID, CoPRFKey>,
}

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
/// P256. To achieve this, we take the approach of evaluating HMAC-SHA256
/// on the identifier of the key to be generated, keyed by the master
/// secret. The resulting bytestring is interpreted as a serialized scalar
/// and deserialized to obtain a key in the set of scalars.
pub fn derive_key(msk: CoPRFMasterSecret, key_id: CoPRFKeyID) -> CoPRFKey {
    use libcrux::hmac;
    let bytes = hmac(hmac::Algorithm::Sha256, &msk, &key_id, None);
    P256Scalar::from_be_bytes(&bytes)
}

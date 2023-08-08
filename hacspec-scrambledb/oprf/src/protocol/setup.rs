//! ## 3.2.  Key Generation and Context Setup

use crate::p256_sha256::hash_to_scalar;
use crate::protocol::configuration::{create_context_string, ModeID};
use crate::protocol::{ServerPrivateKey, ServerPublicKey};
use crate::util::*;
use crate::Error;
use p256::NatMod;

/// In the offline setup phase, the server generates a fresh, random key
/// pair (skS, pkS).  There are two ways to generate this key pair.  The
/// first of which is using the GenerateKeyPair function described below.
///
/// ``` text
/// Input: None
///
/// Output:
///
///   Scalar skS
///   Element pkS
///
/// Parameters:
///
///   Group G
///
/// def GenerateKeyPair():
///   skS = G.RandomScalar()
///   pkS = G.ScalarMultGen(skS)
///   return skS, pkS
/// ```
///
/// The second way to generate the key pair is via the deterministic key
/// generation function DeriveKeyPair described in Section 3.2.1.
/// Applications and implementations can use either method in practice.
pub fn generate_key_pair() -> Result<(ServerPrivateKey, ServerPublicKey), Error> {
    let skS = random_scalar();
    let pkS = p256::p256_point_mul_base(skS)?;
    Ok((skS, pkS))
}

/// Also during the offline setup phase, both the client and server
/// create a context used for executing the online phase of the protocol
/// after agreeing on a mode and ciphersuite identifier.  The context,
/// such as OPRFServerContext, is an implementation-specific data
/// structure that stores a context string and the relevant key material
/// for each party.
pub struct OPRFServerContext {
    context_string: Vec<u8>,
    skS: ServerPrivateKey,
}

pub struct OPRFClientContext {
    context_string: Vec<u8>,
}

pub struct VOPRFServerContext {
    context_string: Vec<u8>,
    skS: ServerPrivateKey,
}

pub struct VOPRFClientContext {
    context_string: Vec<u8>,
    pkS: ServerPublicKey,
}

pub struct POPRFServerContext {
    context_string: Vec<u8>,
    skS: ServerPrivateKey,
}

pub struct POPRFClientContext {
    context_string: Vec<u8>,
    pkS: ServerPublicKey,
}

/// The OPRF variant server and client contexts are created as follows:
///
/// ``` text
/// def SetupOPRFServer(identifier, skS):
///   contextString = CreateContextString(modeOPRF, identifier)
///   return OPRFServerContext(contextString, skS)
/// ```
pub fn setup_oprf_server(identifier: &[u8], skS: ServerPrivateKey) -> OPRFServerContext {
    OPRFServerContext {
        context_string: create_context_string(ModeID::modeOPRF, identifier),
        skS,
    }
}

/// ``` text
/// def SetupOPRFClient(identifier):
///   contextString = CreateContextString(modeOPRF, identifier)
///   return OPRFClientContext(contextString)
/// ```
pub fn setup_oprf_client(identifier: &[u8]) -> OPRFClientContext {
    OPRFClientContext {
        context_string: create_context_string(ModeID::modeOPRF, identifier),
    }
}

/// The VOPRF variant server and client contexts are created as follows:
///
/// ``` text
/// def SetupVOPRFServer(identifier, skS):
///   contextString = CreateContextString(modeVOPRF, identifier)
///   return VOPRFServerContext(contextString, skS)
/// ```
pub fn setup_voprf_server(identifier: &[u8], skS: ServerPrivateKey) -> VOPRFServerContext {
    VOPRFServerContext {
        context_string: create_context_string(ModeID::modeVOPRF, identifier),
        skS,
    }
}

/// ``` text
/// def SetupVOPRFClient(identifier, pkS):
///   contextString = CreateContextString(modeVOPRF, identifier)
///   return VOPRFClientContext(contextString, pkS)
/// ```
pub fn setup_voprf_client(identifier: &[u8], pkS: ServerPublicKey) -> VOPRFClientContext {
    VOPRFClientContext {
        context_string: create_context_string(ModeID::modeVOPRF, identifier),
        pkS,
    }
}

/// The POPRF variant server and client contexts are created as follows:
///
/// ``` text
/// def SetupPOPRFServer(identifier, skS):
///   contextString = CreateContextString(modePOPRF, identifier)
///   return POPRFServerContext(contextString, skS)
/// ```
pub fn setup_poprf_server(identifier: &[u8], skS: ServerPrivateKey) -> POPRFServerContext {
    POPRFServerContext {
        context_string: create_context_string(ModeID::modePOPRF, identifier),
        skS,
    }
}

/// ``` text
/// def SetupPOPRFClient(identifier, pkS):
///   contextString = CreateContextString(modePOPRF, identifier)
///   return POPRFClientContext(contextString, pkS)
/// ```
pub fn setup_poprf_client(identifier: &[u8], pkS: ServerPublicKey) -> POPRFClientContext {
    POPRFClientContext {
        context_string: create_context_string(ModeID::modePOPRF, identifier),
        pkS,
    }
}

/// ### 3.2.1.  Deterministic Key Generation
///
/// This section describes a deterministic key generation function,
/// DeriveKeyPair.  It accepts a seed of Ns bytes generated from a
/// cryptographically secure random number generator and an optional
/// (possibly empty) info string.  The constant Ns corresponds to the
/// size in bytes of a serialized Scalar and is defined in Section 2.1.
/// Note that by design knowledge of seed and info is necessary to
/// compute this function, which means that the secrecy of the output
/// private key (skS) depends on the secrecy of seed (since the info
/// string is public).
///
/// ``` text
/// Input:
///
///   opaque seed[Ns]
///   PublicInput info
///
/// Output:
///
///   Scalar skS
///   Element pkS
///
/// Parameters:
///
///   Group G
///   PublicInput contextString
///
/// Errors: DeriveKeyPairError
///
/// def DeriveKeyPair(seed, info):
///   deriveInput = seed || I2OSP(len(info), 2) || info
///   counter = 0
///   skS = 0
///   while skS == 0:
/// 	if counter > 255:
/// 	  raise DeriveKeyPairError
/// 	skS = G.HashToScalar(deriveInput || I2OSP(counter, 1),
/// 						  DST = "DeriveKeyPair" || contextString)
/// 	counter = counter + 1
///   pkS = G.ScalarMultGen(skS)
///   return skS, pkS
/// ```
pub fn derive_key_pair(
    seed: &[u8],
    info: &[u8],
    context_string: &[u8],
) -> Result<(ServerPrivateKey, ServerPublicKey), Error> {
    let mut deriveInput = seed.to_vec();
    deriveInput.extend_from_slice(&i2osp(info.len(), 2));
    deriveInput.extend_from_slice(&info);

    let mut counter = 0usize;
    let mut skS = ServerPrivateKey::zero();

    while skS == ServerPrivateKey::zero() {
        if counter > 255 {
            return Err(Error::DeriveKeyPairError);
        }

        let mut payload = deriveInput.clone();
        payload.extend_from_slice(&i2osp(counter, 1));

        let mut dst = b"DeriveKeyPair".to_vec();
        dst.extend_from_slice(context_string);

        skS = hash_to_scalar(&payload, &dst);

        counter = counter + 1;
    }

    let pkS = p256::p256_point_mul_base(skS)?;

    Ok((skS, pkS))
}

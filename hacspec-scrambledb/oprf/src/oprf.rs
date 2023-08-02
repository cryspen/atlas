use p256::{P256Point, P256Scalar};
use crate::util::*;

type ServerPrivateKey = P256Scalar;
type ServerPublicKey = P256Point;

type KeyGenerationResult = Result<(ServerPrivateKey,ServerPublicKey), Error>;

pub fn generate_key_pair() -> (ServerPrivateKey, ServerPublicKey){
    let skS = random_scalar();
    let pkS = p256::p256_point_mul_base(skS).unwrap();
    (skS, pkS)
}

pub fn derive_key_pair(seed: &[u8], info: &[u8]) -> (ServerPrivateKey, ServerPublicKey) {
    let mut deriveInput = Vec::new();
    deriveInput.extend_from_slice(seed);
    concat_length_prefixed(&mut deriveInput, info, 2);

    unimplemented!()
}

///  Each of the three protocol variants are identified with a one-byte
///    value (in hexadecimal):
///
/// | Mode      | Value |
/// |-----------|-------|
/// | modeOPRF  | 0x00  |
/// | modeVOPRF | 0x01  |
/// | modePOPRF | 0x02  |
///
///
#[allow(non_camel_case_types)]
pub enum ModeID {
    modeOPRF = 0x00,
    modeVOPRF = 0x01,
    modePOPRF = 0x02,
}

/// The mode and ciphersuite identifier values are combined to create a
/// "context string" used throughout the protocol with the following
/// function:
///
/// ```text
///    def CreateContextString(mode, identifier):
///      return "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
/// ```
pub fn create_context_string(mode: ModeID, suite_id: &[u8]) -> Vec<u8> {
    let mut res = Vec::from(b"OPRFV1-".as_slice());
    res.extend_from_slice(&[mode as u8]);
    res.extend_from_slice(b"-".as_slice());
    res.extend_from_slice(suite_id);

    res
}
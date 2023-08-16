//! ## 3.1. Configuration

use scrambledb_util::i2osp;

///  Each of the three protocol variants are identified with a one-byte
///    value (in hexadecimal):
///
/// | Mode      | Value |
/// |-----------|-------|
/// | modeOPRF  | 0x00  |
/// | modeVOPRF | 0x01  |
/// | modePOPRF | 0x02  |
/// |           |       |
/// | modecoPRF | 0x03  |
///
/// **Note:** `modecoPRF` is not part of the original draft document, but belongs to our Convertible OPRF extension.
#[allow(non_camel_case_types)]
pub enum ModeID {
    modeOPRF = 0x00,
    modeVOPRF = 0x01,
    modePOPRF = 0x02,
    modecoPRF = 0x03,
}

impl From<u32> for ModeID {
    fn from(value: u32) -> Self {
        match value {
            0 => ModeID::modeOPRF,
            1 => ModeID::modeVOPRF,
            2 => ModeID::modePOPRF,
            3 => ModeID::modecoPRF,
            _ => panic!("Invalid ModeID."),
        }
    }
}

/// Additionally, each protocol variant is instantiated with a
/// ciphersuite, or suite.  Each ciphersuite is identified with an ASCII
/// string identifier, referred to as identifier; see Section 4 for the
/// set of initial ciphersuite values.
///
/// The mode and ciphersuite identifier values are combined to create a
/// "context string" used throughout the protocol with the following
/// function:
///
/// ```text
///    def CreateContextString(mode, identifier):
///      return "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
/// ```
pub fn create_context_string(mode: ModeID, identifier: &[u8]) -> Vec<u8> {
    let mut res = b"OPRFV1-".to_vec(); // "OPRVV1-"
    res.extend_from_slice(&i2osp(mode as usize, 1)); //    || I2OSP(mode, 1)
    res.extend_from_slice(b"-"); //    || "-"
    res.extend_from_slice(identifier); //    || identifier

    res
}

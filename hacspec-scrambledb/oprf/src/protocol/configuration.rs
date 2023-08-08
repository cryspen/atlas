//! ## 3.1. Configuration

use crate::util::i2osp;

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
    let mut res = b"OPRFV1-".to_vec();                 // "OPRVV1-"
    res.extend_from_slice(&i2osp(mode as usize, 1));  //    || I2OSP(mode, 1)
    res.extend_from_slice(b"-".as_slice());                    //    || "-"
    res.extend_from_slice(identifier);                         //    || identifier

    res
}

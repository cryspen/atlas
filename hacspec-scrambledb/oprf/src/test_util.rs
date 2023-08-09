use crate::protocol::configuration::create_context_string;
use crate::protocol::setup::derive_key_pair;
use std::fs::read_to_string;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct TestVector {
    #[serde(with = "hex")]
    groupDST: Vec<u8>,
    hash: String,
    identifier: String,
    #[serde(with = "hex")]
    keyInfo: Vec<u8>,
    mode: u32,
    #[serde(with = "hex")]
    seed: Vec<u8>,
    #[serde(with = "hex")]
    skSm: Vec<u8>,
    vectors: Vec<Batch>,
}

#[derive(Deserialize)]
pub struct Batch {
    Batch: usize,
    Blind: String,
    BlindedElement: String,
    EvaluationElement: String,
    Info: Option<String>,
    Input: String,
    Output: String,
    Proof: Option<Proof>,
}

#[derive(Deserialize)]
pub struct Proof {
    #[serde(with = "hex")]
    proof: Vec<u8>,
    #[serde(with = "hex")]
    r: Vec<u8>,
}

pub fn load_vectors(path: &str) -> Vec<TestVector> {
    serde_json::from_str(&read_to_string(path).expect("File not found.")).unwrap()
}

#[test]
fn oprf() {
    use p256::{NatMod, P256Scalar};
    let _ = pretty_env_logger::try_init();
    let tests = load_vectors("allVectors.json");

    for test in tests {
        if test.identifier == "P256-SHA256" && test.mode == 0 {
            let context_string =
                create_context_string(test.mode.into(), test.identifier.as_bytes());
            let (skS, _pkS) = derive_key_pair(&test.seed, &test.keyInfo, &context_string).unwrap();

            assert_eq!(skS, P256Scalar::from_be_bytes(&test.skSm));

            for batch in test.vectors {
                let (blind, blindedElement) = crate::protocol::online::oprf::blind(batch.Input.as_bytes(), &context_string).unwrap();

                assert_eq!(blind, P256Scalar::from_be_bytes(batch.Blind.as_bytes()));
                //assert_eq!(blindedElement, )
            }
        }
    }
}

// thread 'test_util::oprf' panicked at 'assertion failed: `(left == right)`
//   left: `P256Scalar { value: [29, 19, 55, 92, 235, 247, 191, 145, 185, 100, 189, 206, 66, 50, 249, 0, 21, 31, 157, 81, 57, 17, 53, 212, 245, 21, 194, 198, 23, 246, 252, 50] }`,
//  right: `P256Scalar { value: [243, 180, 110, 135, 165, 154, 17, 212, 239, 235, 2, 136, 147, 182, 119, 116, 89, 27, 185, 165, 161, 56, 18, 157, 52, 201, 249, 134, 29, 27, 134, 77] }`', oprf/src/test_util.rs:64:17
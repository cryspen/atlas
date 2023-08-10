use crate::protocol::online::oprf::{blind_evaluate, evaluate};
use crate::protocol::setup::derive_key_pair;
use crate::protocol::{configuration::create_context_string, online::oprf::finalize};
use std::fs::read_to_string;

use serde::Deserialize;
#[allow(unused)]
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

#[allow(unused)]
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

#[allow(unused)]
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
fn oprf_blind_evaluate() {
    use p256::{NatMod, P256Scalar};

    let tests = load_vectors("allVectors.json");

    for test in tests {
        if test.identifier == "P256-SHA256" && test.mode == 0 {
            let skS = P256Scalar::from_be_bytes(&test.skSm);

            for batch in test.vectors {
                let blindedElements: Vec<p256::P256Point> = batch
                    .BlindedElement
                    .split(",")
                    .map(|b| {
                        crate::p256_sha256::deserialize_element(
                            hex::decode(b).unwrap().try_into().unwrap_or_else(|_| {
                                panic!(
                                    "Attempt to deserialize invalid byte string: {:?} ({})",
                                    b.as_bytes(),
                                    b.as_bytes().len()
                                )
                            }),
                        )
                        .expect("Could not deserialize")
                    })
                    .collect();

                let expected_evaluatedElements: Vec<p256::P256Point> = batch
                    .EvaluationElement
                    .split(",")
                    .map(|e| {
                        crate::p256_sha256::deserialize_element(
                            hex::decode(e)
                                .unwrap()
                                .try_into()
                                .expect("Attempt to deserialize invalid byte string."),
                        )
                        .expect("Could not deserialize")
                    })
                    .collect();

                for (blindedElement, expected_evaluatedElement) in
                    blindedElements.iter().zip(expected_evaluatedElements)
                {
                    let evaluatedElement = blind_evaluate(skS, *blindedElement).unwrap();
                    assert_eq!(evaluatedElement, expected_evaluatedElement);
                }
            }
        }
    }
}

#[test]
fn oprf_key_derivation() {
    use p256::{NatMod, P256Scalar};
    let tests = load_vectors("allVectors.json");

    for test in tests {
        if test.identifier == "P256-SHA256" && test.mode == 0 {
            let context_string =
                create_context_string(test.mode.into(), test.identifier.as_bytes());
            let (skS, _pkS) = derive_key_pair(&test.seed, &test.keyInfo, &context_string).unwrap();

            assert_eq!(skS, P256Scalar::from_be_bytes(&test.skSm));
        }
    }
}

#[test]
fn oprf_finalize() {
    use p256::{NatMod, P256Scalar};

    let tests = load_vectors("allVectors.json");

    for test in tests {
        if test.identifier == "P256-SHA256" && test.mode == 0 {
            for batch in test.vectors {
                let Inputs: Vec<Vec<u8>> = batch
                    .Input
                    .split(",")
                    .map(|i| hex::decode(i).unwrap())
                    .collect();
                let Blinds: Vec<P256Scalar> = batch
                    .Blind
                    .split(",")
                    .map(|b| P256Scalar::from_be_bytes(&hex::decode(b).unwrap()))
                    .collect();
                let evaluatedElements: Vec<p256::P256Point> = batch
                    .EvaluationElement
                    .split(",")
                    .map(|e| {
                        crate::p256_sha256::deserialize_element(
                            hex::decode(e)
                                .unwrap()
                                .try_into()
                                .expect("Attempt to deserialize invalid byte string."),
                        )
                        .expect("Could not deserialize")
                    })
                    .collect();
                let expectedOutputs: Vec<Vec<u8>> = batch
                    .Output
                    .split(",")
                    .map(|o| hex::decode(o).unwrap())
                    .collect();

                for i in 0..batch.Batch {
                    let output = finalize(&Inputs[i], Blinds[i], evaluatedElements[i]).unwrap();
                    assert_eq!(output, expectedOutputs[i]);
                }
            }
        }
    }
}

#[test]
fn oprf_evaluate() {
    use p256::{NatMod, P256Scalar};

    let tests = load_vectors("allVectors.json");

    for test in tests {
        if test.identifier == "P256-SHA256" && test.mode == 0 {
            let skS = P256Scalar::from_be_bytes(&test.skSm);
            let context_string =
                create_context_string(test.mode.into(), test.identifier.as_bytes());

            for batch in test.vectors {
                let Inputs: Vec<Vec<u8>> = batch
                    .Input
                    .split(",")
                    .map(|i| hex::decode(i).unwrap())
                    .collect();
                let expectedOutputs: Vec<Vec<u8>> = batch
                    .Output
                    .split(",")
                    .map(|o| hex::decode(o).unwrap())
                    .collect();

                for case in 0..batch.Batch {
                    let output = evaluate(skS, &Inputs[case], &context_string).unwrap();
                    assert_eq!(output, expectedOutputs[case]);
                }
            }
        }
    }
}

#[test]
fn oprf_evaluate_blinded() {
    use crate::protocol::online::oprf::blind;
    use p256::{NatMod, P256Scalar};

    let tests = load_vectors("allVectors.json");

    for test in tests {
        if test.identifier == "P256-SHA256" && test.mode == 0 {
            let skS = P256Scalar::from_be_bytes(&test.skSm);
            let context_string =
                create_context_string(test.mode.into(), test.identifier.as_bytes());

            for batch in test.vectors {
                let Inputs: Vec<Vec<u8>> = batch
                    .Input
                    .split(",")
                    .map(|i| hex::decode(i).unwrap())
                    .collect();
                let expectedOutputs: Vec<Vec<u8>> = batch
                    .Output
                    .split(",")
                    .map(|o| hex::decode(o).unwrap())
                    .collect();

                for case in 0..batch.Batch {
                    let (blind, blindedElement) = blind(&Inputs[case], &context_string).unwrap();
                    let evaluatedElement = blind_evaluate(skS, blindedElement).unwrap();
                    let output = finalize(&Inputs[case], blind, evaluatedElement).unwrap();

                    assert_eq!(output, expectedOutputs[case]);
                }
            }
        }
    }
}

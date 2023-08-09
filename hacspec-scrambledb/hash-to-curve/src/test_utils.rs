use std::fs::read_to_string;

use crate::{
    expand_message,
    hash_suite::{hash_to_field, Ciphersuite, EncodeToCurve, HashToCurve, HashToField},
    prime_curve::MapToCurve,
    ExpandMessageType,
};
use p256::{NatMod, P256FieldElement, P256Point};
use serde_json::Value;

    pub fn load_vectors(path: &std::path::Path) -> Value {
        serde_json::from_str(&read_to_string(path).expect("File not found.")).unwrap()
    }

pub fn test_hash_to_field_plain(ciphersuite: crate::Ciphersuite) {
    let mut vector_path = std::path::Path::new("vectors").join(ciphersuite.ID);
    vector_path.set_extension("json");
    eprintln!(" Reading {}", vector_path.display());

    let tests = load_vectors(vector_path.as_path());
    let dst = tests["dst"].as_str().unwrap().as_bytes();

    assert_eq!(tests["ciphersuite"].as_str().unwrap(), ciphersuite.ID);

    for test_case in tests["vectors"].as_array().unwrap().iter() {
        let msg_str = test_case["msg"].as_str().unwrap();
        let msg = msg_str.as_bytes();

        let u_expected: Vec<_> = test_case["u"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u_i| {
                let u_i = u_i.as_str().unwrap();
                let u0_expected = u_i.trim_start_matches("0x");
                P256FieldElement::from_be_bytes(&hex::decode(u0_expected).unwrap())
                // FIXME
            })
            .collect();

        // FIXME
        let expand_message_type = match ciphersuite.ID {
            "P256_XMD:SHA-256_SSWU_RO_" => ExpandMessageType::P256_SHA256,
            _ => panic!("Unsupported"),
        };
        let u_real: Vec<Vec<P256FieldElement>> = hash_to_field(
            expand_message_type,
            msg,
            dst,
            2,
            ciphersuite.L,
            ciphersuite.M,
        )
        .unwrap();
        assert_eq!(u_real.len(), u_expected.len());
        for (u_real, u_expected) in u_real.iter().zip(u_expected.iter()) {
            assert!(u_real.len() == 1);
            assert_eq!(
                u_expected.as_ref(),
                u_real[0].as_ref(),
                "u0 did not match for {msg_str}",
            );
        }
    }
}

pub fn test_hash_to_field<const LEN: usize, C>()
where
    C: HashToField,
    <C as Ciphersuite>::BaseField: NatMod<{ LEN }> + AsRef<[u8]>,
{
    let mut vector_path = std::path::Path::new("vectors").join(C::ID);
    vector_path.set_extension("json");
    eprintln!(" Reading {}", vector_path.display());

    let tests = load_vectors(vector_path.as_path());
    let dst = tests["dst"].as_str().unwrap().as_bytes();

    assert_eq!(tests["ciphersuite"].as_str().unwrap(), C::ID);

    for test_case in tests["vectors"].as_array().unwrap().iter() {
        let msg_str = test_case["msg"].as_str().unwrap();
        let msg = msg_str.as_bytes();

        let u_expected: Vec<_> = test_case["u"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u_i| {
                let u_i = u_i.as_str().unwrap();
                let u0_expected = u_i.trim_start_matches("0x");
                C::BaseField::from_be_bytes(&hex::decode(u0_expected).unwrap())
            })
            .collect();

        let u_real = C::hash_to_field(msg, dst, 2).unwrap();
        assert_eq!(u_real.len(), u_expected.len());
        for (u_real, u_expected) in u_real.iter().zip(u_expected.iter()) {
            assert_eq!(
                u_expected.as_ref(),
                u_real.as_ref(),
                "u0 did not match for {msg_str}",
            );
        }
    }
}

pub fn test_map_to_curve<const LEN: usize, C>()
where
    C: HashToField,
    <C as Ciphersuite>::BaseField:
        NatMod<{ LEN }> + AsRef<[u8]> + MapToCurve<TargetCurve = C::OutputCurve>,
{
    let mut vector_path = std::path::Path::new("vectors").join(C::ID);
    vector_path.set_extension("json");
    let vectors = load_vectors(vector_path.as_path());

    let test_cases = vectors["vectors"].as_array().unwrap().clone();

    for test_case in test_cases.iter() {
        let u = test_case["u"].as_array().unwrap();
        let u0 = u[0].as_str().unwrap().trim_start_matches("0x");
        let u0 = P256FieldElement::from_be_bytes(&hex::decode(u0).unwrap());
        let u1 = u[1].as_str().unwrap().trim_start_matches("0x");
        let u1 = P256FieldElement::from_be_bytes(&hex::decode(u1).unwrap());

        let (q0_x, q0_y) = u0.map_to_curve().into();
        let (q1_x, q1_y) = u1.map_to_curve().into();

        let q0_expected = &test_case["Q0"];
        let q0_x_expected = q0_expected["x"].as_str().unwrap().trim_start_matches("0x");
        let q0_x_expected = P256FieldElement::from_be_bytes(&hex::decode(q0_x_expected).unwrap());
        let q0_y_expected = q0_expected["y"].as_str().unwrap().trim_start_matches("0x");
        let q0_y_expected = P256FieldElement::from_be_bytes(&hex::decode(q0_y_expected).unwrap());

        let q1_expected = &test_case["Q1"];
        let q1_x_expected = q1_expected["x"].as_str().unwrap().trim_start_matches("0x");
        let q1_x_expected = P256FieldElement::from_be_bytes(&hex::decode(q1_x_expected).unwrap());
        let q1_y_expected = q1_expected["y"].as_str().unwrap().trim_start_matches("0x");
        let q1_y_expected = P256FieldElement::from_be_bytes(&hex::decode(q1_y_expected).unwrap());

        assert_eq!(q0_x_expected, q0_x, "x0 incorrect");
        assert_eq!(q0_y_expected, q0_y, "y0 incorrect");

        assert_eq!(q1_x_expected, q1_x, "x1 incorrect");
        assert_eq!(q1_y_expected, q1_y, "y1 incorrect");
    }
}

pub fn test_hash_to_curve<const LEN: usize, C>()
where
    C: HashToCurve,
    <C as Ciphersuite>::BaseField: NatMod<{ LEN }> + AsRef<[u8]>,
{
    let mut vector_path = std::path::Path::new("vectors").join(C::ID);
    vector_path.set_extension("json");
    let vectors = load_vectors(vector_path.as_path());

    let dst = vectors["dst"].as_str().unwrap();
    let dst = dst.as_bytes();
    let test_cases = vectors["vectors"].as_array().unwrap().clone();

    for test_case in test_cases.iter() {
        let msg = test_case["msg"].as_str().unwrap();
        let msg = msg.as_bytes();

        let p_expected = &test_case["P"];
        let p_x_expected = p_expected["x"].as_str().unwrap().trim_start_matches("0x");
        let p_x_expected = C::BaseField::from_be_bytes(&hex::decode(p_x_expected).unwrap());
        let p_y_expected = p_expected["y"].as_str().unwrap().trim_start_matches("0x");
        let p_y_expected = C::BaseField::from_be_bytes(&hex::decode(p_y_expected).unwrap());

        let (x, y) = C::hash_to_curve(msg, dst).unwrap();

        // assert!(!inf, "Point should not be infinite");
        assert_eq!(p_x_expected.as_ref(), x.as_ref(), "x-coordinate incorrect");
        assert_eq!(p_y_expected.as_ref(), y.as_ref(), "y-coordinate incorrect");
    }
}

pub fn test_encode_to_curve<const LEN: usize, C>()
where
    C: EncodeToCurve,
    <C as Ciphersuite>::BaseField: NatMod<{ LEN }> + AsRef<[u8]>,
{
    let mut vector_path = std::path::Path::new("vectors").join(C::ID);
    vector_path.set_extension("json");
    let vectors = load_vectors(vector_path.as_path());

    let dst = vectors["dst"].as_str().unwrap();
    let dst = dst.as_bytes();
    let test_cases = vectors["vectors"].as_array().unwrap().clone();

    for test_case in test_cases.iter() {
        let msg = test_case["msg"].as_str().unwrap();
        let msg = msg.as_bytes();

        let p_expected = &test_case["P"];
        let p_x_expected = p_expected["x"].as_str().unwrap().trim_start_matches("0x");
        let p_x_expected = C::BaseField::from_be_bytes(&hex::decode(p_x_expected).unwrap());
        let p_y_expected = p_expected["y"].as_str().unwrap().trim_start_matches("0x");
        let p_y_expected = C::BaseField::from_be_bytes(&hex::decode(p_y_expected).unwrap());

        let (x, y) = C::encode_to_curve(msg, dst).unwrap();

        // assert!(!inf, "Point should not be infinite");
        assert_eq!(p_x_expected.as_ref(), x.as_ref(), "x-coordinate incorrect");
        assert_eq!(p_y_expected.as_ref(), y.as_ref(), "y-coordinate incorrect");
    }
}

use hacspec_lib::hacspec_helper::NatMod;
use hacspec_lib::Randomness;
use p256::{P256Point, P256Scalar};

use crate::data_types::{DataValue, EncryptedDataValue};
use crate::error::Error;
use crate::setup::{StoreDecryptionKey, StoreEncryptionKey};

fn encode_byte(byte: &u8) -> P256Point {
    let mut scalar_encoding = P256Scalar::one();
    for _i in 0..*byte {
        scalar_encoding = scalar_encoding.fadd(P256Scalar::one());
    }
    p256::p256_point_mul_base(scalar_encoding).unwrap()
}

fn decode_point(point: P256Point) -> u8 {
    let mut byte_candidate = 0u8;
    let mut candidate_encoding = P256Scalar::one();
    for _i in 0..256 {
        let candidate_point = p256::p256_point_mul_base(candidate_encoding).unwrap();
        if candidate_point == point {
            break;
        }
        candidate_encoding = candidate_encoding.fadd(P256Scalar::one());
        byte_candidate += 1;
    }
    byte_candidate
}

pub(crate) fn encrypt(
    data: &DataValue,
    ek: &StoreEncryptionKey,
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    let encoded_data = data.value.iter().map(encode_byte);
    let encrypted_data: Vec<(P256Point, P256Point)> = encoded_data
        .map(|p| elgamal::encrypt(ek.0, p, randomness).unwrap())
        .collect();
    let encryted_data_value = EncryptedDataValue {
        attribute_name: data.attribute_name.clone(),
        value: encrypted_data,
    };
    Ok(encryted_data_value)
}

pub(crate) fn decrypt(
    data: &EncryptedDataValue,
    dk: &StoreDecryptionKey,
) -> Result<DataValue, Error> {
    let decrypted_data = data
        .value
        .iter()
        .map(|c| elgamal::decrypt(dk.0, *c).unwrap());
    let decoded_data = decrypted_data.map(decode_point).collect();
    Ok(DataValue {
        attribute_name: data.attribute_name.clone(),
        value: decoded_data,
    })
}

pub(crate) fn rerandomize(
    data: &EncryptedDataValue,
    ek: &StoreEncryptionKey,
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    let rerandomized_data = data
        .value
        .iter()
        .map(|c| elgamal::rerandomize(ek.0, *c, randomness).unwrap())
        .collect();
    Ok(EncryptedDataValue {
        attribute_name: data.attribute_name.clone(),
        value: rerandomized_data,
    })
}

#[test]
fn encode_decode() {
    assert_eq!(1u8, decode_point(encode_byte(&1u8)));
    assert_eq!(17u8, decode_point(encode_byte(&17u8)));
    assert_eq!(0u8, decode_point(encode_byte(&0u8)));
    assert_eq!(u8::MAX, decode_point(encode_byte(&u8::MAX)));
}

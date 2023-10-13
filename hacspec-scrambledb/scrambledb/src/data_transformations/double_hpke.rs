//! This module defines HPKE-based double encryption and decryption for use in
//! individual data tranformations as defined in [crate::data_transformations].
//!
//! A plain text data value can be encrypted once to obtain a level-1
//! encryption of the data value.
//!
//! A level-1 encrypted data value can be encrypted a second time to obtain a
//! level-2 encryption of the data value.
//!
//! Only level-2 encrypted data values can be decrypted, and only if both
//! encryptions were performed towards the same receiver.

use libcrux::hpke::kem::Nsk;

use libcrux::hpke::{HpkeOpen, HpkeSeal};

use crate::SerializedHPKE;

use crate::data_types::{DataValue, EncryptedDataValue};

use libcrux::hpke::HPKEConfig;

use crate::error::Error;

use hacspec_lib::Randomness;

/// HPKE double encryption level 1 `info` string.
const HPKE_LEVEL_1_INFO: &[u8] = b"Hpke-Level-1";

/// HPKE double encryption level 2 `info` string.
const HPKE_LEVEL_2_INFO: &[u8] = b"Hpke-Level-2";

/// Level-1 encrypt a plain text data value.
///
/// Inputs:
/// - data_value: A plain text data value
/// - ek: The receivers public encryption key
/// - randomness: Random bytes
///
/// Output:
/// A level-1 encrypted data value.
///
/// Raises:
/// - CorruptedData: If the internal encryption fails.
///
/// Panics:
/// - on insufficient randomness
pub(crate) fn hpke_seal_level_1(
    data_value: &DataValue,
    ek: &[u8],
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    let HPKEConfig(_, kem, _, _) = crate::HPKE_CONF;
    let encrypted_data_value = EncryptedDataValue {
        attribute_name: data_value.attribute_name.clone(),
        value: SerializedHPKE::from_hpke_ct(&HpkeSeal(
            crate::HPKE_CONF,
            ek,
            HPKE_LEVEL_1_INFO,
            b"",
            &data_value.value,
            None,
            None,
            None,
            randomness.bytes(Nsk(kem)).unwrap().to_vec(),
        )?)
        .to_bytes(),
        encryption_level: 1u8,
    };
    Ok(encrypted_data_value)
}

/// Level-2 encrypt a level-1 encrypted data value.
///
/// Inputs:
/// - data_value: A level-1 encrypted data value
/// - ek: The receivers public encryption key
/// - randomness: Random bytes
///
/// Output:
/// A level-2 encrypted data value.
///
/// Raises:
/// - InvalidInput: If the input data value is not level-1 encrypted.
/// - CorruptedData: If the internal encryption fails.
///
/// Panics:
/// - on insufficient randomness
pub(crate) fn hpke_seal_level_2(
    data_value: &EncryptedDataValue,
    ek: &[u8],
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    if data_value.encryption_level != 1u8 {
        return Err(Error::InvalidInput);
    }

    let HPKEConfig(_, kem, _, _) = crate::HPKE_CONF;
    let data_value = EncryptedDataValue {
        attribute_name: data_value.attribute_name.clone(),
        value: SerializedHPKE::from_hpke_ct(&HpkeSeal(
            crate::HPKE_CONF,
            ek,
            HPKE_LEVEL_2_INFO,
            b"",
            &data_value.value,
            None,
            None,
            None,
            randomness.bytes(Nsk(kem)).unwrap().to_vec(),
        )?)
        .to_bytes(),
        encryption_level: 2u8,
    };
    Ok(data_value)
}

/// Decrypt a level-2 encrypted data value.
///
/// Inputs:
/// - data_value: A Level-2 encrypted data value
/// - sk: The receiver's decryption key
///
/// Outputs:
/// A plain text data value.
///
/// Raises:
/// - InvalidInput: If the input data value is not level-2 encrypted.
/// - CorruptedData: If the internal decryption fails, e.g. because of
///   inconsistent level-1 and level-2 receivers.
pub(crate) fn hpke_open_level_2(
    data_value: &EncryptedDataValue,
    sk: &[u8],
) -> Result<DataValue, Error> {
    if data_value.encryption_level != 2u8 {
        return Err(Error::InvalidInput);
    }

    let outer_encryption = SerializedHPKE::from_bytes(&data_value.value).to_hpke_ct();
    let inner_encryption = SerializedHPKE::from_bytes(&HpkeOpen(
        crate::HPKE_CONF,
        &outer_encryption,
        sk,
        HPKE_LEVEL_2_INFO,
        b"",
        None,
        None,
        None,
    )?)
    .to_hpke_ct();
    let data_value = DataValue {
        attribute_name: data_value.attribute_name.clone(),
        value: HpkeOpen(
            crate::HPKE_CONF,
            &inner_encryption,
            sk,
            HPKE_LEVEL_1_INFO,
            b"",
            None,
            None,
            None,
        )?,
    };
    Ok(data_value)
}

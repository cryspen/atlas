#[cfg(feature = "double-hpke")]
pub(crate) mod double_hpke;

#[cfg(not(feature = "double-hpke"))]
pub(crate) mod elgamal;

use crate::data_types::{DataValue, EncryptedDataValue};
use crate::error::Error;
use crate::setup::{StoreContext, StoreEncryptionKey};
use hacspec_lib::Randomness;

/// Encrypt a data value towards a data store.
///
/// Inputs:
/// - `data`: The data value to encrypt.
/// - `ek`: The receiver's public encryption key.
/// - `randomness`: Random bytes
///
/// Output:
/// A new [EncryptedDataValue], the encryption of `data`.
#[cfg(feature = "double-hpke")]
pub(crate) fn encrypt_data_value(
    data: &DataValue,
    ek: &StoreEncryptionKey,
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    let encrypted_data_value = double_hpke::hpke_seal_level_1(data, &ek.0, randomness)?;
    Ok(encrypted_data_value)
}

/// Encrypt a data value towards a data store.
///
/// Inputs:
/// - `data`: The data value to encrypt.
/// - `ek`: The receiver's public encryption key.
/// - `randomness`: Random bytes
///
/// Output:
/// A new [EncryptedDataValue], the encryption of `data`.
#[cfg(not(feature = "double-hpke"))]
pub(crate) fn encrypt_data_value(
    data: &DataValue,
    ek: &StoreEncryptionKey,
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    let encrypted_data_value = elgamal::encrypt(data, ek, randomness)?;
    Ok(encrypted_data_value)
}

/// Rerandomize the encryption of an encrypted data value.
///
/// Inputs:
/// - `data`: The encrypted data value.
/// - `ek`: The receiver's public encryption key.
/// - `randomness`: Random bytes
///
/// Output:
/// A new, rerandomized [EncryptedDataValue].
#[cfg(feature = "double-hpke")]
pub(crate) fn rerandomize_encryption(
    data: &EncryptedDataValue,
    ek: &StoreEncryptionKey,
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    double_hpke::hpke_seal_level_2(data, &ek.0, randomness)
}

/// Rerandomize the encryption of an encrypted data value.
///
/// Inputs:
/// - `data`: The encrypted data value.
/// - `ek`: The receiver's public encryption key.
/// - `randomness`: Random bytes
///
/// Output:
/// A new, rerandomized [EncryptedDataValue].
#[cfg(not(feature = "double-hpke"))]
pub(crate) fn rerandomize_encryption(
    data: &EncryptedDataValue,
    ek: &StoreEncryptionKey,
    randomness: &mut Randomness,
) -> Result<EncryptedDataValue, Error> {
    elgamal::rerandomize(data, ek, randomness)
}

/// Decrypt an encrypted data value.
///
/// Inputs:
/// - `data`: The value to decrypt.
/// - `store_context`: The data store's long term private state, including in particular its decryption key.
///
/// Output:
/// The decrypted [DataValue] or an [Error] on decryption failure.
#[cfg(feature = "double-hpke")]
pub(crate) fn decrypt_data_value(
    data: &EncryptedDataValue,
    store_context: &StoreContext,
) -> Result<DataValue, Error> {
    double_hpke::hpke_open_level_2(data, &store_context.dk.0)
}

/// Decrypt an encrypted data value.
///
/// Inputs:
/// - `data`: The value to decrypt.
/// - `store_context`: The data store's long term private state, including in particular its decryption key.
///
/// Output:
/// The decrypted [DataValue] or an [Error] on decryption failure.
#[cfg(not(feature = "double-hpke"))]
pub(crate) fn decrypt_data_value(
    data: &EncryptedDataValue,
    store_context: &StoreContext,
) -> Result<DataValue, Error> {
    elgamal::decrypt(data, &store_context.dk)
}

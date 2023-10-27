//! This module defines ScrambleDB transformations at the level of individual
//! pieces of data as defined in [`data_types`](crate::data_types).
//!
//! These transformations are:
//! - blinding identifiable and pseudonymous data
//! - pseudonymizing blinded identifiable data
//! - converting blinded pseudonymous data
//! - finalizing blinded pseudonymous data

use hacspec_lib::Randomness;
use oprf::coprf::{
    coprf_online::{blind, blind_convert, blind_evaluate, prepare_blind_convert},
    coprf_setup::{derive_key, BlindingPublicKey, CoPRFEvaluatorContext},
};

use crate::{data_types::*, error::Error, setup::StoreContext};

use self::double_hpke::{hpke_open_level_2, hpke_seal_level_1, hpke_seal_level_2};

pub(crate) mod double_hpke;

/// CoPRF context string for domain separation of intial pseudonymization.
const PSEUDONYMIZATION_CONTEXT: &[u8] = b"CoPRF-Context-Pseudonymization";

/// Blind an identifiable datum as a first step in initial pseudonym
/// generation.
///
/// Inputs:
/// - `bpk`: Receiver's blinding public key
/// - `ek`: Receiver's public encryption key
/// - `datum`: Identifiable data
/// - `randomness`: Random bytes
///
/// Output:
/// [Blinded data](crate::data_types::BlindedIdentifiableData) such that the
/// datum's handle is blinded for CoPRF evaluation and the datum's value is
/// level-1 encrypted.
pub fn blind_identifiable_datum(
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &IdentifiableData,
    randomness: &mut Randomness,
) -> Result<BlindedIdentifiableData, Error> {
    // Blind orthonym towards receiver.
    let blinded_handle = BlindedIdentifiableHandle(blind(
        *bpk,
        datum.handle.as_bytes(),
        PSEUDONYMIZATION_CONTEXT.to_vec(),
        randomness,
    )?);

    // Level-1 encrypt data value towards receiver.
    let encrypted_data_value = hpke_seal_level_1(&datum.data_value, ek, randomness)?;

    Ok(BlindedIdentifiableData {
        blinded_handle,
        encrypted_data_value,
    })
}

/// Blind a pseudonymous datum as a first step in pseudonym
/// conversion.
///
/// Inputs:
/// - `store_context`: The data store's long term private state including the pseudonym
///   hardening keys
/// - `bpk`: Receiver's blinding public key
/// - `ek`: Receiver's public encryption key
/// - `datum`: Pseudonymized data
/// - `randomness`: Random bytes
///
/// Output:
/// [Blinded pseudonymized data](BlindedPseudonymizedData) such that the
/// datum's handle is blinded for CoPRF conversion and the datum's value is
/// level-1 encrypted.
pub fn blind_pseudonymized_datum(
    store_context: &StoreContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &PseudonymizedData,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedData, Error> {
    // Blind recovered raw pseudonym towards receiver.
    let blinded_handle = BlindedPseudonymizedHandle(prepare_blind_convert(
        *bpk,
        store_context.recover_raw_pseudonym(datum.handle)?,
        randomness,
    )?);

    // Level-1 encrypt data value towards receiver.
    let encrypted_data_value = hpke_seal_level_1(&datum.data_value, ek, randomness)?;

    Ok(BlindedPseudonymizedData {
        blinded_handle,
        encrypted_data_value,
    })
}

/// Obliviously pseudonymmize a blinded identifiable datum.
///
/// Inputs:
/// - `coprf_context`: The converter's CoPRF evaluation context
/// - `bpk`: The receiver's blinding public key
/// - `ek`: The receiver's public encryption key
/// - `datum`: A blinded datum output by [`blind_identifiable_datum`]
/// - `randomness`: Random bytes
///
/// Output:
/// [Blinded pseudonymized data](BlindedPseudonymizedData) such that the
///  datum's blinded handle has been obliviously evaluated to a pseudonym and
///  the datum's value has been level-2 encrypted towards the receiver.
pub fn pseudonymize_blinded_datum(
    coprf_context: &CoPRFEvaluatorContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &BlindedIdentifiableData,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedData, Error> {
    let key = derive_key(
        &coprf_context,
        datum.encrypted_data_value.attribute_name.as_bytes(),
    )?;

    // Obliviously generate raw pseudonym.
    let blinded_handle = BlindedPseudonymizedHandle(blind_evaluate(
        key,
        *bpk,
        datum.blinded_handle.0,
        randomness,
    )?);

    // Level-2 encrypt data value towards receiver.
    let encrypted_data_value = hpke_seal_level_2(&datum.encrypted_data_value, ek, randomness)?;

    Ok(BlindedPseudonymizedData {
        blinded_handle,
        encrypted_data_value,
    })
}

/// Obliviously convert a blinded pseudonymous datum to a given target pseudonym key.
///
/// Inputs:
/// - `coprf_context`: The Converters CoPRF evaluation context
/// - `bpk`: The receiver's blinding public key
/// - `ek`: The receiver's public encryption key
/// - `conversion_target`: Target pseudonym key identifier
/// - `randomness`: Random bytes
///
/// Output:
/// [Blinded pseudonymized data](BlindedPseudonymizedData)such that the
/// datum's pseudonymous handle is converted to the target pseudonym key and
/// the datum's value is level-2 encrypted towards the receiver.
pub fn convert_blinded_datum(
    coprf_context: &CoPRFEvaluatorContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    conversion_target: &[u8],
    datum: &BlindedPseudonymizedData,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedData, Error> {
    // Re-derive original pseudonymization key.
    let key_from = derive_key(
        &coprf_context,
        datum.encrypted_data_value.attribute_name.as_bytes(),
    )?;

    // Derive target key.
    let key_to = derive_key(&coprf_context, conversion_target)?;

    // Obliviously convert pseudonym.
    let blinded_handle = BlindedPseudonymizedHandle(blind_convert(
        *bpk,
        key_from,
        key_to,
        datum.blinded_handle.0,
        randomness,
    )?);

    // Level-2 encrypt data value towards receiver.
    let encrypted_data_value = hpke_seal_level_2(&datum.encrypted_data_value, ek, randomness)?;

    Ok(BlindedPseudonymizedData {
        blinded_handle,
        encrypted_data_value,
    })
}

/// Finalize a blinded pseudonymous datum for storage or analysis.
///
/// Inputs:
/// - `store_context`: The data store's long term private state including the
///   receiver's coPRF unblinding key, private decryption key, as well as
///   pseudonym hardening key
/// - `datum`: blinded pseudonymous datum output by [`convert_blinded_datum`] or
///   [`pseudonymize_blinded_datum`]
///
/// Output:
/// [Pseudonymized data](PseudonymizedData) such that the datum's pseudonymous
/// handle has been unblinded and hardened and the datum's value has been
/// decrypted.
pub fn finalize_blinded_datum(
    store_context: &StoreContext,
    datum: &BlindedPseudonymizedData,
) -> Result<PseudonymizedData, Error> {
    // Finalize pseudonym for storage.
    let handle = store_context.finalize_pseudonym(datum.blinded_handle)?;

    // Decrypt data value for storage.
    let data_value = hpke_open_level_2(&datum.encrypted_data_value, &store_context.hpke_sk)?;

    Ok(PseudonymizedData { handle, data_value })
}

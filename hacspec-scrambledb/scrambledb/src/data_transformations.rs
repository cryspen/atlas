use hacspec_lib::Randomness;
use libcrux::hpke::{kem::Nsk, HPKEConfig, HpkeOpen, HpkeSeal};
use oprf::coprf::{
    coprf_online::{blind, blind_convert, blind_evaluate, prepare_blind_convert},
    coprf_setup::{derive_key, BlindingPublicKey, CoPRFEvaluatorContext},
};

use crate::{data_types::*, error::Error, setup::StoreContext, SerializedHPKE};

fn pseudonymization_context_string() -> Vec<u8> {
    b"CoPRF-Context-Pseudonymization".to_vec()
}

fn hpke_level_1_info() -> Vec<u8> {
    b"Level-1".to_vec()
}

fn hpke_level_2_info() -> Vec<u8> {
    b"Level-2".to_vec()
}

/// Blind an identifiable datum as a first step in initial pseudonym
/// generation.
///
/// Inputs:
/// - bpk: Receiver's blinding public key
/// - ek: Receiver's public encryption key
/// - datum: Identifiable datum
/// - randomness: Random bytes
///
/// Output:
/// [BlindedIdentifiableDatum] such that the datum's handle is blinded for
/// CoPRF evaluation and the datum's value is level-1 encrypted.
pub fn blind_identifiable_datum(
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &IdentifiableData,
    randomness: &mut Randomness,
) -> Result<BlindedIdentifiableData, Error> {
    // Blind orthonym towards receiver
    let blinded_handle = BlindedIdentifiableHandle(blind(
        *bpk,
        datum.handle.as_bytes(),
        pseudonymization_context_string(),
        randomness,
    )?);

    // Encrypt data towards receiver
    let HPKEConfig(_, kem, _, _) = crate::HPKE_CONF;
    let encrypted_data_value = EncryptedDataValue {
        attribute_name: datum.data_value.attribute_name.clone(),
        value: SerializedHPKE::from_hpke_ct(&HpkeSeal(
            crate::HPKE_CONF,
            ek,
            &hpke_level_1_info(),
            b"",
            &datum.data_value.value,
            None,
            None,
            None,
            randomness.bytes(Nsk(kem))?.to_vec(),
        )?)
        .to_bytes(),
    };

    Ok(BlindedIdentifiableData {
        handle: blinded_handle,
        data_value: encrypted_data_value,
    })
}

/// Blind a pseudonymous datum as a first step in pseudonym
/// conversion.
///
/// Inputs:
/// - store_context: The data store's long term private state including the pseudonym
///   hardening keys
/// - bpk: Receiver's blinding public key
/// - ek: Receiver's public encryption key
/// - datum: Pseudonymized datum
/// - randomness: Random bytes
///
/// Output:
/// [BlindedPseudonymizedDatum] such that the datum's handle is blinded for
/// CoPRF conversion and the datum's value is level-1 encrypted.
pub fn blind_pseudonymized_datum(
    store_context: &StoreContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &PseudonymizedData,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedData, Error> {
    // Blind recovered raw pseudonym towards receiver
    let blinded_handle = BlindedPseudonymizedHandle(prepare_blind_convert(
        *bpk,
        store_context.recover_raw_pseudonym(datum.handle.0)?,
        randomness,
    )?);

    // Encrypt data towards receiver
    let HPKEConfig(_, kem, _, _) = crate::HPKE_CONF;
    let encrypted_data_value = EncryptedDataValue {
        attribute_name: datum.data_value.attribute_name.clone(),
        value: SerializedHPKE::from_hpke_ct(&HpkeSeal(
            crate::HPKE_CONF,
            ek,
            &hpke_level_1_info(),
            b"",
            &datum.data_value.value,
            None,
            None,
            None,
            randomness.bytes(Nsk(kem))?.to_vec(),
        )?)
        .to_bytes(),
    };

    Ok(BlindedPseudonymizedData {
        handle: blinded_handle,
        data_value: encrypted_data_value,
    })
}

/// Obliviously pseudonymmize a blinded identifiable datum.
///
/// Inputs:
/// - coprf_context: The converter's CoPRF evaluation context
/// - bpk: The receiver's blinding public key
/// - ek: The receiver's public encryption key
/// - datum: A blinded datum output by [blind_identifiable_datum]
/// - randomness: Random bytes
///
/// Output:
/// [BlindedPseudonymizedDatum] such that the datum's blinded handle has been
/// obliviously evaluated to a pseudonym and the datum's value has been level-2
/// encrypted towards the receiver.
pub fn pseudonymize_blinded_datum(
    coprf_context: &CoPRFEvaluatorContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &BlindedIdentifiableData,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedData, Error> {
    let key = derive_key(&coprf_context, datum.data_value.attribute_name.as_bytes())?;

    // Obliviously generate Pseudonym
    let handle = BlindedPseudonymizedHandle(blind_evaluate(key, *bpk, datum.handle.0, randomness)?);

    // Double encrypt data towards data lake
    let HPKEConfig(_, kem, _, _) = crate::HPKE_CONF;
    let data_value = EncryptedDataValue {
        attribute_name: datum.data_value.attribute_name.clone(),
        value: SerializedHPKE::from_hpke_ct(&HpkeSeal(
            crate::HPKE_CONF,
            ek,
            &hpke_level_2_info(),
            b"",
            &datum.data_value.value,
            None,
            None,
            None,
            randomness.bytes(Nsk(kem))?.to_vec(),
        )?)
        .to_bytes(),
    };

    Ok(BlindedPseudonymizedData { handle, data_value })
}

/// Obliviously convert a blinded pseudonymous datum to a given target pseudonym key.
///
/// Inputs:
/// - coprf_context: The Converters CoPRF evaluation context
/// - bpk: The receiver's blinding public key
/// - ek: The receiver's public encryption key
/// - conversion_target: Target pseudonym key identifier
/// - randomness: Random bytes
///
/// Output:
/// [BlindedPseudonymizedDatum] such that the datum's pseudonymous handle is
/// converted to the target pseudonym key and the datum's value is level-2
/// encrypted towards the receiver.
pub fn convert_blinded_datum(
    coprf_context: &CoPRFEvaluatorContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    conversion_target: &[u8],
    datum: &BlindedPseudonymizedData,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedData, Error> {
    let key_from = derive_key(&coprf_context, datum.data_value.attribute_name.as_bytes())?;

    let key_to = derive_key(&coprf_context, conversion_target)?;

    // Obliviously convert pseudonym
    let handle = BlindedPseudonymizedHandle(blind_convert(
        *bpk,
        key_from,
        key_to,
        datum.handle.0,
        randomness,
    )?);

    // Encrypt data towards data lake
    let HPKEConfig(_, kem, _, _) = crate::HPKE_CONF;
    let data_value = EncryptedDataValue {
        attribute_name: datum.data_value.attribute_name.clone(),
        value: SerializedHPKE::from_hpke_ct(&HpkeSeal(
            crate::HPKE_CONF,
            ek,
            &hpke_level_2_info(),
            b"",
            &datum.data_value.value,
            None,
            None,
            None,
            randomness.bytes(Nsk(kem))?.to_vec(),
        )?)
        .to_bytes(),
    };

    Ok(BlindedPseudonymizedData { handle, data_value })
}

/// Finalize a blinded pseudonymous datum for storage or analysis.
///
/// Inputs:
/// - store_context: The data store's long term private state including the
///   receiver's coPRF unblinding key, private decryption key, as well as
///   pseudonym hardening key
/// - datum: blinded pseudonymous datum output by [convert_blinded_datum] or
///   [pseudonymize_blinded_datum]
///
/// Output:
/// [PseudonymizedDatum] such that the datum's pseudonymous handle has been
/// unblinded and hardened and the datum's value has been decrypted.
pub fn finalize_blinded_datum(
    store_context: &StoreContext,
    datum: &BlindedPseudonymizedData,
) -> Result<PseudonymizedData, Error> {
    let handle = FinalizedPseudonym(store_context.finalize_pseudonym(datum.handle.0)?);

    let outer_encryption = SerializedHPKE::from_bytes(&datum.data_value.value).to_hpke_ct();

    let inner_encryption = SerializedHPKE::from_bytes(&HpkeOpen(
        crate::HPKE_CONF,
        &outer_encryption,
        &store_context.hpke_sk,
        b"Level-2",
        b"",
        None,
        None,
        None,
    )?)
    .to_hpke_ct();

    let data_value = DataValue {
        attribute_name: datum.data_value.attribute_name.clone(),
        value: HpkeOpen(
            crate::HPKE_CONF,
            &inner_encryption,
            &store_context.hpke_sk,
            b"Level-1",
            b"",
            None,
            None,
            None,
        )?,
    };

    Ok(PseudonymizedData { handle, data_value })
}

use hacspec_lib::Randomness;
use libcrux::hpke::{kem::Nsk, HPKEConfig, HpkeOpen, HpkeSeal};
use oprf::coprf::coprf_setup::BlindingPublicKey;

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
pub fn blind_identifiable_datum(
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &IdentifiableDatum,
    randomness: &mut Randomness,
) -> Result<BlindedIdentifiableDatum, Error> {
    // Blind orthonym towards data lake
    let blinded_handle = BlindedIdentifiableHandle(oprf::coprf::coprf_online::blind(
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

    Ok(BlindedIdentifiableDatum {
        handle: blinded_handle,
        data_value: encrypted_data_value,
    })
}

pub fn blind_pseudonymized_datum(
    store_context: &StoreContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &PseudonymizedDatum,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedDatum, Error> {
    // Blind recovered raw pseudonym towards receiver
    let blinded_handle =
        BlindedPseudonymizedHandle(oprf::coprf::coprf_online::prepare_blind_convert(
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

    Ok(BlindedPseudonymizedDatum {
        handle: blinded_handle,
        data_value: encrypted_data_value,
    })
}
pub fn pseudonymize_blinded_datum(
    coprf_context: oprf::coprf::coprf_setup::CoPRFEvaluatorContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &BlindedIdentifiableDatum,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedDatum, Error> {
    let key = oprf::coprf::coprf_setup::derive_key(
        &coprf_context,
        datum.data_value.attribute_name.as_bytes(),
    )?;

    // Obliviously generate Pseudonym
    let handle = BlindedPseudonymizedHandle(oprf::coprf::coprf_online::blind_evaluate(
        key,
        *bpk,
        datum.handle.0,
        randomness,
    )?);

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

    Ok(BlindedPseudonymizedDatum { handle, data_value })
}

pub fn convert_blinded_datum(
    coprf_context: oprf::coprf::coprf_setup::CoPRFEvaluatorContext,
    bpk: &BlindingPublicKey,
    ek: &[u8],
    conversion_target: &[u8],
    datum: &BlindedPseudonymizedDatum,
    randomness: &mut Randomness,
) -> Result<BlindedPseudonymizedDatum, Error> {
    let key_from = oprf::coprf::coprf_setup::derive_key(
        &coprf_context,
        datum.data_value.attribute_name.as_bytes(),
    )?;

    let key_to = oprf::coprf::coprf_setup::derive_key(&coprf_context, conversion_target)?;

    // Obliviously convert pseudonym
    let handle = BlindedPseudonymizedHandle(oprf::coprf::coprf_online::blind_convert(
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

    Ok(BlindedPseudonymizedDatum { handle, data_value })
}

pub fn finalize_blinded_datum(
    store_context: &StoreContext,
    datum: &BlindedPseudonymizedDatum,
) -> Result<PseudonymizedDatum, Error> {
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

    Ok(PseudonymizedDatum { handle, data_value })
}

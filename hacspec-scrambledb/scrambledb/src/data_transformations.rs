use hacspec_lib::Randomness;
use libcrux::hpke::{kem::Nsk, HPKEConfig, HpkeSeal};
use oprf::coprf::coprf_setup::{BlindingPrivateKey, BlindingPublicKey};

use crate::{data_types::*, error::Error, SerializedHPKE};

fn pseudonymization_context_string() -> Vec<u8> {
    b"CoPRF-Context-Pseudonymization".to_vec()
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

    // Encrypt data towards data lake
    let HPKEConfig(_, kem, _, _) = crate::HPKE_CONF;
    let encrypted_data_value = EncryptedDataValue {
        attribute_name: datum.data_value.attribute_name.clone(),
        value: SerializedHPKE::from_hpke_ct(&HpkeSeal(
            crate::HPKE_CONF,
            ek,
            b"Level-1",
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

pub fn pseudonymize_blinded_datum(
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &BlindedIdentifiableDatum,
) -> BlindedPseudonymizedDatum {
    todo!()
}

pub fn convert_blinded_datum(
    bpk: &BlindingPublicKey,
    ek: &[u8],
    conversion_target: &[u8],
    datum: &BlindedPseudonymizedDatum,
) -> BlindedPseudonymizedDatum {
    todo!()
}

pub fn finalize_blinded_datum(
    bpk: &BlindingPrivateKey,
    dk: &[u8],
    datum: &BlindedPseudonymizedDatum,
) -> PseudonymizedDatum {
    todo!()
}

use oprf::coprf::coprf_setup::{BlindingPrivateKey, BlindingPublicKey};

use crate::{data_types::*, table::BlindIdentifier};

pub fn blind_identifiable_datum(
    bpk: &BlindingPublicKey,
    ek: &[u8],
    datum: &IdentifiableDatum,
) -> BlindedIdentifiableDatum {
    todo!()
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

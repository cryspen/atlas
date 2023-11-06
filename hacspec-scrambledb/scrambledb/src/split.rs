//! # Pseudonymization
use hacspec_lib::Randomness;
use libcrux::hpke::HpkePublicKey;
use oprf::coprf::coprf_setup::BlindingPublicKey;

use crate::{
    data_transformations::{blind_identifiable_datum, pseudonymize_blinded_datum},
    data_types::{BlindedIdentifiableData, BlindedPseudonymizedData, IdentifiableData},
    error::Error,
    setup::ConverterContext,
    table::Table,
};

/// ## Blinding Orthonymous Tables
///
/// Prepare a table of orthonymous data values for pseudonymization by applying
/// the blinding operation on each entry and shuffling the result.
///
/// Inputs:
/// - `ek_receiver`: The receiver's public encryption key
/// - `bpk_receiver`: The receiver's public blinding key
/// - `table`: A table of identifiable data values
/// - `randomness`: Random bytes
///
/// Outputs:
/// A table of blinded identifiable data.
pub fn blind_orthonymous_table(
    ek_receiver: &HpkePublicKey,
    bpk_receiver: BlindingPublicKey,
    table: Table<IdentifiableData>,
    randomness: &mut Randomness,
) -> Result<Table<BlindedIdentifiableData>, Error> {
    let mut blinded_table_entries = table
        .data()
        .iter()
        .map(|entry| blind_identifiable_datum(&bpk_receiver, ek_receiver, entry, randomness))
        .collect::<Result<Vec<BlindedIdentifiableData>, Error>>()?;

    blinded_table_entries.sort();

    Ok(Table::new(table.identifier().into(), blinded_table_entries))
}

/// ## Oblivious Pseudonymization
///
/// Obliviously pseudonymize a table of blinded orthonymous data values by
/// applying the oblivious pseudonymization operation on each entry and
/// shuffling the result.
///
/// Inputs:
/// - `converter_context`: The Converter's coPRF evaluation context
/// - `ek_receiver`: The receiver's public encryption key
/// - `bpk_receiver`: The receiver's public blinding key
/// - `blinded_table`: A table of blinded identifiable data values
/// - `randomness`: Random bytes
///
/// Outputs:
/// A table of blinded pseudonymized data.
pub fn pseudonymize_blinded_table(
    converter_context: &ConverterContext,
    bpk_receiver: BlindingPublicKey,
    ek_receiver: &HpkePublicKey,
    blinded_table: Table<BlindedIdentifiableData>,
    randomness: &mut Randomness,
) -> Result<Table<BlindedPseudonymizedData>, Error> {
    let mut blinded_pseudonymized_entries = blinded_table
        .data()
        .iter()
        .map(|entry| {
            pseudonymize_blinded_datum(
                &converter_context.coprf_context,
                &bpk_receiver,
                ek_receiver,
                entry,
                randomness,
            )
        })
        .collect::<Result<Vec<BlindedPseudonymizedData>, Error>>()?;
    blinded_pseudonymized_entries.sort();

    Ok(Table::new(
        blinded_table.identifier().into(),
        blinded_pseudonymized_entries,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{setup::StoreContext, test_util::generate_plain_table};

    use super::*;

    #[test]
    fn test_split_full() {
        use rand::prelude::*;

        let mut rng = rand::thread_rng();
        let mut randomness = [0u8; 1000000];
        rng.fill_bytes(&mut randomness);
        let mut randomness = Randomness::new(randomness.to_vec());

        let converter_context = ConverterContext::setup(&mut randomness).unwrap();
        let lake_context = StoreContext::setup(&mut randomness).unwrap();

        // == Generate Plain Table ==
        let plain_table = generate_plain_table();

        let (lake_ek, lake_bpk) = lake_context.public_keys();

        // == Blind Table for Pseudonymization ==
        let blind_table = crate::split::blind_orthonymous_table(
            &lake_ek,
            lake_bpk,
            plain_table.clone(),
            &mut randomness,
        )
        .unwrap();

        // == Blind Pseudonymized Table ==
        let converted_tables = crate::split::pseudonymize_blinded_table(
            &converter_context,
            lake_bpk,
            &lake_ek,
            blind_table,
            &mut randomness,
        )
        .unwrap();

        // == Unblinded Pseudonymized Table ==
        let lake_tables =
            crate::finalize::finalize_blinded_table(&lake_context, converted_tables).unwrap();

        let mut pseudonym_set = HashSet::new();
        // test that data is preserved
        for pseudonymized_data in lake_tables.data() {
            assert!(
                // plain_values.iter().any(|set| { *set == table_values }),
                plain_table
                    .data()
                    .iter()
                    .any(|entry| entry.data_value == pseudonymized_data.data_value),
                "Data was not preserved during pseudonymization."
            );

            // test if all pseudonyms are unique
            assert!(
                pseudonym_set.insert(pseudonymized_data.handle.clone()),
                "Generated pseudonyms are not unique."
            );
        }
    }
}

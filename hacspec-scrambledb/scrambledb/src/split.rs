//! # Split Conversion
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

/// ## Preparation
///
/// - For each column of the table, go entry by entry, blinding the table key for the
/// data lake as coPRF receiver and additionaly encrypting the entry value towards the
/// data lake
/// - Sort each column by the blinded table keys (this implements a random shuffle)
pub fn prepare_split_conversion(
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

/// ## Conversion
/// One part of the joint creation of pseudonomized and unlinkable data to
/// be fed into the data lake.  The input table is part of a
/// pseudonymization request by a data source. Its data contents are
/// encrypted towards the data lake and the keys (unpseudonymized
/// identifiers) are blinded to allow conversion.
///
/// The output tables are to be fed into the data lake. Each table
/// corresponds to one column (one data attribute) of the original
/// table. All table entries have been assigned pseudonymized keys. In
/// addition the entry ciphertexts have been rerandomized and table rows
/// have been shuffled to prevent correlation of the incoming with the
/// outgoing table data.
pub fn split_conversion(
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
        let blind_table = crate::split::prepare_split_conversion(
            &lake_ek,
            lake_bpk,
            plain_table.clone(),
            &mut randomness,
        )
        .unwrap();

        // == Blind Pseudonymized Table ==
        let converted_tables = crate::split::split_conversion(
            &converter_context,
            lake_bpk,
            &lake_ek,
            blind_table,
            &mut randomness,
        )
        .unwrap();

        // == Unblinded Pseudonymized Table ==
        let lake_tables =
            crate::finalize::finalize_conversion(&lake_context, converted_tables).unwrap();

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

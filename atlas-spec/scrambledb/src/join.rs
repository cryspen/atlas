//! # Pseudonym Conversion
use hacspec_lib::Randomness;
use oprf::coprf::coprf_setup::BlindingPublicKey;

use crate::{
    data_transformations::{blind_pseudonymized_datum, convert_blinded_datum},
    data_types::{BlindedPseudonymizedData, PseudonymizedData},
    error::Error,
    setup::{ConverterContext, StoreContext, StoreEncryptionKey},
    table::Table,
    SECPAR_BYTES,
};

/// ## Blinding Pseudonymous Tables
///
/// Prepare a table of pseudonymous data values for join conversion by applying
/// the blinding operation on each entry and shuffling the result.
///
/// Inputs:
/// - `store_context`: The data store's pseudonymization context
/// - `ek_receiver`: The receiver's public encryption key
/// - `bpk_receiver`: The receiver's public blinding key
/// - `pseudonymized_table`: A table of pseudonymous data values
/// - `randomness`: Random bytes
///
/// Outputs:
/// A table of blinded pseudonymous data values.
pub fn blind_pseudonymous_table(
    store_context: &StoreContext,
    bpk_receiver: BlindingPublicKey,
    ek_receiver: &StoreEncryptionKey,
    pseudonymized_table: Table<PseudonymizedData>,
    randomness: &mut Randomness,
) -> Result<Table<BlindedPseudonymizedData>, Error> {
    let mut blinded_data = pseudonymized_table
        .data()
        .iter()
        .map(|entry| {
            blind_pseudonymized_datum(store_context, &bpk_receiver, ek_receiver, entry, randomness)
        })
        .collect::<Result<Vec<BlindedPseudonymizedData>, Error>>()?;

    blinded_data.sort();
    Ok(Table::new(
        pseudonymized_table.identifier().into(),
        blinded_data,
    ))
}

pub fn join_identifier(identifier: String) -> String {
    let mut join_identifier = identifier;
    join_identifier.push('-');
    join_identifier.push_str("Join");
    join_identifier
}

/// ## Oblivious Conversion
///
/// Obliviously convert a table of blinded pseudonymous data values to fresh
/// join-pseudonyms by applying the pseudonym conversion transformation to
/// each entry and shuffling the result.
///
/// Inputs:
/// - `converter_context`: The Converter's coPRF conversion context
/// - `bpk_receiver`: The receiver's public blinding key
/// - `ek_receiver`: The receiver's public encryption key
/// - `table`: A table of blinded pseudonymous data values
/// - `randomness`: Random bytes
///
/// Outputs:
/// A table of consistently join-pseudonymized data values.
pub fn convert_blinded_table(
    converter_context: &ConverterContext,
    bpk_receiver: BlindingPublicKey,
    ek_receiver: &StoreEncryptionKey,
    table: Table<BlindedPseudonymizedData>,
    randomness: &mut Randomness,
) -> Result<Table<BlindedPseudonymizedData>, Error> {
    let conversion_target = randomness.bytes(SECPAR_BYTES)?.to_owned();
    let mut converted_data = table
        .data()
        .iter()
        .map(|entry| {
            convert_blinded_datum(
                &converter_context.coprf_context,
                &bpk_receiver,
                ek_receiver,
                &conversion_target,
                entry,
                randomness,
            )
        })
        .collect::<Result<Vec<BlindedPseudonymizedData>, Error>>()?;

    converted_data.sort();

    Ok(Table::new(table.identifier().into(), converted_data))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{setup::StoreContext, test_util::generate_plain_table};

    use super::*;

    #[test]
    fn test_join_full() {
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

        for entry in lake_tables.data() {
            // store lake_pseudonyms for test against join pseudonyms
            pseudonym_set.insert(entry.handle.clone());
        }

        // select first two lake tables for join
        let join_table = Table::new(
            "Join".into(),
            lake_tables
                .data()
                .iter()
                .filter_map(|entry| {
                    if entry.data_value.attribute_name == "Address"
                        || entry.data_value.attribute_name == "Favorite Color"
                    {
                        Some(entry.clone())
                    } else {
                        None
                    }
                })
                .collect(),
        );

        let processor_context = StoreContext::setup(&mut randomness).unwrap();

        let (ek_processor, bpk_processor) = processor_context.public_keys();
        let blind_tables = crate::join::blind_pseudonymous_table(
            &lake_context,
            bpk_processor,
            &ek_processor,
            join_table,
            &mut randomness,
        )
        .unwrap();

        let converted_join_tables = crate::join::convert_blinded_table(
            &converter_context,
            bpk_processor,
            &ek_processor,
            blind_tables,
            &mut randomness,
        )
        .unwrap();

        let joined_tables =
            crate::finalize::finalize_blinded_table(&processor_context, converted_join_tables)
                .unwrap();

        for entry in joined_tables.data() {
            let mut lake_pseudonyms = pseudonym_set.clone();

            // test if all pseudonyms are fresh compared to lake_pseudonyms

            debug_assert!(
                lake_pseudonyms.insert(entry.handle.clone()),
                "Generated pseudonyms are not unique."
            );

            debug_assert!(
                plain_table
                    .data()
                    .iter()
                    .any(|entry| entry.data_value == entry.data_value),
                "Data was not preserved during join."
            );
        }
    }
}

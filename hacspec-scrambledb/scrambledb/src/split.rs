//! # Split Conversion
use hacspec_lib::Randomness;
use libcrux::hpke::HpkePublicKey;
use oprf::coprf::coprf_setup::BlindingPublicKey;

use crate::{
    data_transformations::{blind_identifiable_datum, pseudonymize_blinded_datum},
    data_types::{BlindedIdentifiableDatum, DataValue, EncryptedDataValue, IdentifiableDatum},
    error::Error,
    setup::ConverterContext,
    table::{BlindTable, Column, ConvertedTable, PlainTable},
};

fn split_identifier(identifier: String, attribute: String) -> String {
    let mut split_identifier = identifier;
    split_identifier.push('-');
    split_identifier.push_str(&attribute);
    split_identifier
}

/// ## Preparation
///
/// - For each column of the table, go entry by entry, blinding the table key for the
/// data lake as coPRF receiver and additionaly encrypting the entry value towards the
/// data lake
/// - Sort each column by the blinded table keys (this implements a random shuffle)
pub fn prepare_split_conversion(
    ek_receiver: &HpkePublicKey,
    bpk_receiver: BlindingPublicKey,
    table: PlainTable,
    randomness: &mut Randomness,
) -> Result<BlindTable, Error> {
    let mut blinded_columns = Vec::new();

    for column in table.columns() {
        let attribute = column.attribute();

        let mut blinded_column_data = Vec::new();

        for (plaintext_id, plaintext_value) in column.data() {
            let datum = IdentifiableDatum {
                handle: plaintext_id,
                data_value: DataValue {
                    attribute_name: attribute.clone(),
                    value: plaintext_value,
                },
            };
            let blinded_datum =
                blind_identifiable_datum(&bpk_receiver, ek_receiver, &datum, randomness)?;

            blinded_column_data.push((blinded_datum.handle.0, blinded_datum.data_value.value));
        }
        let mut blinded_column = Column::new(attribute, blinded_column_data);
        blinded_column.sort();

        blinded_columns.push(blinded_column);
    }
    Ok(BlindTable::new(table.identifier(), blinded_columns))
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
    blinded_table: BlindTable,
    randomness: &mut Randomness,
) -> Result<Vec<ConvertedTable>, Error> {
    let mut converted_tables = Vec::new();

    for blinded_column in blinded_table.columns() {
        let attribute = blinded_column.attribute();

        let mut converted_column_data = Vec::new();
        for (blind_identifier, encrypted_value) in blinded_column.data() {
            let blinded_datum = BlindedIdentifiableDatum {
                handle: crate::data_types::BlindedIdentifiableHandle(blind_identifier),
                data_value: EncryptedDataValue {
                    attribute_name: attribute.clone(),
                    value: encrypted_value,
                },
            };

            let blinded_pseudonymized_datum = pseudonymize_blinded_datum(
                &converter_context.coprf_context,
                &bpk_receiver,
                ek_receiver,
                &blinded_datum,
                randomness,
            )?;

            converted_column_data.push((
                blinded_pseudonymized_datum.handle.0,
                blinded_pseudonymized_datum.data_value.value,
            ));
        }

        let mut converted_column = Column::new(attribute.clone(), converted_column_data);
        converted_column.sort();
        converted_tables.push(ConvertedTable::new(
            split_identifier(blinded_table.identifier(), attribute),
            converted_column,
        ));
    }

    Ok(converted_tables)
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

        let plain_values: Vec<HashSet<Vec<u8>>> = plain_table
            .clone()
            .columns()
            .iter()
            .map(|column| HashSet::from_iter(column.values()))
            .collect();

        let mut pseudonym_set = HashSet::new();
        // test that data is preserved
        for table in lake_tables {
            let table_values: HashSet<Vec<u8>> = HashSet::from_iter(table.values());
            assert!(
                plain_values.iter().any(|set| { *set == table_values }),
                "Data was not preserved during pseudonymization."
            );

            // test if all pseudonyms are unique
            for key in table.keys() {
                assert!(
                    pseudonym_set.insert(key),
                    "Generated pseudonyms are not unique."
                );
            }
        }
    }
}

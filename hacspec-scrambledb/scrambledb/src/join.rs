//! ## Join Conversion
use hacspec_lib::Randomness;
use libcrux::hpke::HpkePublicKey;
use oprf::coprf::coprf_setup::BlindingPublicKey;

use crate::{
    data_transformations::{blind_pseudonymized_datum, convert_blinded_datum},
    data_types::{
        BlindedPseudonymizedDatum, BlindedPseudonymizedHandle, DataValue, EncryptedDataValue,
        FinalizedPseudonym, PseudonymizedDatum,
    },
    error::Error,
    setup::{ConverterContext, StoreContext},
    table::{BlindTable, Column, ConvertedTable, PseudonymizedTable},
    SECPAR_BYTES,
};

/// ### Preparation
/// In order to process a join request on a number of pseudonymized
/// columns, they are prepared as follows:
/// - To allow for conversion to the join pseudonym, the unblinded coPRF
///   outputs are first retrieved from the lake pseudonyms by applying the
///   inverse of the PRP used when the data was imported to the lake.
/// - Afterwards a blinding of these coPRF outputs is performed towards
///   the data processor as receiver.
/// - In addition the table values are encrypted towards the data
///   processor.
///
/// ``` text
/// Inputs:
///     context: StoreContext
///     bpk_target: coPRF.BlindingPublicKey
///     ek_target: RPKE.EncryptionKey
///     pseudonymized_tables: List of PseudonymizedTables
///     randomness: uniformly random bytes
///
/// Output:
///     blinded_tables: List of BlindedTables
///
/// fn prepare_join_conversion(context,
///                            bpk_target,
///                            ek_target,
///                            pseudonymized_tables,
///                            randomness):
///     let blind_tables = Vec::new();
///     for table in pseudonymized_tables {
///         let blind_column = BlindColumn::new(table.column.attribute());
///
///         for (pseudonym, value) in table.column() {
///             let raw_pseudonym = recover_raw_pseudonym(context, pseudonym);
///             let blinded_pseudonym = prepare_blind_convert(bpk_target, raw_pseudonym, randomness);
///
///             let encrypted_value = RPKE.encrypt(ek_target, value, randomness);
///
///             blind_column.push((blinded_pseudonym, encrypted_value));
///         }
///         blind_column.sort();
///
///         let blind_table = BlindTable::new(table.identifier(), vec![blind_column]);
///         blind_tables.push(blind_table)
///     }
///     return blind_tables
/// ```
pub fn prepare_join_conversion(
    store_context: &StoreContext,
    bpk_receiver: BlindingPublicKey,
    ek_receiver: &HpkePublicKey,
    pseudonymized_tables: Vec<PseudonymizedTable>,
    randomness: &mut Randomness,
) -> Result<Vec<BlindTable>, Error> {
    let mut blind_columns = Vec::new();

    for table in pseudonymized_tables.iter() {
        let mut blind_column_data = Vec::new();

        for (pseudonym, value) in table.column().data() {
            let pseudonymized_datum = PseudonymizedDatum {
                handle: FinalizedPseudonym(pseudonym),
                data_value: DataValue {
                    attribute_name: table.column().attribute(),
                    value: value,
                },
            };
            let blinded_pseudonymized_datum = blind_pseudonymized_datum(
                &store_context,
                &bpk_receiver,
                &ek_receiver,
                &pseudonymized_datum,
                randomness,
            )?;

            blind_column_data.push((
                blinded_pseudonymized_datum.handle.0,
                blinded_pseudonymized_datum.data_value.value,
            ));
        }

        let mut blind_column = Column::new(table.column().attribute(), blind_column_data);
        blind_column.sort();

        let blind_table = BlindTable::new(table.identifier(), vec![blind_column]);
        blind_columns.push(blind_table)
    }
    Ok(blind_columns)
}

pub fn join_identifier(identifier: String) -> String {
    let mut join_identifier = identifier;
    join_identifier.push('-');
    join_identifier.push_str("Join");
    join_identifier
}

/// ### Conversion
/// Join requests are processed by blindly converting coPRF outputs to a
/// fresh-per-session join evaluation key.
///
/// For each of the blinded columns sent for joining by the lake, the
/// pseudonymous column table key is blindly converted to a fresh join
/// evaluation key.
///
pub fn join_conversion(
    converter_context: &ConverterContext,
    bpk_receiver: BlindingPublicKey,
    ek_receiver: &HpkePublicKey,
    tables: Vec<BlindTable>,
    randomness: &mut Randomness,
) -> Result<Vec<ConvertedTable>, Error> {
    let mut converted_tables = Vec::new();
    let conversion_target = randomness.bytes(SECPAR_BYTES)?.to_owned();

    for table in tables {
        for blind_column in table.columns() {
            let attribute = blind_column.attribute();

            let mut converted_data = Vec::new();
            for (blind_identifier, encrypted_value) in blind_column.data() {
                let blinded_pseudonymized_datum = BlindedPseudonymizedDatum {
                    handle: BlindedPseudonymizedHandle(blind_identifier),
                    data_value: EncryptedDataValue {
                        attribute_name: attribute.clone(),
                        value: encrypted_value,
                    },
                };
                let blinded_pseudonymized_datum = convert_blinded_datum(
                    &converter_context.coprf_context,
                    &bpk_receiver,
                    &ek_receiver,
                    &conversion_target,
                    &blinded_pseudonymized_datum,
                    randomness,
                )?;

                converted_data.push((
                    blinded_pseudonymized_datum.handle.0,
                    blinded_pseudonymized_datum.data_value.value,
                ));
            }
            let mut converted_table_column = Column::new(attribute.clone(), converted_data);
            converted_table_column.sort();
            converted_tables.push(ConvertedTable::new(
                join_identifier(table.identifier()),
                converted_table_column,
            ));
        }
    }
    Ok(converted_tables)
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

        for table in lake_tables.clone() {
            // store lake_pseudonyms for test against join pseudonyms
            for key in table.keys() {
                pseudonym_set.insert(key);
            }
        }

        // select first two lake tables for join
        let join_tables = vec![lake_tables[0].clone(), lake_tables[1].clone()];
        let processor_context = StoreContext::setup(&mut randomness).unwrap();

        let (ek_processor, bpk_processor) = processor_context.public_keys();
        let blind_tables = crate::join::prepare_join_conversion(
            &lake_context,
            bpk_processor,
            &ek_processor,
            join_tables,
            &mut randomness,
        )
        .unwrap();

        let converted_join_tables = crate::join::join_conversion(
            &converter_context,
            bpk_processor,
            &ek_processor,
            blind_tables,
            &mut randomness,
        )
        .unwrap();

        let joined_tables =
            crate::finalize::finalize_conversion(&processor_context, converted_join_tables)
                .unwrap();

        for table in joined_tables {
            let mut lake_pseudonyms = pseudonym_set.clone();

            // test if all pseudonyms are fresh compared to lake_pseudonyms
            for key in table.keys() {
                assert!(
                    lake_pseudonyms.insert(key),
                    "Generated pseudonyms are not unique."
                );
            }

            let table_values: HashSet<Vec<u8>> = HashSet::from_iter(table.values());
            assert!(
                plain_values.iter().any(|set| { *set == table_values }),
                "Data was not preserved during join."
            );
        }
    }
}

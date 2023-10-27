//! ## Join Conversion
use hacspec_lib::Randomness;
use libcrux::hpke::HpkePublicKey;
use oprf::coprf::coprf_setup::BlindingPublicKey;

use crate::{
    data_transformations::{blind_pseudonymized_datum, convert_blinded_datum},
    data_types::{BlindedPseudonymizedData, PseudonymizedData},
    error::Error,
    setup::{ConverterContext, StoreContext},
    table::Table,
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
    // for table in tables {
    //     for blind_column in table.columns() {
    //         let attribute = blind_column.attribute();

    //         let mut converted_data = Vec::new();
    //         for (blind_identifier, encrypted_value) in blind_column.data() {
    //             let blinded_pseudonymized_datum = BlindedPseudonymizedData {
    //                 blinded_handle: BlindedPseudonymizedHandle(blind_identifier),
    //                 encrypted_data_value: EncryptedDataValue {
    //                     attribute_name: attribute.clone(),
    //                     value: encrypted_value,
    //                     encryption_level: 1u8,
    //                 },
    //             };
    //             let blinded_pseudonymized_datum = convert_blinded_datum(
    //                 &converter_context.coprf_context,
    //                 &bpk_receiver,
    //                 &ek_receiver,
    //                 &conversion_target,
    //                 &blinded_pseudonymized_datum,
    //                 randomness,
    //             )?;

    //             converted_data.push((
    //                 blinded_pseudonymized_datum.blinded_handle.0,
    //                 blinded_pseudonymized_datum.encrypted_data_value.value,
    //             ));
    //         }
    //         let mut converted_table_column = Column::new(attribute.clone(), converted_data);
    //         converted_table_column.sort();
    //         converted_tables.push(ConvertedTable::new(
    //             join_identifier(table.identifier()),
    //             converted_table_column,
    //         ));
    //     }
    // }
    // Ok(converted_tables)
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
        let blind_tables = crate::join::prepare_join_conversion(
            &lake_context,
            bpk_processor,
            &ek_processor,
            join_table,
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

        for entry in joined_tables.data() {
            let mut lake_pseudonyms = pseudonym_set.clone();

            // test if all pseudonyms are fresh compared to lake_pseudonyms

            assert!(
                lake_pseudonyms.insert(entry.handle.clone()),
                "Generated pseudonyms are not unique."
            );

            assert!(
                plain_table
                    .data()
                    .iter()
                    .any(|entry| entry.data_value == entry.data_value),
                "Data was not preserved during join."
            );
        }
    }
}

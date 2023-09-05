//! # Split Conversion
use elgamal::{encrypt, EncryptionKey};
use hacspec_lib::Randomness;
use oprf::coprf::{
    coprf_online::{blind, blind_evaluate},
    coprf_setup::{derive_key, BlindingPublicKey},
};

use crate::{
    error::Error,
    setup::ConverterContext,
    table::{BlindTable, Column, ConvertedTable, PlainTable},
};

pub fn split_identifier(identifier: String, attribute: String) -> String {
    let mut split_identifier = identifier.clone();
    split_identifier.push_str("-");
    split_identifier.push_str(&attribute);
    split_identifier
}

pub fn split_conversion_context() -> Vec<u8> {
    b"Split-".to_vec()
}

/// ## Preparation
///
/// - For each column of the table, go entry by entry, blinding the table key for the
/// data lake as coPRF receiver and additionaly encrypting the entry value towards the
/// data lake
/// - Sort each column by the blinded table keys (this implements a random shuffle)
pub fn prepare_split_conversion(
    ek_store: EncryptionKey,
    bpk_store: BlindingPublicKey,
    table: PlainTable,
    randomness: &mut Randomness,
) -> Result<BlindTable, Error> {
    let mut columns = Vec::new();
    for column in table.columns() {
        let attribute = column.attribute();

        let mut data = Vec::new();

        for (entity_id, value) in column.data() {
            let blinded_key = blind(
                bpk_store,
                entity_id.as_bytes(),
                split_conversion_context(),
                randomness,
            )?;

            let encrypted_value = encrypt(ek_store, value, randomness)?;
            data.push((blinded_key, encrypted_value));
        }
        let mut blind_column = Column::new(attribute, data);
        blind_column.sort();

        columns.push(blind_column);
    }
    Ok(BlindTable::new(table.identifier(), columns))
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
    bpk_store: BlindingPublicKey,
    ek_store: EncryptionKey,
    table: BlindTable,
    randomness: &mut Randomness,
) -> Result<Vec<ConvertedTable>, Error> {
    let mut converted_tables = Vec::new();
    for blind_column in table.columns() {
        let attribute = blind_column.attribute();
        let conversion_key = derive_key(&converter_context.coprf_context, attribute.as_bytes())?;

        let mut converted_data = Vec::new();
        for (blind_identifier, encrypted_value) in blind_column.data() {
            let blind_pseudonym =
                blind_evaluate(conversion_key, bpk_store, blind_identifier, randomness)?;
            let encrypted_value = elgamal::rerandomize(ek_store, encrypted_value, randomness)?;

            converted_data.push((blind_pseudonym, encrypted_value));
        }
        let mut converted_table_column = Column::new(attribute.clone(), converted_data);
        converted_table_column.sort();
        converted_tables.push(ConvertedTable::new(
            split_identifier(table.identifier(), attribute),
            converted_table_column,
        ));
    }
    Ok(converted_tables)
}

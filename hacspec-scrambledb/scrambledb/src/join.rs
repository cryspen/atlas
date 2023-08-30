//! ## Join Conversion
use elgamal::EncryptionKey;
use hacspec_lib::Randomness;
use oprf::coprf::{
    coprf_online::{blind_evaluate, prepare_blind_convert},
    coprf_setup::{derive_key, BlindingPublicKey},
};

use crate::{
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
    origin_context: StoreContext,
    bpk_target: BlindingPublicKey,
    ek_target: EncryptionKey,
    pseudonymized_tables: Vec<PseudonymizedTable>,
    randomness: &mut Randomness,
) -> Result<Vec<BlindTable>, Error> {
    let mut blind_tables = Vec::new();
    for table in pseudonymized_tables {
        let mut blind_column_data = Vec::new();
        for (pseudonym, value) in table.column().data() {
            let raw_pseudonym = origin_context.recover_raw_pseudonym(pseudonym)?;
            let blinded_pseudonym = prepare_blind_convert(bpk_target, raw_pseudonym, randomness)?;

            let encrypted_value = elgamal::encrypt(ek_target, value, randomness)?;

            blind_column_data.push((blinded_pseudonym, encrypted_value));
        }
        let mut blind_column = Column::new(table.column().attribute(), blind_column_data);
        blind_column.sort();

        let blind_table = BlindTable::new(table.identifier(), vec![blind_column]);
        blind_tables.push(blind_table)
    }
    Ok(blind_tables)
}

pub fn join_identifier(identifier: String, attribute: String) -> String {
    let mut join_identifier = identifier;
    join_identifier.push('-');
    join_identifier.push_str(&attribute);
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
    converter_context: ConverterContext,
    bpk_target: BlindingPublicKey,
    ek_target: EncryptionKey,
    tables: Vec<BlindTable>,
    randomness: &mut Randomness,
) -> Result<Vec<ConvertedTable>, Error> {
    let mut converted_tables = Vec::new();
    let join_conversion_key = derive_key(
        &converter_context.coprf_context,
        randomness.bytes(SECPAR_BYTES)?,
    )?;

    for table in tables {
        for blind_column in table.columns() {
            let attribute = blind_column.attribute();

            let mut converted_data = Vec::new();
            for (blind_identifier, encrypted_value) in blind_column.data() {
                let blind_pseudonym = blind_evaluate(
                    join_conversion_key,
                    bpk_target,
                    blind_identifier,
                    randomness,
                )?;
                let encrypted_value = elgamal::rerandomize(ek_target, encrypted_value, randomness)?;

                converted_data.push((blind_pseudonym, encrypted_value));
            }
            let mut converted_table_column = Column::new(attribute.clone(), converted_data);
            converted_table_column.sort();
            converted_tables.push(ConvertedTable::new(
                join_identifier(table.identifier(), attribute),
                converted_table_column,
            ));
        }
    }
    Ok(converted_tables)
}

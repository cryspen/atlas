//! # Conversion Finalization
use crate::{
    error::Error,
    setup::StoreContext,
    table::{Column, ConvertedTable, PseudonymizedTable},
};

/// The result of a split or join conversion is a set of blinded
/// pseudonymized tables which have been encrypted towards a data store.
///
/// For permanent storage of the pseudonymized data, the raw pseudonyms have
/// to be unblinded and subsequently hardened into permanent pseudonyms.
///
/// In addition the encrypted values need to be decrypted to be available
/// for future conversions towards other data stores.
pub fn finalize_conversion(
    store_context: &StoreContext,
    converted_tables: Vec<ConvertedTable>,
) -> Result<Vec<PseudonymizedTable>, Error> {
    let mut pseudonymized_tables = Vec::new();

    for blinded_table in converted_tables {
        let mut pseudonymized_column_data = Vec::new();

        for (blinded_pseudonym, encrypted_value) in blinded_table.column().data() {
            let pseudonym = store_context.finalize_pseudonym(blinded_pseudonym)?;
            let value = store_context.decrypt_value(encrypted_value)?;

            pseudonymized_column_data.push((pseudonym, value));
        }

        let mut pseudonymized_column = Column::new(
            blinded_table.column().attribute(),
            pseudonymized_column_data,
        );
        pseudonymized_column.sort();

        pseudonymized_tables.push(PseudonymizedTable::new(
            blinded_table.identifier(),
            pseudonymized_column,
        ))
    }

    Ok(pseudonymized_tables)
}

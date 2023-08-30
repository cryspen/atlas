use crate::{
    error::Error,
    setup::StoreContext,
    table::{Column, ConvertedTable, PseudonymizedTable},
};

pub fn finalize_conversion(
    store_context: StoreContext,
    converted_tables: Vec<ConvertedTable>,
) -> Result<Vec<PseudonymizedTable>, Error> {
    let mut pseudonymized_tables = Vec::new();

    for table in converted_tables {
        let mut pseudonymized_table_data = Vec::new();

        for (blind_pseudonym, encrypted_value) in table.column().data() {
            let pseudonym = store_context.finalize_pseudonym(blind_pseudonym)?;
            let value = store_context.decrypt_value(encrypted_value)?;

            pseudonymized_table_data.push((pseudonym, value));
        }
        let mut pseudonymized_column =
            Column::new(table.column().attribute(), pseudonymized_table_data);
        pseudonymized_column.sort();
        pseudonymized_tables.push(PseudonymizedTable::new(
            table.identifier(),
            pseudonymized_column,
        ))
    }
    Ok(pseudonymized_tables)
}

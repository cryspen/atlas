use crate::{
    data_transformations::finalize_blinded_datum,
    data_types::{BlindedPseudonymizedData, PseudonymizedData},
    error::Error,
    setup::StoreContext,
    table::Table,
};

/// ## Finalization of Pseudonymous and Converted Tables
///
/// Finalization of pseudonyms is the same regardless of pseudonym type,
/// i.e. whether they are long term storage pseudonyms at the Data Lake or
/// join pseudonyms at a Data Processor.
///
/// Finalize a table of blinded pseudonymized data values by applying the
/// finalization operation on each entry and shuffling the result:
///
/// Inputs:
/// - `store_context`: The data store's pseudonymization context
/// - `table`: A table of blinded pseudonymized data values
///
/// Output:
/// A table of pseudonymized data values.
pub fn finalize_blinded_table(
    store_context: &StoreContext,
    table: Table<BlindedPseudonymizedData>,
) -> Result<Table<PseudonymizedData>, Error> {
    let mut pseudonymized_data = table
        .data()
        .iter()
        .map(|entry| finalize_blinded_datum(store_context, entry))
        .collect::<Result<Vec<PseudonymizedData>, Error>>()?;

    pseudonymized_data.sort();

    Ok(Table::new(table.identifier().into(), pseudonymized_data))
}

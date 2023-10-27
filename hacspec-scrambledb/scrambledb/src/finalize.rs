//! # Conversion Finalization

use crate::{
    data_transformations::finalize_blinded_datum,
    data_types::{BlindedPseudonymizedData, PseudonymizedData},
    error::Error,
    setup::StoreContext,
    table::Table,
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

use std::collections::HashMap;

use elgamal::{encrypt, EncryptionKey};
use oprf::coprf::{coprf_online::blind, coprf_setup::CoPRFRequesterContext};
use scrambledb_util::{random_scalar, subbytes};

use crate::{
    table::{SourceInputTable, SourceOutputTable, TableKey},
    Error, RANDBYTES_SCALAR,
};

pub struct SourceContext {
    coprf_requester_context: CoPRFRequesterContext,
    ek_lake: EncryptionKey,
}

/// Prepare a pseudonymization request.
///
/// - For each column of the table, go entry by entry, blinding the table key for the
/// data lake as coPRF receiver and additionaly encrypting the entry value towards the
/// data lake
/// - Sort each column by the blinded table keys (this implements a random shuffle)
pub fn pseudonymization_request(
    source_context: SourceContext,
    table: SourceInputTable,
    randomness: &[u8],
) -> Result<SourceOutputTable, Error> {
    let mut rand_offset = 0usize;

    let mut output_table_inner = HashMap::new();
    for attr in table.attributes() {
        let mut output_attr_column = Vec::new();
        let col = table.get_column(attr).unwrap();

        for (table_key, table_value) in col.iter() {
            let randomizer_coprf =
                random_scalar(subbytes(randomness, rand_offset, RANDBYTES_SCALAR)).unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let table_key = match table_key {
                TableKey::Plain(key) => key,
                _ => panic!("Invalid Table Key"),
            };

            let blinded_key = blind(
                source_context.coprf_requester_context.bpk,
                table_key,
                &source_context.coprf_requester_context.context_string,
                randomizer_coprf,
            )
            .unwrap();

            let randomizer_enc =
                random_scalar(subbytes(randomness, rand_offset, RANDBYTES_SCALAR)).unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let encrypted_value =
                encrypt(source_context.ek_lake, *table_value, randomizer_enc).unwrap();
            output_attr_column.push((blinded_key, encrypted_value));
        }
        output_attr_column.sort_by_key(|(blinded_key, _)| *blinded_key);
        output_table_inner.insert(attr.clone(), output_attr_column);
    }
    let output_table = SourceOutputTable::new(table.identifier(), output_table_inner);

    Ok(output_table)
}

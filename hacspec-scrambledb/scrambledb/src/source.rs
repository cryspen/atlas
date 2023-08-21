use std::collections::HashMap;

use scrambledb_util::get_subbytes;

use crate::{types::table::SourceOutputTable, Error, RANDBYTES_SCALAR};

pub struct SourceContext {
    coprf_requester_context: oprf::coprf::coprf_setup::CoPRFRequesterContext,
    ek_lake: elgamal::EncryptionKey,
}

pub fn pseudonymization_request(
    source_context: SourceContext,
    table: crate::types::table::SourceInputTable,
    randomness: &[u8],
) -> Result<crate::types::table::SourceOutputTable, Error> {
    let mut rand_offset = 0usize;

    let mut output_table_inner = HashMap::new();
    for attr in table.attributes() {
        let mut output_attr_column = HashMap::new();
        let col = table.get_column(attr).unwrap();

        for (table_key, table_value) in col.iter() {
            let randomizer_coprf = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let blinded_key = oprf::coprf::coprf_online::blind(
                source_context.coprf_requester_context.bpk,
                table_key,
                &source_context.coprf_requester_context.context_string,
                randomizer_coprf,
            )
            .unwrap();

            let randomizer_enc = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let encrypted_value =
                elgamal::encrypt(source_context.ek_lake, *table_value, randomizer_enc).unwrap();
            output_attr_column.insert(blinded_key, encrypted_value);
        }
        output_table_inner.insert(attr.clone(), output_attr_column);
    }
    let mut output_table = SourceOutputTable::new(table.identifier(), output_table_inner);
    output_table.shuffle();

    Ok(output_table)
}

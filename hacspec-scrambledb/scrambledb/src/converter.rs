use crate::types::table::{
    LakeInputTable, LakeOutputTable, ProcessorInputTable, SourceOutputTable,
};
use crate::{Error, RANDBYTES_SCALAR, SECPAR_BYTES};
use elgamal::EncryptionKey;
use oprf::coprf::coprf_online;
use oprf::coprf::coprf_setup::{self, BlindingPublicKey};
use oprf::coprf::coprf_setup::{setup_coprf_evaluator, CoPRFEvaluatorContext};
use scrambledb_util::get_subbytes;

pub struct ConverterContext {
    coprf_context: CoPRFEvaluatorContext,
    bpk_lake: BlindingPublicKey,
    ek_lake: EncryptionKey,
}

pub fn setup_converter(
    msk: [u8; 32],
    bpk_lake: BlindingPublicKey,
    ek_lake: EncryptionKey,
) -> Result<ConverterContext, Error> {
    Ok(ConverterContext {
        coprf_context: setup_coprf_evaluator(b"coPRF-P256-SHA256", msk),
        bpk_lake,
        ek_lake,
    })
}

/// One part of the joint creation of pseudonomized and unlinkable data to be fed into the data lake.
/// The input table is part of a pseudonymization request by a data source. Its data contents are encrypted towards the data lake and the keys (unpseudonymized identifiers) are blinded to allow conversion.
///
/// The output tables are to be fed into the data lake. Each table corresponds to one column (one data attribute) of the original table. All table entries have been assigned pseudonymized keys. In addition the entry ciphertexts have been rerandomized and table rows have been shuffled to prevent correlation of the incoming with the outgoing table data.
///
///  cf. [Lehmann], p. 13, Section 2.a of Fig. 4
pub fn handle_pseudonymization_request(
    converter_context: ConverterContext,
    table: &SourceOutputTable,
    randomness: Vec<u8>,
) -> Result<Vec<LakeInputTable>, Error> {
    assert_eq!(randomness.len(), table.size() * 2 * RANDBYTES_SCALAR);
    let mut rand_offset = 0usize;

    let mut lake_input_tables = Vec::new();
    for attribute in table.attributes() {
        let mut lake_input_table_inner = Vec::new();
        let coprf_key =
            coprf_setup::derive_key(converter_context.coprf_context.msk, attribute).unwrap();

        let column = table.get_column(attribute).unwrap();
        for (table_key, table_value) in column.iter() {
            let randomizer_value = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let rerandomized_value =
                elgamal::rerandomize(converter_context.ek_lake, *table_value, randomizer_value)
                    .unwrap();

            // eval coprf on key
            let randomizer_coprf = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let blinded_pseudonym = coprf_online::blind_evaluate(
                coprf_key,
                converter_context.bpk_lake,
                *table_key,
                randomizer_coprf,
            )
            .unwrap();
            lake_input_table_inner.push((blinded_pseudonym, rerandomized_value));
        }
        // Shuffle by sorting based on the pseudorandom keys.
        lake_input_table_inner.sort_by_key(|&(blinded_pseudonym, _)| blinded_pseudonym);
        let lake_input_table =
            LakeInputTable::new(&table.identifier(), attribute, lake_input_table_inner);
        lake_input_tables.push(lake_input_table);
    }

    Ok(lake_input_tables)
}

pub fn handle_join_request(
    converter_context: ConverterContext,
    bpk_processor: BlindingPublicKey,
    ek_processor: EncryptionKey,
    tables: Vec<LakeOutputTable>,
    randomness: Vec<u8>,
) -> Result<Vec<ProcessorInputTable>, Error> {
    assert_eq!(randomness.len(), SECPAR_BYTES);
    let mut rand_offset = 0usize;

    let coprf_join_key = coprf_setup::derive_key(
        converter_context.coprf_context.msk,
        get_subbytes(&randomness, rand_offset, SECPAR_BYTES),
    )
    .unwrap();
    rand_offset += SECPAR_BYTES;

    let mut processor_input_tables = Vec::new();
    for table in tables {
        let mut processor_input_table_inner = Vec::new();
        let attribute = table.attr();
        let coprf_table_key =
            coprf_setup::derive_key(converter_context.coprf_context.msk, attribute).unwrap();
        for &(blind_pseudonym, encrypted_value) in table.entries() {
            let randomizer_coprf = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let converted_pseudonym = coprf_online::blind_convert(
                bpk_processor,
                coprf_table_key,
                coprf_join_key,
                blind_pseudonym,
                randomizer_coprf,
            )
            .unwrap();

            // rerandomize entry value
            let randomizer_value = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let rerandomized_value =
                elgamal::rerandomize(ek_processor, encrypted_value, randomizer_value).unwrap();

            processor_input_table_inner.push((converted_pseudonym, rerandomized_value));
        }
        processor_input_table_inner.sort_by_key(|&(pseudoym, _)| pseudoym);
        processor_input_tables.push(ProcessorInputTable::new(
            &table.identifier().to_vec(),
            &table.attr().to_vec(),
            processor_input_table_inner,
        ));
    }
    Ok(processor_input_tables)
}

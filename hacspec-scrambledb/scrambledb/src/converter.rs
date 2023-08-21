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
pub fn generate_pseudonyms(
    converter_context: ConverterContext,
    table: &SourceOutputTable,
    randomness: Vec<u8>,
) -> Result<Vec<LakeInputTable>, Error> {
    assert_eq!(randomness.len(), table.size() * 2 * RANDBYTES_SCALAR);
    let mut rand_offset = 0usize;

    let mut pre_lake_tables = Vec::new();
    for attr_j in table.attributes() {
        let k_j = coprf_setup::derive_key(converter_context.coprf_context.msk, attr_j).unwrap();

        let mut pre_lake_table_j_inner = Vec::new();
        let col_j = table.get_column(attr_j).unwrap();
        for key_i in col_j.keys() {
            // rerandomize keys entry
            let randomizer_value = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let val_ij = elgamal::rerandomize(
                converter_context.ek_lake,
                *col_j.get(key_i).clone().unwrap(),
                randomizer_value,
            )
            .unwrap();

            // eval coprf on key
            let randomizer_coprf = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let key_ij = coprf_online::blind_evaluate(
                k_j,
                converter_context.bpk_lake,
                *key_i,
                randomizer_coprf,
            )
            .unwrap();
            pre_lake_table_j_inner.push((key_ij, val_ij));
        }
        // Shuffle by sorting based on the pseudorandom keys.
        pre_lake_table_j_inner.sort_by_key(|(pseudonym, _)| *pseudonym);
        let pre_lake_table_j =
            LakeInputTable::new(&table.identifier(), attr_j, pre_lake_table_j_inner);
        pre_lake_tables.push(pre_lake_table_j);
    }

    Ok(pre_lake_tables)
}

pub fn convert_pseudonyms(
    converter_context: ConverterContext,
    tables: Vec<LakeOutputTable>,
    bpk_processor: BlindingPublicKey,
    randomness: Vec<u8>,
) -> Result<Vec<ProcessorInputTable>, Error> {
    assert_eq!(randomness.len(), SECPAR_BYTES);
    let mut rand_offset = 0usize;

    let k_star = coprf_setup::derive_key(
        converter_context.coprf_context.msk,
        get_subbytes(&randomness, rand_offset, SECPAR_BYTES),
    )
    .unwrap();
    rand_offset += SECPAR_BYTES;

    let mut processor_input_tables = Vec::new();
    for table in tables {
        let mut processor_input_table_inner = Vec::new();
        let attr_j = table.attr();
        let k_j = coprf_setup::derive_key(converter_context.coprf_context.msk, &attr_j).unwrap();
        for (blind_pseudonym, value) in table.entries() {
            // convert pseudonym
            let randomizer_coprf = scrambledb_util::random_scalar(get_subbytes(
                &randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;
            let converted_pseudonym = coprf_online::blind_convert(
                bpk_processor,
                k_j,
                k_star,
                *blind_pseudonym,
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

            let randomized_value =
                elgamal::rerandomize(converter_context.ek_lake, *value, randomizer_value).unwrap();

            processor_input_table_inner.push((converted_pseudonym, randomized_value));
        }
        processor_input_table_inner.sort_by_key(|(pseudoym, _)| *pseudoym);
        processor_input_tables.push(ProcessorInputTable::new(
            &table.identifier().to_vec(),
            &table.attr().to_vec(),
            processor_input_table_inner,
        ));
    }
    Ok(processor_input_tables)
}

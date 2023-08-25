use crate::{
    table::{LakeInputTable, LakeOutputTable, ProcessorInputTable, SourceOutputTable},
    Error, SECPAR_BYTES,
};
use elgamal::EncryptionKey;
use hacspec_lib::Randomness;
use oprf::coprf::{
    coprf_online::{blind_convert, blind_evaluate},
    coprf_setup::{derive_key, BlindingPublicKey, CoPRFEvaluatorContext},
};

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
        coprf_context: CoPRFEvaluatorContext::new(msk),
        bpk_lake,
        ek_lake,
    })
}

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
///
///  cf. [Lehmann], p. 13, Section 2.a of Fig. 4
///
pub fn handle_pseudonymization_request(
    converter_context: ConverterContext,
    table: &SourceOutputTable,
    randomness: &mut Randomness,
) -> Result<Vec<LakeInputTable>, Error> {
    let mut lake_input_tables = Vec::new();
    for attribute in table.attributes() {
        let mut lake_input_table_inner = Vec::new();
        let coprf_key = derive_key(&converter_context.coprf_context, attribute.as_bytes())?;

        let column = table.get_column(attribute).ok_or(Error::CorruptedData)?;
        for (table_key, table_value) in column.iter() {
            let rerandomized_value =
                elgamal::rerandomize(converter_context.ek_lake, *table_value, randomness)?;

            let blinded_pseudonym = blind_evaluate(
                coprf_key,
                converter_context.bpk_lake,
                *table_key,
                randomness,
            )?;
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

/// Join requests are processed by blindly converting coPRF outputs to a
/// fresh-per-session join evaluation key.
///
/// For each of the blinded columns sent for joining by the lake, the
/// pseudonymous column table key is blindly converted to a fresh join
/// evaluation key.
///
pub fn handle_join_request(
    converter_context: ConverterContext,
    bpk_processor: BlindingPublicKey,
    ek_processor: EncryptionKey,
    tables: Vec<LakeOutputTable>,
    randomness: &mut Randomness,
) -> Result<Vec<ProcessorInputTable>, Error> {
    let coprf_join_key = derive_key(
        &converter_context.coprf_context,
        randomness.bytes(SECPAR_BYTES)?,
    )?;

    let mut processor_input_tables = Vec::new();
    for table in tables {
        let mut processor_input_table_inner = Vec::new();
        let attribute = table.attr();
        let coprf_table_key = derive_key(&converter_context.coprf_context, attribute.as_bytes())?;
        for &(blind_pseudonym, encrypted_value) in table.entries() {
            let converted_pseudonym = blind_convert(
                bpk_processor,
                coprf_table_key,
                coprf_join_key,
                blind_pseudonym,
                randomness,
            )?;

            let rerandomized_value =
                elgamal::rerandomize(ek_processor, encrypted_value, randomness)?;

            processor_input_table_inner.push((converted_pseudonym, rerandomized_value));
        }
        processor_input_table_inner.sort_by_key(|&(pseudoym, _)| pseudoym);
        processor_input_tables.push(ProcessorInputTable::new(
            &table.identifier(),
            &table.attr(),
            processor_input_table_inner,
        ));
    }
    Ok(processor_input_tables)
}

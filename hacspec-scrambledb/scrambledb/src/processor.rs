use std::collections::HashMap;

use elgamal::{DecryptionKey, EncryptionKey};
use hacspec_lib::Randomness;
use oprf::coprf::{
    coprf_online::{self},
    coprf_setup::{BlindingPublicKey, CoPRFReceiverContext},
};
use prp::prp;

use crate::{
    table::{JoinedTable, ProcessorInputTable, TableKey},
    Error, JOIN_ID,
};

pub struct ProcessorContext {
    coprf_receiver_context: CoPRFReceiverContext,
    ek: EncryptionKey,
    dk: DecryptionKey,
    k_prp: [u8; 32],
}

impl ProcessorContext {
    pub fn get_public_keys(&self) -> (EncryptionKey, BlindingPublicKey) {
        (self.ek, self.coprf_receiver_context.get_bpk())
    }
}

pub fn setup_processor(mut randomness: Randomness) -> Result<ProcessorContext, Error> {
    let coprf_receiver_context = CoPRFReceiverContext::new(&mut randomness);

    let (dk, ek) = elgamal::generate_keys(&mut randomness)?;

    let k_prp = randomness.bytes(32)?.try_into()?;

    Ok(ProcessorContext {
        coprf_receiver_context,
        ek,
        dk,
        k_prp,
    })
}

/// The final result of a join-request are table columns corresponding to
/// the requested join attributes, where the set of table keys is the same
/// for each column, namely a set of join-specific non-transitive
/// pseudonym keys.
///
/// To retrieve this result from the output of the converter:
/// - Unblind each table key and apply a PRF to obtain the final
///   join-pseudonyms for each table.
/// - Decrypt the table values.
pub fn finalize_join_request(
    processor_context: ProcessorContext,
    converter_tables: Vec<ProcessorInputTable>,
) -> Result<JoinedTable, Error> {
    let mut joined_table_inner = HashMap::new();
    for table in converter_tables {
        let mut joined_column_inner = Vec::new();

        for (blinded_pseudonym, encrypted_value) in table.entries() {
            let raw_pseudonym = coprf_online::finalize(
                &processor_context.coprf_receiver_context,
                *blinded_pseudonym,
            )?;

            let pseudonym =
                TableKey::Pseudonym(prp(raw_pseudonym.raw_bytes(), &processor_context.k_prp));

            let value = elgamal::decrypt(processor_context.dk, *encrypted_value)?;

            joined_column_inner.push((pseudonym, value));
        }
        joined_column_inner.sort_by_key(|(pseudonym, _)| {
            if let TableKey::Pseudonym(pseudonym) = pseudonym {
                *pseudonym
            } else {
                panic!("Invalid Table key instead of pseudonym")
            }
        });
        joined_table_inner.insert(table.attr(), joined_column_inner);
    }

    Ok(JoinedTable::new(String::from(JOIN_ID), joined_table_inner))
}

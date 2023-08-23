use std::collections::HashMap;

use elgamal::{decrypt, generate_keys, DecryptionKey, EncryptionKey};
use libcrux::aead::{self, encrypt_detached, Algorithm, Key};
use oprf::{
    coprf::{
        coprf_online::finalize,
        coprf_setup::{generate_blinding_key_pair, BlindingPrivateKey, BlindingPublicKey},
    },
    p256_sha256::serialize_element,
};
use scrambledb_util::subbytes;

use crate::{
    table::{JoinedTable, ProcessorInputTable, TableKey},
    Error, JOIN_ID, RANDBYTES_SCALAR,
};

pub struct ProcessorContext {
    bsk: BlindingPrivateKey,
    dk: DecryptionKey,
    k_prf: Key,
}

pub fn setup_processor(
    randomness: &[u8],
) -> Result<(ProcessorContext, (BlindingPublicKey, EncryptionKey)), Error> {
    let mut rand_offset = 0usize;
    let (bsk, bpk) =
        generate_blinding_key_pair(subbytes(randomness, rand_offset, RANDBYTES_SCALAR)).unwrap();
    rand_offset += RANDBYTES_SCALAR;

    let (dk, ek) = generate_keys(subbytes(randomness, rand_offset, RANDBYTES_SCALAR)).unwrap();
    rand_offset += RANDBYTES_SCALAR;

    let k_prf = Key::from_bytes(
        Algorithm::Chacha20Poly1305,
        subbytes(
            randomness,
            rand_offset,
            Algorithm::Chacha20Poly1305.key_size(),
        )
        .to_vec(),
    )
    .unwrap();

    Ok((ProcessorContext { bsk, dk, k_prf }, (bpk, ek)))
}

pub fn finalize_join_request(
    processor_context: ProcessorContext,
    converter_tables: Vec<ProcessorInputTable>,
) -> Result<JoinedTable, Error> {
    let mut joined_table_inner = HashMap::new();
    for table in converter_tables {
        let mut joined_column_inner = Vec::new();

        for (blinded_pseudonym, encrypted_value) in table.entries() {
            let raw_pseudonym = finalize(processor_context.bsk, *blinded_pseudonym).unwrap();

            let pseudonym = serialize_element(&raw_pseudonym).to_vec();

            let pseudonym: TableKey = encrypt_detached(
                &processor_context.k_prf,
                pseudonym,
                aead::Iv::new(b"").unwrap(),
                b"",
            )
            .unwrap()
            .into();

            let value = decrypt(processor_context.dk, *encrypted_value).unwrap();

            joined_column_inner.push((pseudonym, value));
        }
        joined_column_inner.sort_by_key(|(pseudonym, _)| {
            if let TableKey::Pseudonym(_, pseudonym) = pseudonym {
                pseudonym.clone()
            } else {
                panic!("Invalid Table key instead of pseudonym")
            }
        });
        joined_table_inner.insert(table.attr().to_vec(), joined_column_inner);
    }

    Ok(JoinedTable::new(b"Join".to_vec(), joined_table_inner))
}

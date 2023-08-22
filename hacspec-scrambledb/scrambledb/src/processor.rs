use std::collections::HashMap;

use elgamal::{generate_keys, DecryptionKey, EncryptionKey};
use oprf::coprf::coprf_setup::{generate_blinding_key_pair, BlindingPrivateKey, BlindingPublicKey};
use scrambledb_util::get_subbytes;

use crate::{
    types::table::{JoinedTable, ProcessorInputTable, TableKey},
    Error, RANDBYTES_SCALAR,
};

pub struct ProcessorContext {
    bsk: BlindingPrivateKey,
    dk: DecryptionKey,
    k_prf: libcrux::aead::Key,
}

pub fn setup_processor(
    randomness: &[u8],
) -> Result<(ProcessorContext, (BlindingPublicKey, EncryptionKey)), Error> {
    let mut rand_offset = 0usize;
    let (bsk, bpk) =
        generate_blinding_key_pair(get_subbytes(randomness, rand_offset, RANDBYTES_SCALAR))
            .unwrap();
    rand_offset += RANDBYTES_SCALAR;

    let (dk, ek) = generate_keys(get_subbytes(randomness, rand_offset, RANDBYTES_SCALAR)).unwrap();
    rand_offset += RANDBYTES_SCALAR;

    let k_prf = libcrux::aead::Key::from_bytes(
        libcrux::aead::Algorithm::Chacha20Poly1305,
        get_subbytes(
            randomness,
            rand_offset,
            libcrux::aead::Algorithm::Chacha20Poly1305.key_size(),
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
            let raw_pseudoymn =
                oprf::coprf::coprf_online::finalize(processor_context.bsk, *blinded_pseudonym)
                    .unwrap();

            let pseudonym = oprf::p256_sha256::serialize_element(&raw_pseudoymn).to_vec();

            let pseudonym: TableKey = libcrux::aead::encrypt_detached(
                &processor_context.k_prf,
                pseudonym,
                libcrux::aead::Iv::new(b"").unwrap(),
                b"",
            )
            .unwrap()
            .into();

            let value = elgamal::decrypt(processor_context.dk, *encrypted_value).unwrap();

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

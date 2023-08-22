use elgamal::{generate_keys, DecryptionKey, EncryptionKey};
use oprf::coprf::coprf_setup::{generate_blinding_key_pair, BlindingPrivateKey, BlindingPublicKey};
use scrambledb_util::get_subbytes;

use crate::{
    types::table::{LakeInputTable, LakeOutputTable, LakeTable, TableKey},
    Error, RANDBYTES_SCALAR,
};

pub struct LakeContext {
    bsk: BlindingPrivateKey,
    dk: DecryptionKey,
    k_prp: libcrux::aead::Key,
}

pub fn setup_lake(
    randomness: &[u8],
) -> Result<(LakeContext, (BlindingPublicKey, EncryptionKey)), Error> {
    let mut rand_offset = 0usize;
    let (bsk, bpk) =
        generate_blinding_key_pair(get_subbytes(randomness, rand_offset, RANDBYTES_SCALAR))
            .unwrap();
    rand_offset += RANDBYTES_SCALAR;

    let (dk, ek) = generate_keys(get_subbytes(randomness, rand_offset, RANDBYTES_SCALAR)).unwrap();
    rand_offset += RANDBYTES_SCALAR;

    let k_prp = libcrux::aead::Key::from_bytes(
        libcrux::aead::Algorithm::Chacha20Poly1305,
        get_subbytes(
            randomness,
            rand_offset,
            libcrux::aead::Algorithm::Chacha20Poly1305.key_size(),
        )
        .to_vec(),
    )
    .unwrap();

    Ok((LakeContext { bsk, dk, k_prp }, (bpk, ek)))
}

pub fn finalize_pseudonymization_request(
    lake_context: LakeContext,
    input_tables: Vec<LakeInputTable>,
) -> Result<Vec<LakeTable>, Error> {
    let mut lake_tables = Vec::new();
    for table in input_tables {
        let mut lake_table_inner = Vec::new();

        for &(blinded_pseudonym, encrypted_value) in table.entries() {
            let unblinded_raw_pseudonym =
                oprf::coprf::coprf_online::finalize(lake_context.bsk, blinded_pseudonym).unwrap();

            let mut pseudonym =
                oprf::p256_sha256::serialize_element(&unblinded_raw_pseudonym).to_vec();

            let pseudonym = libcrux::aead::encrypt_detached(
                &lake_context.k_prp,
                &mut pseudonym,
                libcrux::aead::Iv::new(b"").unwrap(),
                b"",
            )
            .unwrap()
            .into();

            let table_value = elgamal::decrypt(lake_context.dk, encrypted_value).unwrap();

            lake_table_inner.push((pseudonym, table_value));
        }
        lake_table_inner.sort_by_key(|(pseudonym, _)| {
            if let TableKey::Pseudonym(_, pseudonym) = pseudonym {
                pseudonym.clone()
            } else {
                panic!("Invalid Table key instead of pseudonym")
            }
        });
        let lake_table = LakeTable::new(
            table.identifier().to_vec(),
            table.attr().to_vec(),
            lake_table_inner,
        );

        lake_tables.push(lake_table);
    }

    Ok(lake_tables)
}

pub fn join_request(
    lake_context: LakeContext,
    bpk_processor: BlindingPublicKey,
    ek_processor: EncryptionKey,
    lake_tables: Vec<LakeTable>,
    randomness: &[u8],
) -> Result<Vec<LakeOutputTable>, Error> {
    let mut rand_offset = 0usize;

    let mut output_tables = Vec::new();
    for table in lake_tables {
        let mut output_table_inner = Vec::new();

        for (pseudonym, table_value) in table.entries() {
            let (tag, pseudonym) = match pseudonym {
                TableKey::Pseudonym(tag, pseudonym) => (tag, pseudonym),
                _ => panic!("Invalid Table Key"),
            };

            let raw_pseudonym_compressed = libcrux::aead::decrypt_detached(
                &lake_context.k_prp,
                pseudonym,
                libcrux::aead::Iv::new(b"").unwrap(),
                b"",
                tag,
            )
            .unwrap();

            let raw_pseudonym = oprf::p256_sha256::deserialize_element(
                raw_pseudonym_compressed.try_into().unwrap(),
            )
            .unwrap();

            let randomizer_coprf = scrambledb_util::random_scalar(get_subbytes(
                randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let blinded_pseudonym = oprf::coprf::coprf_online::prepare_blind_convert(
                bpk_processor,
                raw_pseudonym,
                randomizer_coprf,
            )
            .unwrap();

            let randomizer_enc = scrambledb_util::random_scalar(get_subbytes(
                randomness,
                rand_offset,
                RANDBYTES_SCALAR,
            ))
            .unwrap();
            rand_offset += RANDBYTES_SCALAR;

            let encrypted_value =
                elgamal::encrypt(ek_processor, *table_value, randomizer_enc).unwrap();

            output_table_inner.push((blinded_pseudonym, encrypted_value));
        }
        output_table_inner.sort_by_key(|&(blinded_pseudonym, _)| blinded_pseudonym);

        let output_table = LakeOutputTable::new(
            &table.identifier().to_vec(),
            &table.attr().to_vec(),
            output_table_inner,
        );

        output_tables.push(output_table);
    }
    Ok(output_tables)
}

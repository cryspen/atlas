use elgamal::{decrypt, encrypt, generate_keys, DecryptionKey, EncryptionKey};
use hacspec_lib::Randomness;
use oprf::coprf::{
    coprf_online::{finalize, prepare_blind_convert},
    coprf_setup::{BlindingPublicKey, CoPRFReceiverContext},
};
use p256::P256Point;
use prp::prp;

use crate::{
    table::{LakeInputTable, LakeOutputTable, LakeTable, TableKey},
    Error,
};

pub struct LakeContext {
    coprf_receiver_context: CoPRFReceiverContext,
    ek: EncryptionKey,
    dk: DecryptionKey,
    k_prp: [u8; 32],
}

impl LakeContext {
    pub fn get_public_keys(&self) -> (EncryptionKey, BlindingPublicKey) {
        (self.ek, self.coprf_receiver_context.get_bpk())
    }
}

pub fn setup_lake(mut randomness: Randomness) -> Result<LakeContext, Error> {
    let receiver_context = CoPRFReceiverContext::new(&mut randomness);

    let (dk, ek) = generate_keys(&mut randomness)?;

    let k_prp = randomness.bytes(32)?.try_into()?;

    Ok(LakeContext {
        coprf_receiver_context: receiver_context,
        ek,
        dk,
        k_prp,
    })
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
                finalize(&lake_context.coprf_receiver_context, blinded_pseudonym)?;

            let pseudonym = TableKey::Pseudonym(prp(
                unblinded_raw_pseudonym.raw_bytes(),
                &lake_context.k_prp,
            ));

            let table_value = decrypt(lake_context.dk, encrypted_value)?;

            lake_table_inner.push((pseudonym, table_value));
        }
        lake_table_inner.sort_by_key(|(pseudonym, _)| {
            if let TableKey::Pseudonym(pseudonym) = pseudonym {
                *pseudonym
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
    randomness: &mut Randomness,
) -> Result<Vec<LakeOutputTable>, Error> {
    let mut output_tables = Vec::new();
    for table in lake_tables {
        let mut output_table_inner = Vec::new();

        for (pseudonym, table_value) in table.entries() {
            let pseudonym = match pseudonym {
                TableKey::Pseudonym(pseudonym) => pseudonym,
                _ => return Err(Error::CorruptedData),
            };

            let raw_pseudonym = P256Point::from_raw_bytes(prp(*pseudonym, &lake_context.k_prp))?;

            let blinded_pseudonym =
                prepare_blind_convert(bpk_processor, raw_pseudonym, randomness)?;

            let encrypted_value = encrypt(ek_processor, *table_value, randomness)?;

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

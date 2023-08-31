//! # Setup

use elgamal::{generate_keys, DecryptionKey, EncryptionKey};
use hacspec_lib::Randomness;
use oprf::coprf::{
    coprf_online,
    coprf_setup::{BlindingPublicKey, CoPRFEvaluatorContext, CoPRFReceiverContext},
};
use p256::P256Point;

use crate::{
    error::Error,
    table::{BlindPseudonym, EncryptedValue, PlainValue, Pseudonym},
};

pub struct ConverterContext {
    pub(crate) coprf_context: CoPRFEvaluatorContext,
}

pub struct StoreContext {
    coprf_receiver_context: CoPRFReceiverContext,
    ek: EncryptionKey,
    dk: DecryptionKey,
    k_prp: [u8; 32],
}

pub type LakeContext = StoreContext;
pub type ProcessorContext = StoreContext;

impl ConverterContext {
    /// ## Converter Setup
    /// On setup the converter initializes a coPRF evaluator context.
    ///
    /// ``` text
    /// Inputs:
    ///     msk: Nmsk uniformly random bytes
    ///
    /// Output:
    ///     coprf_evaluator_context: coPRFEvaluatorContext
    ///
    /// fn setup_converter_context(msk) -> ConverterContext:
    ///     return coPRFEvaluatorContext::new(msk)
    /// ```
    pub fn setup(msk: [u8; 32]) -> Self {
        ConverterContext {
            coprf_context: CoPRFEvaluatorContext::new(msk),
        }
    }
}

impl StoreContext {
    /// ## Data Store Setup
    /// On setup, a data store initializes a coPRFReceiverContext, derives a
    /// pair of encryption and decryption keys for the RPKE as well as a
    /// private PRP key.
    ///
    /// ``` text
    /// Inputs:
    ///     randomness: (NcoPRFReceiver + NRPKEKeyGen + NPRP) uniformly random bytes
    ///
    /// Outputs:
    ///     coprf_receiver_context: CoPRFReceiverContext
    ///     ek: RPKE.EncryptionKey
    ///     dk: RPKE.DecryptionKey
    ///     k_prp: PRP.PRPKey
    ///
    /// fn setup(randomness) -> StoreContext:
    ///     let coprf_receiver_context =
    ///     CoPRFReceiverContext::new(randomness[NcoPRFReceiver]);
    ///     let (ek, dk) = RPKE.generate_keys(randomness[NRPKEKeyGen]);
    ///     let k_prp = PRP.KeyGen(randomness[NPRP]);
    ///     StoreContext{
    ///       coprf_receiver_context,
    ///       ek,
    ///       dk,
    ///       k_prp
    ///     }
    /// ```
    pub fn setup(mut randomness: Randomness) -> Result<Self, Error> {
        let receiver_context = CoPRFReceiverContext::new(&mut randomness);

        let (dk, ek) = generate_keys(&mut randomness)?;

        let k_prp = randomness.bytes(32)?.try_into()?;

        Ok(Self {
            coprf_receiver_context: receiver_context,
            ek,
            dk,
            k_prp,
        })
    }

    /// Given a store context generated as above, the following methods are
    /// available:
    ///
    /// - Retrieve store public keys for encryption and coPRF blinding.
    /// ``` text
    /// Input:
    ///     context: StoreContext
    /// Output:
    ///     ek: RPKE.EncryptionKey
    ///     bpk: CoPRF.BlindingPublicKey
    ///
    /// fn public_keys(context):
    ///     let ek = context.ek;
    ///     let bpk = context.coprf_receiver_context.public_key()
    ///     return (ek, bpk);
    /// ```
    pub fn public_keys(&self) -> (EncryptionKey, BlindingPublicKey) {
        (self.ek, self.coprf_receiver_context.get_bpk())
    }

    /// - Finalize Pseudonym: As part of the finalization of a split or join
    ///   conversion the raw pseudonyms that are the unblinded result of coPRF
    ///   evaluation are further hardened by application of a PRP.
    ///
    /// ``` text
    /// Input:
    ///     context: StoreContext
    ///     blind_pseudonym: CoPRFBlindOutput
    /// Output:
    ///     pseudonym: Pseudonym
    ///
    /// fn finalize_pseudonym(context, blind_pseudonym):
    ///     let raw_pseudonym =
    ///     context.coprf_receiver_context.finalize(blind_pseudonym);
    ///     return PRP.eval(context.k_prp, raw_pseudonym)
    /// ```
    pub fn finalize_pseudonym(&self, blind_pseudonym: BlindPseudonym) -> Result<Pseudonym, Error> {
        let raw_pseudonym = coprf_online::finalize(&self.coprf_receiver_context, blind_pseudonym)?;
        Ok(prp::prp(raw_pseudonym.raw_bytes(), &self.k_prp))
    }

    /// - Recover Raw Pseudonym: In preparation of a join conversion, the raw
    ///   pseudonyms, i.e. coPRF outputs must be recovered from the hardened
    ///   pseudonyms before they can be sent to the converter for blind
    ///   conversion.
    ///
    ///   ``` text
    ///   Inputs:
    ///       context: StoreContext
    ///       pseudonym: Pseudonym
    ///
    ///   Output:
    ///       raw_pseudonym: CoPRFOutput
    ///
    ///   fn recover_raw_pseudonym(context, pseudonym):
    ///       return PRP.invert(context.k_prp, pseudonym)
    ///   ```
    pub fn recover_raw_pseudonym(&self, pseudonym: Pseudonym) -> Result<P256Point, Error> {
        P256Point::from_raw_bytes(prp::prp(pseudonym, &self.k_prp)).map_err(|e| e.into())
    }

    /// - Decrypt table values: As part of the finalization of a split or join
    ///   conversion, the table values that were encrypted for oblivious processing by
    ///   the converter can be decrypted.
    ///
    ///   ``` text
    ///   Inputs:
    ///       context: StoreContext
    ///       encrypted_value: RPKE.Ciphertext
    ///
    ///   Outputs:
    ///       value: DataValue
    ///
    ///   fn decrypt_value(context, encrypted_value):
    ///       return RPKE.decrypt(context.dk, encrypted_value)
    ///   ```
    pub fn decrypt_value(&self, encrypted_value: EncryptedValue) -> Result<PlainValue, Error> {
        elgamal::decrypt(self.dk, encrypted_value).map_err(|e| e.into())
    }
}

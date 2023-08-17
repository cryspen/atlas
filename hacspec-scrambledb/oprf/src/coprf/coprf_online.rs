#![warn(missing_docs)]
//! ## EXT.2. CoPRF Online Protocol
//! ```text
//!     Requester(bpk, input)                                        Evaluator(k)                                   Receiver(bpk, bsk)
//!   --------------------------------------------------------------------------------------------------------------------------------
//!   blindedElement = Blind(bpk, input)
//!
//!                                  blindedElement
//!                                    ---------->
//!
//!                                               evaluatedElement = BlindEvaluate(k, blindedElement)
//!
//!                                                                                           evaluatedElement
//!                                                                                             ---------->
//!
//!                                                                                                  output = Finalize(bsk, evaluatedElement)
//! ```

use elgamal::Ciphertext;

use super::coprf_setup::{BlindingPrivateKey, BlindingPublicKey, CoPRFKey};
use crate::{p256_sha256, Error};
use p256::{NatMod, P256Point, P256Scalar};

// =========== Unblinded Operations ===========

/// The clear evaluation of the PRF based on the PRF by Naor, Pinkas, and Reingold:
///
/// ```text
/// PRF: K x X -> G
///
/// PRF(k, x) = k * H(x)
/// ```
///
/// where
/// * `K` is a set of keys, in our case the scalars of P-256,
/// * `X` is the set of inputs, in our case arbitrary bitstrings,
/// * `G` is a group where DDH problem is assumed to be computationally hard, in our case P-256,
/// * `H` is a random oracle mapping bitstring to `G`, in our case as specified in [hash-to-curve].
pub fn evaluate(
    key: CoPRFKey,
    input: &[u8],
    context_string: &[u8],
) -> Result<p256::P256Point, Error> {
    let inputElement = p256_sha256::hash_to_group(input, context_string)?;

    if inputElement == p256_sha256::identity() {
        return Err(Error::InvalidInputError);
    }

    let evaluatedElement = p256::p256_point_mul(key, inputElement.into())?.into();

    Ok(evaluatedElement)
}

/// We require that a converted output is always the same as if the output
/// had been generated under the target key in the first place, i.e. for
/// all master secrets `msk`, all `k_i, k_j` output by `derive_key(msk,
/// i), derive_key(msk,j)` and all input `x` in `X` it should hold that
///
/// ```text
/// evaluate(k_j, x) = convert(k_i, k_j, evaluate(k_i, x))
/// ```
///
/// In our instantiation based on the Naor-Pinkas-Reingold PRF, conversion is performed by first computing a `delta` scalar from both evaluation keys, which when mulitplied with the output to convert will cancel out the original evaluation key and multiply by the target evaluation key.
pub fn convert(key_i: CoPRFKey, key_j: CoPRFKey, y: P256Point) -> Result<P256Point, Error> {
    let delta = key_j * key_i.inv();
    let result = p256::p256_point_mul(delta, y.into())?.into();

    Ok(result)
}

type BlindedElement = Ciphertext;

// =========== Unblinded Operations ===========

/// The requester blinds a query for blind evaluation by Elgamal encryption with the blinding public key of the target receiver after applying the RO-mapping into the base group used by the encryption scheme to the input bytes.
pub fn blind(
    bpk: BlindingPublicKey,
    input: &[u8],
    context_string: &[u8],
    randomizer: p256::P256Scalar,
) -> Result<BlindedElement, Error> {
    let inputElement = p256_sha256::hash_to_group(input, context_string)?;

    if inputElement == p256_sha256::identity() {
        return Err(Error::InvalidInputError);
    }

    let blindedElement = elgamal::encrypt(bpk, inputElement, randomizer)?;

    Ok(blindedElement)
}

/// Blind PRF Evaluation is performed using the homomorphic properties of Elgamal ciphertexts. Further, the converter rerandomizes every ciphertext that it receives in order to achieve resistance against collusion between requester and receiver.
pub fn blind_evaluate(
    key: CoPRFKey,
    bpk: BlindingPublicKey,
    ctx: BlindedElement,
    randomizer: p256::P256Scalar,
) -> Result<BlindedElement, Error> {
    let ctx_rerandomized = elgamal::rerandomize(bpk, ctx, randomizer)?;
    elgamal::scalar_mul_ciphertext(key, ctx_rerandomized).map_err(|e| e.into())
}

/// To recover the PRF output, the receiver performs unblinding of the blind evaluation result by Elgamal decryption.
pub fn finalize(bsk: BlindingPrivateKey, ctx: BlindedElement) -> Result<P256Point, Error> {
    elgamal::decrypt(bsk, ctx).map_err(|e| e.into())
}

/// A PRF output can be blinded for blind conversion by perfoming an Elgamal encryption of it under the target blinding public key.
pub fn prepare_blind_convert(
    bpk: BlindingPublicKey,
    y: P256Point,
    randomizer: P256Scalar,
) -> Result<BlindedElement, Error> {
    elgamal::encrypt(bpk, y, randomizer).map_err(|e| e.into())
}

/// Blind conversion is performed using the homomorphic properties of the Elgamal ciphertext.
/// Like all other ciphertexts received by the evaluator, the blinded output is rerandomized to provide collusion-resistance.
pub fn blind_convert(
    bpk: BlindingPublicKey,
    key_i: CoPRFKey,
    key_j: CoPRFKey,
    ctx: BlindedElement,
    randomizer: P256Scalar,
) -> Result<BlindedElement, Error> {
    let delta = key_j * key_i.inv();
    let ctx_rerandomized = elgamal::rerandomize(bpk, ctx, randomizer)?;
    elgamal::scalar_mul_ciphertext(delta, ctx_rerandomized).map_err(|e| e.into())
}

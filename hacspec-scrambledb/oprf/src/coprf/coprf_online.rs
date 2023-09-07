#![warn(missing_docs)]
//! ## E.2. CoPRF Online Protocol
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
use hacspec_lib::Randomness;

use super::coprf_setup::{BlindingPublicKey, CoPRFKey};
use crate::{coprf::coprf_setup::CoPRFReceiverContext, p256_sha256, Error};
use p256::{NatMod, P256Point};

/// CoPRF Inputs can be arbitrary byte strings.
pub type Input<'a> = &'a [u8];
/// The coPRF range is the range of the underlying PRF, in our case the
/// group of points on P-256.
pub type Output = P256Point;

/// The blinded coPRF input corresponds to a ciphertext of the underlying
/// rerandomizable encryption scheme, in our case an Elgamal ciphertext.
pub type BlindInput = Ciphertext;
/// Since blind evaluation is performed via the homomorphic properties and
/// rerandomizability of the underlying encryption scheme, a coPRF output
/// is also a ciphertext of the underlying encryption scheme.
pub type BlindOutput = Ciphertext;

/// The requester blinds a query for blind evaluation by Elgamal
/// encryption with the blinding public key of the target receiver after
/// applying the RO-mapping into the base group used by the encryption
/// scheme to the input bytes.
pub fn blind(
    bpk: BlindingPublicKey,
    input: Input,
    context_string: Vec<u8>,
    randomness: &mut Randomness,
) -> Result<BlindInput, Error> {
    let inputElement = p256_sha256::hash_to_group(input, &context_string)?;

    if inputElement == p256_sha256::identity() {
        return Err(Error::InvalidInputError);
    }

    let blindInput = elgamal::encrypt(bpk, inputElement, randomness)?;

    Ok(blindInput)
}

/// Blind PRF Evaluation is performed using the homomorphic properties of
/// Elgamal ciphertexts. Further, the converter rerandomizes every
/// ciphertext that it receives in order to achieve resistance against
/// collusion between requester and receiver.
pub fn blind_evaluate(
    key: CoPRFKey,
    bpk: BlindingPublicKey,
    blind_input: BlindInput,
    randomness: &mut Randomness,
) -> Result<BlindOutput, Error> {
    let input_rerandomized = elgamal::rerandomize(bpk, blind_input, randomness)?;
    elgamal::scalar_mul_ciphertext(key, input_rerandomized).map_err(|e| e.into())
}

/// To recover the PRF output, the receiver performs unblinding of the
/// blind evaluation result by Elgamal decryption.
pub fn finalize(
    context: &CoPRFReceiverContext,
    blind_output: BlindOutput,
) -> Result<Output, Error> {
    elgamal::decrypt(context.bsk, blind_output).map_err(|e| e.into())
}

/// A PRF output can be blinded for blind conversion by perfoming an
/// Elgamal encryption of it under the target blinding public key.
pub fn prepare_blind_convert(
    bpk: BlindingPublicKey,
    y: Output,
    randomness: &mut Randomness,
) -> Result<BlindInput, Error> {
    elgamal::encrypt(bpk, y, randomness).map_err(|e| e.into())
}

/// Blind conversion is performed using the homomorphic properties of the
/// Elgamal ciphertext.  Like all other ciphertexts received by the
/// evaluator, the blinded output is rerandomized to provide
/// collusion-resistance.
pub fn blind_convert(
    bpk: BlindingPublicKey,
    key_from: CoPRFKey,
    key_to: CoPRFKey,
    blind_input: BlindInput,
    randomness: &mut Randomness,
) -> Result<BlindOutput, Error> {
    let delta = key_to * key_from.inv();
    let ctx_rerandomized = elgamal::rerandomize(bpk, blind_input, randomness)?;
    elgamal::scalar_mul_ciphertext(delta, ctx_rerandomized).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use crate::coprf::coprf_setup::{derive_key, CoPRFEvaluatorContext};

    use super::*;

    // =========== Unblinded Operations ===========

    /// The cleartext evaluation of the PRF based on the PRF by Naor, Pinkas, and Reingold:
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
    pub fn evaluate(context_string: &[u8], key: CoPRFKey, input: Input) -> Result<Output, Error> {
        let inputElement = p256_sha256::hash_to_group(input, context_string)?;

        if inputElement == P256Point::AtInfinity {
            return Err(Error::InvalidInputError);
        }

        let evaluatedElement = p256::p256_point_mul(key, inputElement)?;

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
    /// In our instantiation based on the Naor-Pinkas-Reingold PRF, conversion
    /// is performed by first computing a `delta` scalar from both evaluation
    /// keys, which when mulitplied with the output to convert will cancel out
    /// the original evaluation key and multiply by the target evaluation key.
    pub fn convert(
        key_origin: CoPRFKey,
        key_destination: CoPRFKey,
        y: Output,
    ) -> Result<Output, Error> {
        let delta = key_destination * key_origin.inv();
        let result = p256::p256_point_mul(delta, y)?;

        Ok(result)
    }

    fn generate_randomness() -> Randomness {
        use rand::prelude::*;

        let mut rng = rand::thread_rng();
        let mut randomness = [0u8; 1000000];
        rng.fill_bytes(&mut randomness);
        let randomness = Randomness::new(randomness.to_vec());

        randomness
    }

    #[test]
    fn self_test_eval_convert() {
        let mut randomness = generate_randomness();

        let test_context = b"Test";
        let test_input = b"TestInput";
        let evaluator_context = CoPRFEvaluatorContext::new(&mut randomness).unwrap();

        let key_origin1 = derive_key(&evaluator_context, b"1").unwrap();
        let key_origin2 = derive_key(&evaluator_context, b"2").unwrap();
        let key_destination = derive_key(&evaluator_context, b"3").unwrap();

        let y_under_origin1 = evaluate(test_context, key_origin1, test_input).unwrap();
        let y_under_origin2 = evaluate(test_context, key_origin2, test_input).unwrap();

        let y_under_destination = evaluate(test_context, key_destination, test_input).unwrap();
        let converted_y_from_1 = convert(key_origin1, key_destination, y_under_origin1).unwrap();
        let converted_y_from_2 = convert(key_origin2, key_destination, y_under_origin2).unwrap();

        assert_eq!(converted_y_from_1, converted_y_from_2);
        assert_eq!(converted_y_from_1, y_under_destination);
    }

    #[test]
    fn test_blind_evaluate() {
        let mut randomness = generate_randomness();

        let test_context = b"Test";
        let test_input = b"TestInput";
        let evaluator_context = CoPRFEvaluatorContext::new(&mut randomness).unwrap();
        let receiver_context = CoPRFReceiverContext::new(&mut randomness);

        let blind_input = blind(
            receiver_context.get_bpk(),
            test_input,
            test_context.to_vec(),
            &mut randomness,
        )
        .unwrap();

        let evaluation_key = derive_key(&evaluator_context, b"TestKey").unwrap();
        let blind_result = blind_evaluate(
            evaluation_key,
            receiver_context.get_bpk(),
            blind_input,
            &mut randomness,
        )
        .unwrap();

        let unblinded_result = finalize(&receiver_context, blind_result).unwrap();

        let expected_result = evaluate(test_context, evaluation_key, test_input).unwrap();

        assert_eq!(unblinded_result, expected_result);
    }

    #[test]
    fn blind_convergence() {
        let mut randomness = generate_randomness();

        let test_context = b"Test";
        let test_input = b"TestInput";
        let evaluator_context = CoPRFEvaluatorContext::new(&mut randomness).unwrap();
        let receiver_context = CoPRFReceiverContext::new(&mut randomness);

        let key_origin1 = derive_key(&evaluator_context, b"1").unwrap();
        let key_origin2 = derive_key(&evaluator_context, b"2").unwrap();
        let key_destination = derive_key(&evaluator_context, b"3").unwrap();

        let y_under_destination = evaluate(test_context, key_destination, test_input).unwrap();
        let y1 = evaluate(test_context, key_origin1, test_input).unwrap();
        let y2 = evaluate(test_context, key_origin2, test_input).unwrap();

        let blind1 =
            prepare_blind_convert(receiver_context.get_bpk(), y1, &mut randomness).unwrap();
        let blind2 =
            prepare_blind_convert(receiver_context.get_bpk(), y2, &mut randomness).unwrap();

        let blind_result_1 = blind_convert(
            receiver_context.get_bpk(),
            key_origin1,
            key_destination,
            blind1,
            &mut randomness,
        )
        .unwrap();

        let blind_result_2 = blind_convert(
            receiver_context.get_bpk(),
            key_origin2,
            key_destination,
            blind2,
            &mut randomness,
        )
        .unwrap();

        let res1 = finalize(&receiver_context, blind_result_1).unwrap();
        let res2 = finalize(&receiver_context, blind_result_2).unwrap();

        assert_eq!(res1, res2);
        assert_eq!(res1, y_under_destination);
    }
    #[test]
    fn test_blind_conversion() {
        let mut randomness = generate_randomness();

        let test_context = b"Test";
        let test_input = b"TestInput";
        let evaluator_context = CoPRFEvaluatorContext::new(&mut randomness).unwrap();
        let receiver_context = CoPRFReceiverContext::new(&mut randomness);

        let blind_input = blind(
            receiver_context.get_bpk(),
            test_input,
            test_context.to_vec(),
            &mut randomness,
        )
        .unwrap();

        let key_eval = derive_key(&evaluator_context, b"TestKey").unwrap();
        let key_destination = derive_key(&evaluator_context, b"DestinationKey").unwrap();

        let blind_result = blind_evaluate(
            key_eval,
            receiver_context.get_bpk(),
            blind_input,
            &mut randomness,
        )
        .unwrap();

        let expected_result = evaluate(test_context, key_destination, test_input).unwrap();

        // converting the blinded result directly
        let blind_converted_result = blind_convert(
            receiver_context.get_bpk(),
            key_eval,
            key_destination,
            blind_result,
            &mut randomness,
        )
        .unwrap();

        let unblinded_converted_result =
            finalize(&receiver_context, blind_converted_result).unwrap();
        assert_eq!(expected_result, unblinded_converted_result);

        // converting after unblinding and re-blinding
        let unblinded_intermediate_result = finalize(&receiver_context, blind_result).unwrap();

        let prepped_input = prepare_blind_convert(
            receiver_context.get_bpk(),
            unblinded_intermediate_result,
            &mut randomness,
        )
        .unwrap();

        let blind_converted_result = blind_convert(
            receiver_context.get_bpk(),
            key_eval,
            key_destination,
            prepped_input,
            &mut randomness,
        )
        .unwrap();

        let unblinded_converted_result =
            finalize(&receiver_context, blind_converted_result).unwrap();
        assert_eq!(expected_result, unblinded_converted_result);
    }
}

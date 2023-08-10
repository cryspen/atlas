//! 3.3.1.  OPRF Protocol
//!
//! The OPRF protocol begins with the client blinding its input, as
//! described by the Blind function below.  Note that this function can
//! fail with an InvalidInputError error for certain inputs that map to
//! the group identity element.  Dealing with this failure is an
//! application-specific decision; see Section 5.3.

use crate::p256_sha256::hash;
use crate::Error;
use crate::{p256_sha256, protocol::ServerPrivateKey, util::random_scalar};
use p256::{P256Point, P256Scalar};
use scrambledb_util::i2osp;

/// ``` text
/// Input:
///
///   PrivateInput input
///
/// Output:
///
///   Scalar blind
///   Element blindedElement
///
/// Parameters:
///
///   Group G
///
/// Errors: InvalidInputError
///
/// def Blind(input):
///   blind = G.RandomScalar()
///   inputElement = G.HashToGroup(input)
///   if inputElement == G.Identity():
///     raise InvalidInputError
///   blindedElement = blind * inputElement
///
///   return blind, blindedElement
/// ```
///
/// Clients store blind locally, and send blindedElement to the server
/// for evaluation.
pub fn blind(input: &[u8], context_string: &[u8]) -> Result<(P256Scalar, P256Point), Error> {
    let blind = random_scalar();
    let inputElement = p256_sha256::hash_to_group(input, context_string)?;
    if inputElement == p256_sha256::identity() {
        return Err(Error::InvalidInputError);
    }

    let blindedElement = p256::p256_point_mul(blind, inputElement.into())?;

    Ok((blind, blindedElement.into()))
}

/// Upon receipt, servers process blindedElement using
/// the BlindEvaluate function described below.
///
/// ``` text
/// Input:
///
///   Scalar skS
///   Element blindedElement
///
/// Output:
///
///   Element evaluatedElement
///
/// def BlindEvaluate(skS, blindedElement):
///   evaluatedElement = skS * blindedElement
///   return evaluatedElement
/// ```
///
/// Servers send the output evaluatedElement to clients for processing.
/// Recall that servers may process multiple client inputs by applying
/// the BlindEvaluate function to each blindedElement received, and
/// returning an array with the corresponding evaluatedElement values.
pub fn blind_evaluate(
    skS: ServerPrivateKey,
    blindedElement: P256Point,
) -> Result<P256Point, Error> {
    let evaluatedElement = p256::p256_point_mul(skS, blindedElement.into())?;
    Ok(evaluatedElement.into())
}

/// Upon receipt of evaluatedElement, clients process it to complete the
/// OPRF evaluation with the Finalize function described below.
///
/// ``` text
/// Input:
///
///   PrivateInput input
///   Scalar blind
///   Element evaluatedElement
///
/// Output:
///
///   opaque output[Nh]
///
/// Parameters:
///
///   Group G
///
/// def Finalize(input, blind, evaluatedElement):
///   N = G.ScalarInverse(blind) * evaluatedElement
///   unblindedElement = G.SerializeElement(N)
///
///   hashInput = I2OSP(len(input), 2) || input ||
///                       I2OSP(len(unblindedElement), 2) || unblindedElement ||
///                       "Finalize"
///   return Hash(hashInput)
/// ```
pub fn finalize(
    input: &[u8],
    blind: P256Scalar,
    evaluatedElement: P256Point,
) -> Result<Vec<u8>, Error> {
    let n = p256::p256_point_mul(p256_sha256::scalar_inverse(blind), evaluatedElement.into())?;
    let unblindedElement = p256_sha256::serialize_element(&n.into());

    let mut hashInput = Vec::new();
    hashInput.extend_from_slice(&i2osp(input.len(), 2));
    hashInput.extend_from_slice(input);
    hashInput.extend_from_slice(&i2osp(unblindedElement.len(), 2));
    hashInput.extend_from_slice(&unblindedElement);
    hashInput.extend_from_slice(b"Finalize".as_slice());

    Ok(hash(&hashInput))
}

/// An entity which knows both the private key and the input can compute
/// the PRF result using the following Evaluate function.
///
/// ``` text
/// Input:
///
///   Scalar skS
///   PrivateInput input
///
/// Output:
///
///   opaque output[Nh]
///
/// Parameters:
///
///   Group G
///
/// Errors: InvalidInputError
///
/// def Evaluate(skS, input):
///   inputElement = G.HashToGroup(input)
///   if inputElement == G.Identity():
///     raise InvalidInputError
///   evaluatedElement = skS * inputElement
///   issuedElement = G.SerializeElement(evaluatedElement)
///
///   hashInput = I2OSP(len(input), 2) || input ||
///                       I2OSP(len(issuedElement), 2) || issuedElement ||
///                       "Finalize"
///   return Hash(hashInput)
/// ```
pub fn evaluate(
    skS: ServerPrivateKey,
    input: &[u8],
    context_string: &[u8],
) -> Result<Vec<u8>, Error> {
    let inputElement = p256_sha256::hash_to_group(input, context_string)?;

    if inputElement == p256_sha256::identity() {
        return Err(Error::InvalidInputError);
    }

    let evaluatedElement = p256::p256_point_mul(skS, inputElement.into())?;

    let issuedElement = p256_sha256::serialize_element(&evaluatedElement.into());

    let mut hashInput = Vec::new();
    hashInput.extend_from_slice(&i2osp(input.len(), 2));
    hashInput.extend_from_slice(input);
    hashInput.extend_from_slice(&i2osp(issuedElement.len(), 2));
    hashInput.extend_from_slice(&issuedElement);
    hashInput.extend_from_slice(b"Finalize".as_slice());

    Ok(hash(&hashInput))
}

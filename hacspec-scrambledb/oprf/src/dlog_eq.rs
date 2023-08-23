//! ## 2.2.  Discrete Logarithm Equivalence Proofs
//!
//! A proof of knowledge allows a prover to convince a verifier that some
//! statement is true.  If the prover can generate a proof without
//! interaction with the verifier, the proof is noninteractive.  If the
//! verifier learns nothing other than whether the statement claimed by
//! the prover is true or false, the proof is zero-knowledge.
//!
//! This section describes a noninteractive zero-knowledge proof for
//! discrete logarithm equivalence (DLEQ), which is used in the
//! construction of VOPRF and POPRF.  A DLEQ proof demonstrates that two
//! pairs of group elements have the same discrete logarithm without
//! revealing the discrete logarithm.
//!
//! The DLEQ proof resembles the Chaum-Pedersen [ChaumPedersen] proof,
//! which is shown to be zero-knowledge by Jarecki, et al.  [JKK14] and
//! is noninteractive after applying the Fiat-Shamir transform [FS00].
//! Furthermore, Davidson, et al.  [DGSTV18] showed a proof system for
//! batching DLEQ proofs that has constant-size proofs with respect to
//! the number of inputs.  The specific DLEQ proof system presented below
//! follows this latter construction with two modifications: (1) the
//! transcript used to generate the seed includes more context
//! information, and (2) the individual challenges for each element in
//! the proof is derived from a seed-prefixed hash-to-scalar invocation
//! rather than being sampled from a seeded PRNG.  The description is
//! split into two sub-sections: one for generating the proof, which is
//! done by servers in the verifiable protocols, and another for
//! verifying the proof, which is done by clients in the protocol.

use crate::p256_sha256::serialize_element;
use crate::util::*;
use crate::Error;
use libcrux::digest::{hash, Algorithm};
use p256::{p256_point_mul, P256Point, P256Scalar};
use scrambledb_util::i2osp;

/// ### 2.2.1.  Proof Generation
///
/// Generating a proof is done with the GenerateProof function, defined
/// below.  Given elements A and B, two non-empty lists of elements C and
/// D of length m, and a scalar k; this function produces a proof that
/// k*A == B and k*C[i] == D[i] for each i in [0, ..., m - 1].  The
/// output is a value of type Proof, which is a tuple of two Scalar
/// values.  We use the notation proof[0] and proof[1] to denote the
/// first and second elements in this tuple, respectively.
///
/// GenerateProof accepts lists of inputs to amortize the cost of proof
/// generation.  Applications can take advantage of this functionality to
/// produce a single, constant-sized proof for m DLEQ inputs, rather than
/// m proofs for m DLEQ inputs.
///
/// ``` text
/// Input:
///
///   Scalar k
///   Element A
///   Element B
///   Element C[m]
///   Element D[m]
///
/// Output:
///
///   Proof proof
///
/// Parameters:
///
///   Group G
///
/// def GenerateProof(k, A, B, C, D)
///   (M, Z) = ComputeCompositesFast(k, B, C, D)
///
///   r = G.RandomScalar()
///   t2 = r * A
///   t3 = r * M
///
///   Bm = G.SerializeElement(B)
///   a0 = G.SerializeElement(M)
///   a1 = G.SerializeElement(Z)
///   a2 = G.SerializeElement(t2)
///   a3 = G.SerializeElement(t3)
///
///   challengeTranscript =
///     I2OSP(len(Bm), 2) || Bm ||
///     I2OSP(len(a0), 2) || a0 ||
///     I2OSP(len(a1), 2) || a1 ||
///     I2OSP(len(a2), 2) || a2 ||
///     I2OSP(len(a3), 2) || a3 ||
///     "Challenge"
///
///   c = G.HashToScalar(challengeTranscript)
///   s = r - c * k
///
///   return [c, s]
/// ```
///
/// **NOTE**: We allow passing in the random scalar as a function argument instead of
/// generating it from the given seed, so we can test proof generation using
/// the provided test vectors.
#[allow(non_snake_case)]
pub fn generate_proof(
    k: P256Scalar,
    A: P256Point,
    B: P256Point,
    C: Vec<P256Point>,
    D: Vec<P256Point>,
    r: Option<P256Scalar>,
    seed: &[u8; 32],
    context_string: &[u8],
) -> Result<(P256Scalar, P256Scalar), Error> {
    // C and D must be of the same length
    assert_eq!(C.len(), D.len());
    let (M, Z) = compute_composites_fast(k, B, C, D, context_string)?; // (M, Z) = ComputeCompositesFast(k, B, C, D)

    // NOTE: Allowing to pass in the random scalar instead of
    // generating it freshly, so we can test proof generation using
    // the provided test vectors.
    let r = r.unwrap_or(random_scalar(seed)); // r = G.RandomScalar()

    let t2 = p256_point_mul(r, A.into())?; // t2 = r * A
    let t3 = p256_point_mul(r, M.into())?; // t3 = r * M

    let Bm = serialize_element(&B); // Bm = G.SerializeElement(B)
    let a0 = serialize_element(&M); // a0 = G.SerializeElement(M)
    let a1 = serialize_element(&Z); // a1 = G.SerializeElement(Z)
    let a2 = serialize_element(&t2.into()); // a2 = G.SerializeElement(t2)
    let a3 = serialize_element(&t3.into()); // a3 = G.SerializeElement(t3)

    let mut challenge_transcript = Vec::new(); // challengeTranscript =
    challenge_transcript.extend_from_slice(&i2osp(Bm.len(), 2)); //        I2OSP(len(Bm), 2) || Bm ||
    challenge_transcript.extend_from_slice(&Bm);
    challenge_transcript.extend_from_slice(&i2osp(a0.len(), 2)); //        I2OSP(len(a0), 2) || a0 ||
    challenge_transcript.extend_from_slice(&a0);
    challenge_transcript.extend_from_slice(&i2osp(a1.len(), 2)); //        I2OSP(len(a1), 2) || a1 ||
    challenge_transcript.extend_from_slice(&a1);
    challenge_transcript.extend_from_slice(&i2osp(a2.len(), 2)); //        I2OSP(len(a2), 2) || a2 ||
    challenge_transcript.extend_from_slice(&a2);
    challenge_transcript.extend_from_slice(&i2osp(a3.len(), 2)); //        I2OSP(len(a3), 2) || a3 ||
    challenge_transcript.extend_from_slice(&a3);
    challenge_transcript.extend_from_slice(b"Challenge"); //        "Challenge"

    // c = G.HashToScalar(challengeTranscript)
    let c = crate::p256_sha256::hash_to_scalar(&challenge_transcript, context_string);

    let s = r - c * k; // s = r - c * k

    Ok((c, s)) //return [c, s]
}

/// The helper function ComputeCompositesFast is as defined below, and is
/// an optimization of the ComputeComposites function for servers since
/// they have knowledge of the private key.
///
/// ``` text
/// Input:
///
///   Scalar k
///   Element B
///   Element C[m]
///   Element D[m]
///
/// Output:
///
///   Element M
///   Element Z
///
/// Parameters:
///
///   Group G
///   PublicInput contextString
///
/// def ComputeCompositesFast(k, B, C, D):
///   Bm = G.SerializeElement(B)
///   seedDST = "Seed-" || contextString
///   seedTranscript =
///     I2OSP(len(Bm), 2) || Bm ||
///     I2OSP(len(seedDST), 2) || seedDST
///   seed = Hash(seedTranscript)
///
///   M = G.Identity()
///   for i in range(m):
///     Ci = G.SerializeElement(C[i])
///     Di = G.SerializeElement(D[i])
///     compositeTranscript =
///       I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
///       I2OSP(len(Ci), 2) || Ci ||
///       I2OSP(len(Di), 2) || Di ||
///       "Composite"
///
///     di = G.HashToScalar(compositeTranscript)
///     M = di * C[i] + M
///
///   Z = k * M
///
///   return (M, Z)
/// ```
///
/// When used in the protocol described in Section 3, the parameter
/// contextString is as defined in Section 3.2.
///
#[allow(non_snake_case)]
fn compute_composites_fast(
    k: P256Scalar,
    B: P256Point,
    C: Vec<P256Point>,
    D: Vec<P256Point>,
    context_string: &[u8],
) -> Result<(P256Point, P256Point), Error> {
    let Bm = serialize_element(&B); // Bm = G.SerializeElement(B)
    let mut seed_dst: Vec<u8> = "Seed".into(); //seedDST = "Seed-" || contextString
    seed_dst.extend_from_slice(context_string);

    let mut seed_transcript = Vec::new(); //  seedTranscript =
    seed_transcript.extend_from_slice(&i2osp(Bm.len(), 2)); //     I2OSP(len(Bm), 2) || Bm ||
    seed_transcript.extend_from_slice(&Bm);
    seed_transcript.extend_from_slice(&i2osp(seed_dst.len(), 2)); //     I2OSP(len(seedDST), 2) || seedDST
    seed_transcript.extend_from_slice(&seed_dst);

    let seed = hash(Algorithm::Sha256, &seed_transcript); // seed = Hash(seedTranscript)

    let mut M = crate::p256_sha256::identity(); // M = G.Identity()

    for i in 0..C.len() {
        let Ci = serialize_element(&C[i]); // Ci = G.SerializeElement(C[i])
        let Di = serialize_element(&D[i]); // Di = G.SerializeElement(D[i])

        let mut composite_transcript = Vec::new(); // compositeTranscript =
        composite_transcript.extend_from_slice(&i2osp(seed.len(), 2)); //          I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
        composite_transcript.extend_from_slice(&seed);
        composite_transcript.extend_from_slice(&i2osp(i, 2));

        composite_transcript.extend_from_slice(&i2osp(Ci.len(), 2)); //          I2OSP(len(Ci), 2) || Ci ||
        composite_transcript.extend_from_slice(&Ci);
        composite_transcript.extend_from_slice(&i2osp(Di.len(), 2)); //          I2OSP(len(Ci), 2) || Ci ||
        composite_transcript.extend_from_slice(&Di);

        composite_transcript.extend_from_slice(b"Composite"); //          "Composite"

        // di = G.HashToScalar(challengeTranscript)
        let di = crate::p256_sha256::hash_to_scalar(&composite_transcript, context_string);

        M = p256::point_add_noninf(M.into(), p256_point_mul(di, C[i].into())?)?.into();
        // M = di * C[i] + M
    }

    let Z = p256_point_mul(k, M.into())?; // Z = k * M

    Ok((M, Z.into())) // return (M,Z)
}

/// ### 2.2.2.  Proof Verification
///
/// Verifying a proof is done with the VerifyProof function, defined
/// below.  This function takes elements A and B, two non-empty lists of
/// elements C and D of length m, and a Proof value output from
/// GenerateProof.  It outputs a single boolean value indicating whether
/// or not the proof is valid for the given DLEQ inputs.  Note this
/// function can verify proofs on lists of inputs whenever the proof was
/// generated as a batched DLEQ proof with the same inputs.
///
/// ``` text
/// Input:
///
///   Element A
///   Element B
///   Element C[m]
///   Element D[m]
///   Proof proof
///
/// Output:
///
///   boolean verified
///
/// Parameters:
///
///   Group G
///
/// def VerifyProof(A, B, C, D, proof):
///   (M, Z) = ComputeComposites(B, C, D)
///   c = proof[0]
///   s = proof[1]
///
///   t2 = ((s * A) + (c * B))
///   t3 = ((s * M) + (c * Z))
///
///   Bm = G.SerializeElement(B)
///   a0 = G.SerializeElement(M)
///   a1 = G.SerializeElement(Z)
///   a2 = G.SerializeElement(t2)
///   a3 = G.SerializeElement(t3)
///
///   challengeTranscript =
///     I2OSP(len(Bm), 2) || Bm ||
///     I2OSP(len(a0), 2) || a0 ||
///     I2OSP(len(a1), 2) || a1 ||
///     I2OSP(len(a2), 2) || a2 ||
///     I2OSP(len(a3), 2) || a3 ||
///     "Challenge"
///
///   expectedC = G.HashToScalar(challengeTranscript)
///   verified = (expectedC == c)
///
///   return verified
/// ```
#[allow(non_snake_case)]
pub fn verify_proof(
    A: P256Point,
    B: P256Point,
    C: Vec<P256Point>,
    D: Vec<P256Point>,
    proof: (P256Scalar, P256Scalar),
    context_string: &[u8],
) -> Result<bool, Error> {
    let (M, Z) = compute_composites(B, C, D, context_string)?;
    let (c, s) = proof;

    let t2 =
        p256::point_add_noninf(p256_point_mul(s, A.into())?, p256_point_mul(c, B.into())?)?.into();
    let t3 =
        p256::point_add_noninf(p256_point_mul(s, M.into())?, p256_point_mul(c, Z.into())?)?.into();

    let Bm = serialize_element(&B); // Bm = G.SerializeElement(B)
    let a0 = serialize_element(&M); // a0 = G.SerializeElement(M)
    let a1 = serialize_element(&Z); // a1 = G.SerializeElement(Z)
    let a2 = serialize_element(&t2); // a2 = G.SerializeElement(t2)
    let a3 = serialize_element(&t3); // a3 = G.SerializeElement(t3)

    let mut challenge_transcript = Vec::new(); // challengeTranscript =
    challenge_transcript.extend_from_slice(&i2osp(Bm.len(), 2)); //        I2OSP(len(Bm), 2) || Bm ||
    challenge_transcript.extend_from_slice(&Bm);
    challenge_transcript.extend_from_slice(&i2osp(a0.len(), 2)); //        I2OSP(len(a0), 2) || a0 ||
    challenge_transcript.extend_from_slice(&a0);
    challenge_transcript.extend_from_slice(&i2osp(a1.len(), 2)); //        I2OSP(len(a1), 2) || a1 ||
    challenge_transcript.extend_from_slice(&a1);
    challenge_transcript.extend_from_slice(&i2osp(a2.len(), 2)); //        I2OSP(len(a2), 2) || a2 ||
    challenge_transcript.extend_from_slice(&a2);
    challenge_transcript.extend_from_slice(&i2osp(a3.len(), 2)); //        I2OSP(len(a3), 2) || a3 ||
    challenge_transcript.extend_from_slice(&a3);
    challenge_transcript.extend_from_slice(b"Challenge"); //        "Challenge"

    // G.HashToScalar(challengeTranscript)
    let expected_c = crate::p256_sha256::hash_to_scalar(&challenge_transcript, context_string);

    Ok(expected_c == c)
}

/// The definition of ComputeComposites is given below.
///
/// ``` text
/// Input:
///
///   Element B
///   Element C[m]
///   Element D[m]
///
/// Output:
///
///   Element M
///   Element Z
///
/// Parameters:
///
///   Group G
///   PublicInput contextString
///
/// def ComputeComposites(B, C, D):
///   Bm = G.SerializeElement(B)
///   seedDST = "Seed-" || contextString
///   seedTranscript =
///     I2OSP(len(Bm), 2) || Bm ||
///     I2OSP(len(seedDST), 2) || seedDST
///   seed = Hash(seedTranscript)
///
///   M = G.Identity()
///   Z = G.Identity()
///   for i in range(m):
///     Ci = G.SerializeElement(C[i])
///     Di = G.SerializeElement(D[i])
///     compositeTranscript =
///       I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
///       I2OSP(len(Ci), 2) || Ci ||
///       I2OSP(len(Di), 2) || Di ||
///       "Composite"
///
///     di = G.HashToScalar(compositeTranscript)
///     M = di * C[i] + M
///     Z = di * D[i] + Z
///
///   return (M, Z)
/// ```
///
/// When used in the protocol described in Section 3, the parameter
/// contextString is as defined in Section 3.2.
#[allow(non_snake_case)]
fn compute_composites(
    B: P256Point,
    C: Vec<P256Point>,
    D: Vec<P256Point>,
    context_string: &[u8],
) -> Result<(P256Point, P256Point), Error> {
    let Bm = serialize_element(&B); // Bm = G.SerializeElement(B)
    let mut seed_dst: Vec<u8> = "Seed-".into(); //seedDST = "Seed-" || contextString
    seed_dst.extend_from_slice(context_string);

    let mut seed_transcript = Vec::new(); //  seedTranscript =
    seed_transcript.extend_from_slice(&i2osp(Bm.len(), 2)); //     I2OSP(len(Bm), 2) || Bm ||
    seed_transcript.extend_from_slice(&Bm);
    seed_transcript.extend_from_slice(&i2osp(seed_dst.len(), 2)); //     I2OSP(len(seedDST), 2) || seedDST
    seed_transcript.extend_from_slice(&seed_dst);

    let seed = hash(Algorithm::Sha256, &seed_transcript); // seed = Hash(seedTranscript)

    let mut M = crate::p256_sha256::identity(); // M = G.Identity()
    let mut Z = crate::p256_sha256::identity(); // Z = G.Identity()

    for i in 0..C.len() {
        let Ci = serialize_element(&C[i]); // Ci = G.SerializeElement(C[i])
        let Di = serialize_element(&D[i]); // Di = G.SerializeElement(D[i])

        let mut composite_transcript = Vec::new(); // compositeTranscript =
        composite_transcript.extend_from_slice(&i2osp(seed.len(), 2)); //          I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
        composite_transcript.extend_from_slice(&seed);
        composite_transcript.extend_from_slice(&i2osp(i, 2));

        composite_transcript.extend_from_slice(&i2osp(Ci.len(), 2)); //          I2OSP(len(Ci), 2) || Ci ||
        composite_transcript.extend_from_slice(&Ci);
        composite_transcript.extend_from_slice(&i2osp(Di.len(), 2)); //          I2OSP(len(Ci), 2) || Ci ||
        composite_transcript.extend_from_slice(&Di);

        composite_transcript.extend_from_slice(b"Composite"); //          "Composite"

        // di = G.HashToScalar(challengeTranscript)
        let di = crate::p256_sha256::hash_to_scalar(&composite_transcript, context_string);

        M = p256::point_add_noninf(M.into(), p256_point_mul(di, C[i].into())?)?.into(); // M = di * C[i] + M
        Z = p256::point_add_noninf(Z.into(), p256_point_mul(di, D[i].into())?)?.into();
        // M = di * C[i] + M
    }

    Ok((M, Z)) // return (M,Z)
}

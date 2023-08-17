#![allow(non_camel_case_types, non_snake_case)]
/*!
# Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups

> This is a hacspec representation of the [VOPRF Draft]. The text is mostly verbatim from the RFC with changes where required.

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol between client and server for computing the output of a Pseudorandom Function (PRF). The server provides the PRF private key, and the client provides the PRF input. At the end of the protocol, the client learns the PRF output without learning anything about the PRF private key, and the server learns neither the PRF input nor output. An OPRF can also satisfy a notion of 'verifiability', called a VOPRF. A VOPRF ensures clients can verify that the server used a specific private key during the execution of the protocol. A VOPRF can also be partially-oblivious, called a POPRF. A POPRF allows clients and servers to provide public input to the PRF computation. This document specifies an OPRF, VOPRF, and POPRF instantiated within standard prime-order groups, including elliptic curves.

The original document is a product of the Crypto Forum Research Group (CFRG) in the IRTF.

# 1. Introduction

A Pseudorandom Function (PRF) F(k, x) is an efficiently computable function taking a private key k and a value x as input. This function is pseudorandom if the keyed function K(_) = F(k, _) is indistinguishable from a randomly sampled function acting on the same domain and range as K(). An Oblivious PRF (OPRF) is a two-party protocol between a server and a client, where the server holds a PRF key k and the client holds some input x. The protocol allows both parties to cooperate in computing F(k, x) such that the client learns F(k, x) without learning anything about k; and the server does not learn anything about x or F(k, x). A Verifiable OPRF (VOPRF) is an OPRF wherein the server also proves to the client that F(k, x) was produced by the key k corresponding to the server's public key, which the client knows. A Partially-Oblivious PRF (POPRF) is a variant of a VOPRF wherein client and server interact in computing F(k, x, y), for some PRF F with server-provided key k, client-provided input x, and public input y, and client receives proof that F(k, x, y) was computed using k corresponding to the public key that the client knows. A POPRF with fixed input y is functionally equivalent to a VOPRF.

OPRFs have a variety of applications, including: password-protected secret sharing schemes [JKKX16], privacy-preserving password stores [SJKS17], and password-authenticated key exchange or PAKE [OPAQUE]. Verifiable OPRFs are necessary in some applications such as Privacy Pass [PRIVACYPASS]. Verifiable OPRFs have also been used for password-protected secret sharing schemes such as that of [JKK14].

This document specifies OPRF, VOPRF, and POPRF protocols built upon prime-order groups. The document describes each protocol variant, along with application considerations, and their security properties.

This document represents the consensus of the Crypto Forum Research Group (CFRG). It is not an IETF product and is not a standard.

## 1.3. Notation and Terminology

The following functions and notation are used throughout the document.

* For any object x, we write len(x) to denote its length in bytes.
* For two byte arrays x and y, write x || y to denote their concatenation.
* I2OSP(x, xLen): Converts a non-negative integer x into a byte array of specified length xLen as described in [RFC8017]. Note that this function returns a byte array in big-endian byte order.
* The notation T U[N] refers to an array called U containing N items of type T. The type opaque means one single byte of uninterpreted data. Items of the array are zero-indexed and referred as U[j] such that 0 <= j < N.

All algorithms and procedures described in this document are laid out in a Python-like pseudocode. Each function takes a set of inputs and parameters and produces a set of output values. Parameters become constant values once the protocol variant and the ciphersuite are fixed.

The PrivateInput data type refers to inputs that are known only to the client in the protocol, whereas the PublicInput data type refers to inputs that are known to both client and server in the protocol. Both PrivateInput and PublicInput are opaque byte strings of arbitrary length no larger than 216 - 1 bytes. This length restriction exists because PublicInput and PrivateInput values are length-prefixed with two bytes before use throughout the protocol.

String values such as "DeriveKeyPair", "Seed-", and "Finalize" are ASCII string literals.

The following terms are used throughout this document.
* PRF: Pseudorandom Function.
* OPRF: Oblivious Pseudorandom Function.VOPRF: Verifiable Oblivious
* Pseudorandom Function.POPRF: Partially Oblivious Pseudorandom Function.
* Client: Protocol initiator. Learns pseudorandom function evaluation as the output of the protocol.
* Server: Computes the pseudorandom function using a private key. Learns nothing about the client's input or output.

[voprf draft]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/
*/

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    VerifyError,
    DeserializeError,
    InputValidationError,
    InvalidInputError,
    InverseError,
    DeriveKeyPairError,

    CurveError,
    HashToCurveError,
    ElgamalError,
}

impl From<p256::Error> for Error {
    fn from(_: p256::Error) -> Self {
        Self::CurveError
    }
}

impl From<hash_to_curve::Error> for Error {
    fn from(_: hash_to_curve::Error) -> Self {
        Self::HashToCurveError
    }
}

impl From<elgamal::Error> for Error {
    fn from(_: elgamal::Error) -> Self {
        Self::ElgamalError
    }
}

// 2.1 Prime-Order Group
pub mod prime_order_group;

// 2.2 Discrete Logarithm Equivalence Proofs
pub mod dlog_eq;

// 3. Protocol
pub mod protocol;

// 4. Ciphersuites
pub mod oprf_suite;

// 4.2 OPRF(P-256, SHA-256)
mod p256_sha256;

pub mod coprf;

mod util;

#[cfg(test)]
mod test_util;

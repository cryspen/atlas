//! # 3. Protocol
//!
//!
//! In this section, we define and describe three protocol variants
//! referred to as the OPRF, VOPRF, and POPRF modes.  Each of these
//! variants involve two messages between client and server but differ
//! slightly in terms of the security properties; see Section 7.1 for
//! more information.  A high level description of the functionality of
//! each mode follows.
//!
//! In the OPRF mode, a client and server interact to compute output =
//! F(skS, input), where input is the client's private input, skS is the
//! server's private key, and output is the OPRF output.  After the
//! execution of the protocol, the client learns output and the server
//! learns nothing.  This interaction is shown below.
//!
//! ``` text
//!     Client(input)                                        Server(skS)
//!   -------------------------------------------------------------------
//!   blind, blindedElement = Blind(input)
//!
//!                                                      blindedElement
//!                                                        ---------->
//!
//!                             evaluatedElement = BlindEvaluate(skS, blindedElement)
//!
//!                                                      evaluatedElement
//!                                                        <----------
//!
//!   output = Finalize(input, blind, evaluatedElement)
//!
//!                                Figure 1: OPRF protocol overview
//! ```
//!
//! In the VOPRF mode, the client additionally receives proof that the
//! server used skS in computing the function.  To achieve verifiability,
//! as in [JKK14], the server provides a zero-knowledge proof that the
//! key provided as input by the server in the BlindEvaluate function is
//! the same key as it used to produce the server's public key, pkS,
//! which the client receives as input to the protocol.  This proof does
//! not reveal the server's private key to the client.  This interaction
//! is shown below.
//!
//! ``` text
//!     Client(input, pkS)       <---- pkS ------        Server(skS, pkS)
//!   -------------------------------------------------------------------
//!   blind, blindedElement = Blind(input)
//!
//!                                                      blindedElement
//!                                                        ---------->
//!
//!                       evaluatedElement, proof = BlindEvaluate(skS, pkS,
//!                                                                                                       blindedElement)
//!
//!                                              evaluatedElement, proof
//!                                                        <----------
//!
//!   output = Finalize(input, blind, evaluatedElement,
//!                                     blindedElement, pkS, proof)
//!
//! Figure 2: VOPRF protocol overview with additional proof
//! ```
//!
//! The POPRF mode extends the VOPRF mode such that the client and server
//! can additionally provide a public input info that is used in
//! computing the pseudorandom function.  That is, the client and server
//! interact to compute output = F(skS, input, info) as is shown below.
//!
//! ``` text
//!     Client(input, pkS, info) <---- pkS ------  Server(skS, pkS, info)
//!   -------------------------------------------------------------------
//!   blind, blindedElement, tweakedKey = Blind(input, info, pkS)
//!
//!                                                      blindedElement
//!                                                        ---------->
//!
//!              evaluatedElement, proof = BlindEvaluate(skS, blindedElement,
//!                                                                                              info)
//! ```
//!
//! ```text
//!                                              evaluatedElement, proof
//!                                                        <----------
//!
//!   output = Finalize(input, blind, evaluatedElement,
//!                                     blindedElement, proof, info, tweakedKey)
//!
//! Figure 3: POPRF protocol overview with additional public input
//! ```
//!
//! Each protocol consists of an offline setup phase and an online phase,
//! described in Section 3.2 and Section 3.3, respectively.
//! Configuration details for the offline phase are described in
//! Section 3.1.

pub mod configuration;

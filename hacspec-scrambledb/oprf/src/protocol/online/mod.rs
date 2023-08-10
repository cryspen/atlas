//! ## 3.3.  Online Protocol
//!
//! In the online phase, the client and server engage in a two message
//! protocol to compute the protocol output.  This section describes the
//! protocol details for each protocol variant.  Throughout each
//! description the following parameters are assumed to exist:
//!
//! *  G, a prime-order Group implementing the API described in
//!    Section 2.1.
//!
//! *  contextString, a PublicInput domain separation tag constructed
//!    during context setup as created in Section 3.1.
//!
//! *  skS and pkS, a Scalar and Element representing the private and
//!    public keys configured for client and server in Section 3.2.
//!
//! Applications serialize protocol messages between client and server
//! for transmission.  Elements and scalars are serialized to byte
//! arrays, and values of type Proof are serialized as the concatenation
//! of two serialized scalars.  Deserializing these values can fail, in
//! which case the application MUST abort the protocol raising a
//! DeserializeError failure.
//!
//! Applications MUST check that input Element values received over the
//! wire are not the group identity element.  This check is handled after
//! deserializing Element values; see Section 4 for more information and
//! requirements on input validation for each ciphersuite.


pub mod oprf;
pub mod voprf;
pub mod poprf;

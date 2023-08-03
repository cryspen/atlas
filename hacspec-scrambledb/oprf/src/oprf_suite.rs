//! # 4.  Ciphersuites
//!
//! A ciphersuite (also referred to as 'suite' in this document) for the
//! protocol wraps the functionality required for the protocol to take
//! place.  The ciphersuite should be available to both the client and
//! server, and agreement on the specific instantiation is assumed
//! throughout.
//!
//! A ciphersuite contains instantiations of the following
//! functionalities:
//!
//! *  Group: A prime-order Group exposing the API detailed in
//!    Section 2.1, with the generator element defined in the
//!    corresponding reference for each group.  Each group also specifies
//!    HashToGroup, HashToScalar, and serialization functionalities.  For
//!    HashToGroup, the domain separation tag (DST) is constructed in
//!    accordance with the recommendations in
//!    [I-D.irtf-cfrg-hash-to-curve], Section 3.1.  For HashToScalar,
//!    each group specifies an integer order that is used in reducing
//!    integer values to a member of the corresponding scalar field.
//!
//! *  Hash: A cryptographic hash function whose output length is Nh
//!    bytes long.
//!
//! This section includes an initial set of ciphersuites with supported
//! groups and hash functions.  It also includes implementation details
//! for each ciphersuite, focusing on input validation.  Future documents
//! can specify additional ciphersuites as needed provided they meet the
//! requirements in Section 4.6.
//!
//! For each ciphersuite, contextString is that which is computed in the
//! Setup functions.  Applications should take caution in using
//! ciphersuites targeting P-256 and ristretto255.  See Section 7.2 for
//! related discussion.

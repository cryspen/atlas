#![allow(clippy::assign_op_pattern)]
//! # Extension E. Convertible PRF (coPRF)
//!
//! This part of the document describes an extension to the OPRF protocol
//! called convertible PRF (coPRF) introduced in [Lehmann].
//!
//! A coPRF is a protocol for blind evaluation of a PRF between three
//! parties, as opposed to the two parties in the regular OPRF setting.  A
//! **requester** wishes the PRF to be evaluated blindly under the key
//! held by the **evaluator**. Unlike in the two-party OPRF setting, the
//! blinded evaluation result is not returned to the requester, but to a
//! third party, the **receiver**. Only the receiver can unblind the
//! evaluation result and thus receive the PRF output.
//!
//! CoPRFs further provide the possiblity of converting PRF outputs, both
//! in blinded and unblinded form, from one PRF key to another.
pub mod coprf_online;
pub mod coprf_setup;

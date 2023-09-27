# evercrypt cryptolib

This crate wraps all cryptographic primitives from [evercrypt] commonly used by protocols such
as TLS, HPKE or MLS.

It is a drop-in replacement for the `hacspec_cryptolib` exposing the same API.

> 💡 Note that this module contains more functions than necessary for each individual use case.

[evercrypt]: https://github.com/franziskuskiefer/evercrypt-rust/

use p256::P256Scalar;

/// ### 4.7.2 Random Number Generation Using Extra Random Bits
///
/// Generate a random byte array with L = ceil(((3 *
/// ceil(log2(G.Order()))) / 2) / 8) bytes, and interpret it as an
/// integer; reduce the integer modulo G.Order() and return the result.
/// See [I-D.irtf-cfrg-hash-to-curve], Section 5 for the underlying
/// derivation of L.
///
/// For P-256:
/// ceil(log2(G.Order())) = 256
/// ceil(((3 * 256) / 2) / 8) = 48
pub fn random_scalar(seed: &[u8; 32]) -> P256Scalar {
    scrambledb_util::random_scalar(seed).unwrap()
}

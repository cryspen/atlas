use libcrux::digest::{hash, Algorithm};

pub trait HashAlgorithm {
    /// b / 8 for b the output size of H in bits
    const B_IN_BYTES: usize;

    /// the input block size of H in bytes
    const S_IN_BYTES: usize;

    fn hash(payload: &[u8]) -> Vec<u8>;
}

pub struct SHA256 {}
impl HashAlgorithm for SHA256 {
    const B_IN_BYTES: usize = libcrux::digest::digest_size(Algorithm::Sha256); // output size of H = SHA-256 in bytes
    const S_IN_BYTES: usize = 64; // input block size of H = SHA-256

    fn hash(payload: &[u8]) -> Vec<u8> {
        hash(Algorithm::Sha256, payload)
    }
}

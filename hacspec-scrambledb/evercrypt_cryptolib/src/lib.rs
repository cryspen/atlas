//! # evercrypt cryptolib
//!
//! This crate wraps all cryptographic primitives from [evercrypt] commonly used by protocols such
//! as TLS, HPKE or MLS.
//!
//! It is a drop-in replacement for the `hacspec_cryptolib` exposing the same API.
use hacspec_lib::*;

use evercrypt::prelude::*;

// === Types === //
pub type CryptoError = u8;

pub type Key = ByteSeq;
pub type PSK = Key;
pub type Digest = ByteSeq;
pub type MacKey = ByteSeq;
pub type HMAC = ByteSeq;

pub type SignatureKey = ByteSeq;
pub type VerificationKey = ByteSeq;
pub type Signature = ByteSeq;

pub type AeadKey = ByteSeq;
pub type AeadIv = ByteSeq;
pub type AeadKeyIV = (AeadKey, AeadIv);

pub type Entropy = ByteSeq;

pub type DhSk = ByteSeq;
pub type DhPk = ByteSeq;
pub type KemScheme = NamedGroup;
pub type KemSk = ByteSeq;
pub type KemPk = ByteSeq;

bytes!(EcOidTag, 9);
bytes!(Random32, 32);

type DhPkResult = Result<DhPk, CryptoError>;
type EmptyResult = Result<(), CryptoError>;
type CryptoByteSeqResult = Result<ByteSeq, CryptoError>;
type CryptoByteSeq2Result = Result<(ByteSeq, ByteSeq), CryptoError>;

// === Constants === //
pub const CRYPTO_ERROR: CryptoError = 1u8;
pub const HKDF_ERROR: CryptoError = 2u8;
pub const INSUFFICIENT_ENTROPY: CryptoError = 3u8;
pub const INVALID_CERT: CryptoError = 4u8;
pub const MAC_FAILED: CryptoError = 5u8;
pub const UNSUPPORTED_ALGORITHM: CryptoError = 6u8;
pub const VERIFY_FAILED: CryptoError = 7u8;

// === Enums for configuring algorithms. === //

/// Named ECC curves.
///
/// `Secp256r1` and `X25519` are supported.
#[derive(Clone, Copy, PartialEq)]
pub enum NamedGroup {
    X25519,
    X448,
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

/// Hash algorithms
///
/// Only `SHA256` is supported.
#[derive(Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

/// AEAD algorithms
///
/// `Chacha20Poly1305` and `Aes128Gcm` are supported.
#[derive(Clone, Copy, PartialEq)]
pub enum AeadAlgorithm {
    Chacha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

/// Signature algorithms
///
/// `ED25519` and `EcdsaSecp256r1Sha256` are supported.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SignatureScheme {
    ED25519,
    EcdsaSecp256r1Sha256,
    RsaPssRsaSha256,
}

// === Allow checking support for algorithms === //
/// Check if a [NamedGroup] is supported.
pub fn named_group_support(named_group: &NamedGroup) -> EmptyResult {
    match named_group {
        NamedGroup::X25519 => EmptyResult::Ok(()),
        NamedGroup::Secp256r1 => EmptyResult::Ok(()),
        NamedGroup::X448 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [HashAlgorithm] is supported.
pub fn hash_support(hash: &HashAlgorithm) -> EmptyResult {
    match hash {
        HashAlgorithm::SHA256 => EmptyResult::Ok(()),
        HashAlgorithm::SHA384 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [AeadAlgorithm] is supported.
pub fn aead_support(aead: &AeadAlgorithm) -> EmptyResult {
    match aead {
        AeadAlgorithm::Chacha20Poly1305 => EmptyResult::Ok(()),
        AeadAlgorithm::Aes128Gcm => EmptyResult::Ok(()),
        AeadAlgorithm::Aes256Gcm => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [SignatureScheme] is supported.
pub fn signature_support(signature: &SignatureScheme) -> EmptyResult {
    match signature {
        SignatureScheme::ED25519 => EmptyResult::Ok(()),
        SignatureScheme::EcdsaSecp256r1Sha256 => EmptyResult::Ok(()),
        SignatureScheme::RsaPssRsaSha256 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === Helper functions to get the length of different configurations. === //

/// Get the length of the digest for the given [`HashAlgorithm`] in bytes.
pub fn hash_len(ha: &HashAlgorithm) -> usize {
    match ha {
        HashAlgorithm::SHA256 => 32,
        HashAlgorithm::SHA384 => 48,
        HashAlgorithm::SHA512 => 64,
    }
}

/// Get the length of the tag for the given [`HashAlgorithm`] in bytes.
pub fn hmac_tag_len(ha: &HashAlgorithm) -> usize {
    match ha {
        HashAlgorithm::SHA256 => 32,
        HashAlgorithm::SHA384 => 48,
        HashAlgorithm::SHA512 => 64,
    }
}

/// Get the length of the key for the given [`AeadAlgorithm`] in bytes.
pub fn ae_key_len(ae: &AeadAlgorithm) -> usize {
    match ae {
        AeadAlgorithm::Chacha20Poly1305 => 32,
        AeadAlgorithm::Aes128Gcm => 16,
        AeadAlgorithm::Aes256Gcm => 16,
    }
}

/// Get the length of the nonce for the given [`AeadAlgorithm`] in bytes.
pub fn ae_iv_len(ae: &AeadAlgorithm) -> usize {
    match ae {
        AeadAlgorithm::Chacha20Poly1305 => 12,
        AeadAlgorithm::Aes128Gcm => 12,
        AeadAlgorithm::Aes256Gcm => 12,
    }
}

/// Get the length of the private key for the given [`NamedGroup`] in bytes.
pub fn dh_priv_len(gn: &NamedGroup) -> usize {
    match gn {
        NamedGroup::X25519 => 32,
        NamedGroup::X448 => 56,
        NamedGroup::Secp256r1 => 32,
        NamedGroup::Secp384r1 => 48,
        NamedGroup::Secp521r1 => 66,
    }
}

/// Get the length of the public key for the given [`NamedGroup`] in bytes.
pub fn dh_pub_len(gn: &NamedGroup) -> usize {
    match gn {
        NamedGroup::X25519 => 32,
        NamedGroup::X448 => 56,
        NamedGroup::Secp256r1 => 64,
        NamedGroup::Secp384r1 => 96,
        NamedGroup::Secp521r1 => 132,
    }
}

/// Get an all-zero key of length corresponding to the digest of the [`HashAlgorithm`].
pub fn zero_key(ha: &HashAlgorithm) -> Key {
    Key::new(hash_len(ha) as usize)
}

// === ECDH === //

// Unsafe ECDH functions converting hacspec types to native Rust types for
// evercrypt.
// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_base_unsafe(x: &DhSk) -> CryptoByteSeqResult {
    match p256_base(&x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}
// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_unsafe(x: &DhSk, p: &DhPk) -> CryptoByteSeqResult {
    match p256(&p.to_native(), &x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}
// FIXME: #98 add #[unsafe_hacspec] attribute
fn x25519_base_unsafe(x: &DhSk) -> CryptoByteSeqResult {
    match ecdh_derive_base(EcdhMode::X25519, &x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}
// FIXME: #98 add #[unsafe_hacspec] attribute
fn x25519_unsafe(x: &DhSk, p: &DhPk) -> CryptoByteSeqResult {
    match ecdh_derive(EcdhMode::X25519, &p.to_native(), &x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}

/// Convert a DH secret key to the corresponding public key in the given group
pub fn secret_to_public(group_name: &NamedGroup, x: &DhSk) -> DhPkResult {
    match group_name {
        NamedGroup::Secp256r1 => p256_base_unsafe(x),
        NamedGroup::X25519 => x25519_base_unsafe(x),
        NamedGroup::X448 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Compute the ECDH on [`DhSk`] and [`DhPk`].
pub fn ecdh(group_name: &NamedGroup, x: &DhSk, y: &DhPk) -> CryptoByteSeqResult {
    match group_name {
        NamedGroup::Secp256r1 => p256_unsafe(x, y),
        NamedGroup::X25519 => x25519_unsafe(x, y),
        NamedGroup::X448 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Validate a candidate [`DhSk`].
///
/// Return `true` if `bytes` is a valid private key for the given group and `false`
/// otherwise.
pub fn valid_private_key(named_group: &NamedGroup, bytes: &DhSk) -> bool {
    match named_group {
        NamedGroup::X25519 => bytes.len() == dh_priv_len(named_group),
        NamedGroup::X448 => bytes.len() == dh_priv_len(named_group),
        NamedGroup::Secp256r1 => match p256::validate_sk(&bytes.to_native()) {
            Ok(_) => true,
            Err(_) => false,
        },
        NamedGroup::Secp384r1 => false,
        NamedGroup::Secp521r1 => false,
    }
}

/// Parse a public key and return it if it's valid.
pub fn parse_public_key(named_group: &NamedGroup, bytes: &DhPk) -> Result<DhPk, CryptoError> {
    match named_group {
        NamedGroup::X25519 => Result::<DhPk, CryptoError>::Ok(bytes.clone()),
        NamedGroup::X448 => Result::<DhPk, CryptoError>::Ok(bytes.clone()),
        NamedGroup::Secp256r1 => match p256::validate_pk(&bytes.to_native()) {
            Ok(pk) => Result::<DhPk, CryptoError>::Ok(ByteSeq::from_public_slice(&pk)),
            Err(_) => Result::<DhPk, CryptoError>::Err(CRYPTO_ERROR),
        },
        NamedGroup::Secp384r1 => Result::<DhPk, CryptoError>::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => Result::<DhPk, CryptoError>::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === Key Encapsulation === //

/// Get the length of the private key for the given [`KemScheme`] in bytes.
pub fn kem_priv_len(ks: &KemScheme) -> usize {
    dh_priv_len(ks)
}

/// Get the length of the public key for the given [`KemScheme`] in bytes.
pub fn kem_pub_len(ks: &KemScheme) -> usize {
    dh_pub_len(ks)
}

/// Compute the public key for a private key of the given [`KemScheme`].
pub fn kem_priv_to_pub(ks: &KemScheme, sk: &KemSk) -> CryptoByteSeqResult {
    secret_to_public(ks, sk)
}

/// Generate a key pair for the [`KemScheme`] based on the provided [`Entropy`].
///
/// The provided [`Entropy`] must be at least of length [`kem_priv_len()`].
pub fn kem_keygen(ks: &KemScheme, ent: Entropy) -> CryptoByteSeq2Result {
    let mut result = CryptoByteSeq2Result::Err(INSUFFICIENT_ENTROPY);
    if ent.len() >= kem_priv_len(ks) {
        let sk = KemSk::from_seq(&ent.slice_range(0..kem_priv_len(ks)));
        let pk = kem_priv_to_pub(ks, &sk)?;
        result = CryptoByteSeq2Result::Ok((sk, pk));
    }
    result
}

/// Encapsulate a shared secret to the provided `pk` and return the `(Key, Enc)` tuple.
pub fn kem_encap(ks: &KemScheme, pk: &KemPk, ent: Entropy) -> CryptoByteSeq2Result {
    let (x, gx) = kem_keygen(ks, ent)?;
    let gxy = ecdh(ks, &x, pk)?;
    CryptoByteSeq2Result::Ok((gxy, gx))
}

/// Decapsulate the shared secret in `ct` using the private key `sk`.
pub fn kem_decap(ks: &KemScheme, ct: &ByteSeq, sk: KemSk) -> CryptoByteSeqResult {
    let gxy = ecdh(ks, &sk, ct)?;
    CryptoByteSeqResult::Ok(gxy)
}

// === Hashing === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn sha256_unsafe(payload: &ByteSeq) -> CryptoByteSeqResult {
    Ok(Digest::from_public_slice(&evercrypt::digest::hash(
        DigestMode::Sha256,
        &payload.to_native(),
    )))
}

/// Hash the `payload` with [`HashAlgorithm`].
pub fn hash(ha: &HashAlgorithm, payload: &ByteSeq) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => sha256_unsafe(payload),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === HMAC === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn hmac_sha256_unsafe(mk: &MacKey, payload: &ByteSeq) -> CryptoByteSeqResult {
    Ok(HMAC::from_public_slice(&evercrypt::hmac::hmac(
        HmacMode::Sha256,
        &mk.to_native(),
        &payload.to_native(),
        None,
    )))
}

/// Compute tha HMAC tag on the given `payload` with the [`HashAlgorithm`] and [`MacKey`].
pub fn hmac_tag(ha: &HashAlgorithm, mk: &MacKey, payload: &ByteSeq) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => hmac_sha256_unsafe(mk, payload),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

fn check_tag_len(a: &HMAC, b: &HMAC) -> EmptyResult {
    if a.len() == b.len() {
        EmptyResult::Ok(())
    } else {
        EmptyResult::Err(MAC_FAILED)
    }
}

fn check_bytes(a: U8, b: U8) -> EmptyResult {
    if !a.equal(b) {
        EmptyResult::Err(MAC_FAILED)
    } else {
        EmptyResult::Ok(())
    }
}

/// Verify the validity of a given [`HMAC`] tag.
///
/// Returns a [`CryptoError`] if the tag is invalid.
pub fn hmac_verify(ha: &HashAlgorithm, mk: &MacKey, payload: &ByteSeq, t: &HMAC) -> EmptyResult {
    let my_hmac = hmac_tag(ha, mk, payload)?;
    check_tag_len(t, &my_hmac)?;
    for i in 0..t.len() {
        check_bytes(my_hmac[i], t[i])?;
    }
    EmptyResult::Ok(())
}

// === Signatures === //

// Some ASN.1 helper functions
fn get_length_length(b: &ByteSeq) -> usize {
    if U8::declassify(b[0]) >> 7 == 1u8 {
        declassify_usize_from_U8(b[0] & U8(0x7fu8))
    } else {
        0
    }
}
fn get_length(b: &ByteSeq, len: usize) -> usize {
    declassify_u32_from_U32(U32_from_be_bytes(U32Word::from_slice(b, 0, len))) as usize
        >> ((4 - len) * 8)
}
fn get_short_length(b: &ByteSeq) -> usize {
    declassify_usize_from_U8(b[0] & U8(0x7fu8))
}

// Very basic ASN.1 parser to read the ECDSA public key from an X.509 certificate.
pub fn verification_key_from_cert(cert: &ByteSeq) -> Result<VerificationKey, CryptoError> {
    // cert is an ASN.1 sequence. Take the first sequence inside the outer.
    // Skip 1 + length bytes
    let skip = 2 + get_length_length(&cert.slice_range(1..cert.len())) + 1;
    let seq1_len_len = get_length_length(&cert.slice_range(skip..cert.len()));
    let skip = skip + 1;
    let seq1_len = get_length(&cert.slice(skip, cert.len() - skip), seq1_len_len);
    let mut seq1 = cert.slice_range(skip + seq1_len_len..skip + seq1_len_len + seq1_len);

    // Read sequences until we find the ecPublicKey (we don't support anything else right now)
    let mut pk = VerificationKey::new(0);
    for _ in 0..seq1.len() {
        // FIXME: we really need a break statement.
        if seq1.len() > 0 {
            let element_type = U8::declassify(seq1[0]);
            seq1 = seq1.slice(1, seq1.len() - 1);
            let len_len = get_length_length(&seq1);
            let mut len = get_short_length(&seq1);
            seq1 = seq1.slice(1, seq1.len() - 1);
            if len_len != 0 {
                len = get_length(&seq1, len_len) + len_len;
            }
            // XXX: Unfortunately we can't break so we don't go in here if we have
            //      the pk already.
            if element_type == 0x30u8 && pk.len() == 0 {
                // peek into this sequence to see if sequence again with an ecPublicKey
                // as first element
                let seq2 = seq1.slice(len_len, len);
                let element_type = U8::declassify(seq2[0]);
                let seq2 = seq2.slice(1, seq2.len() - 1);
                if element_type == 0x30u8 {
                    let len_len = get_length_length(&seq2);
                    if len_len == 0 {
                        let oid_len = get_short_length(&seq2);
                        if oid_len >= 9 {
                            // ecPublicKey oid incl tag: 06 07 2A 86 48 CE 3D 02 01
                            // FIXME: This shouldn't be necessary. Instead public_byte_seq!
                            //        should be added to the typechecker. #136
                            let expected = ByteSeq::from_seq(&EcOidTag(secret_bytes!([
                                0x06u8, 0x07u8, 0x2Au8, 0x86u8, 0x48u8, 0xCEu8, 0x3Du8, 0x02u8,
                                0x01u8
                            ])));
                            let oid = seq2.slice(1, 9);
                            let mut ec_pk_oid = true;
                            for i in 0..9 {
                                let oid_byte_equal =
                                    U8::declassify(oid[i]) == U8::declassify(expected[i]);
                                ec_pk_oid = ec_pk_oid && oid_byte_equal;
                            }
                            if ec_pk_oid {
                                // We have an ecPublicKey, skip the inner sequences
                                // and read the public key from the bit string
                                let bit_string = seq2.slice(oid_len + 1, seq2.len() - oid_len - 1);
                                // We only support uncompressed points
                                if U8::declassify(bit_string[0]) == 0x03u8 {
                                    let pk_len = declassify_usize_from_U8(bit_string[1]); // 42
                                    let _zeroes = declassify_usize_from_U8(bit_string[2]); // 00
                                    let _uncompressed = declassify_usize_from_U8(bit_string[3]); // 04
                                    pk = bit_string.slice(4, pk_len - 2);
                                }
                            }
                        }
                    }
                }
            }
            seq1 = seq1.slice(len, seq1.len() - len);
        }
    }
    if pk.len() == 0 {
        CryptoByteSeqResult::Err(INVALID_CERT)
    } else {
        CryptoByteSeqResult::Ok(pk)
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_sha256_sign_unsafe(
    ps: &SignatureKey,
    payload: &ByteSeq,
    random: &Entropy,
) -> CryptoByteSeqResult {
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&ps.to_native());
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&random.to_native());
    match p256_sign(DigestMode::Sha256, &payload.to_native(), &sk, &nonce) {
        // FIXME: this must encode the signature with ASN.1
        Ok(s) => Ok(Signature::from_public_slice(&s.raw())),
        Err(_e) => Err(CRYPTO_ERROR),
    }
}

/// Sign the `payload` with the given [`SignatureKey`] and [`SignatureScheme`].
pub fn sign(
    sa: &SignatureScheme,
    ps: &SignatureKey,
    payload: &ByteSeq,
    ent: Entropy,
) -> Result<Signature, CryptoError> {
    match sa {
        SignatureScheme::EcdsaSecp256r1Sha256 => p256_sha256_sign_unsafe(ps, payload, &ent),
        SignatureScheme::ED25519 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        SignatureScheme::RsaPssRsaSha256 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_sha256_verify_unsafe(
    pk: &VerificationKey,
    payload: &ByteSeq,
    sig: &ByteSeq,
) -> EmptyResult {
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig.to_native());
    let result = p256_verify(
        DigestMode::Sha256,
        &payload.to_native(),
        &pk.to_native(),
        &EcdsaSignature::from_bytes(&sig_bytes),
    );
    if let Ok(r) = result {
        if r {
            Ok(())
        } else {
            Err(VERIFY_FAILED)
        }
    } else {
        Err(VERIFY_FAILED)
    }
}

/// Verify the signature on the `payload` with the given [`VerificationKey`] and
/// [`SignatureScheme`].
pub fn verify(
    sa: &SignatureScheme,
    pk: &VerificationKey,
    payload: &ByteSeq,
    sig: &ByteSeq,
) -> EmptyResult {
    match sa {
        SignatureScheme::EcdsaSecp256r1Sha256 => p256_sha256_verify_unsafe(pk, payload, sig),
        SignatureScheme::ED25519 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        SignatureScheme::RsaPssRsaSha256 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === HKDF === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn hkdf_extract_unsafe(k: &Key, salt: &Key) -> CryptoByteSeqResult {
    Ok(Key::from_public_slice(&hkdf::extract(
        HmacMode::Sha256,
        &salt.to_native(),
        &k.to_native(),
    )))
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn hkdf_expand_unsafe(k: &Key, info: &ByteSeq, len: usize) -> CryptoByteSeqResult {
    Ok(Key::from_public_slice(&hkdf::expand(
        HmacMode::Sha256,
        &k.to_native(),
        &info.to_native(),
        len,
    )))
}

/// HKDF Extract.
pub fn hkdf_extract(ha: HashAlgorithm, k: &Key, salt: &Key) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => hkdf_extract_unsafe(k, salt),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// HKDF Expand.
pub fn hkdf_expand(ha: HashAlgorithm, k: &Key, info: &ByteSeq, len: usize) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => hkdf_expand_unsafe(k, info, len),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === AEAD === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn aesgcm_encrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::encrypt(
        AeadMode::Aes128Gcm,
        &k.to_native(),
        &payload.to_native(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok((c, t)) => Ok(ByteSeq::from_public_slice(&c).concat(&ByteSeq::from_public_slice(&t))),
        Err(_e) => Err(CRYPTO_ERROR),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn chachapoly_encrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::encrypt(
        AeadMode::Chacha20Poly1305,
        &k.to_native(),
        &payload.to_native(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok((c, t)) => Ok(ByteSeq::from_public_slice(&c).concat(&ByteSeq::from_public_slice(&t))),
        Err(_e) => Err(CRYPTO_ERROR),
    }
}

/// AEAD encrypt the `payload` with the [`AeadAlgorithm`].
pub fn aead_encrypt(
    a: &AeadAlgorithm,
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    match a {
        AeadAlgorithm::Aes128Gcm => aesgcm_encrypt_unsafe(k, iv, payload, ad),
        AeadAlgorithm::Chacha20Poly1305 => chachapoly_encrypt_unsafe(k, iv, payload, ad),
        AeadAlgorithm::Aes256Gcm => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn aesgcm_decrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::decrypt(
        AeadMode::Aes128Gcm,
        &k.to_native(),
        &ciphertext
            .slice_range(0..ciphertext.len() - 16)
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &ciphertext
            .slice_range(ciphertext.len() - 16..ciphertext.len())
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok(ptxt) => Ok(ByteSeq::from_public_slice(&ptxt)),
        Err(_e) => Err(MAC_FAILED),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn chachapoly_decrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::decrypt(
        AeadMode::Chacha20Poly1305,
        &k.to_native(),
        &ciphertext
            .slice_range(0..ciphertext.len() - 16)
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &ciphertext
            .slice_range(ciphertext.len() - 16..ciphertext.len())
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok(ptxt) => Ok(ByteSeq::from_public_slice(&ptxt)),
        Err(_e) => Err(MAC_FAILED),
    }
}

/// AEAD decrypt the `ciphertext` with the [`AeadAlgorithm`] and return the payload.
pub fn aead_decrypt(
    a: &AeadAlgorithm,
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    match a {
        AeadAlgorithm::Aes128Gcm => aesgcm_decrypt_unsafe(k, iv, ciphertext, ad),
        AeadAlgorithm::Chacha20Poly1305 => chachapoly_decrypt_unsafe(k, iv, ciphertext, ad),
        AeadAlgorithm::Aes256Gcm => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

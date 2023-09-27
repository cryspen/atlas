use hacspec_lib::*;
use hpke_kem::{KEM::*, *};

#[test]
fn derive_x25519() {
    // A.1.1. test vector
    let ikm_e =
        ByteSeq::from_hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    let ikm_r =
        ByteSeq::from_hex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    let expected_sk_e =
        ByteSeq::from_hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    let expected_pk_e =
        ByteSeq::from_hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    let expected_sk_r =
        ByteSeq::from_hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let expected_pk_r =
        ByteSeq::from_hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");

    let (sk_e, pk_e) =
        DeriveKeyPair(DHKEM_X25519_HKDF_SHA256, &ikm_e).expect("Error deriving key pair");
    let (sk_r, pk_r) =
        DeriveKeyPair(DHKEM_X25519_HKDF_SHA256, &ikm_r).expect("Error deriving key pair");

    assert_secret_seq_eq!(expected_sk_e, sk_e, U8);
    assert_secret_seq_eq!(expected_sk_r, sk_r, U8);
    assert_secret_seq_eq!(expected_pk_e, pk_e, U8);
    assert_secret_seq_eq!(expected_pk_r, pk_r, U8);
}

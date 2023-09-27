use hacspec_lib::*;
use hpke_kem::*;

#[test]
fn self_test() {
    let alg = KEM::DHKEM_X25519_HKDF_SHA256;
    let ikm_r = ByteSeq::from_hex("93c7c22beb0f44ae5582c9197f4d7ec3");
    let rand_s = ByteSeq::from_hex("53dd33701a0486b1a3630e82b20eabf9");

    let (sk_r, pk_r) = DeriveKeyPair(alg, &ikm_r).expect("Error generating key pair");

    let (zz_s, enc) = Encap(alg, &pk_r, rand_s).expect("Error encapsulating");
    let zz_r = Decap(alg, &enc, &sk_r).expect("Error decapsulating");
    assert_secret_seq_eq!(zz_r, zz_s, U8);
}

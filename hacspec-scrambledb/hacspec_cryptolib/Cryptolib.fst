module Cryptolib

#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

open FStar.Mul

open Hacspec.Lib

open Hacspec.Aes

open Hacspec.Aes128.Gcm

open Hacspec.Chacha20

open Hacspec.Chacha20poly1305

open Hacspec.Curve25519

open Hacspec.Ecdsa.P256.Sha256

open Hacspec.Gf128

open Hacspec.Hkdf

open Hacspec.Hmac

open Hacspec.P256

open Hacspec.Poly1305

open Hacspec.Sha256

type crypto_error_t = pub_uint8

type key_t = byte_seq

type psk_t = key_t

type digest_t = byte_seq

type mac_key_t = byte_seq

type hmac_t = byte_seq

type signature_key_t = byte_seq

type verification_key_t = byte_seq

type signature_t = byte_seq

type aead_key_t = byte_seq

type aead_iv_t = byte_seq

type aead_key_iv_t = (aead_key_t & aead_iv_t)

type entropy_t = byte_seq

type dh_sk_t = byte_seq

type dh_pk_t = byte_seq

type kem_scheme_t = named_group_t

type kem_sk_t = byte_seq

type kem_pk_t = byte_seq

type ec_oid_tag_t = lseq (uint8) (usize 9)

type random32_t = lseq (uint8) (usize 32)

type dh_pk_result_t = (result dh_pk_t crypto_error_t)

type empty_result_t = (result () crypto_error_t)

type crypto_byte_seq_result_t = (result byte_seq crypto_error_t)

type crypto_byte_seq2_result_t = (result (byte_seq & byte_seq) crypto_error_t)

let crypto_error_v : crypto_error_t =
  pub_u8 0x1

let hkdf_error_v : crypto_error_t =
  pub_u8 0x2

let insufficient_entropy_v : crypto_error_t =
  pub_u8 0x3

let invalid_cert_v : crypto_error_t =
  pub_u8 0x4

let mac_failed_v : crypto_error_t =
  pub_u8 0x5

let unsupported_algorithm_v : crypto_error_t =
  pub_u8 0x6

let verify_failed_v : crypto_error_t =
  pub_u8 0x7

noeq type named_group_t =
| X25519_named_group_t : named_group_t
| X448_named_group_t : named_group_t
| Secp256r1_named_group_t : named_group_t
| Secp384r1_named_group_t : named_group_t
| Secp521r1_named_group_t : named_group_t

noeq type hash_algorithm_t =
| SHA256_hash_algorithm_t : hash_algorithm_t
| SHA384_hash_algorithm_t : hash_algorithm_t

noeq type aead_algorithm_t =
| Chacha20Poly1305_aead_algorithm_t : aead_algorithm_t
| Aes128Gcm_aead_algorithm_t : aead_algorithm_t
| Aes256Gcm_aead_algorithm_t : aead_algorithm_t

noeq type signature_scheme_t =
| ED25519_signature_scheme_t : signature_scheme_t
| EcdsaSecp256r1Sha256_signature_scheme_t : signature_scheme_t
| RsaPssRsaSha256_signature_scheme_t : signature_scheme_t

let named_group_support (named_group_0 : named_group_t) : empty_result_t =
  match named_group_0 with
  | X25519_named_group_t -> Ok (())
  | Secp256r1_named_group_t -> Ok (())
  | X448_named_group_t -> Err (unsupported_algorithm_v)
  | Secp384r1_named_group_t -> Err (unsupported_algorithm_v)
  | Secp521r1_named_group_t -> Err (unsupported_algorithm_v)

let hash_support (hash_1 : hash_algorithm_t) : empty_result_t =
  match hash_1 with
  | SHA256_hash_algorithm_t -> Ok (())
  | SHA384_hash_algorithm_t -> Err (unsupported_algorithm_v)

let aead_support (aead_2 : aead_algorithm_t) : empty_result_t =
  match aead_2 with
  | Chacha20Poly1305_aead_algorithm_t -> Ok (())
  | Aes128Gcm_aead_algorithm_t -> Ok (())
  | Aes256Gcm_aead_algorithm_t -> Err (unsupported_algorithm_v)

let signature_support (signature_3 : signature_scheme_t) : empty_result_t =
  match signature_3 with
  | ED25519_signature_scheme_t -> Ok (())
  | EcdsaSecp256r1Sha256_signature_scheme_t -> Ok (())
  | RsaPssRsaSha256_signature_scheme_t -> Err (unsupported_algorithm_v)

let hash_len (ha_4 : hash_algorithm_t) : uint_size =
  match ha_4 with
  | SHA256_hash_algorithm_t -> usize 32
  | SHA384_hash_algorithm_t -> usize 48

let hmac_tag_len (ha_5 : hash_algorithm_t) : uint_size =
  match ha_5 with
  | SHA256_hash_algorithm_t -> usize 32
  | SHA384_hash_algorithm_t -> usize 48

let ae_key_len (ae_6 : aead_algorithm_t) : uint_size =
  match ae_6 with
  | Chacha20Poly1305_aead_algorithm_t -> usize 32
  | Aes128Gcm_aead_algorithm_t -> usize 16
  | Aes256Gcm_aead_algorithm_t -> usize 16

let ae_iv_len (ae_7 : aead_algorithm_t) : uint_size =
  match ae_7 with
  | Chacha20Poly1305_aead_algorithm_t -> usize 12
  | Aes128Gcm_aead_algorithm_t -> usize 12
  | Aes256Gcm_aead_algorithm_t -> usize 12

let dh_priv_len (gn_8 : named_group_t) : uint_size =
  match gn_8 with
  | X25519_named_group_t -> usize 32
  | X448_named_group_t -> usize 56
  | Secp256r1_named_group_t -> usize 32
  | Secp384r1_named_group_t -> usize 48
  | Secp521r1_named_group_t -> usize 66

let dh_pub_len (gn_9 : named_group_t) : uint_size =
  match gn_9 with
  | X25519_named_group_t -> usize 32
  | X448_named_group_t -> usize 56
  | Secp256r1_named_group_t -> usize 64
  | Secp384r1_named_group_t -> usize 96
  | Secp521r1_named_group_t -> usize 132

let zero_key (ha_10 : hash_algorithm_t) : key_t =
  seq_new_ (secret (pub_u8 0x0)) (usize (hash_len (ha_10)))

let secret_to_public
  (group_name_11 : named_group_t)
  (x_12 : dh_sk_t)
  : dh_pk_result_t =
  match group_name_11 with
  | Secp256r1_named_group_t -> match p256_point_mul_base (
    nat_from_byte_seq_be (0xunknown) (0) (x_12)) with
  | Ok (x_13, y_14) -> Ok (
    seq_concat (nat_to_byte_seq_be (0xunknown) (0) (x_13)) (
      nat_to_byte_seq_be (0xunknown) (0) (y_14)))
  | Err _ -> Err (crypto_error_v)
  | X25519_named_group_t -> Ok (
    seq_from_seq (x25519_secret_to_public (array_from_seq (32) (x_12))))
  | X448_named_group_t -> Err (unsupported_algorithm_v)
  | Secp384r1_named_group_t -> Err (unsupported_algorithm_v)
  | Secp521r1_named_group_t -> Err (unsupported_algorithm_v)

let p256_check_point_len (p_15 : dh_pk_t) : empty_result_t =
  if ((seq_len (p_15)) <> (usize 64)) then (Err (crypto_error_v)) else (Ok (()))

let p256_ecdh (x_16 : dh_sk_t) (y_17 : dh_pk_t) : crypto_byte_seq_result_t =
  match (p256_check_point_len (y_17)) with
  | Err x -> Err x
  | Ok  _ ->
    let pk_18 =
      (
        nat_from_byte_seq_be (0xunknown) (0) (
          seq_slice_range (y_17) ((usize 0, usize 32))),
        nat_from_byte_seq_be (0xunknown) (0) (
          seq_slice_range (y_17) ((usize 32, usize 64)))
      )
    in
    match p256_point_mul (nat_from_byte_seq_be (0xunknown) (0) (x_16)) (
      pk_18) with
    | Ok (x_19, y_20) -> Ok (
      seq_concat (nat_to_byte_seq_be (0xunknown) (0) (x_19)) (
        nat_to_byte_seq_be (0xunknown) (0) (y_20)))
    | Err _ -> Err (crypto_error_v)

let ecdh
  (group_name_21 : named_group_t)
  (x_22 : dh_sk_t)
  (y_23 : dh_pk_t)
  : crypto_byte_seq_result_t =
  match group_name_21 with
  | Secp256r1_named_group_t -> p256_ecdh (x_22) (y_23)
  | X25519_named_group_t -> Ok (
    seq_from_seq (
      x25519_scalarmult (array_from_seq (32) (x_22)) (
        array_from_seq (32) (y_23))))
  | X448_named_group_t -> Err (unsupported_algorithm_v)
  | Secp384r1_named_group_t -> Err (unsupported_algorithm_v)
  | Secp521r1_named_group_t -> Err (unsupported_algorithm_v)

let kem_priv_len (ks_24 : kem_scheme_t) : uint_size =
  dh_priv_len (ks_24)

let kem_pub_len (ks_25 : kem_scheme_t) : uint_size =
  dh_pub_len (ks_25)

let kem_priv_to_pub
  (ks_26 : kem_scheme_t)
  (sk_27 : kem_sk_t)
  : crypto_byte_seq_result_t =
  secret_to_public (ks_26) (sk_27)

let kem_keygen
  (ks_28 : kem_scheme_t)
  (ent_29 : entropy_t)
  : crypto_byte_seq2_result_t =
  let result_30 =
    Err (insufficient_entropy_v)
  in
  match (
    if (seq_len (ent_29)) >= (kem_priv_len (ks_28)) then begin
      let sk_31 =
        seq_from_seq (
          seq_slice_range (ent_29) ((usize 0, kem_priv_len (ks_28))))
      in
      match (kem_priv_to_pub (ks_28) (sk_31)) with
      | Err x -> Err x
      | Ok  pk_32 ->
        let result_30 =
          Ok ((sk_31, pk_32))
        in
        Ok ((result_30))
    end else begin Ok ((result_30))
    end) with
  | Err x -> Err x
  | Ok  (result_30) ->
    result_30

let kem_encap
  (ks_33 : kem_scheme_t)
  (pk_34 : kem_pk_t)
  (ent_35 : entropy_t)
  : crypto_byte_seq2_result_t =
  match (kem_keygen (ks_33) (ent_35)) with
  | Err x -> Err x
  | Ok  (x_36, gx_37) ->
    match (ecdh (ks_33) (x_36) (pk_34)) with
    | Err x -> Err x
    | Ok  gxy_38 ->
      Ok ((gxy_38, gx_37))

let kem_decap
  (ks_39 : kem_scheme_t)
  (ct_40 : byte_seq)
  (sk_41 : kem_sk_t)
  : crypto_byte_seq_result_t =
  match (ecdh (ks_39) (sk_41) (ct_40)) with
  | Err x -> Err x
  | Ok  gxy_42 ->
    Ok (gxy_42)

let hash
  (ha_43 : hash_algorithm_t)
  (payload_44 : byte_seq)
  : crypto_byte_seq_result_t =
  match ha_43 with
  | SHA256_hash_algorithm_t -> Ok (seq_from_seq (sha256 (payload_44)))
  | SHA384_hash_algorithm_t -> Err (unsupported_algorithm_v)

let hmac_tag
  (ha_45 : hash_algorithm_t)
  (mk_46 : mac_key_t)
  (payload_47 : byte_seq)
  : crypto_byte_seq_result_t =
  match ha_45 with
  | SHA256_hash_algorithm_t -> Ok (seq_from_seq (hmac (mk_46) (payload_47)))
  | SHA384_hash_algorithm_t -> Err (unsupported_algorithm_v)

let check_tag_len (a_48 : hmac_t) (b_49 : hmac_t) : empty_result_t =
  if ((seq_len (a_48)) = (seq_len (b_49))) then (Ok (())) else (
    Err (mac_failed_v))

let check_bytes (a_50 : uint8) (b_51 : uint8) : empty_result_t =
  if (not (uint8_equal (a_50) (b_51))) then (Err (mac_failed_v)) else (Ok (()))

let hmac_verify
  (ha_52 : hash_algorithm_t)
  (mk_53 : mac_key_t)
  (payload_54 : byte_seq)
  (t_55 : hmac_t)
  : empty_result_t =
  match (hmac_tag (ha_52) (mk_53) (payload_54)) with
  | Err x -> Err x
  | Ok  my_hmac_56 ->
    match (check_tag_len (t_55) (my_hmac_56)) with
    | Err x -> Err x
    | Ok  _ ->
      match (
        foldi_result (usize 0) (seq_len (t_55)) (fun i_57 () ->
          match (
            check_bytes (seq_index (my_hmac_56) (i_57)) (
              seq_index (t_55) (i_57))) with
          | Err x -> Err x
          | Ok  _ ->
            Ok (()))
        ()) with
      | Err x -> Err x
      | Ok  () ->
        Ok (())

let get_length_length (b_58 : byte_seq) : uint_size =
  if (
    (
      (uint8_declassify (seq_index (b_58) (usize 0))) `shift_right` (
        usize 7)) = (pub_u8 0x1)) then (
    declassify_usize_from_uint8 (
      (seq_index (b_58) (usize 0)) &. (secret (pub_u8 0x7f)))) else (usize 0)

let get_length (b_59 : byte_seq) (len_60 : uint_size) : uint_size =
  (
    v (
      cast U32 PUB (
        declassify_u32_from_uint32 (
          uint32_from_be_bytes (
            array_from_slice (secret (pub_u8 0x0)) (4) (b_59) (usize 0) (
              len_60)))))) `usize_shift_right` (
    ((usize 4) - (len_60)) * (usize 8))

let get_short_length (b_61 : byte_seq) : uint_size =
  declassify_usize_from_uint8 (
    (seq_index (b_61) (usize 0)) &. (secret (pub_u8 0x7f)))

let verification_key_from_cert
  (cert_62 : byte_seq)
  : (result verification_key_t crypto_error_t) =
  let skip_63 =
    (
      (usize 2) + (
        get_length_length (
          seq_slice_range (cert_62) ((usize 1, seq_len (cert_62)))))) + (
      usize 1)
  in
  let seq1_len_len_64 =
    get_length_length (seq_slice_range (cert_62) ((skip_63, seq_len (cert_62))))
  in
  let skip_65 =
    (skip_63) + (usize 1)
  in
  let seq1_len_66 =
    get_length (
      seq_slice (cert_62) (skip_65) ((seq_len (cert_62)) - (skip_65))) (
      seq1_len_len_64)
  in
  let seq1_67 =
    seq_slice_range (cert_62) (
      (
        (skip_65) + (seq1_len_len_64),
        ((skip_65) + (seq1_len_len_64)) + (seq1_len_66)
      ))
  in
  let pk_68 =
    seq_new_ (secret (pub_u8 0x0)) (usize 0)
  in
  let (seq1_67, pk_68) =
    foldi (usize 0) (seq_len (seq1_67)) (fun _ (seq1_67, pk_68) ->
      let (seq1_67, pk_68) =
        if (seq_len (seq1_67)) > (usize 0) then begin
          let element_type_69 =
            uint8_declassify (seq_index (seq1_67) (usize 0))
          in
          let seq1_67 =
            seq_slice (seq1_67) (usize 1) ((seq_len (seq1_67)) - (usize 1))
          in
          let len_len_70 =
            get_length_length (seq1_67)
          in
          let len_71 =
            get_short_length (seq1_67)
          in
          let seq1_67 =
            seq_slice (seq1_67) (usize 1) ((seq_len (seq1_67)) - (usize 1))
          in
          let (len_71) =
            if (len_len_70) <> (usize 0) then begin
              let len_71 =
                (get_length (seq1_67) (len_len_70)) + (len_len_70)
              in
              (len_71)
            end else begin (len_71)
            end
          in
          let (pk_68) =
            if ((element_type_69) = (pub_u8 0x30)) && (
              (seq_len (pk_68)) = (usize 0)) then begin
              let seq2_72 =
                seq_slice (seq1_67) (len_len_70) (len_71)
              in
              let element_type_73 =
                uint8_declassify (seq_index (seq2_72) (usize 0))
              in
              let seq2_74 =
                seq_slice (seq2_72) (usize 1) ((seq_len (seq2_72)) - (usize 1))
              in
              let (pk_68) =
                if (element_type_73) = (pub_u8 0x30) then begin
                  let len_len_75 =
                    get_length_length (seq2_74)
                  in
                  let (pk_68) =
                    if (len_len_75) = (usize 0) then begin
                      let oid_len_76 =
                        get_short_length (seq2_74)
                      in
                      let (pk_68) =
                        if (oid_len_76) >= (usize 9) then begin
                          let expected_77 =
                            seq_from_seq (
                              array_from_list (
                                let l =
                                  [
                                    secret (pub_u8 0x6);
                                    secret (pub_u8 0x7);
                                    secret (pub_u8 0x2a);
                                    secret (pub_u8 0x86);
                                    secret (pub_u8 0x48);
                                    secret (pub_u8 0xce);
                                    secret (pub_u8 0x3d);
                                    secret (pub_u8 0x2);
                                    secret (pub_u8 0x1)
                                  ]
                                in assert_norm (List.Tot.length l == 9); l))
                          in
                          let oid_78 =
                            seq_slice (seq2_74) (usize 1) (usize 9)
                          in
                          let ec_pk_oid_79 =
                            true
                          in
                          let (ec_pk_oid_79) =
                            foldi (usize 0) (usize 9) (fun i_80 (ec_pk_oid_79
                              ) ->
                              let oid_byte_equal_81 =
                                (
                                  uint8_declassify (
                                    seq_index (oid_78) (i_80))) = (
                                  uint8_declassify (
                                    seq_index (expected_77) (i_80)))
                              in
                              let ec_pk_oid_79 =
                                (ec_pk_oid_79) && (oid_byte_equal_81)
                              in
                              (ec_pk_oid_79))
                            (ec_pk_oid_79)
                          in
                          let (pk_68) =
                            if ec_pk_oid_79 then begin
                              let bit_string_82 =
                                seq_slice (seq2_74) ((oid_len_76) + (usize 1)) (
                                  ((seq_len (seq2_74)) - (oid_len_76)) - (
                                    usize 1))
                              in
                              let (pk_68) =
                                if (
                                  uint8_declassify (
                                    seq_index (bit_string_82) (usize 0))) = (
                                  pub_u8 0x3) then begin
                                  let pk_len_83 =
                                    declassify_usize_from_uint8 (
                                      seq_index (bit_string_82) (usize 1))
                                  in
                                  let zeroes_84 =
                                    declassify_usize_from_uint8 (
                                      seq_index (bit_string_82) (usize 2))
                                  in
                                  let uncompressed_85 =
                                    declassify_usize_from_uint8 (
                                      seq_index (bit_string_82) (usize 3))
                                  in
                                  let pk_68 =
                                    seq_slice (bit_string_82) (usize 4) (
                                      (pk_len_83) - (usize 2))
                                  in
                                  (pk_68)
                                end else begin (pk_68)
                                end
                              in
                              (pk_68)
                            end else begin (pk_68)
                            end
                          in
                          (pk_68)
                        end else begin (pk_68)
                        end
                      in
                      (pk_68)
                    end else begin (pk_68)
                    end
                  in
                  (pk_68)
                end else begin (pk_68)
                end
              in
              (pk_68)
            end else begin (pk_68)
            end
          in
          let seq1_67 =
            seq_slice (seq1_67) (len_71) ((seq_len (seq1_67)) - (len_71))
          in
          (seq1_67, pk_68)
        end else begin (seq1_67, pk_68)
        end
      in
      (seq1_67, pk_68))
    (seq1_67, pk_68)
  in
  if ((seq_len (pk_68)) = (usize 0)) then (Err (invalid_cert_v)) else (
    Ok (pk_68))

let concat_signature
  (r_86 : p256_scalar_t)
  (s_87 : p256_scalar_t)
  : (result signature_t crypto_error_t) =
  let signature_88 =
    seq_concat_owned (
      seq_concat_owned (seq_new_ (secret (pub_u8 0x0)) (usize 0)) (
        nat_to_byte_seq_be (0xunknown) (0) (r_86))) (
      nat_to_byte_seq_be (0xunknown) (0) (s_87))
  in
  Ok (signature_88)

let p256_sign
  (ps_89 : signature_key_t)
  (payload_90 : byte_seq)
  (entropy_91 : entropy_t)
  : (result signature_t crypto_error_t) =
  let (entropy_92, _) =
    seq_split_off (entropy_91) (usize 32)
  in
  let nonce_93 =
    nat_from_byte_seq_be (0xunknown) (0) (entropy_92)
  in
  match ecdsa_p256_sha256_sign (payload_90) (
    nat_from_byte_seq_be (0xunknown) (0) (ps_89)) (nonce_93) with
  | Ok (r_94, s_95) -> concat_signature (r_94) (s_95)
  | Err _ -> Err (crypto_error_v)

let sign
  (sa_96 : signature_scheme_t)
  (ps_97 : signature_key_t)
  (payload_98 : byte_seq)
  (ent_99 : entropy_t)
  : (result signature_t crypto_error_t) =
  match sa_96 with
  | EcdsaSecp256r1Sha256_signature_scheme_t -> p256_sign (ps_97) (payload_98) (
    ent_99)
  | ED25519_signature_scheme_t -> Err (unsupported_algorithm_v)
  | RsaPssRsaSha256_signature_scheme_t -> Err (unsupported_algorithm_v)

let p256_verify
  (pk_100 : verification_key_t)
  (payload_101 : byte_seq)
  (sig_102 : byte_seq)
  : empty_result_t =
  let (pk_x_103, pk_y_104) =
    (
      nat_from_byte_seq_be (0xunknown) (0) (
        seq_slice (pk_100) (usize 0) (usize 32)),
      nat_from_byte_seq_be (0xunknown) (0) (
        seq_slice (pk_100) (usize 32) (usize 32))
    )
  in
  let (r_105, s_106) =
    (
      nat_from_byte_seq_be (0xunknown) (0) (
        seq_slice (sig_102) (usize 0) (usize 32)),
      nat_from_byte_seq_be (0xunknown) (0) (
        seq_slice (sig_102) (usize 32) (usize 32))
    )
  in
  match ecdsa_p256_sha256_verify (payload_101) ((pk_x_103, pk_y_104)) (
    (r_105, s_106)) with
  | Ok () -> Ok (())
  | Err _ -> Err (verify_failed_v)

let verify
  (sa_107 : signature_scheme_t)
  (pk_108 : verification_key_t)
  (payload_109 : byte_seq)
  (sig_110 : byte_seq)
  : empty_result_t =
  match sa_107 with
  | EcdsaSecp256r1Sha256_signature_scheme_t -> p256_verify (pk_108) (
    payload_109) (sig_110)
  | ED25519_signature_scheme_t -> Err (unsupported_algorithm_v)
  | RsaPssRsaSha256_signature_scheme_t -> Err (unsupported_algorithm_v)

let hkdf_extract
  (ha_111 : hash_algorithm_t)
  (k_112 : key_t)
  (salt_113 : key_t)
  : crypto_byte_seq_result_t =
  match ha_111 with
  | SHA256_hash_algorithm_t -> Ok (seq_from_seq (extract (salt_113) (k_112)))
  | SHA384_hash_algorithm_t -> Err (unsupported_algorithm_v)

let hkdf_expand
  (ha_114 : hash_algorithm_t)
  (k_115 : key_t)
  (info_116 : byte_seq)
  (len_117 : uint_size)
  : crypto_byte_seq_result_t =
  match ha_114 with
  | SHA256_hash_algorithm_t -> match expand (k_115) (info_116) (len_117) with
  | Ok b_118 -> Ok (b_118)
  | Err _ -> Err (hkdf_error_v)
  | SHA384_hash_algorithm_t -> Err (unsupported_algorithm_v)

let aes128_encrypt
  (k_119 : aead_key_t)
  (iv_120 : aead_iv_t)
  (payload_121 : byte_seq)
  (ad_122 : byte_seq)
  : crypto_byte_seq_result_t =
  let (ctxt_123, tag_124) =
    encrypt_aes128 (array_from_seq (0) (k_119)) (array_from_seq (0) (iv_120)) (
      ad_122) (payload_121)
  in
  Ok (seq_concat (ctxt_123) (tag_124))

let chacha_encrypt
  (k_125 : aead_key_t)
  (iv_126 : aead_iv_t)
  (payload_127 : byte_seq)
  (ad_128 : byte_seq)
  : crypto_byte_seq_result_t =
  let (ctxt_129, tag_130) =
    chacha20_poly1305_encrypt (array_from_seq (32) (k_125)) (
      array_from_seq (12) (iv_126)) (ad_128) (payload_127)
  in
  Ok (seq_concat (ctxt_129) (tag_130))

let aead_encrypt
  (a_131 : aead_algorithm_t)
  (k_132 : aead_key_t)
  (iv_133 : aead_iv_t)
  (payload_134 : byte_seq)
  (ad_135 : byte_seq)
  : crypto_byte_seq_result_t =
  match a_131 with
  | Aes128Gcm_aead_algorithm_t -> aes128_encrypt (k_132) (iv_133) (
    payload_134) (ad_135)
  | Aes256Gcm_aead_algorithm_t -> Err (unsupported_algorithm_v)
  | Chacha20Poly1305_aead_algorithm_t -> chacha_encrypt (k_132) (iv_133) (
    payload_134) (ad_135)

let aes128_decrypt
  (k_136 : aead_key_t)
  (iv_137 : aead_iv_t)
  (ciphertext_138 : byte_seq)
  (ad_139 : byte_seq)
  : crypto_byte_seq_result_t =
  match decrypt_aes128 (array_from_seq (0) (k_136)) (
    array_from_seq (0) (iv_137)) (ad_139) (
    seq_slice_range (ciphertext_138) (
      (usize 0, (seq_len (ciphertext_138)) - (usize 16)))) (
    array_from_seq (0) (
      seq_slice_range (ciphertext_138) (
        ((seq_len (ciphertext_138)) - (usize 16), seq_len (ciphertext_138)
        )))) with
  | Ok m_140 -> Ok (m_140)
  | Err _ -> Err (mac_failed_v)

let chacha_decrypt
  (k_141 : aead_key_t)
  (iv_142 : aead_iv_t)
  (ciphertext_143 : byte_seq)
  (ad_144 : byte_seq)
  : crypto_byte_seq_result_t =
  match chacha20_poly1305_decrypt (array_from_seq (32) (k_141)) (
    array_from_seq (12) (iv_142)) (ad_144) (
    seq_slice_range (ciphertext_143) (
      (usize 0, (seq_len (ciphertext_143)) - (usize 16)))) (
    array_from_seq (16) (
      seq_slice_range (ciphertext_143) (
        ((seq_len (ciphertext_143)) - (usize 16), seq_len (ciphertext_143)
        )))) with
  | Ok ptxt_145 -> Ok (ptxt_145)
  | Err _ -> Err (mac_failed_v)

let aead_decrypt
  (a_146 : aead_algorithm_t)
  (k_147 : aead_key_t)
  (iv_148 : aead_iv_t)
  (ciphertext_149 : byte_seq)
  (ad_150 : byte_seq)
  : crypto_byte_seq_result_t =
  match a_146 with
  | Aes128Gcm_aead_algorithm_t -> aes128_decrypt (k_147) (iv_148) (
    ciphertext_149) (ad_150)
  | Aes256Gcm_aead_algorithm_t -> Err (unsupported_algorithm_v)
  | Chacha20Poly1305_aead_algorithm_t -> chacha_decrypt (k_147) (iv_148) (
    ciphertext_149) (ad_150)


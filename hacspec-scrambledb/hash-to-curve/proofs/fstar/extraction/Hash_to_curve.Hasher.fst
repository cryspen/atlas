module Hash_to_curve.Hasher
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

class t_HashAlgorithm (v_Self: Type) = {
  b_IN_BYTES:usize;
  s_IN_BYTES:usize;
  hash:slice u8 -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

type t_SHA256 = | SHA256 : t_SHA256

let impl: t_HashAlgorithm t_SHA256 =
  {
    b_IN_BYTES = (fun  -> Libcrux.Digest.digest_size Libcrux.Digest.Algorithm_Sha256);
    s_IN_BYTES = (fun  -> 64sz);
    hash = fun (payload: slice u8) -> Libcrux.Digest.hash Libcrux.Digest.Algorithm_Sha256 payload
  }
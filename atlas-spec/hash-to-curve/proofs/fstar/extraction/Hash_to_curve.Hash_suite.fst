module Hash_to_curve.Hash_suite
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

class t_HashToCurve (v_Self: Type) = {
  iD:string;
  k:usize;
  l:usize;
  outputCurve:Type;
  outputCurve_implements_t_Sized:Core.Marker.t_Sized _;
  baseField:Type;
  baseField_implements_t_Sized:Core.Marker.t_Sized _;
  hash_to_curve:slice u8 -> slice u8 -> Core.Result.t_Result _ Hash_to_curve.t_Error
}
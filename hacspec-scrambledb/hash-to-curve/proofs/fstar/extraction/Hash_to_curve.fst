module Hash_to_curve
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

type t_Error =
  | Error_InvalidEll : t_Error
  | Error_InvalidAddition : t_Error
  | Error_PointAtInfinity : t_Error
  | Error_UnsupportedCiphersuite : t_Error
  | Error_CurveError : t_Error

let impl: Core.Convert.t_From t_Error P256.t_Error =
  { from = fun (v__value: P256.t_Error) -> Error_CurveError }
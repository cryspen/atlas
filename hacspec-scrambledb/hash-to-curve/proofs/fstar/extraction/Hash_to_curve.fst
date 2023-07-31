module Hash_to_curve
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

type t_Error = | Error_InvalidEll : t_Error
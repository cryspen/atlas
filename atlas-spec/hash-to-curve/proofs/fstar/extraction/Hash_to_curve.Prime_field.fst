module Hash_to_curve.Prime_field
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

class t_PrimeField (v_Self: Type) = {
  is_square:self -> bool;
  sqrt:self -> self;
  sgn0:self -> bool;
  hash_to_field_prime_order:usize -> usize -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
    -> Alloc.Vec.t_Vec self Alloc.Alloc.t_Global
}
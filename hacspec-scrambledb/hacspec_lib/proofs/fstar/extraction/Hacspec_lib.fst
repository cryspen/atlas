module Hacspec_lib
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

class t_FunctionalVec (v_Self: Type) = {
  concat:self -> slice u8 -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  concat_byte:self -> u8 -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

let impl: t_FunctionalVec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
  {
    concat
    =
    (fun (self: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (other: slice u8) ->
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Core.Clone.Clone.clone self in
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.extend_from_slice_under_impl_2 out other
        in
        out);
    concat_byte
    =
    fun (self: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (other: u8) ->
      let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Core.Clone.Clone.clone self in
      let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.push_under_impl_1 out other in
      out
  }

let impl: t_FunctionalVec (slice u8) =
  {
    concat
    =
    (fun (self: slice u8) (other: slice u8) ->
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Slice.to_vec_under_impl self in
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.extend_from_slice_under_impl_2 out other
        in
        out);
    concat_byte
    =
    fun (self: slice u8) (other: u8) ->
      let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Slice.to_vec_under_impl self in
      let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.push_under_impl_1 out other in
      out
  }

class t_Conversions (v_Self: Type) = { to_le_bytes:self -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global }

let impl (#len: usize) : t_Conversions (array u64 v_LEN) =
  {
    to_le_bytes
    =
    fun (#len: usize) (self: array u64 v_LEN) ->
      let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Alloc.Vec.with_capacity_under_impl (v_LEN *. 8sz <: usize)
      in
      let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Core.Iter.Traits.Iterator.Iterator.fold (Core.Iter.Traits.Collect.IntoIterator.into_iter self

            <:
            _)
          out
          (fun out item ->
              Alloc.Vec.extend_from_slice_under_impl_2 out
                (Rust_primitives.unsize (Core.Num.to_le_bytes_under_impl_9 item <: array u8 8sz)
                  <:
                  slice u8)
              <:
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      in
      out
  }
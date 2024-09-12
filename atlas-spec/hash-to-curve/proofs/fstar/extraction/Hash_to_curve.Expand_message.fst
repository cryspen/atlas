module Hash_to_curve.Expand_message
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

let expand_message_xof
      (msg dst: slice u8)
      (len_in_bytes v_B_IN_BYTES v_S_IN_BYTES: usize)
      (hash: (slice u8 -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Rust_primitives.Hax.never_to_any (Core.Panicking.panic "not implemented"
      <:
      Rust_primitives.Hax.t_Never)

let expand_message_xmd
      (#h: Type)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] __0: Core.Marker.t_Sized h)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] __1: Hash_to_curve.Hasher.t_HashAlgorithm h)
      (msg dst: slice u8)
      (len_in_bytes: usize)
    : Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Hash_to_curve.t_Error =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let ell:usize =
        ((len_in_bytes +. Hash_to_curve.Hasher.HashAlgorithm.v_B_IN_BYTES <: usize) -. 1sz <: usize) /.
        Hash_to_curve.Hasher.HashAlgorithm.v_B_IN_BYTES
      in
      let* _:Prims.unit =
        if
          Prims.op_BarBar (Prims.op_BarBar (ell >. 255sz) (len_in_bytes >. 65535sz))
            ((Core.Slice.len_under_impl dst <: usize) >. 255sz)
        then
          let* hoist1:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Result.Result_Err
                Hash_to_curve.Error_InvalidEll)
          in
          Core.Ops.Control_flow.ControlFlow_Continue
          (let ():Prims.unit = Rust_primitives.Hax.never_to_any hoist1 in
            ())
        else Core.Ops.Control_flow.ControlFlow_Continue ()
      in
      Core.Ops.Control_flow.ControlFlow_Continue
      (let dst_prime:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hash_to_curve.Hacspec_helper.FunctionalVec.concat_byte dst
            (cast (Core.Slice.len_under_impl dst <: usize))
        in
        let z_pad:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.from_elem 0uy Hash_to_curve.Hasher.HashAlgorithm.v_S_IN_BYTES
        in
        let l_i_b_str:array u8 2sz = Core.Num.to_be_bytes_under_impl_7 (cast len_in_bytes) in
        let msg_prime:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hash_to_curve.Hacspec_helper.FunctionalVec.concat (Hash_to_curve.Hacspec_helper.FunctionalVec.concat
                (Hash_to_curve.Hacspec_helper.FunctionalVec.concat (Hash_to_curve.Hacspec_helper.FunctionalVec.concat
                        z_pad
                        msg
                      <:
                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    (Rust_primitives.unsize l_i_b_str <: slice u8)
                  <:
                  Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                (Rust_primitives.unsize (Rust_primitives.Hax.repeat 0uy 1sz <: array u8 1sz)
                  <:
                  slice u8)
              <:
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            (Core.Ops.Deref.Deref.deref dst_prime <: slice u8)
        in
        let b_0_:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hash_to_curve.Hasher.HashAlgorithm.hash (Core.Ops.Deref.Deref.deref msg_prime <: slice u8)
        in
        let payload_1_:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hash_to_curve.Hacspec_helper.FunctionalVec.concat (Hash_to_curve.Hacspec_helper.FunctionalVec.concat_byte
                b_0_
                1uy
              <:
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            (Core.Ops.Deref.Deref.deref dst_prime <: slice u8)
        in
        let b_i:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hash_to_curve.Hasher.HashAlgorithm.hash (Core.Ops.Deref.Deref.deref payload_1_ <: slice u8
            )
        in
        let uniform_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Core.Clone.Clone.clone b_i in
        let b_i, uniform_bytes:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
          Core.Iter.Traits.Iterator.Iterator.fold (Core.Iter.Traits.Collect.IntoIterator.into_iter (Core.Ops.Range.new_under_impl_7
                    2sz
                    ell
                  <:
                  Core.Ops.Range.t_RangeInclusive usize)
              <:
              _)
            (b_i, uniform_bytes)
            (fun (b_i, uniform_bytes) i ->
                let payload_i:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                  Hash_to_curve.Hacspec_helper.FunctionalVec.concat (Hash_to_curve.Hacspec_helper.FunctionalVec.concat_byte
                        (strxor (Core.Ops.Deref.Deref.deref b_0_ <: slice u8)
                            (Core.Ops.Deref.Deref.deref b_i <: slice u8)
                          <:
                          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                        (cast i)
                      <:
                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    (Core.Ops.Deref.Deref.deref dst_prime <: slice u8)
                in
                let b_i:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                  Hash_to_curve.Hasher.HashAlgorithm.hash (Core.Ops.Deref.Deref.deref payload_i
                      <:
                      slice u8)
                in
                let uniform_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                  Alloc.Vec.extend_from_slice_under_impl_2 uniform_bytes
                    (Core.Ops.Deref.Deref.deref b_i <: slice u8)
                in
                b_i, uniform_bytes)
        in
        let uniform_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.truncate_under_impl_1 uniform_bytes len_in_bytes
        in
        Core.Result.Result_Ok uniform_bytes))

let strxor (a b: slice u8) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let _:Prims.unit =
    match Core.Slice.len_under_impl a, Core.Slice.len_under_impl b with
    | left_val, right_val ->
      if ~.(left_val =. right_val <: bool)
      then
        let kind:Core.Panicking.t_AssertKind = Core.Panicking.AssertKind_Eq in
        let ():Prims.unit =
          Rust_primitives.Hax.never_to_any (Core.Panicking.assert_failed kind
                left_val
                right_val
                Core.Option.Option_None
              <:
              Rust_primitives.Hax.t_Never)
        in
        ()
  in
  Core.Iter.Traits.Iterator.Iterator.collect (Core.Iter.Traits.Iterator.Iterator.map (Core.Iter.Traits.Iterator.Iterator.zip
            (Core.Slice.iter_under_impl a <: Core.Slice.Iter.t_Iter u8)
            (Core.Slice.iter_under_impl b <: Core.Slice.Iter.t_Iter u8)
          <:
          Core.Iter.Adapters.Zip.t_Zip (Core.Slice.Iter.t_Iter u8) _)
        (fun (a, b) -> a ^. b <: _)
      <:
      Core.Iter.Adapters.Map.t_Map
        (Core.Iter.Adapters.Zip.t_Zip (Core.Slice.Iter.t_Iter u8) (Core.Slice.Iter.t_Iter u8))
        ((u8 & u8) -> u8))
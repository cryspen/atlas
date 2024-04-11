module Hash_to_curve.P256_hash
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

type t_P256_XMD_SHA256_SSWU_RO = | P256_XMD_SHA256_SSWU_RO : t_P256_XMD_SHA256_SSWU_RO

let v_L: usize = 48sz

let v_B_IN_BYTES: usize = Libcrux.Digest.digest_size Libcrux.Digest.Algorithm_Sha256

let v_S_IN_BYTES: usize = 64sz

let expand_message (msg dst: slice u8) (len_in_bytes: usize)
    : Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Hash_to_curve.t_Error =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let ell:usize =
        ((len_in_bytes +. v_B_IN_BYTES <: usize) -. 1sz <: usize) /. v_B_IN_BYTES
      in
      let* _:Prims.unit =
        if
          Prims.op_BarBar (Prims.op_BarBar (ell >. 255sz)
                (len_in_bytes >. (Core.Convert.Into.into Core.Num.v_MAX_under_impl_7 <: usize)))
            ((Core.Slice.len_under_impl dst <: usize) >. 255sz)
        then
          let* hoist1:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Result.Result_Err
                Hash_to_curve.Error_InvalidEll)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist1)
        else Core.Ops.Control_flow.ControlFlow_Continue ()
      in
      Core.Ops.Control_flow.ControlFlow_Continue
      (let dst_prime:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hacspec_lib.FunctionalVec.concat_byte dst (cast (Core.Slice.len_under_impl dst <: usize))
        in
        let z_pad:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.from_elem 0uy v_S_IN_BYTES in
        let l_i_b_str:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hacspec_lib.i2osp len_in_bytes 2sz
        in
        let msg_prime:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hacspec_lib.FunctionalVec.concat (Hacspec_lib.FunctionalVec.concat (Hacspec_lib.FunctionalVec.concat
                    (Hacspec_lib.FunctionalVec.concat z_pad msg
                      <:
                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    (Core.Ops.Deref.Deref.deref l_i_b_str <: slice u8)
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
          Libcrux.Digest.hash Libcrux.Digest.Algorithm_Sha256
            (Core.Ops.Deref.Deref.deref msg_prime <: slice u8)
        in
        let payload_1_:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Hacspec_lib.FunctionalVec.concat (Hacspec_lib.FunctionalVec.concat_byte b_0_ 1uy
              <:
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            (Core.Ops.Deref.Deref.deref dst_prime <: slice u8)
        in
        let b_i:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Libcrux.Digest.hash Libcrux.Digest.Algorithm_Sha256
            (Core.Ops.Deref.Deref.deref payload_1_ <: slice u8)
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
                  Hacspec_lib.FunctionalVec.concat (Hacspec_lib.FunctionalVec.concat_byte (strxor (Core.Ops.Deref.Deref.deref
                                b_0_
                              <:
                              slice u8)
                            (Core.Ops.Deref.Deref.deref b_i <: slice u8)
                          <:
                          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                        (cast i)
                      <:
                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    (Core.Ops.Deref.Deref.deref dst_prime <: slice u8)
                in
                let b_i:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                  Libcrux.Digest.hash Libcrux.Digest.Algorithm_Sha256
                    (Core.Ops.Deref.Deref.deref payload_i <: slice u8)
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
        Rust_primitives.Hax.never_to_any (Core.Panicking.assert_failed kind
              left_val
              right_val
              Core.Option.Option_None
            <:
            Rust_primitives.Hax.t_Never)
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

let hash_to_field (msg dst: slice u8) (count: usize)
    : Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
      Hash_to_curve.t_Error =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let len_in_bytes:usize = count *. v_L in
      let* uniform_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        match
          Core.Ops.Try_trait.Try.branch (expand_message msg dst len_in_bytes
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Hash_to_curve.t_Error)
        with
        | Core.Ops.Control_flow.ControlFlow_Break residual ->
          let* hoist2:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                  residual
                <:
                Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
                  Hash_to_curve.t_Error)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist2)
        | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
          Core.Ops.Control_flow.ControlFlow_Continue v_val
      in
      Core.Ops.Control_flow.ControlFlow_Continue
      (let u:Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global =
          Alloc.Vec.with_capacity_under_impl count
        in
        let u:Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global =
          Core.Iter.Traits.Iterator.Iterator.fold (Core.Iter.Traits.Collect.IntoIterator.into_iter ({
                    Core.Ops.Range.Range.f_start = 0sz;
                    Core.Ops.Range.Range.f_end = count
                  })
              <:
              _)
            u
            (fun u i ->
                let elm_offset:usize = v_L *. i in
                let tv:slice u8 =
                  uniform_bytes.[ {
                      Core.Ops.Range.Range.f_start = elm_offset;
                      Core.Ops.Range.Range.f_end = v_L *. (i +. 1sz <: usize) <: usize
                    } ]
                in
                let tv:P256.t_P256FieldElement = P256.Hacspec_helper.NatMod.from_be_bytes tv in
                let u:Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global =
                  Alloc.Vec.push_under_impl_1 u tv
                in
                u)
        in
        Core.Result.Result_Ok u))

let hash_to_scalar (msg dst: slice u8) (count: usize)
    : Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256Scalar Alloc.Alloc.t_Global)
      Hash_to_curve.t_Error =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let len_in_bytes:usize = count *. v_L in
      let* uniform_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        match
          Core.Ops.Try_trait.Try.branch (expand_message msg dst len_in_bytes
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Hash_to_curve.t_Error)
        with
        | Core.Ops.Control_flow.ControlFlow_Break residual ->
          let* hoist3:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                  residual
                <:
                Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256Scalar Alloc.Alloc.t_Global)
                  Hash_to_curve.t_Error)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist3)
        | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
          Core.Ops.Control_flow.ControlFlow_Continue v_val
      in
      Core.Ops.Control_flow.ControlFlow_Continue
      (let u:Alloc.Vec.t_Vec P256.t_P256Scalar Alloc.Alloc.t_Global =
          Alloc.Vec.with_capacity_under_impl count
        in
        let u:Alloc.Vec.t_Vec P256.t_P256Scalar Alloc.Alloc.t_Global =
          Core.Iter.Traits.Iterator.Iterator.fold (Core.Iter.Traits.Collect.IntoIterator.into_iter ({
                    Core.Ops.Range.Range.f_start = 0sz;
                    Core.Ops.Range.Range.f_end = count
                  })
              <:
              _)
            u
            (fun u i ->
                let elm_offset:usize = v_L *. i in
                let tv:slice u8 =
                  uniform_bytes.[ {
                      Core.Ops.Range.Range.f_start = elm_offset;
                      Core.Ops.Range.Range.f_end = v_L *. (i +. 1sz <: usize) <: usize
                    } ]
                in
                let tv:P256.t_P256Scalar = P256.Hacspec_helper.NatMod.from_be_bytes tv in
                let u:Alloc.Vec.t_Vec P256.t_P256Scalar Alloc.Alloc.t_Global =
                  Alloc.Vec.push_under_impl_1 u tv
                in
                u)
        in
        Core.Result.Result_Ok u))

let sswu (u a b z: P256.t_P256FieldElement) : (P256.t_P256FieldElement & P256.t_P256FieldElement) =
  let tv1:P256.t_P256FieldElement =
    P256.Hacspec_helper.NatMod.inv0 (((P256.Hacspec_helper.NatMod.pow z (pub_u128 2sz)
            <:
            P256.t_P256FieldElement) *.
          (P256.Hacspec_helper.NatMod.pow u (pub_u128 4sz) <: P256.t_P256FieldElement)
          <:
          _) +.
        (z *. (P256.Hacspec_helper.NatMod.pow u (pub_u128 2sz) <: P256.t_P256FieldElement) <: _)
        <:
        _)
  in
  let x1:P256.t_P256FieldElement =
    if tv1 =. (P256.Hacspec_helper.NatMod.zero <: P256.t_P256FieldElement)
    then b *. (P256.Hacspec_helper.NatMod.inv (z *. a <: _) <: P256.t_P256FieldElement)
    else
      ((P256.Hacspec_helper.NatMod.neg b <: P256.t_P256FieldElement) *.
        (P256.Hacspec_helper.NatMod.inv a <: P256.t_P256FieldElement)
        <:
        _) *.
      (tv1 +. (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 1sz) <: P256.t_P256FieldElement) <: _)
  in
  let gx1 =
    ((P256.Hacspec_helper.NatMod.pow x1 (pub_u128 3sz) <: P256.t_P256FieldElement) +. (a *. x1 <: _)
      <:
      _) +.
    b
  in
  let x2 =
    (z *. (P256.Hacspec_helper.NatMod.pow u (pub_u128 2sz) <: P256.t_P256FieldElement) <: _) *. x1
  in
  let gx2 =
    ((P256.Hacspec_helper.NatMod.pow x2 (pub_u128 3sz) <: P256.t_P256FieldElement) +. (a *. x2 <: _)
      <:
      _) +.
    b
  in
  let output:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
    if P256.is_square gx1 then x1, P256.sqrt gx1 else x2, P256.sqrt gx2
  in
  let output:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
    if (P256.sgn0 u <: bool) <>. (P256.sgn0 output._2 <: bool)
    then
      let output:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
        { output with _2 = P256.Hacspec_helper.NatMod.neg output._2 }
      in
      output
    else output
  in
  output

let map_to_curve (u: P256.t_P256FieldElement) : P256.t_P256Point =
  Core.Convert.Into.into (sswu u
        (P256.Hacspec_helper.NatMod.neg (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 3sz)
              <:
              P256.t_P256FieldElement)
          <:
          P256.t_P256FieldElement)
        (P256.Hacspec_helper.NatMod.from_hex "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"

          <:
          P256.t_P256FieldElement)
        (P256.Hacspec_helper.NatMod.neg (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 10sz)
              <:
              P256.t_P256FieldElement)
          <:
          P256.t_P256FieldElement)
      <:
      (P256.t_P256FieldElement & P256.t_P256FieldElement))

let hash_to_curve (msg dst: slice u8) : Core.Result.t_Result P256.t_P256Point Hash_to_curve.t_Error =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let*
      (u: Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
        P256.t_P256FieldElement Alloc.Alloc.t_Global =
        match
          Core.Ops.Try_trait.Try.branch (hash_to_field msg dst 2sz
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
                Hash_to_curve.t_Error)
        with
        | Core.Ops.Control_flow.ControlFlow_Break residual ->
          let* hoist4:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                  residual
                <:
                Core.Result.t_Result P256.t_P256Point Hash_to_curve.t_Error)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist4)
        | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
          Core.Ops.Control_flow.ControlFlow_Continue v_val
      in
      let q0:P256.t_P256Point = map_to_curve (u.[ 0sz ] <: P256.t_P256FieldElement) in
      let q1:P256.t_P256Point = map_to_curve (u.[ 1sz ] <: P256.t_P256FieldElement) in
      let* r:P256.t_P256Point =
        match
          Core.Ops.Try_trait.Try.branch (P256.point_add q0 q1
              <:
              Core.Result.t_Result P256.t_P256Point P256.t_Error)
        with
        | Core.Ops.Control_flow.ControlFlow_Break residual ->
          let* hoist5:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                  residual
                <:
                Core.Result.t_Result P256.t_P256Point Hash_to_curve.t_Error)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist5)
        | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
          Core.Ops.Control_flow.ControlFlow_Continue v_val
      in
      Core.Ops.Control_flow.ControlFlow_Continue (Core.Result.Result_Ok r))
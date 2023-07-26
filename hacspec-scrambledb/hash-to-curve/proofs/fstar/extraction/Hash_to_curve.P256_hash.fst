module Hash_to_curve.P256_hash
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

type t_P256_XMD_SHA256_SSWU_RO = | P256_XMD_SHA256_SSWU_RO : t_P256_XMD_SHA256_SSWU_RO

let hash_to_field_under_impl (msg dst: slice u8) (count: usize)
    : Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
      Hash_to_curve.t_Error =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let len_in_bytes:usize =
        count *. Hash_to_curve.Hash_suite.HashToCurve.v_L
      in
      let* uniform_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        match
          Core.Ops.Try_trait.Try.branch (Hash_to_curve.Expand_message.expand_message_xmd msg
                dst
                len_in_bytes
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
      (Core.Result.Result_Ok
        (Hash_to_curve.Prime_field.PrimeField.hash_to_field_prime_order count
            Hash_to_curve.Hash_suite.HashToCurve.v_L
            uniform_bytes)))

let impl: Hash_to_curve.Hash_suite.t_HashToCurve t_P256_XMD_SHA256_SSWU_RO =
  {
    iD = (fun  -> "P256_XMD:SHA-256_SSWU_RO_");
    k = (fun  -> 128sz);
    l = (fun  -> 48sz);
    baseField = P256.t_P256FieldElement;
    outputCurve = (P256.t_P256FieldElement & P256.t_P256FieldElement);
    hash_to_curve
    =
    fun (msg: slice u8) (dst: slice u8) ->
      Rust_primitives.Hax.Control_flow_monad.Mexception.run (let* u:Alloc.Vec.t_Vec
            P256.t_P256FieldElement Alloc.Alloc.t_Global =
            match
              Core.Ops.Try_trait.Try.branch (hash_to_field_under_impl msg dst 2sz
                  <:
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
                    Hash_to_curve.t_Error)
            with
            | Core.Ops.Control_flow.ControlFlow_Break residual ->
              let* hoist3:Rust_primitives.Hax.t_Never =
                Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                      residual
                    <:
                    Core.Result.t_Result (P256.t_P256FieldElement & P256.t_P256FieldElement)
                      Hash_to_curve.t_Error)
              in
              Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist3)
            | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
              Core.Ops.Control_flow.ControlFlow_Continue v_val
          in
          Core.Ops.Control_flow.ControlFlow_Continue
          (let q0:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
              Hash_to_curve.P256_hash.PrimeCurveWeierstrass.map_to_curve (u.[ 0sz ]
                  <:
                  P256.t_P256FieldElement)
            in
            let q1:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
              Hash_to_curve.P256_hash.PrimeCurveWeierstrass.map_to_curve (u.[ 1sz ]
                  <:
                  P256.t_P256FieldElement)
            in
            let r:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
              Core.Result.unwrap_under_impl (P256.point_add q0 q1
                  <:
                  Core.Result.t_Result (P256.t_P256FieldElement & P256.t_P256FieldElement)
                    P256.t_Error)
            in
            Core.Result.Result_Ok (Hash_to_curve.P256_hash.PrimeCurveWeierstrass.clear_cofactor r)))
  }

type t_P256_XMD_SHA256_SSWU_NU = | P256_XMD_SHA256_SSWU_NU : t_P256_XMD_SHA256_SSWU_NU

let hash_to_field_under_impl_2 (msg dst: slice u8) (count: usize)
    : Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
      Hash_to_curve.t_Error =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let len_in_bytes:usize =
        count *. Hash_to_curve.Hash_suite.HashToCurve.v_L
      in
      let* uniform_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        match
          Core.Ops.Try_trait.Try.branch (Hash_to_curve.Expand_message.expand_message_xmd msg
                dst
                len_in_bytes
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Hash_to_curve.t_Error)
        with
        | Core.Ops.Control_flow.ControlFlow_Break residual ->
          let* hoist4:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                  residual
                <:
                Core.Result.t_Result (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
                  Hash_to_curve.t_Error)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist4)
        | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
          Core.Ops.Control_flow.ControlFlow_Continue v_val
      in
      Core.Ops.Control_flow.ControlFlow_Continue
      (Core.Result.Result_Ok
        (Hash_to_curve.Prime_field.PrimeField.hash_to_field_prime_order count
            Hash_to_curve.Hash_suite.HashToCurve.v_L
            uniform_bytes)))

let impl: Hash_to_curve.Hash_suite.t_HashToCurve t_P256_XMD_SHA256_SSWU_NU =
  {
    iD = (fun  -> "P256_XMD:SHA-256_SSWU_NU_");
    k = (fun  -> 128sz);
    l = (fun  -> 48sz);
    baseField = P256.t_P256FieldElement;
    outputCurve = (P256.t_P256FieldElement & P256.t_P256FieldElement);
    hash_to_curve
    =
    fun (msg: slice u8) (dst: slice u8) ->
      Rust_primitives.Hax.Control_flow_monad.Mexception.run (let* u:Alloc.Vec.t_Vec
            P256.t_P256FieldElement Alloc.Alloc.t_Global =
            match
              Core.Ops.Try_trait.Try.branch (hash_to_field_under_impl_2 msg dst 1sz
                  <:
                  Core.Result.t_Result
                    (Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global)
                    Hash_to_curve.t_Error)
            with
            | Core.Ops.Control_flow.ControlFlow_Break residual ->
              let* hoist5:Rust_primitives.Hax.t_Never =
                Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                      residual
                    <:
                    Core.Result.t_Result (P256.t_P256FieldElement & P256.t_P256FieldElement)
                      Hash_to_curve.t_Error)
              in
              Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist5)
            | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
              Core.Ops.Control_flow.ControlFlow_Continue v_val
          in
          Core.Ops.Control_flow.ControlFlow_Continue
          (let q:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
              Hash_to_curve.P256_hash.PrimeCurveWeierstrass.map_to_curve (u.[ 0sz ]
                  <:
                  P256.t_P256FieldElement)
            in
            Core.Result.Result_Ok (Hash_to_curve.P256_hash.PrimeCurveWeierstrass.clear_cofactor q)))
  }

let impl: Hash_to_curve.Prime_field.t_PrimeField P256.t_P256FieldElement =
  {
    is_square
    =
    (fun (self: P256.t_P256FieldElement) ->
        let exp =
          (P256.Hacspec_helper.NatMod.neg (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 1sz)
                <:
                P256.t_P256FieldElement)
            <:
            P256.t_P256FieldElement) *.
          (P256.Hacspec_helper.NatMod.inv (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 2sz)
                <:
                P256.t_P256FieldElement)
            <:
            P256.t_P256FieldElement)
        in
        let test:P256.t_P256FieldElement = P256.Hacspec_helper.NatMod.pow_felem self exp in
        Prims.op_BarBar (test =. (P256.Hacspec_helper.NatMod.zero <: P256.t_P256FieldElement))
          (test =. (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 1sz) <: P256.t_P256FieldElement))
    );
    sqrt
    =
    (fun (self: P256.t_P256FieldElement) ->
        let c1 =
          (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 1sz) <: P256.t_P256FieldElement) *.
          (P256.Hacspec_helper.NatMod.inv (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 4sz)
                <:
                P256.t_P256FieldElement)
            <:
            P256.t_P256FieldElement)
        in
        P256.Hacspec_helper.NatMod.pow_felem self c1);
    sgn0
    =
    (fun (self: P256.t_P256FieldElement) -> P256.Hacspec_helper.NatMod.bit self (pub_u128 0sz));
    hash_to_field_prime_order
    =
    fun (count: usize) (l: usize) (uniform_bytes: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) ->
      let u:Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global =
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
              let elm_offset:usize = l *. i in
              let tv:slice u8 =
                uniform_bytes.[ {
                    Core.Ops.Range.Range.f_start = elm_offset;
                    Core.Ops.Range.Range.f_end = l *. (i +. 1sz <: usize) <: usize
                  } ]
              in
              let tv:P256.t_P256FieldElement = P256.Hacspec_helper.NatMod.from_be_bytes tv in
              let u:Alloc.Vec.t_Vec P256.t_P256FieldElement Alloc.Alloc.t_Global =
                Alloc.Vec.push_under_impl_1 u tv
              in
              u)
      in
      u
  }

class t_PrimeCurveWeierstrass (v_Self: Type) = {
  baseField:Type;
  baseField_implements_t_PrimeField:Hash_to_curve.Prime_field.t_PrimeField _;
  baseField_implements_t_Sized:Core.Marker.t_Sized _;
  map_to_curve:_ -> self;
  clear_cofactor:self -> self;
  weierstrass_a:_;
  weierstrass_b:_;
  sswu_z:_
}

let impl: t_PrimeCurveWeierstrass (P256.t_P256FieldElement & P256.t_P256FieldElement) =
  {
    baseField = P256.t_P256FieldElement;
    weierstrass_a
    =
    (fun  ->
        P256.Hacspec_helper.NatMod.neg (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 3sz)
            <:
            P256.t_P256FieldElement));
    weierstrass_b
    =
    (fun  ->
        P256.Hacspec_helper.NatMod.from_hex "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
        );
    sswu_z
    =
    (fun  ->
        P256.Hacspec_helper.NatMod.neg (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 10sz)
            <:
            P256.t_P256FieldElement));
    map_to_curve
    =
    (fun (u: P256.t_P256FieldElement) ->
        let a = Hash_to_curve.P256_hash.PrimeCurveWeierstrass.weierstrass_a in
        let b = Hash_to_curve.P256_hash.PrimeCurveWeierstrass.weierstrass_b in
        let z = Hash_to_curve.P256_hash.PrimeCurveWeierstrass.sswu_z in
        let tv1:P256.t_P256FieldElement =
          P256.Hacspec_helper.NatMod.inv0 (((P256.Hacspec_helper.NatMod.pow z (pub_u128 2sz)
                  <:
                  P256.t_P256FieldElement) *.
                (P256.Hacspec_helper.NatMod.pow u (pub_u128 4sz) <: P256.t_P256FieldElement)
                <:
                _) +.
              (z *. (P256.Hacspec_helper.NatMod.pow u (pub_u128 2sz) <: P256.t_P256FieldElement)
                <:
                _)
              <:
              _)
        in
        let x1 =
          if tv1 =. (P256.Hacspec_helper.NatMod.zero <: P256.t_P256FieldElement)
          then b *. (P256.Hacspec_helper.NatMod.inv (z *. a <: _) <: P256.t_P256FieldElement)
          else
            ((P256.Hacspec_helper.NatMod.neg b <: P256.t_P256FieldElement) *.
              (P256.Hacspec_helper.NatMod.inv a <: P256.t_P256FieldElement)
              <:
              _) *.
            (tv1 +. (P256.Hacspec_helper.NatMod.from_u128 (pub_u128 1sz) <: P256.t_P256FieldElement)
              <:
              _)
        in
        let gx1 =
          ((P256.Hacspec_helper.NatMod.pow x1 (pub_u128 3sz) <: P256.t_P256FieldElement) +.
            (a *. x1 <: _)
            <:
            _) +.
          b
        in
        let x2 =
          (z *. (P256.Hacspec_helper.NatMod.pow u (pub_u128 2sz) <: P256.t_P256FieldElement) <: _) *.
          x1
        in
        let gx2 =
          ((P256.Hacspec_helper.NatMod.pow x2 (pub_u128 3sz) <: P256.t_P256FieldElement) +.
            (a *. x2 <: _)
            <:
            _) +.
          b
        in
        let output:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
          if Hash_to_curve.Prime_field.PrimeField.is_square gx1
          then x1, Hash_to_curve.Prime_field.PrimeField.sqrt gx1
          else x2, Hash_to_curve.Prime_field.PrimeField.sqrt gx2
        in
        let output:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
          if
            (Hash_to_curve.Prime_field.PrimeField.sgn0 u <: bool) <>.
            (Hash_to_curve.Prime_field.PrimeField.sgn0 output._2 <: bool)
          then
            let output:(P256.t_P256FieldElement & P256.t_P256FieldElement) =
              { output with _2 = P256.Hacspec_helper.NatMod.neg output._2 }
            in
            output
          else output
        in
        output);
    clear_cofactor = fun (self: (P256.t_P256FieldElement & P256.t_P256FieldElement)) -> self
  }
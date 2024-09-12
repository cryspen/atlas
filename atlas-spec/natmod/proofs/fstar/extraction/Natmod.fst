module Natmod
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core

type t_NatModAttr = {
  f_mod_str:Alloc.String.t_String;
  f_mod_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_int_size:usize
}

let impl: Syn.Parse.t_Parse t_NatModAttr =
  {
    parse
    =
    fun (input: Syn.Parse.t_ParseBuffer) ->
      Rust_primitives.Hax.Control_flow_monad.Mexception.run (let* hoist2:Syn.Lit.t_LitStr =
            match
              Core.Ops.Try_trait.Try.branch (Syn.Parse.parse_under_impl_9 input
                  <:
                  Core.Result.t_Result Syn.Lit.t_LitStr Syn.Error.t_Error)
            with
            | Core.Ops.Control_flow.ControlFlow_Break residual ->
              let* hoist1:Rust_primitives.Hax.t_Never =
                Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                      residual
                    <:
                    Core.Result.t_Result t_NatModAttr Syn.Error.t_Error)
              in
              Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist1)
            | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
              Core.Ops.Control_flow.ControlFlow_Continue v_val
          in
          let mod_str:Alloc.String.t_String = Syn.Lit.value_under_impl hoist2 in
          let mod_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Core.Result.expect_under_impl (Hex.FromHex.from_hex mod_str
                <:
                Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) _)
              "Invalid hex String"
          in
          let* _:Syn.Token.t_Comma =
            match
              Core.Ops.Try_trait.Try.branch (Syn.Parse.parse_under_impl_9 input
                  <:
                  Core.Result.t_Result Syn.Token.t_Comma Syn.Error.t_Error)
            with
            | Core.Ops.Control_flow.ControlFlow_Break residual ->
              let* hoist3:Rust_primitives.Hax.t_Never =
                Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                      residual
                    <:
                    Core.Result.t_Result t_NatModAttr Syn.Error.t_Error)
              in
              Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist3)
            | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
              Core.Ops.Control_flow.ControlFlow_Continue v_val
          in
          let* hoist6:Syn.Lit.t_LitInt =
            match
              Core.Ops.Try_trait.Try.branch (Syn.Parse.parse_under_impl_9 input
                  <:
                  Core.Result.t_Result Syn.Lit.t_LitInt Syn.Error.t_Error)
            with
            | Core.Ops.Control_flow.ControlFlow_Break residual ->
              let* hoist5:Rust_primitives.Hax.t_Never =
                Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                      residual
                    <:
                    Core.Result.t_Result t_NatModAttr Syn.Error.t_Error)
              in
              Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist5)
            | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
              Core.Ops.Control_flow.ControlFlow_Continue v_val
          in
          let hoist7:Core.Result.t_Result usize Syn.Error.t_Error =
            Syn.Lit.base10_parse_under_impl_4 hoist6
          in
          let hoist8:Core.Ops.Control_flow.t_ControlFlow _ _ =
            Core.Ops.Try_trait.Try.branch hoist7
          in
          let* int_size:usize =
            match hoist8 with
            | Core.Ops.Control_flow.ControlFlow_Break residual ->
              let* hoist4:Rust_primitives.Hax.t_Never =
                Core.Ops.Control_flow.ControlFlow.v_Break (Core.Ops.Try_trait.FromResidual.from_residual
                      residual
                    <:
                    Core.Result.t_Result t_NatModAttr Syn.Error.t_Error)
              in
              Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist4)
            | Core.Ops.Control_flow.ControlFlow_Continue v_val ->
              Core.Ops.Control_flow.ControlFlow_Continue v_val
          in
          Core.Ops.Control_flow.ControlFlow_Continue
          (let _:Prims.unit =
              if ~.(Syn.Parse.is_empty_under_impl_9 input <: bool)
              then
                Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.new_v1_under_impl_2
                          (Rust_primitives.unsize (let list = ["Left over tokens in attribute "] in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                                Rust_primitives.Hax.array_of_list list)
                            <:
                            slice string)
                          (Rust_primitives.unsize (let list =
                                  [
                                    Core.Fmt.Rt.new_debug_under_impl_1 input
                                    <:
                                    Core.Fmt.Rt.t_Argument
                                  ]
                                in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                                Rust_primitives.Hax.array_of_list list)
                            <:
                            slice Core.Fmt.Rt.t_Argument)
                        <:
                        Core.Fmt.t_Arguments)
                    <:
                    Rust_primitives.Hax.t_Never)
            in
            Core.Result.Result_Ok
            ({
                Natmod.NatModAttr.f_mod_str = mod_str;
                Natmod.NatModAttr.f_mod_bytes = mod_bytes;
                Natmod.NatModAttr.f_int_size = int_size
              })))
  }

let nat_mod (attr item: Proc_macro.t_TokenStream) : Proc_macro.t_TokenStream =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let* item_ast:Syn.Derive.t_DeriveInput =
        match Syn.parse item with
        | Core.Result.Result_Ok data -> Core.Ops.Control_flow.ControlFlow_Continue data
        | Core.Result.Result_Err err ->
          let* hoist9:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Convert.From.from (Syn.Error.to_compile_error_under_impl
                      err
                    <:
                    Proc_macro2.t_TokenStream)
                <:
                Proc_macro.t_TokenStream)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist9)
      in
      let ident:Proc_macro2.t_Ident =
        Core.Clone.Clone.clone item_ast.Syn.Derive.DeriveInput.f_ident
      in
      let* args:t_NatModAttr =
        match Syn.parse attr with
        | Core.Result.Result_Ok data -> Core.Ops.Control_flow.ControlFlow_Continue data
        | Core.Result.Result_Err err ->
          let* hoist10:Rust_primitives.Hax.t_Never =
            Core.Ops.Control_flow.ControlFlow.v_Break (Core.Convert.From.from (Syn.Error.to_compile_error_under_impl
                      err
                    <:
                    Proc_macro2.t_TokenStream)
                <:
                Proc_macro.t_TokenStream)
          in
          Core.Ops.Control_flow.ControlFlow_Continue (Rust_primitives.Hax.never_to_any hoist10)
      in
      Core.Ops.Control_flow.ControlFlow_Continue
      (let num_bytes:usize = args.Natmod.NatModAttr.f_int_size in
        let modulus:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = args.Natmod.NatModAttr.f_mod_bytes in
        let modulus_string:Alloc.String.t_String = args.Natmod.NatModAttr.f_mod_str in
        let padded_modulus:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.from_elem 0uy
            (num_bytes -. (Alloc.Vec.len_under_impl_1 modulus <: usize) <: usize)
        in
        let padded_modulus:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
          Alloc.Vec.append_under_impl_1 padded_modulus
            (Core.Clone.Clone.clone modulus <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        in
        let mod_iter1:Core.Slice.Iter.t_Iter u8 =
          Core.Slice.iter_under_impl (Core.Ops.Deref.Deref.deref padded_modulus <: slice u8)
        in
        let mod_iter2:Core.Slice.Iter.t_Iter u8 =
          Core.Slice.iter_under_impl (Core.Ops.Deref.Deref.deref padded_modulus <: slice u8)
        in
        let res:Alloc.String.t_String =
          Alloc.Fmt.format (Core.Fmt.new_v1_under_impl_2 (Rust_primitives.unsize (let list =
                        [""; "_MODULUS"]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list list)
                  <:
                  slice string)
                (Rust_primitives.unsize (let list =
                        [
                          Core.Fmt.Rt.new_display_under_impl_1 (Alloc.Str.to_uppercase_under_impl_5 (
                                  Core.Ops.Deref.Deref.deref (Alloc.String.ToString.to_string ident
                                      <:
                                      Alloc.String.t_String)
                                  <:
                                  string)
                              <:
                              Alloc.String.t_String)
                          <:
                          Core.Fmt.Rt.t_Argument
                        ]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list list)
                  <:
                  slice Core.Fmt.Rt.t_Argument)
              <:
              Core.Fmt.t_Arguments)
        in
        let const_name:Proc_macro2.t_Ident =
          Proc_macro2.new_under_impl_31 (Core.Ops.Deref.Deref.deref res <: string)
            (Proc_macro2.span_under_impl_31 ident <: Proc_macro2.t_Span)
        in
        let res:Alloc.String.t_String =
          Alloc.Fmt.format (Core.Fmt.new_v1_under_impl_2 (Rust_primitives.unsize (let list =
                        [""; "_MODULUS_STR"]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list list)
                  <:
                  slice string)
                (Rust_primitives.unsize (let list =
                        [
                          Core.Fmt.Rt.new_display_under_impl_1 (Alloc.Str.to_uppercase_under_impl_5 (
                                  Core.Ops.Deref.Deref.deref (Alloc.String.ToString.to_string ident
                                      <:
                                      Alloc.String.t_String)
                                  <:
                                  string)
                              <:
                              Alloc.String.t_String)
                          <:
                          Core.Fmt.Rt.t_Argument
                        ]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list list)
                  <:
                  slice Core.Fmt.Rt.t_Argument)
              <:
              Core.Fmt.t_Arguments)
        in
        let static_name:Proc_macro2.t_Ident =
          Proc_macro2.new_under_impl_31 (Core.Ops.Deref.Deref.deref res <: string)
            (Proc_macro2.span_under_impl_31 ident <: Proc_macro2.t_Span)
        in
        let res:Alloc.String.t_String =
          Alloc.Fmt.format (Core.Fmt.new_v1_under_impl_2 (Rust_primitives.unsize (let list =
                        [""; "_mod"]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list list)
                  <:
                  slice string)
                (Rust_primitives.unsize (let list =
                        [
                          Core.Fmt.Rt.new_display_under_impl_1 (Alloc.Str.to_uppercase_under_impl_5 (
                                  Core.Ops.Deref.Deref.deref (Alloc.String.ToString.to_string ident
                                      <:
                                      Alloc.String.t_String)
                                  <:
                                  string)
                              <:
                              Alloc.String.t_String)
                          <:
                          Core.Fmt.Rt.t_Argument
                        ]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list list)
                  <:
                  slice Core.Fmt.Rt.t_Argument)
              <:
              Core.Fmt.t_Arguments)
        in
        let mod_name:Proc_macro2.t_Ident =
          Proc_macro2.new_under_impl_31 (Core.Ops.Deref.Deref.deref res <: string)
            (Proc_macro2.span_under_impl_31 ident <: Proc_macro2.t_Span)
        in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_pound v__s in
        let hoist15:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "derive" in
        let hoist12:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Debug" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Clone" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Copy" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "PartialEq" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Eq" in
        let hoist11:Proc_macro2.t_TokenStream = v__s in
        let hoist13:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist12 Proc_macro2.Delimiter_Parenthesis hoist11
        in
        let v__s:Proc_macro2.t_TokenStream = hoist13 in
        let hoist14:Proc_macro2.t_TokenStream = v__s in
        let hoist16:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist15 Proc_macro2.Delimiter_Bracket hoist14
        in
        let v__s:Proc_macro2.t_TokenStream = hoist16 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#pub" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#struct" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist21:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "value" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let hoist18:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist17:Proc_macro2.t_TokenStream = v__s in
        let hoist19:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist18 Proc_macro2.Delimiter_Bracket hoist17
        in
        let v__s:Proc_macro2.t_TokenStream = hoist19 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let hoist20:Proc_macro2.t_TokenStream = v__s in
        let hoist22:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist21 Proc_macro2.Delimiter_Brace hoist20
        in
        let v__s:Proc_macro2.t_TokenStream = hoist22 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_pound v__s in
        let hoist27:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "allow" in
        let hoist24:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "non_snake_case" in
        let hoist23:Proc_macro2.t_TokenStream = v__s in
        let hoist25:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist24 Proc_macro2.Delimiter_Parenthesis hoist23
        in
        let v__s:Proc_macro2.t_TokenStream = hoist25 in
        let hoist26:Proc_macro2.t_TokenStream = v__s in
        let hoist28:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist27 Proc_macro2.Delimiter_Bracket hoist26
        in
        let v__s:Proc_macro2.t_TokenStream = hoist28 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#mod" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens mod_name v__s in
        let hoist158:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#use" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "super" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_star v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#const" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens const_name v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let hoist30:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist29:Proc_macro2.t_TokenStream = v__s in
        let hoist31:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist30 Proc_macro2.Delimiter_Bracket hoist29
        in
        let v__s:Proc_macro2.t_TokenStream = hoist31 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let hoist37:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__i:usize = 0sz in
        let has_iter:Quote.__private.t_ThereIsNoIteratorInRepetition =
          Quote.__private.ThereIsNoIteratorInRepetition
        in
        let mod_iter1, i:(Core.Slice.Iter.t_Iter u8 & Quote.__private.t_HasIterator) =
          Quote.__private.Ext.RepIteratorExt.quote_into_iter mod_iter1
        in
        let has_iter = has_iter |. i in
        let (_: Quote.__private.t_HasIterator):Quote.__private.t_HasIterator = has_iter in
        let v__i, v__s, mod_iter1:(Prims.unit & Proc_macro2.t_TokenStream &
          Core.Slice.Iter.t_Iter u8) =
          Rust_primitives.Hax.failure "(FunctionalizeLoops) something is not implemented yet.\nOnly for loop are being functionalized for now\n"
            "{\n        (loop {\n            |Tuple3(_i, _s, mod_iter1)| {\n                (if true {\n                    {\n                        let Tuple2(tmp0, out): tuple2<\n                            core::slice::iter::t_Iter<int>,\n                            core::option::t_Option<proj_asso_type!()>,\n                        > = { core::iter::traits::iterator::Iterator::next(mod_iter1) };\n                        {\n                            let mod_iter1: core::slice::iter::t_Iter<int> = { tmp0 };\n                            {\n                                let hoist33: tuple2<\n                                    core::slice::iter::t_Iter<int>,\n                                    core::option::t_Option<proj_asso_type!()>,\n                                > = { out };\n                                {\n                                    let mod_iter1: quote::__private::t_RepInterp<int> = {\n                                        (match hoist33 {\n                                            core::option::Option_Some(_x) => {\n                                                quote::__private::RepInterp(_x)\n                                            }\n                                            core::option::Option_None => {\n                                                let hoist32: rust_primitives::hax::t_Never = {\n                                                    rust_primitives::hax::failure(\"(CfIntoMonads) something is not implemented yet.This is discussed in issue https://github.com/hacspec/hacspec-v2/issues/96.\\nPlease upvote or comment this issue if you see this error message.\\nTODO: Monad for loop-related control flow\\n\",\"(break (Tuple0))\")\n                                                };\n                                                rust_primitives::hax::never_to_any(hoist32)\n                                            }\n                                        })\n                                    };\n                                    {\n                                        let _s: proc_macro2::t_TokenStream = {\n                                            (if core::cmp::PartialOrd::gt(_i, 0) {\n                                                {\n                                                    let _s: proc_macro2::t_TokenStream =\n                                                        { quote::__private::push_comma(_s) };\n                                                    _s\n                                                }\n                                            } else {\n                                                _s\n                                            })\n                                        };\n                                        {\n                                            let _i: tuple0 = { core::ops::arith::Add::add(_i, 1) };\n                                            {\n                                                let _s: proc_macro2::t_TokenStream = {\n                                                    quote::to_tokens::ToTokens::to_tokens(\n                                                        mod_iter1, _s,\n                                                    )\n                                                };\n                                                Tuple3(_i, _s, mod_iter1)\n                                            }\n                                        }\n                                    }\n                                }\n                            }\n                        }\n                    }\n                } else {\n                    {\n                        let hoist34: rust_primitives::hax::t_Never = {\n                            rust_primitives::hax::failure(\"(CfIntoMonads) something is not implemented yet.This is discussed in issue https://github.com/hacspec/hacspec-v2/issues/96.\\nPlease upvote or comment this issue if you see this error message.\\nTODO: Monad for loop-related control flow\\n\",\"(break (Tuple0))\")\n                        };\n                        {\n                            let hoist35: rust_primitives::hax::t_Never =\n                                { rust_primitives::hax::never_to_any(hoist34) };\n                            Tuple3(_i, _s, mod_iter1)\n                        }\n                    }\n                })\n            }\n        })(Tuple3(_i, _s, mod_iter1))\n    }"

        in
        let hoist36:Proc_macro2.t_TokenStream = v__s in
        let hoist38:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist37 Proc_macro2.Delimiter_Bracket hoist36
        in
        let v__s:Proc_macro2.t_TokenStream = hoist38 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#static" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens static_name v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "str" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let v__s:Proc_macro2.t_TokenStream =
          Quote.To_tokens.ToTokens.to_tokens modulus_string v__s
        in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#impl" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "NatMod" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_lt v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_gt v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#for" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist77:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#const" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "MODULUS" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let hoist40:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist39:Proc_macro2.t_TokenStream = v__s in
        let hoist41:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist40 Proc_macro2.Delimiter_Bracket hoist39
        in
        let v__s:Proc_macro2.t_TokenStream = hoist41 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let hoist47:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__i:usize = 0sz in
        let has_iter:Quote.__private.t_ThereIsNoIteratorInRepetition =
          Quote.__private.ThereIsNoIteratorInRepetition
        in
        let mod_iter2, i:(Core.Slice.Iter.t_Iter u8 & Quote.__private.t_HasIterator) =
          Quote.__private.Ext.RepIteratorExt.quote_into_iter mod_iter2
        in
        let has_iter = has_iter |. i in
        let (_: Quote.__private.t_HasIterator):Quote.__private.t_HasIterator = has_iter in
        let v__i, v__s, mod_iter2:(Prims.unit & Proc_macro2.t_TokenStream &
          Core.Slice.Iter.t_Iter u8) =
          Rust_primitives.Hax.failure "(FunctionalizeLoops) something is not implemented yet.\nOnly for loop are being functionalized for now\n"
            "{\n        (loop {\n            |Tuple3(_i, _s, mod_iter2)| {\n                (if true {\n                    {\n                        let Tuple2(tmp0, out): tuple2<\n                            core::slice::iter::t_Iter<int>,\n                            core::option::t_Option<proj_asso_type!()>,\n                        > = { core::iter::traits::iterator::Iterator::next(mod_iter2) };\n                        {\n                            let mod_iter2: core::slice::iter::t_Iter<int> = { tmp0 };\n                            {\n                                let hoist43: tuple2<\n                                    core::slice::iter::t_Iter<int>,\n                                    core::option::t_Option<proj_asso_type!()>,\n                                > = { out };\n                                {\n                                    let mod_iter2: quote::__private::t_RepInterp<int> = {\n                                        (match hoist43 {\n                                            core::option::Option_Some(_x) => {\n                                                quote::__private::RepInterp(_x)\n                                            }\n                                            core::option::Option_None => {\n                                                let hoist42: rust_primitives::hax::t_Never = {\n                                                    rust_primitives::hax::failure(\"(CfIntoMonads) something is not implemented yet.This is discussed in issue https://github.com/hacspec/hacspec-v2/issues/96.\\nPlease upvote or comment this issue if you see this error message.\\nTODO: Monad for loop-related control flow\\n\",\"(break (Tuple0))\")\n                                                };\n                                                rust_primitives::hax::never_to_any(hoist42)\n                                            }\n                                        })\n                                    };\n                                    {\n                                        let _s: proc_macro2::t_TokenStream = {\n                                            (if core::cmp::PartialOrd::gt(_i, 0) {\n                                                {\n                                                    let _s: proc_macro2::t_TokenStream =\n                                                        { quote::__private::push_comma(_s) };\n                                                    _s\n                                                }\n                                            } else {\n                                                _s\n                                            })\n                                        };\n                                        {\n                                            let _i: tuple0 = { core::ops::arith::Add::add(_i, 1) };\n                                            {\n                                                let _s: proc_macro2::t_TokenStream = {\n                                                    quote::to_tokens::ToTokens::to_tokens(\n                                                        mod_iter2, _s,\n                                                    )\n                                                };\n                                                Tuple3(_i, _s, mod_iter2)\n                                            }\n                                        }\n                                    }\n                                }\n                            }\n                        }\n                    }\n                } else {\n                    {\n                        let hoist44: rust_primitives::hax::t_Never = {\n                            rust_primitives::hax::failure(\"(CfIntoMonads) something is not implemented yet.This is discussed in issue https://github.com/hacspec/hacspec-v2/issues/96.\\nPlease upvote or comment this issue if you see this error message.\\nTODO: Monad for loop-related control flow\\n\",\"(break (Tuple0))\")\n                        };\n                        {\n                            let hoist45: rust_primitives::hax::t_Never =\n                                { rust_primitives::hax::never_to_any(hoist44) };\n                            Tuple3(_i, _s, mod_iter2)\n                        }\n                    }\n                })\n            }\n        })(Tuple3(_i, _s, mod_iter2))\n    }"

        in
        let hoist46:Proc_macro2.t_TokenStream = v__s in
        let hoist48:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist47 Proc_macro2.Delimiter_Bracket hoist46
        in
        let v__s:Proc_macro2.t_TokenStream = hoist48 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#const" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "MODULUS_STR" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_lifetime v__s "'static" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "str" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let v__s:Proc_macro2.t_TokenStream =
          Quote.To_tokens.ToTokens.to_tokens modulus_string v__s
        in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#const" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "ZERO" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let hoist50:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist49:Proc_macro2.t_TokenStream = v__s in
        let hoist51:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist50 Proc_macro2.Delimiter_Bracket hoist49
        in
        let v__s:Proc_macro2.t_TokenStream = hoist51 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let hoist53:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.parse v__s "0u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist52:Proc_macro2.t_TokenStream = v__s in
        let hoist54:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist53 Proc_macro2.Delimiter_Bracket hoist52
        in
        let v__s:Proc_macro2.t_TokenStream = hoist54 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "new" in
        let hoist59:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "value" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let hoist56:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist55:Proc_macro2.t_TokenStream = v__s in
        let hoist57:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist56 Proc_macro2.Delimiter_Bracket hoist55
        in
        let v__s:Proc_macro2.t_TokenStream = hoist57 in
        let hoist58:Proc_macro2.t_TokenStream = v__s in
        let hoist60:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist59 Proc_macro2.Delimiter_Parenthesis hoist58
        in
        let v__s:Proc_macro2.t_TokenStream = hoist60 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let hoist65:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let hoist62:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "value" in
        let hoist61:Proc_macro2.t_TokenStream = v__s in
        let hoist63:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist62 Proc_macro2.Delimiter_Brace hoist61
        in
        let v__s:Proc_macro2.t_TokenStream = hoist63 in
        let hoist64:Proc_macro2.t_TokenStream = v__s in
        let hoist66:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist65 Proc_macro2.Delimiter_Brace hoist64
        in
        let v__s:Proc_macro2.t_TokenStream = hoist66 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "value" in
        let hoist68:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let hoist67:Proc_macro2.t_TokenStream = v__s in
        let hoist69:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist68 Proc_macro2.Delimiter_Parenthesis hoist67
        in
        let v__s:Proc_macro2.t_TokenStream = hoist69 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let hoist71:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let hoist70:Proc_macro2.t_TokenStream = v__s in
        let hoist72:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist71 Proc_macro2.Delimiter_Bracket hoist70
        in
        let v__s:Proc_macro2.t_TokenStream = hoist72 in
        let hoist74:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_dot v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "value" in
        let hoist73:Proc_macro2.t_TokenStream = v__s in
        let hoist75:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist74 Proc_macro2.Delimiter_Brace hoist73
        in
        let v__s:Proc_macro2.t_TokenStream = hoist75 in
        let hoist76:Proc_macro2.t_TokenStream = v__s in
        let hoist78:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist77 Proc_macro2.Delimiter_Brace hoist76
        in
        let v__s:Proc_macro2.t_TokenStream = hoist78 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#impl" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "core" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "convert" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "AsRef" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_lt v__s in
        let hoist80:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let hoist79:Proc_macro2.t_TokenStream = v__s in
        let hoist81:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist80 Proc_macro2.Delimiter_Bracket hoist79
        in
        let v__s:Proc_macro2.t_TokenStream = hoist81 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_gt v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#for" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist92:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "as_ref" in
        let hoist83:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let hoist82:Proc_macro2.t_TokenStream = v__s in
        let hoist84:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist83 Proc_macro2.Delimiter_Parenthesis hoist82
        in
        let v__s:Proc_macro2.t_TokenStream = hoist84 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let hoist86:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let hoist85:Proc_macro2.t_TokenStream = v__s in
        let hoist87:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist86 Proc_macro2.Delimiter_Bracket hoist85
        in
        let v__s:Proc_macro2.t_TokenStream = hoist87 in
        let hoist89:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_dot v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "value" in
        let hoist88:Proc_macro2.t_TokenStream = v__s in
        let hoist90:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist89 Proc_macro2.Delimiter_Brace hoist88
        in
        let v__s:Proc_macro2.t_TokenStream = hoist90 in
        let hoist91:Proc_macro2.t_TokenStream = v__s in
        let hoist93:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist92 Proc_macro2.Delimiter_Brace hoist91
        in
        let v__s:Proc_macro2.t_TokenStream = hoist93 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#impl" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "core" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "fmt" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Display" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#for" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist104:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "fmt" in
        let hoist95:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "f" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_and v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#mut" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "core" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "fmt" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Formatter" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_lt v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_lifetime v__s "'_" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_gt v__s in
        let hoist94:Proc_macro2.t_TokenStream = v__s in
        let hoist96:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist95 Proc_macro2.Delimiter_Parenthesis hoist94
        in
        let v__s:Proc_macro2.t_TokenStream = hoist96 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "core" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "fmt" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Result" in
        let hoist101:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "write" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_bang v__s in
        let hoist98:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "f" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.parse v__s "\"{}\"" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_dot v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "to_hex" in
        let v__s:Proc_macro2.t_TokenStream =
          Quote.__private.push_group v__s
            Proc_macro2.Delimiter_Parenthesis
            (Proc_macro2.new_under_impl <: Proc_macro2.t_TokenStream)
        in
        let hoist97:Proc_macro2.t_TokenStream = v__s in
        let hoist99:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist98 Proc_macro2.Delimiter_Parenthesis hoist97
        in
        let v__s:Proc_macro2.t_TokenStream = hoist99 in
        let hoist100:Proc_macro2.t_TokenStream = v__s in
        let hoist102:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist101 Proc_macro2.Delimiter_Brace hoist100
        in
        let v__s:Proc_macro2.t_TokenStream = hoist102 in
        let hoist103:Proc_macro2.t_TokenStream = v__s in
        let hoist105:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist104 Proc_macro2.Delimiter_Brace hoist103
        in
        let v__s:Proc_macro2.t_TokenStream = hoist105 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#impl" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Into" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_lt v__s in
        let hoist107:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist106:Proc_macro2.t_TokenStream = v__s in
        let hoist108:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist107 Proc_macro2.Delimiter_Bracket hoist106
        in
        let v__s:Proc_macro2.t_TokenStream = hoist108 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_gt v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#for" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist119:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "into" in
        let hoist110:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let hoist109:Proc_macro2.t_TokenStream = v__s in
        let hoist111:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist110 Proc_macro2.Delimiter_Parenthesis hoist109
        in
        let v__s:Proc_macro2.t_TokenStream = hoist111 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let hoist113:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "u8" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes v__s in
        let hoist112:Proc_macro2.t_TokenStream = v__s in
        let hoist114:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist113 Proc_macro2.Delimiter_Bracket hoist112
        in
        let v__s:Proc_macro2.t_TokenStream = hoist114 in
        let hoist116:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_dot v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "value" in
        let hoist115:Proc_macro2.t_TokenStream = v__s in
        let hoist117:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist116 Proc_macro2.Delimiter_Brace hoist115
        in
        let v__s:Proc_macro2.t_TokenStream = hoist117 in
        let hoist118:Proc_macro2.t_TokenStream = v__s in
        let hoist120:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist119 Proc_macro2.Delimiter_Brace hoist118
        in
        let v__s:Proc_macro2.t_TokenStream = hoist120 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#impl" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "core" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "ops" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Add" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#for" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist131:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#type" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Output" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "add" in
        let hoist122:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "rhs" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let hoist121:Proc_macro2.t_TokenStream = v__s in
        let hoist123:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist122 Proc_macro2.Delimiter_Parenthesis hoist121
        in
        let v__s:Proc_macro2.t_TokenStream = hoist123 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Output" in
        let hoist128:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_dot v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "fadd" in
        let hoist125:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "rhs" in
        let hoist124:Proc_macro2.t_TokenStream = v__s in
        let hoist126:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist125 Proc_macro2.Delimiter_Parenthesis hoist124
        in
        let v__s:Proc_macro2.t_TokenStream = hoist126 in
        let hoist127:Proc_macro2.t_TokenStream = v__s in
        let hoist129:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist128 Proc_macro2.Delimiter_Brace hoist127
        in
        let v__s:Proc_macro2.t_TokenStream = hoist129 in
        let hoist130:Proc_macro2.t_TokenStream = v__s in
        let hoist132:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist131 Proc_macro2.Delimiter_Brace hoist130
        in
        let v__s:Proc_macro2.t_TokenStream = hoist132 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#impl" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "core" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "ops" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Mul" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#for" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist143:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#type" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Output" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "mul" in
        let hoist134:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "rhs" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let hoist133:Proc_macro2.t_TokenStream = v__s in
        let hoist135:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist134 Proc_macro2.Delimiter_Parenthesis hoist133
        in
        let v__s:Proc_macro2.t_TokenStream = hoist135 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Output" in
        let hoist140:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_dot v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "fmul" in
        let hoist137:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "rhs" in
        let hoist136:Proc_macro2.t_TokenStream = v__s in
        let hoist138:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist137 Proc_macro2.Delimiter_Parenthesis hoist136
        in
        let v__s:Proc_macro2.t_TokenStream = hoist138 in
        let hoist139:Proc_macro2.t_TokenStream = v__s in
        let hoist141:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist140 Proc_macro2.Delimiter_Brace hoist139
        in
        let v__s:Proc_macro2.t_TokenStream = hoist141 in
        let hoist142:Proc_macro2.t_TokenStream = v__s in
        let hoist144:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist143 Proc_macro2.Delimiter_Brace hoist142
        in
        let v__s:Proc_macro2.t_TokenStream = hoist144 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#impl" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "core" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "ops" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Sub" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#for" in
        let v__s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident v__s in
        let hoist155:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#type" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Output" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_eq v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_semi v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "r#fn" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "sub" in
        let hoist146:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_comma v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "rhs" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let hoist145:Proc_macro2.t_TokenStream = v__s in
        let hoist147:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist146 Proc_macro2.Delimiter_Parenthesis hoist145
        in
        let v__s:Proc_macro2.t_TokenStream = hoist147 in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "Output" in
        let hoist152:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "self" in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_dot v__s in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "fsub" in
        let hoist149:Proc_macro2.t_TokenStream = v__s in
        let v__s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let v__s:Proc_macro2.t_TokenStream = Quote.__private.push_ident v__s "rhs" in
        let hoist148:Proc_macro2.t_TokenStream = v__s in
        let hoist150:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist149 Proc_macro2.Delimiter_Parenthesis hoist148
        in
        let v__s:Proc_macro2.t_TokenStream = hoist150 in
        let hoist151:Proc_macro2.t_TokenStream = v__s in
        let hoist153:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist152 Proc_macro2.Delimiter_Brace hoist151
        in
        let v__s:Proc_macro2.t_TokenStream = hoist153 in
        let hoist154:Proc_macro2.t_TokenStream = v__s in
        let hoist156:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist155 Proc_macro2.Delimiter_Brace hoist154
        in
        let v__s:Proc_macro2.t_TokenStream = hoist156 in
        let hoist157:Proc_macro2.t_TokenStream = v__s in
        let hoist159:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist158 Proc_macro2.Delimiter_Brace hoist157
        in
        let v__s:Proc_macro2.t_TokenStream = hoist159 in
        let out_struct:Proc_macro2.t_TokenStream = v__s in
        Core.Convert.Into.into out_struct))

let v___: Prims.unit = ()
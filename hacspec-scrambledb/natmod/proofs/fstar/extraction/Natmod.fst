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
      let hoist1:Core.Result.t_Result t_NatModAttr Syn.Error.t_Error =
        Core.Ops.Try_trait.FromResidual.from_residual (Syn.Parse.parse_under_impl_9 input)
      in
      let mod_str:Alloc.String.t_String = Syn.Lit.value_under_impl hoist1 in
      let mod_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Core.Result.expect_under_impl (Hex.FromHex.from_hex mod_str) "Invalid hex String"
      in
      let _:Core.Result.t_Result t_NatModAttr Syn.Error.t_Error =
        Core.Ops.Try_trait.FromResidual.from_residual (Syn.Parse.parse_under_impl_9 input)
      in
      let hoist2:Core.Result.t_Result t_NatModAttr Syn.Error.t_Error =
        Core.Ops.Try_trait.FromResidual.from_residual (Syn.Parse.parse_under_impl_9 input)
      in
      let hoist3:Core.Result.t_Result usize Syn.Error.t_Error =
        Syn.Lit.base10_parse_under_impl_4 hoist2
      in
      let int_size:Core.Result.t_Result t_NatModAttr Syn.Error.t_Error =
        Core.Ops.Try_trait.FromResidual.from_residual hoist3
      in
      let _:never =
        if ~.(Syn.Parse.is_empty_under_impl_9 input)
        then
          Core.Panicking.panic_fmt (Core.Fmt.new_v1_under_impl_2 (Rust_primitives.unsize (let l =
                        ["Left over tokens in attribute "]
                      in
                      assert_norm (List.Tot.length l == 1);
                      Rust_primitives.Hax.array_of_list l))
                (Rust_primitives.unsize (let l = [Core.Fmt.Rt.new_debug_under_impl_1 input] in
                      assert_norm (List.Tot.length l == 1);
                      Rust_primitives.Hax.array_of_list l)))
      in
      Core.Result.Result_Ok
      ({
          Natmod.NatModAttr.f_mod_str = mod_str;
          Natmod.NatModAttr.f_mod_bytes = mod_bytes;
          Natmod.NatModAttr.f_int_size = int_size
        })
  }

let nat_mod (attr item: Proc_macro.t_TokenStream) : Proc_macro.t_TokenStream =
  Rust_primitives.Hax.Control_flow_monad.Mexception.run (let* item_ast:Syn.Derive.t_DeriveInput =
        match Syn.parse item with
        | Core.Result.Result_Ok data -> Core.Ops.Control_flow.ControlFlow_Continue data
        | Core.Result.Result_Err err ->
          Core.Ops.Control_flow.ControlFlow.v_Break (Core.Convert.From.from (Syn.Error.to_compile_error_under_impl
                    err))
      in
      let ident:Proc_macro2.t_Ident =
        Core.Clone.Clone.clone item_ast.Syn.Derive.DeriveInput.f_ident
      in
      let* args:t_NatModAttr =
        match Syn.parse attr with
        | Core.Result.Result_Ok data -> Core.Ops.Control_flow.ControlFlow_Continue data
        | Core.Result.Result_Err err ->
          Core.Ops.Control_flow.ControlFlow.v_Break (Core.Convert.From.from (Syn.Error.to_compile_error_under_impl
                    err))
      in
      Core.Ops.Control_flow.ControlFlow_Continue
      (let num_bytes:usize = args.Natmod.NatModAttr.f_int_size in
        let modulus:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = args.Natmod.NatModAttr.f_mod_bytes in
        let modulus_string:Alloc.String.t_String = args.Natmod.NatModAttr.f_mod_str in
        let padded_modulus:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.from_elem 0uy (num_bytes -. Alloc.Vec.len_under_impl_1 modulus)
        in
        let _:Prims.unit =
          Rust_primitives.Hax.failure ""
            "alloc::vec::append_under_impl_1(\n        &mut (padded_modulus),\n        &mut (deref(&mut (core::clone::Clone::clone(&(modulus))))),\n    )"

        in
        let mod_iter1:Core.Slice.Iter.t_Iter u8 =
          Core.Slice.iter_under_impl (Core.Ops.Deref.Deref.deref padded_modulus)
        in
        let mod_iter2:Core.Slice.Iter.t_Iter u8 =
          Core.Slice.iter_under_impl (Core.Ops.Deref.Deref.deref padded_modulus)
        in
        let res:Alloc.String.t_String =
          Alloc.Fmt.format (Core.Fmt.new_v1_under_impl_2 (Rust_primitives.unsize (let l =
                        [""; "_MODULUS"]
                      in
                      assert_norm (List.Tot.length l == 2);
                      Rust_primitives.Hax.array_of_list l))
                (Rust_primitives.unsize (let l =
                        [
                          Core.Fmt.Rt.new_display_under_impl_1 (Alloc.Str.to_uppercase_under_impl_5 (
                                  Core.Ops.Deref.Deref.deref (Alloc.String.ToString.to_string ident)
                                ))
                        ]
                      in
                      assert_norm (List.Tot.length l == 1);
                      Rust_primitives.Hax.array_of_list l)))
        in
        let const_name:Proc_macro2.t_Ident =
          Proc_macro2.new_under_impl_31 (Core.Ops.Deref.Deref.deref res)
            (Proc_macro2.span_under_impl_31 ident)
        in
        let res:Alloc.String.t_String =
          Alloc.Fmt.format (Core.Fmt.new_v1_under_impl_2 (Rust_primitives.unsize (let l =
                        [""; "_MODULUS_STR"]
                      in
                      assert_norm (List.Tot.length l == 2);
                      Rust_primitives.Hax.array_of_list l))
                (Rust_primitives.unsize (let l =
                        [
                          Core.Fmt.Rt.new_display_under_impl_1 (Alloc.Str.to_uppercase_under_impl_5 (
                                  Core.Ops.Deref.Deref.deref (Alloc.String.ToString.to_string ident)
                                ))
                        ]
                      in
                      assert_norm (List.Tot.length l == 1);
                      Rust_primitives.Hax.array_of_list l)))
        in
        let static_name:Proc_macro2.t_Ident =
          Proc_macro2.new_under_impl_31 (Core.Ops.Deref.Deref.deref res)
            (Proc_macro2.span_under_impl_31 ident)
        in
        let res:Alloc.String.t_String =
          Alloc.Fmt.format (Core.Fmt.new_v1_under_impl_2 (Rust_primitives.unsize (let l =
                        [""; "_mod"]
                      in
                      assert_norm (List.Tot.length l == 2);
                      Rust_primitives.Hax.array_of_list l))
                (Rust_primitives.unsize (let l =
                        [
                          Core.Fmt.Rt.new_display_under_impl_1 (Alloc.Str.to_uppercase_under_impl_5 (
                                  Core.Ops.Deref.Deref.deref (Alloc.String.ToString.to_string ident)
                                ))
                        ]
                      in
                      assert_norm (List.Tot.length l == 1);
                      Rust_primitives.Hax.array_of_list l)))
        in
        let mod_name:Proc_macro2.t_Ident =
          Proc_macro2.new_under_impl_31 (Core.Ops.Deref.Deref.deref res)
            (Proc_macro2.span_under_impl_31 ident)
        in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_pound _s in
        let hoist8:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "derive" in
        let hoist5:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Clone" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Copy" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "PartialEq" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Eq" in
        let hoist4:Proc_macro2.t_TokenStream = _s in
        let hoist6:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist5 Proc_macro2.Delimiter_Parenthesis hoist4
        in
        let _s:Proc_macro2.t_TokenStream = hoist6 in
        let hoist7:Proc_macro2.t_TokenStream = _s in
        let hoist9:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist8 Proc_macro2.Delimiter_Bracket hoist7
        in
        let _s:Proc_macro2.t_TokenStream = hoist9 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#pub" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#struct" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident _s in
        let hoist14:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "value" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let hoist11:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist10:Proc_macro2.t_TokenStream = _s in
        let hoist12:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist11 Proc_macro2.Delimiter_Bracket hoist10
        in
        let _s:Proc_macro2.t_TokenStream = hoist12 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let hoist13:Proc_macro2.t_TokenStream = _s in
        let hoist15:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist14 Proc_macro2.Delimiter_Brace hoist13
        in
        let _s:Proc_macro2.t_TokenStream = hoist15 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_pound _s in
        let hoist20:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "allow" in
        let hoist17:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "non_snake_case" in
        let hoist16:Proc_macro2.t_TokenStream = _s in
        let hoist18:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist17 Proc_macro2.Delimiter_Parenthesis hoist16
        in
        let _s:Proc_macro2.t_TokenStream = hoist18 in
        let hoist19:Proc_macro2.t_TokenStream = _s in
        let hoist21:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist20 Proc_macro2.Delimiter_Bracket hoist19
        in
        let _s:Proc_macro2.t_TokenStream = hoist21 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#mod" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens mod_name _s in
        let hoist133:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#use" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "super" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_star _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#const" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens const_name _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let hoist23:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist22:Proc_macro2.t_TokenStream = _s in
        let hoist24:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist23 Proc_macro2.Delimiter_Bracket hoist22
        in
        let _s:Proc_macro2.t_TokenStream = hoist24 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_eq _s in
        let hoist27:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _i:usize = 0sz in
        let has_iter:Quote.__private.t_ThereIsNoIteratorInRepetition =
          Quote.__private.ThereIsNoIteratorInRepetition
        in
        let mod_iter1, i:(Core.Slice.Iter.t_Iter u8 & Quote.__private.t_HasIterator) =
          Quote.__private.Ext.RepIteratorExt.quote_into_iter mod_iter1
        in
        let has_iter = has_iter |. i in
        let (_: Quote.__private.t_HasIterator):Quote.__private.t_HasIterator = has_iter in
        let _i, _s, mod_iter1:(Prims.unit & Proc_macro2.t_TokenStream & Core.Slice.Iter.t_Iter u8) =
          Rust_primitives.Hax.failure ""
            "{\n        (loop {\n            |Tuple3(_i, _s, mod_iter1)| {\n                (if true {\n                    {\n                        let Tuple2(todo_fresh_var, mod_iter1_temp): tuple2<\n                            core::option::Option<proj_asso_type!()>,\n                            core::slice::iter::Iter<int>,\n                        > = { core::iter::traits::iterator::Iterator::next(mod_iter1) };\n                        {\n                            let mod_iter1: core::slice::iter::Iter<int> = { mod_iter1_temp };\n                            {\n                                let hoist25: core::option::Option<proj_asso_type!()> =\n                                    { todo_fresh_var };\n                                {\n                                    let mod_iter1: quote::__private::RepInterp<int> = {\n                                        (match hoist25 {\n                                            core::option::Option::Some(_x) => {\n                                                quote::__private::RepInterp(_x)\n                                            }\n                                            core::option::Option::None => {\n                                                rust_primitives::hax::failure(\n                                                    \"\",\n                                                    \"(break (Tuple0))\",\n                                                )\n                                            }\n                                        })\n                                    };\n                                    {\n                                        let _s: proc_macro2::TokenStream = {\n                                            (if core::cmp::PartialOrd::gt(_i, 0) {\n                                                {\n                                                    let _s: proc_macro2::TokenStream =\n                                                        { quote::__private::push_comma(_s) };\n                                                    _s\n                                                }\n                                            } else {\n                                                _s\n                                            })\n                                        };\n                                        {\n                                            let Tuple0: tuple0 =\n                                                { core::ops::arith::Add::add(_i, 1) };\n                                            {\n                                                let _i: tuple0 = { Tuple0 };\n                                                {\n                                                    let _s: proc_macro2::TokenStream = {\n                                                        quote::to_tokens::ToTokens::to_tokens(\n                                                            mod_iter1, _s,\n                                                        )\n                                                    };\n                                                    Tuple3(_i, _s, mod_iter1)\n                                                }\n                                            }\n                                        }\n                                    }\n                                }\n                            }\n                        }\n                    }\n                } else {\n                    {\n                        let _: tuple0 = { rust_primitives::hax::failure(\"\", \"(break (Tuple0))\") };\n                        Tuple3(_i, _s, mod_iter1)\n                    }\n                })\n            }\n        })(Tuple3(_i, _s, mod_iter1))\n    }"

        in
        let hoist26:Proc_macro2.t_TokenStream = _s in
        let hoist28:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist27 Proc_macro2.Delimiter_Bracket hoist26
        in
        let _s:Proc_macro2.t_TokenStream = hoist28 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#static" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens static_name _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "str" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_eq _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens modulus_string _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#impl" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "NatMod" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_lt _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_gt _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#for" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident _s in
        let hoist64:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#const" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "MODULUS" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let hoist30:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist29:Proc_macro2.t_TokenStream = _s in
        let hoist31:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist30 Proc_macro2.Delimiter_Bracket hoist29
        in
        let _s:Proc_macro2.t_TokenStream = hoist31 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_eq _s in
        let hoist34:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _i:usize = 0sz in
        let has_iter:Quote.__private.t_ThereIsNoIteratorInRepetition =
          Quote.__private.ThereIsNoIteratorInRepetition
        in
        let mod_iter2, i:(Core.Slice.Iter.t_Iter u8 & Quote.__private.t_HasIterator) =
          Quote.__private.Ext.RepIteratorExt.quote_into_iter mod_iter2
        in
        let has_iter = has_iter |. i in
        let (_: Quote.__private.t_HasIterator):Quote.__private.t_HasIterator = has_iter in
        let _i, _s, mod_iter2:(Prims.unit & Proc_macro2.t_TokenStream & Core.Slice.Iter.t_Iter u8) =
          Rust_primitives.Hax.failure ""
            "{\n        (loop {\n            |Tuple3(_i, _s, mod_iter2)| {\n                (if true {\n                    {\n                        let Tuple2(todo_fresh_var, mod_iter2_temp): tuple2<\n                            core::option::Option<proj_asso_type!()>,\n                            core::slice::iter::Iter<int>,\n                        > = { core::iter::traits::iterator::Iterator::next(mod_iter2) };\n                        {\n                            let mod_iter2: core::slice::iter::Iter<int> = { mod_iter2_temp };\n                            {\n                                let hoist32: core::option::Option<proj_asso_type!()> =\n                                    { todo_fresh_var };\n                                {\n                                    let mod_iter2: quote::__private::RepInterp<int> = {\n                                        (match hoist32 {\n                                            core::option::Option::Some(_x) => {\n                                                quote::__private::RepInterp(_x)\n                                            }\n                                            core::option::Option::None => {\n                                                rust_primitives::hax::failure(\n                                                    \"\",\n                                                    \"(break (Tuple0))\",\n                                                )\n                                            }\n                                        })\n                                    };\n                                    {\n                                        let _s: proc_macro2::TokenStream = {\n                                            (if core::cmp::PartialOrd::gt(_i, 0) {\n                                                {\n                                                    let _s: proc_macro2::TokenStream =\n                                                        { quote::__private::push_comma(_s) };\n                                                    _s\n                                                }\n                                            } else {\n                                                _s\n                                            })\n                                        };\n                                        {\n                                            let Tuple0: tuple0 =\n                                                { core::ops::arith::Add::add(_i, 1) };\n                                            {\n                                                let _i: tuple0 = { Tuple0 };\n                                                {\n                                                    let _s: proc_macro2::TokenStream = {\n                                                        quote::to_tokens::ToTokens::to_tokens(\n                                                            mod_iter2, _s,\n                                                        )\n                                                    };\n                                                    Tuple3(_i, _s, mod_iter2)\n                                                }\n                                            }\n                                        }\n                                    }\n                                }\n                            }\n                        }\n                    }\n                } else {\n                    {\n                        let _: tuple0 = { rust_primitives::hax::failure(\"\", \"(break (Tuple0))\") };\n                        Tuple3(_i, _s, mod_iter2)\n                    }\n                })\n            }\n        })(Tuple3(_i, _s, mod_iter2))\n    }"

        in
        let hoist33:Proc_macro2.t_TokenStream = _s in
        let hoist35:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist34 Proc_macro2.Delimiter_Bracket hoist33
        in
        let _s:Proc_macro2.t_TokenStream = hoist35 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#const" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "MODULUS_STR" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_lifetime _s "'static" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "str" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_eq _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens modulus_string _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#const" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "ZERO" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let hoist37:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist36:Proc_macro2.t_TokenStream = _s in
        let hoist38:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist37 Proc_macro2.Delimiter_Bracket hoist36
        in
        let _s:Proc_macro2.t_TokenStream = hoist38 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_eq _s in
        let hoist40:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.parse _s "0u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist39:Proc_macro2.t_TokenStream = _s in
        let hoist41:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist40 Proc_macro2.Delimiter_Bracket hoist39
        in
        let _s:Proc_macro2.t_TokenStream = hoist41 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#fn" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "new" in
        let hoist46:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "value" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let hoist43:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist42:Proc_macro2.t_TokenStream = _s in
        let hoist44:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist43 Proc_macro2.Delimiter_Bracket hoist42
        in
        let _s:Proc_macro2.t_TokenStream = hoist44 in
        let hoist45:Proc_macro2.t_TokenStream = _s in
        let hoist47:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist46 Proc_macro2.Delimiter_Parenthesis hoist45
        in
        let _s:Proc_macro2.t_TokenStream = hoist47 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let hoist52:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let hoist49:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "value" in
        let hoist48:Proc_macro2.t_TokenStream = _s in
        let hoist50:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist49 Proc_macro2.Delimiter_Brace hoist48
        in
        let _s:Proc_macro2.t_TokenStream = hoist50 in
        let hoist51:Proc_macro2.t_TokenStream = _s in
        let hoist53:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist52 Proc_macro2.Delimiter_Brace hoist51
        in
        let _s:Proc_macro2.t_TokenStream = hoist53 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#fn" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "value" in
        let hoist55:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let hoist54:Proc_macro2.t_TokenStream = _s in
        let hoist56:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist55 Proc_macro2.Delimiter_Parenthesis hoist54
        in
        let _s:Proc_macro2.t_TokenStream = hoist56 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let hoist58:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let hoist57:Proc_macro2.t_TokenStream = _s in
        let hoist59:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist58 Proc_macro2.Delimiter_Bracket hoist57
        in
        let _s:Proc_macro2.t_TokenStream = hoist59 in
        let hoist61:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_dot _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "value" in
        let hoist60:Proc_macro2.t_TokenStream = _s in
        let hoist62:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist61 Proc_macro2.Delimiter_Brace hoist60
        in
        let _s:Proc_macro2.t_TokenStream = hoist62 in
        let hoist63:Proc_macro2.t_TokenStream = _s in
        let hoist65:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist64 Proc_macro2.Delimiter_Brace hoist63
        in
        let _s:Proc_macro2.t_TokenStream = hoist65 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#impl" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "core" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "convert" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "AsRef" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_lt _s in
        let hoist67:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let hoist66:Proc_macro2.t_TokenStream = _s in
        let hoist68:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist67 Proc_macro2.Delimiter_Bracket hoist66
        in
        let _s:Proc_macro2.t_TokenStream = hoist68 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_gt _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#for" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident _s in
        let hoist79:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#fn" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "as_ref" in
        let hoist70:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let hoist69:Proc_macro2.t_TokenStream = _s in
        let hoist71:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist70 Proc_macro2.Delimiter_Parenthesis hoist69
        in
        let _s:Proc_macro2.t_TokenStream = hoist71 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let hoist73:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let hoist72:Proc_macro2.t_TokenStream = _s in
        let hoist74:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist73 Proc_macro2.Delimiter_Bracket hoist72
        in
        let _s:Proc_macro2.t_TokenStream = hoist74 in
        let hoist76:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_dot _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "value" in
        let hoist75:Proc_macro2.t_TokenStream = _s in
        let hoist77:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist76 Proc_macro2.Delimiter_Brace hoist75
        in
        let _s:Proc_macro2.t_TokenStream = hoist77 in
        let hoist78:Proc_macro2.t_TokenStream = _s in
        let hoist80:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist79 Proc_macro2.Delimiter_Brace hoist78
        in
        let _s:Proc_macro2.t_TokenStream = hoist80 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#impl" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "core" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "fmt" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Display" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#for" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident _s in
        let hoist91:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#fn" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "fmt" in
        let hoist82:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "f" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_and _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#mut" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "core" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "fmt" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Formatter" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_lt _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_lifetime _s "'_" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_gt _s in
        let hoist81:Proc_macro2.t_TokenStream = _s in
        let hoist83:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist82 Proc_macro2.Delimiter_Parenthesis hoist81
        in
        let _s:Proc_macro2.t_TokenStream = hoist83 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "core" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "fmt" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Result" in
        let hoist88:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "write" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_bang _s in
        let hoist85:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "f" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.parse _s "\"{}\"" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_dot _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "to_hex" in
        let _s:Proc_macro2.t_TokenStream =
          Quote.__private.push_group _s Proc_macro2.Delimiter_Parenthesis Proc_macro2.new_under_impl
        in
        let hoist84:Proc_macro2.t_TokenStream = _s in
        let hoist86:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist85 Proc_macro2.Delimiter_Parenthesis hoist84
        in
        let _s:Proc_macro2.t_TokenStream = hoist86 in
        let hoist87:Proc_macro2.t_TokenStream = _s in
        let hoist89:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist88 Proc_macro2.Delimiter_Brace hoist87
        in
        let _s:Proc_macro2.t_TokenStream = hoist89 in
        let hoist90:Proc_macro2.t_TokenStream = _s in
        let hoist92:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist91 Proc_macro2.Delimiter_Brace hoist90
        in
        let _s:Proc_macro2.t_TokenStream = hoist92 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#impl" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Into" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_lt _s in
        let hoist94:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist93:Proc_macro2.t_TokenStream = _s in
        let hoist95:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist94 Proc_macro2.Delimiter_Bracket hoist93
        in
        let _s:Proc_macro2.t_TokenStream = hoist95 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_gt _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#for" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident _s in
        let hoist106:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#fn" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "into" in
        let hoist97:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let hoist96:Proc_macro2.t_TokenStream = _s in
        let hoist98:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist97 Proc_macro2.Delimiter_Parenthesis hoist96
        in
        let _s:Proc_macro2.t_TokenStream = hoist98 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow _s in
        let hoist100:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "u8" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens num_bytes _s in
        let hoist99:Proc_macro2.t_TokenStream = _s in
        let hoist101:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist100 Proc_macro2.Delimiter_Bracket hoist99
        in
        let _s:Proc_macro2.t_TokenStream = hoist101 in
        let hoist103:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_dot _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "value" in
        let hoist102:Proc_macro2.t_TokenStream = _s in
        let hoist104:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist103 Proc_macro2.Delimiter_Brace hoist102
        in
        let _s:Proc_macro2.t_TokenStream = hoist104 in
        let hoist105:Proc_macro2.t_TokenStream = _s in
        let hoist107:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist106 Proc_macro2.Delimiter_Brace hoist105
        in
        let _s:Proc_macro2.t_TokenStream = hoist107 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#impl" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "core" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "ops" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Add" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#for" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident _s in
        let hoist118:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#type" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Output" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_eq _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#fn" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "add" in
        let hoist109:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "rhs" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let hoist108:Proc_macro2.t_TokenStream = _s in
        let hoist110:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist109 Proc_macro2.Delimiter_Parenthesis hoist108
        in
        let _s:Proc_macro2.t_TokenStream = hoist110 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Output" in
        let hoist115:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_dot _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "fadd" in
        let hoist112:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "rhs" in
        let hoist111:Proc_macro2.t_TokenStream = _s in
        let hoist113:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist112 Proc_macro2.Delimiter_Parenthesis hoist111
        in
        let _s:Proc_macro2.t_TokenStream = hoist113 in
        let hoist114:Proc_macro2.t_TokenStream = _s in
        let hoist116:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist115 Proc_macro2.Delimiter_Brace hoist114
        in
        let _s:Proc_macro2.t_TokenStream = hoist116 in
        let hoist117:Proc_macro2.t_TokenStream = _s in
        let hoist119:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist118 Proc_macro2.Delimiter_Brace hoist117
        in
        let _s:Proc_macro2.t_TokenStream = hoist119 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#impl" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "core" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "ops" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Mul" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#for" in
        let _s:Proc_macro2.t_TokenStream = Quote.To_tokens.ToTokens.to_tokens ident _s in
        let hoist130:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#type" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Output" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_eq _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_semi _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "r#fn" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "mul" in
        let hoist121:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_comma _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "rhs" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let hoist120:Proc_macro2.t_TokenStream = _s in
        let hoist122:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist121 Proc_macro2.Delimiter_Parenthesis hoist120
        in
        let _s:Proc_macro2.t_TokenStream = hoist122 in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_rarrow _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_colon2 _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "Output" in
        let hoist127:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "self" in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_dot _s in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "fmul" in
        let hoist124:Proc_macro2.t_TokenStream = _s in
        let _s:Proc_macro2.t_TokenStream = Proc_macro2.new_under_impl in
        let _s:Proc_macro2.t_TokenStream = Quote.__private.push_ident _s "rhs" in
        let hoist123:Proc_macro2.t_TokenStream = _s in
        let hoist125:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist124 Proc_macro2.Delimiter_Parenthesis hoist123
        in
        let _s:Proc_macro2.t_TokenStream = hoist125 in
        let hoist126:Proc_macro2.t_TokenStream = _s in
        let hoist128:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist127 Proc_macro2.Delimiter_Brace hoist126
        in
        let _s:Proc_macro2.t_TokenStream = hoist128 in
        let hoist129:Proc_macro2.t_TokenStream = _s in
        let hoist131:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist130 Proc_macro2.Delimiter_Brace hoist129
        in
        let _s:Proc_macro2.t_TokenStream = hoist131 in
        let hoist132:Proc_macro2.t_TokenStream = _s in
        let hoist134:Proc_macro2.t_TokenStream =
          Quote.__private.push_group hoist133 Proc_macro2.Delimiter_Brace hoist132
        in
        let _s:Proc_macro2.t_TokenStream = hoist134 in
        let out_struct:Proc_macro2.t_TokenStream = _s in
        Core.Convert.Into.into out_struct))

let v___: Prims.unit = ()
//! // This trait lives in the library
//!
//! ```ignore
//! pub trait NatModTrait<T> {
//!     const MODULUS: T;
//! }
//!
//! #[nat_mod("123456", 10)]
//! struct MyNatMod {}
//! ```

use hex::FromHex;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Parse, parse_macro_input, DeriveInput, Ident, LitInt, LitStr, Result, Token};

#[derive(Clone, Debug)]
struct NatModAttr {
    /// Modulus as hex string and bytes
    mod_str: String,
    mod_bytes: Vec<u8>,
    /// Number of bytes to use for the integer
    int_size: usize,
}

impl Parse for NatModAttr {
    fn parse(input: syn::parse::ParseStream) -> Result<Self> {
        let mod_str = input.parse::<LitStr>()?.value();
        let mod_bytes = Vec::<u8>::from_hex(&mod_str).expect("Invalid hex String");
        input.parse::<Token![,]>()?;
        let int_size = input.parse::<LitInt>()?.base10_parse::<usize>()?;
        assert!(input.is_empty(), "Left over tokens in attribute {input:?}");
        Ok(NatModAttr {
            mod_str,
            mod_bytes,
            int_size,
        })
    }
}

#[proc_macro_attribute]
pub fn nat_mod(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_ast = parse_macro_input!(item as DeriveInput);
    let ident = item_ast.ident.clone();
    let args = parse_macro_input!(attr as NatModAttr);

    let num_bytes = args.int_size;
    let modulus = args.mod_bytes;
    let modulus_string = args.mod_str;

    let mut padded_modulus = vec![0u8; num_bytes - modulus.len()];
    padded_modulus.append(&mut modulus.clone());
    let mod_iter1 = padded_modulus.iter();
    let mod_iter2 = padded_modulus.iter();
    let const_name = Ident::new(
        &format!("{}_MODULUS", ident.to_string().to_uppercase()),
        ident.span(),
    );
    let static_name = Ident::new(
        &format!("{}_MODULUS_STR", ident.to_string().to_uppercase()),
        ident.span(),
    );
    let mod_name = Ident::new(
        &format!("{}_mod", ident.to_string().to_uppercase()),
        ident.span(),
    );

    let out_struct = quote! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct #ident {
            value: [u8; #num_bytes],
        }

        //#[not_hax]
        #[allow(non_snake_case)]
        mod #mod_name {
            use super::*;

            const #const_name: [u8; #num_bytes] = [#(#mod_iter1),*];
            static #static_name: &str = #modulus_string;

            impl NatMod<#num_bytes> for #ident {
                const MODULUS: [u8; #num_bytes] = [#(#mod_iter2),*];
                const MODULUS_STR: &'static str = #modulus_string;
                const ZERO: [u8; #num_bytes] = [0u8; #num_bytes];


                fn new(value: [u8; #num_bytes]) -> Self {
                    Self {
                        value
                    }
                }
                fn value(&self) -> &[u8] {
                    &self.value
                }
            }

            impl core::convert::AsRef<[u8]> for #ident {
                fn as_ref(&self) -> &[u8] {
                    &self.value
                }
            }

            impl core::fmt::Display for #ident {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", self.to_hex())
                }
            }


            impl Into<[u8; #num_bytes]> for #ident {
                fn into(self) -> [u8; #num_bytes] {
                    self.value
                }
            }

            impl core::ops::Add for #ident {
                type Output = Self;

                fn add(self, rhs: Self) -> Self::Output {
                    self.fadd(rhs)
                }
            }

            impl core::ops::Mul for #ident {
                type Output = Self;

                fn mul(self, rhs: Self) -> Self::Output {
                    self.fmul(rhs)
                }
            }

            impl core::ops::Sub for #ident {
                type Output = Self;

                fn sub(self, rhs: Self) -> Self::Output {
                    self.fsub(rhs)
                }
            }
        }
    };

    out_struct.into()
}

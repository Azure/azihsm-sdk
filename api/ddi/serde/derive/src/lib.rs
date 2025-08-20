// Copyright (C) Microsoft Corporation. All rights reserved.

mod decode;
mod encode;
mod len;

mod open_enum;
mod r#struct;

use proc_macro::TokenStream;
use syn::spanned::Spanned;

/// Derive macro for generating DDI encoding/decoding functions
///
/// # Arguments
///
/// * `input` - Input `TokenStream`
///
/// # Returns
///
/// * Output `TokenStream`
#[proc_macro_derive(Ddi, attributes(ddi))]
pub fn ddi(input: TokenStream) -> TokenStream {
    let mut input = syn::parse_macro_input!(input as syn::DeriveInput);
    let result = match &input.data {
        syn::Data::Struct(datastruct) => match &datastruct.fields {
            syn::Fields::Named(_) => on_struct(&mut input),
            syn::Fields::Unnamed(_) => on_open_enum(&mut input),
            syn::Fields::Unit => {
                let msg = "deriving `mcr-ddi-derive::Ddi` for a `struct` with unit fields is not supported";
                Err(syn::Error::new(datastruct.fields.span(), msg))
            }
        },
        syn::Data::Enum(e) => {
            let msg = "deriving `mcr-ddi-derive::Ddi` for an `enum` is not supported";
            Err(syn::Error::new(e.enum_token.span(), msg))
        }
        syn::Data::Union(u) => {
            let msg = "deriving `mcr-ddi-derive::Ddi` for a `union` is not supported";
            Err(syn::Error::new(u.union_token.span(), msg))
        }
    };
    proc_macro::TokenStream::from(result.unwrap_or_else(|e| e.to_compile_error()))
}

fn on_struct(input: &mut syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let ddi_struct = r#struct::prase_struct(input)?;
    let len = len::struct_len(&ddi_struct)?;
    let encode = encode::struct_encode(&ddi_struct)?;
    let decode = decode::struct_decode(&ddi_struct)?;

    Ok(quote::quote! {
        #len
        #encode
        #decode
    })
}

fn on_open_enum(input: &mut syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let ddi_open_enum = open_enum::prase_open_enum(input)?;
    let len = len::open_enum_len(&ddi_open_enum)?;
    let encode = encode::open_enum_encode(&ddi_open_enum)?;
    let decode = decode::open_enum_decode(&ddi_open_enum)?;

    Ok(quote::quote! {
        #len
        #encode
        #decode
    })
}

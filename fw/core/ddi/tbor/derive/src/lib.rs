// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tabular Binary Object Representation (TBOR) — derive macros.
//!
//! Provides the `#[tbor]` attribute macro for generating zero-copy
//! View, Encoder, and Frame types from schema struct declarations.

#![allow(clippy::unwrap_used)]

mod codegen_enc;
mod codegen_enum;
mod codegen_fields;
mod codegen_view;
mod codegen_view_mut;
mod schema;

use proc_macro::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::spanned::Spanned;

/// Attribute macro for TBOR protocol types.
///
/// Apply to structs to generate zero-copy View, typestate Encoder, and
/// Frame types. Apply to enums to generate `TryFrom`/`From` conversions.
///
/// # Struct attributes
///
/// - `#[tbor(opcode = 0x09)]` — request message with the given opcode
/// - `#[tbor(response)]` — response message
/// - `#[tbor(fields)]` — reusable field group (no top-level codec)
#[proc_macro_attribute]
pub fn tbor(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input: syn::Item = syn::parse_macro_input!(item as syn::Item);

    let result = match input {
        syn::Item::Struct(ref s) => on_struct(attr.into(), s),
        syn::Item::Enum(ref e) => codegen_enum::gen_enum(e),
        _ => Err(syn::Error::new(
            input.span(),
            "#[tbor] can only be applied to structs and enums",
        )),
    };

    TokenStream::from(result.unwrap_or_else(|e| e.to_compile_error()))
}

/// Handle `#[tbor]` on a struct: parse the schema and generate the View,
/// Encoder, Frame, and namespace struct.
fn on_struct(
    attr: proc_macro2::TokenStream,
    input: &syn::ItemStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    let schema = schema::parse_struct_schema(attr, input)?;

    // Field groups get different codegen — no full encoder/decoder/frame.
    if matches!(schema.kind, schema::MessageKind::Fields) {
        return Ok(codegen_fields::gen_field_group(&schema));
    }

    let align_assertions = schema.align_assertions();
    let view_tokens = codegen_view::gen_view(&schema);
    let view_mut_tokens = codegen_view_mut::gen_view_mut(&schema);
    let enc_tokens = codegen_enc::gen_encoder_and_frame(&schema);

    let name = &schema.name;
    let vis = &schema.vis;
    let view_name = format_ident!("{}View", schema.name);
    let view_mut_name = format_ident!("{}ViewMut", schema.name);
    let enc_name = format_ident!("{}Enc", schema.name);
    let s0 = format_ident!("{}S0", schema.name);

    let validation = codegen_view::gen_validation_standalone(&schema);

    let decode_fn = quote! {
        pub fn decode(buf: &azihsm_fw_hsm_pal_traits::DmaBuf) -> Result<#view_name<'_>, azihsm_fw_hsm_pal_traits::HsmError> {
            #validation
            Ok(#view_name::from_validated(buf))
        }
    };

    // `decode_mut` is emitted only when the schema opts in via
    // `#[tbor(mutable)]` on at least one field. The body is built by
    // `codegen_view_mut`: a full validation pass via a shared
    // reborrow, then a pipelined `split_at_mut` that hands out
    // per-field borrows at the parent buffer's lifetime.
    let decode_mut_fn = if let Some(body) = codegen_view_mut::gen_decode_mut_body(&schema) {
        quote! {
            pub fn decode_mut(buf: &mut azihsm_fw_hsm_pal_traits::DmaBuf) -> Result<#view_mut_name<'_>, azihsm_fw_hsm_pal_traits::HsmError> {
                #body
            }
        }
    } else {
        quote! {}
    };

    let encode_fn = match schema.kind {
        schema::MessageKind::Request { .. } => quote! {
            pub fn encode<'a>(buf: &'a mut [u8]) -> Result<#enc_name<'a, #s0>, azihsm_fw_hsm_pal_traits::HsmError> {
                #enc_name::new(buf)
            }
        },
        schema::MessageKind::Response => quote! {
            pub fn encode<'a>(buf: &'a mut [u8], status: u32, fips_approved: bool) -> Result<#enc_name<'a, #s0>, azihsm_fw_hsm_pal_traits::HsmError> {
                #enc_name::new(buf, status, fips_approved)
            }
        },
        schema::MessageKind::Fields => unreachable!(),
    };

    let max_encoded_size = schema.max_encoded_size();

    // Generate trait impl for dispatch.
    let trait_impl = match schema.kind {
        schema::MessageKind::Request { opcode } => quote! {
            impl azihsm_fw_ddi_tbor::TborRequest for #name {
                const OPCODE: u8 = #opcode;
                type View<'a> = #view_name<'a>;

                fn decode(buf: &azihsm_fw_hsm_pal_traits::DmaBuf) -> Result<Self::View<'_>, azihsm_fw_hsm_pal_traits::HsmError> {
                    #name::decode(buf)
                }
            }
        },
        schema::MessageKind::Response => quote! {
            impl azihsm_fw_ddi_tbor::TborResponse for #name {
                type View<'a> = #view_name<'a>;

                fn decode(buf: &azihsm_fw_hsm_pal_traits::DmaBuf) -> Result<Self::View<'_>, azihsm_fw_hsm_pal_traits::HsmError> {
                    #name::decode(buf)
                }
            }
        },
        schema::MessageKind::Fields => unreachable!(),
    };

    Ok(quote! {
        #vis struct #name;

        #align_assertions

        impl #name {
            /// Maximum possible encoded message size for this type.
            pub const MAX_ENCODED_SIZE: usize = #max_encoded_size;
            #decode_fn
            #decode_mut_fn
            #encode_fn
        }

        #trait_impl

        #view_tokens
        #view_mut_tokens
        #enc_tokens
    })
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for [`MborEncode`] trait implementations.
//!
//! This module emits `MborEncode` impls for two DDI item kinds:
//!
//! * **Map structs** (`#[ddi(map)]`) — encoded by writing an MBOR map header
//!   with the active field count (excluding `None` optionals), followed by
//!   each field's ID and value. Byte-slice fields include length validation
//!   and appropriate padding.
//! * **Open-enum newtypes** (`#[ddi(enumeration)]`) — encoded by writing the
//!   inner `u32` directly.

use quote::quote;

use crate::open_enum::DdiOpenEnum;
use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructField;
use crate::r#struct::DdiStructFieldKind;

/// Generates an `impl MborEncode` block for a `#[ddi(map)]` struct.
///
/// The generated code:
/// 1. Computes the active field count by starting from the total number of
///    fields and subtracting one for each `Option` field that is `None`.
/// 2. Writes an MBOR map header with that count.
/// 3. For each field, writes the field ID (`u8`) followed by the encoded
///    value. Optional fields are guarded by `if let Some(…)`.
///    Byte-slice fields include a length check (`len` or `max_len`) before
///    encoding with [`MborByteSlice`] or [`MborPaddedByteSlice`].
///
/// # Parameters
/// - `ddi`: Parsed struct descriptor from [`crate::r#struct::parse_struct`].
pub(crate) fn struct_encode(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;
    let field_cnt = ddi.fields.len();
    let lifetimes = &ddi.lifetimes;

    let enc_cnt = ddi
        .fields
        .iter()
        .map(|f| {
            if f.opt {
                let fname = &f.ident;
                quote! { if self.#fname.is_none() { cnt -= 1; } }
            } else {
                quote!()
            }
        })
        .collect::<Vec<_>>();

    let enc_fields = ddi
        .fields
        .iter()
        .map(encode_field_binding)
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<#(#lifetimes,)*> azihsm_fw_ddi_mbor::MborEncode for #ident<#(#lifetimes,)*> {
            fn mbor_encode(
                &self,
                encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'_>,
            ) -> Result<(), azihsm_fw_ddi_mbor::MborEncodeError>
            {
                let mut cnt = #field_cnt as azihsm_fw_ddi_mbor::MborId;
                #(#enc_cnt)*
                azihsm_fw_ddi_mbor::MborMap(cnt).mbor_encode(encoder)?;
                #( #enc_fields )*
                Ok(())
            }
        }
    })
}

/// Bind a field value and generate its encode body.
///
/// Optional fields use `if let Some(name) = &self.name`;
/// required fields use `let name = &self.name`.
fn encode_field_binding(f: &DdiStructField) -> proc_macro2::TokenStream {
    let name = &f.ident;
    let body = mbor_encode_field(f);

    if f.opt {
        quote! { if let Some(#name) = &self.#name { #body } }
    } else {
        quote! { let #name = &self.#name; #body }
    }
}

/// Generate the encode body for a single field (after the `let name = ...`
/// binding has been emitted by the caller).
fn mbor_encode_field(field: &DdiStructField) -> proc_macro2::TokenStream {
    let id = field.id;

    let len_check = encode_len_check(field);
    let value_encode = encode_value(field);

    quote! {
        #len_check
        #id.mbor_encode(encoder)?;
        #value_encode
    }
}

/// Generate an optional length validation check for Slice fields.
///
/// - `len = N`     → `if name.len() != N { return Err(InvalidLen) }`
/// - `max_len = N` → `if name.len() > N  { return Err(InvalidLen) }`
/// - neither       → empty (no check)
/// - non-Slice     → empty
fn encode_len_check(field: &DdiStructField) -> proc_macro2::TokenStream {
    let name = &field.ident;

    if field.kind != DdiStructFieldKind::Slice {
        return quote! {};
    }

    if let Some(exact) = field.len {
        quote! {
            if #name.len() != #exact {
                return Err(azihsm_fw_ddi_mbor::MborEncodeError::InvalidLen);
            }
        }
    } else if let Some(max) = field.max_len {
        quote! {
            if #name.len() > #max {
                return Err(azihsm_fw_ddi_mbor::MborEncodeError::InvalidLen);
            }
        }
    } else {
        quote! {}
    }
}

/// Generate the value-encoding expression for a field.
fn encode_value(field: &DdiStructField) -> proc_macro2::TokenStream {
    let name = &field.ident;

    match field.kind {
        DdiStructFieldKind::Array => {
            quote! { azihsm_fw_ddi_mbor::MborByteSlice(#name).mbor_encode(encoder)?; }
        }
        DdiStructFieldKind::Slice if field.len.is_some() => {
            // Fixed-size, no padding (was [u8; N])
            quote! { azihsm_fw_ddi_mbor::MborByteSlice(#name).mbor_encode(encoder)?; }
        }
        DdiStructFieldKind::Slice => {
            // Variable-size, padded (was MborByteArray<N>)
            let data_ref = if field.opt {
                quote! { *#name }
            } else {
                quote! { #name }
            };
            quote! {
                let pad = azihsm_fw_ddi_mbor::pad4(encoder.position() as u32 + 3) as u8;
                azihsm_fw_ddi_mbor::MborPaddedByteSlice(#data_ref, pad).mbor_encode(encoder)?;
            }
        }
        DdiStructFieldKind::Normal => {
            quote! { #name.mbor_encode(encoder)?; }
        }
    }
}

/// Generates an `impl MborEncode` block for a `#[ddi(enumeration)]`
/// open-enum newtype.
///
/// The generated code delegates to `self.0.mbor_encode(encoder)`, encoding
/// the inner `u32` directly without a map header or field ID.
///
/// # Parameters
/// - `ddi`: Parsed open-enum descriptor from [`crate::open_enum::parse_open_enum`].
pub(crate) fn open_enum_encode(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl azihsm_fw_ddi_mbor::MborEncode for #ident {
            fn mbor_encode(
                &self,
                encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'_>,
            ) -> Result<(), azihsm_fw_ddi_mbor::MborEncodeError>
            {
                self.0.mbor_encode(encoder)
            }
        }
    })
}

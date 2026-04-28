// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for [`MborLen`] trait implementations.
//!
//! This module emits `MborLen` impls that compute the total encoded byte
//! length of a DDI item without actually writing any data. The length is
//! accumulated via an [`MborLenAccumulator`] so that callers can pre-allocate
//! an appropriately sized buffer before encoding.
//!
//! Two DDI item kinds are supported:
//!
//! * **Map structs** (`#[ddi(map)]`) — the length includes the map header,
//!   each field ID, and each field value. Optional fields that are `None` are
//!   excluded from both the count and the accumulated length. Padded byte-slice
//!   fields account for 4-byte alignment.
//! * **Open-enum newtypes** (`#[ddi(enumeration)]`) — the length is simply
//!   that of the inner `u32`.

use quote::quote;

use crate::open_enum::DdiOpenEnum;
use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructField;
use crate::r#struct::DdiStructFieldKind;

/// Generates an `impl MborLen` block for a `#[ddi(map)]` struct.
///
/// The generated `mbor_len` method:
/// 1. Starts with the total field count, then subtracts one for each `Option`
///    field that is `None` at runtime.
/// 2. Accumulates the MBOR map header length for that count.
/// 3. For each present field, accumulates the field ID length and the value
///    length. Byte-slice fields use [`MborByteSlice`] (fixed-size) or
///    [`MborPaddedByteSlice`] (variable-size with 4-byte alignment padding).
///
/// # Parameters
/// - `ddi`: Parsed struct descriptor from [`crate::r#struct::parse_struct`].
pub(crate) fn struct_len(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;
    let field_cnt = ddi.fields.len() as u8;
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

    let lens = ddi
        .fields
        .iter()
        .map(|f| {
            if f.opt {
                len_optional_field(f)
            } else {
                len_required_field(f)
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<#(#lifetimes,)*> azihsm_fw_ddi_mbor::MborLen for #ident<#(#lifetimes,)*> {
            fn mbor_len(&self, acc: &mut azihsm_fw_ddi_mbor::MborLenAccumulator) {
                let mut cnt = #field_cnt as azihsm_fw_ddi_mbor::MborId;
                #(#enc_cnt)*
                azihsm_fw_ddi_mbor::MborMap(cnt).mbor_len(acc);
                #(#lens)*
            }
        }
    })
}

/// Generate length accumulation for a required field.
fn len_required_field(f: &DdiStructField) -> proc_macro2::TokenStream {
    let name = &f.ident;
    let id = &f.id;
    let value_len = match f.kind {
        DdiStructFieldKind::Array => {
            quote! { azihsm_fw_ddi_mbor::MborByteSlice(&self.#name).mbor_len(acc); }
        }
        DdiStructFieldKind::Slice if f.len.is_some() => {
            quote! { azihsm_fw_ddi_mbor::MborByteSlice(self.#name).mbor_len(acc); }
        }
        DdiStructFieldKind::Slice => {
            quote! {
                let pad = azihsm_fw_ddi_mbor::pad4(acc.len() as u32 + 3);
                azihsm_fw_ddi_mbor::MborPaddedByteSlice(self.#name, pad as u8).mbor_len(acc);
            }
        }
        DdiStructFieldKind::Normal => {
            quote! { self.#name.mbor_len(acc); }
        }
    };
    quote! {
        #id.mbor_len(acc);
        #value_len
    }
}

/// Generate length accumulation for an optional field.
fn len_optional_field(f: &DdiStructField) -> proc_macro2::TokenStream {
    let name = &f.ident;
    let id = &f.id;
    let value_len = match f.kind {
        DdiStructFieldKind::Array => {
            quote! { azihsm_fw_ddi_mbor::MborByteSlice(value).mbor_len(acc); }
        }
        DdiStructFieldKind::Slice if f.len.is_some() => {
            quote! { azihsm_fw_ddi_mbor::MborByteSlice(*value).mbor_len(acc); }
        }
        DdiStructFieldKind::Slice => {
            quote! {
                let pad = azihsm_fw_ddi_mbor::pad4(acc.len() as u32 + 3);
                azihsm_fw_ddi_mbor::MborPaddedByteSlice(*value, pad as u8).mbor_len(acc);
            }
        }
        DdiStructFieldKind::Normal => {
            quote! { value.mbor_len(acc); }
        }
    };
    quote! {
        if let Some(value) = &self.#name {
            #id.mbor_len(acc);
            #value_len
        }
    }
}

/// Generates an `impl MborLen` block for a `#[ddi(enumeration)]` open-enum
/// newtype.
///
/// The generated `mbor_len` method delegates to `self.0.mbor_len(acc)`,
/// accumulating the encoded length of the inner `u32`.
///
/// # Parameters
/// - `ddi`: Parsed open-enum descriptor from [`crate::open_enum::parse_open_enum`].
pub(crate) fn open_enum_len(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl azihsm_fw_ddi_mbor::MborLen for #ident {
            fn mbor_len(&self, acc: &mut azihsm_fw_ddi_mbor::MborLenAccumulator) {
                self.0.mbor_len(acc);
            }
        }
    })
}

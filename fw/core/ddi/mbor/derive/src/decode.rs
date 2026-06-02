// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for [`MborDecode`] trait implementations.
//!
//! This module emits `MborDecode<'bytes>` impls for two DDI item kinds:
//!
//! * **Map structs** (`#[ddi(map)]`) — decoded by reading an MBOR map header
//!   and then each field in field-ID order, handling optional fields via
//!   peek-ahead and byte-slice fields via dedicated slice decoders.
//! * **Open-enum newtypes** (`#[ddi(enumeration)]`) — decoded by reading a
//!   single `u32` and wrapping it in the newtype.

use quote::quote;
use syn::GenericArgument;
use syn::PathArguments::AngleBracketed;

use crate::open_enum::DdiOpenEnum;
use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructFieldKind;

/// Generates an `impl MborDecode<'bytes>` block for a `#[ddi(map)]` struct.
///
/// The generated code:
/// 1. Decodes an MBOR map header to obtain the field count.
/// 2. For each field (sorted by `id`), decodes the field ID and value.
///    - Required fields must appear in order; a missing or mismatched ID
///      produces `MborDecodeError::InvalidId`.
///    - Optional fields peek at the next ID and decode only if it matches,
///      otherwise they are set to `None`.
///    - Byte-slice fields use [`slice_decode_expr`] for exact-length or
///      variable-length decoding.
/// 3. Verifies the remaining map count is zero.
///
/// # Parameters
/// - `ddi`: Parsed struct descriptor from [`crate::r#struct::parse_struct`].
pub(crate) fn struct_decode(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;
    let lifetimes = &ddi.lifetimes;
    let map = quote! { let mut cnt = azihsm_fw_ddi_mbor::MborMap::mbor_decode(dec)?; };

    let fields = ddi
        .fields
        .iter()
        .map(|f| {
            if f.opt {
                decode_optional_field(f)
            } else {
                decode_required_field(f)
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<'bytes: #(#lifetimes +)* , #(#lifetimes,)*> azihsm_fw_ddi_mbor::MborDecode<'bytes> for #ident<#(#lifetimes,)*> {
            fn mbor_decode(dec: &mut azihsm_fw_ddi_mbor::MborDecoder<'bytes>) -> Result<Self, azihsm_fw_ddi_mbor::MborDecodeError>
            {
                #map
                let obj = Self {
                    #(#fields,)*
                };

                if cnt.0 != 0 {
                    Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidLen)?;
                }

                Ok(obj)
            }
        }
    })
}

/// Generate decode code for a required (non-optional) field.
fn decode_required_field(f: &crate::r#struct::DdiStructField) -> proc_macro2::TokenStream {
    let fname = &f.ident;
    let ftype = &f.ty;
    let id = f.id;

    let value_expr = if f.kind == DdiStructFieldKind::Slice {
        slice_decode_expr(&f.len, &f.max_len)
    } else {
        quote! { <#ftype>::mbor_decode(dec)? }
    };

    quote! {
        #fname: {
            if cnt.0 == 0 {
                Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidId)?
            }
            let id = u8::mbor_decode(dec)?;
            cnt.0 -= 1;
            if id != #id {
                Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidId)?
            }
            #value_expr
        }
    }
}

/// Generate decode code for an optional field.
///
/// Peeks at the next field ID; if it matches, consumes the ID and
/// decodes the value. Otherwise returns `None` without consuming.
fn decode_optional_field(f: &crate::r#struct::DdiStructField) -> proc_macro2::TokenStream {
    let fname = &f.ident;
    let ftype = &f.ty;
    let id = f.id;

    let value_expr = if f.kind == DdiStructFieldKind::Slice {
        let decode = slice_decode_expr(&f.len, &f.max_len);
        quote! { { let data = { #decode }; Some(data) } }
    } else {
        let inner = opt_type(ftype);
        quote! { Some(<#inner>::mbor_decode(dec)?) }
    };

    quote! {
        #fname: {
            let matched = cnt.0 > 0
                && dec.peek_u8().map_or(false, |next_id| next_id == #id);
            if matched {
                cnt.0 -= 1;
                u8::mbor_decode(dec)?;
                #value_expr
            } else {
                None
            }
        }
    }
}

fn opt_type(ftype: &syn::Type) -> proc_macro2::TokenStream {
    if let syn::Type::Path(p) = ftype {
        if let Some(s) = p.path.segments.last() {
            if let AngleBracketed(a) = s.arguments.clone() {
                if let Some(GenericArgument::Type(t)) = a.args.last() {
                    return quote! { #t };
                }
            }
        }
    }
    quote!()
}

/// Generates an `impl MborDecode<'bytes>` block for a `#[ddi(enumeration)]`
/// open-enum newtype.
///
/// The generated code decodes a single `u32` from the MBOR stream and wraps
/// it in `Self(val)`. No map header or field IDs are involved.
///
/// # Parameters
/// - `ddi`: Parsed open-enum descriptor from [`crate::open_enum::parse_open_enum`].
pub(crate) fn open_enum_decode(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl<'bytes> azihsm_fw_ddi_mbor::MborDecode<'bytes> for #ident {
            fn mbor_decode(dec: &mut azihsm_fw_ddi_mbor::MborDecoder<'bytes>) -> Result<Self, azihsm_fw_ddi_mbor::MborDecodeError>
            {
                let val = u32::mbor_decode(dec)?;
                Ok(Self(val))
            }
        }
    })
}

/// Generate the decode expression for a byte-slice field.
///
/// - `len = N`:     exact length, no padding → `decode_byte_slice_exact(N)`
/// - `max_len = N`: variable length, padded  → `decode_byte_slice()` + max check
/// - neither:       variable length, padded  → `decode_byte_slice()`, no check
fn slice_decode_expr(len: &Option<usize>, max_len: &Option<usize>) -> proc_macro2::TokenStream {
    if let Some(exact) = len {
        // Fixed-size, no padding
        quote! {
            dec.decode_byte_slice_exact(#exact)?
        }
    } else if let Some(max) = max_len {
        // Variable-size, padded, with upper bound
        quote! {
            {
                let (_pad, data) = dec.decode_byte_slice()?;
                if data.len() > #max {
                    Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidLen)?
                }
                data
            }
        }
    } else {
        // Variable-size, padded, no bound
        quote! {
            {
                let (_pad, data) = dec.decode_byte_slice()?;
                data
            }
        }
    }
}

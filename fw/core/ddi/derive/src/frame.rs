// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for the `frame()` encode-then-fill pattern.
//!
//! For structs that contain byte-slice fields, this module generates:
//!
//! * A companion **`<Struct>Frame<'a>`** struct whose fields are `&'a mut [u8]`
//!   slices pointing into reserved regions of the output buffer.
//! * A **`frame()`** associated function on the original struct that encodes
//!   all MBOR framing (map header, field IDs, padding, primitive values) and
//!   reserves space for variable-length byte fields via
//!   [`MborEncoder::encode_reserve`]. The caller can then fill those mutable
//!   slices in-place (e.g., for hardware DMA writes) without a second copy.
//!
//! Structs with only primitive/normal fields produce no frame output.

use quote::format_ident;
use quote::quote;

use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructField;
use crate::r#struct::DdiStructFieldKind;

/// Generates a `<Struct>Frame<'a>` companion struct and a `frame()` associated
/// function for structs that have non-optional byte-slice fields.
///
/// The generated `frame()` function accepts primitive field values directly and
/// byte-slice lengths (as `<field>_len: usize`). It:
/// 1. Writes the MBOR map header with the non-optional field count.
/// 2. Encodes primitive and array fields inline.
/// 3. For each byte-slice field, encodes the field ID and calls
///    `encode_reserve(len, pad)` to obtain a `&'a mut [u8]` in the output
///    buffer. Fixed-size slices (`len` attribute) use no padding; variable-size
///    slices are 4-byte aligned.
/// 4. Returns a `<Struct>Frame` whose fields are the reserved mutable slices.
///
/// If the struct has no non-optional slice fields, no code is generated.
///
/// # Parameters
/// - `ddi`: Parsed struct descriptor from [`crate::r#struct::parse_struct`].
pub(crate) fn struct_frame(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let has_reservable = ddi
        .fields
        .iter()
        .any(|f| !f.opt && f.kind == DdiStructFieldKind::Slice);

    if !has_reservable {
        return Ok(quote! {});
    }

    let ident = &ddi.ident;
    let frame_ident = format_ident!("{}Frame", ident);

    // ── Frame struct fields: &'a mut [u8] for each Slice field ─────
    let frame_fields = ddi
        .fields
        .iter()
        .filter(|f| !f.opt && f.kind == DdiStructFieldKind::Slice)
        .map(|f| {
            let name = &f.ident;
            quote! { pub #name: &'a mut [u8] }
        })
        .collect::<Vec<_>>();

    // ── frame() parameters: primitives by value, slices by length ─────
    let frame_params = ddi
        .fields
        .iter()
        .filter(|f| !f.opt)
        .map(|f| {
            let name = &f.ident;
            match f.kind {
                DdiStructFieldKind::Slice => {
                    let len_name = format_ident!("{}_len", name);
                    quote! { #len_name: usize }
                }
                DdiStructFieldKind::Normal | DdiStructFieldKind::Array => {
                    let ty = &f.ty;
                    quote! { #name: #ty }
                }
            }
        })
        .collect::<Vec<_>>();

    // ── frame() body: encode inline primitives, reserve slices ────────
    let field_cnt = ddi.fields.iter().filter(|f| !f.opt).count();
    let frame_body = ddi
        .fields
        .iter()
        .filter(|f| !f.opt)
        .map(frame_encode_field)
        .collect::<Vec<_>>();

    // ── Frame struct construction ─────────────────────────────────────
    let frame_init = ddi
        .fields
        .iter()
        .filter(|f| !f.opt && f.kind == DdiStructFieldKind::Slice)
        .map(|f| {
            let name = &f.ident;
            quote! { #name }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        /// Frame struct with mutable slices for hardware DMA.
        ///
        /// Each `&mut [u8]` field points to a reserved region in the
        /// output buffer where hardware engines can write directly.
        pub struct #frame_ident<'a> {
            #(#frame_fields,)*
        }

        impl #ident<'_> {
            /// Write all MBOR structure (map header, field IDs, markers,
            /// lengths, padding) into the encoder and return mutable
            /// slices for byte-array fields.
            ///
            /// Primitive fields are encoded inline. Byte-slice fields are
            /// reserved via [`MborEncoder::encode_reserve`] and returned
            /// as `&mut [u8]` in the frame struct for hardware to fill.
            pub fn frame<'a>(
                encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'a>,
                #(#frame_params,)*
            ) -> Result<#frame_ident<'a>, azihsm_fw_ddi_mbor::MborEncodeError> {
                use azihsm_fw_ddi_mbor::MborEncode;

                let cnt = #field_cnt as azihsm_fw_ddi_mbor::MborId;
                azihsm_fw_ddi_mbor::MborMap(cnt).mbor_encode(encoder)?;

                #(#frame_body)*

                Ok(#frame_ident {
                    #(#frame_init,)*
                })
            }
        }
    })
}

/// Generate the frame encode body for a single non-optional field.
///
/// - **Slice** fields: encode field ID, then `encode_reserve()` to get
///   a `&mut [u8]` for hardware to fill. Uses padding for variable-size
///   fields, no padding for fixed-size (`len`).
/// - **Array/Normal** fields: encode field ID + value inline.
fn frame_encode_field(f: &DdiStructField) -> proc_macro2::TokenStream {
    let id = f.id;
    let name = &f.ident;

    match f.kind {
        DdiStructFieldKind::Slice => {
            let len_name = format_ident!("{}_len", name);
            let pad_expr = if f.len.is_some() {
                quote! { 0 }
            } else {
                quote! { azihsm_fw_ddi_mbor::pad4(encoder.position() as u32 + 3) as u8 }
            };
            quote! {
                (#id).mbor_encode(encoder)?;
                let pad = #pad_expr;
                let #name = encoder.encode_reserve(#len_name, pad)?;
            }
        }
        DdiStructFieldKind::Array => {
            quote! {
                (#id).mbor_encode(encoder)?;
                azihsm_fw_ddi_mbor::MborByteSlice(&#name).mbor_encode(encoder)?;
            }
        }
        DdiStructFieldKind::Normal => {
            quote! {
                (#id).mbor_encode(encoder)?;
                #name.mbor_encode(encoder)?;
            }
        }
    }
}

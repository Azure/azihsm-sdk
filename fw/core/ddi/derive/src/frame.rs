// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use quote::format_ident;
use quote::quote;

use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructFieldKind;

/// Generate a `[Struct]Frame<'a>` struct and a `frame()` associated function
/// for structs that have Slice or Array fields. Structs with only Normal
/// fields produce no frame output.
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
        .map(|f| {
            let id = f.id;
            let name = &f.ident;
            match f.kind {
                DdiStructFieldKind::Slice => {
                    let len_name = format_ident!("{}_len", name);
                    if f.len.is_some() {
                        // Fixed-size, no padding (was [u8; N])
                        quote! {
                            (#id).mbor_encode(encoder)?;
                            let #name = encoder.encode_reserve(#len_name, 0)?;
                        }
                    } else {
                        // Variable-size, padded (was MborByteArray<N>)
                        quote! {
                            (#id).mbor_encode(encoder)?;
                            let pad = azihsm_fw_ddi_mbor::pad4(encoder.position() as u32 + 3) as u8;
                            let #name = encoder.encode_reserve(#len_name, pad)?;
                        }
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
        })
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

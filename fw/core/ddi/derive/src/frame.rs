// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for the `frame()` encode-then-fill pattern.
//!
//! For structs that contain byte-slice fields or `#[ddi(frame)]` children,
//! this module generates:
//!
//! * A companion **`<Struct>Frame<'a>`** struct whose fields are `&'a mut [u8]`
//!   slices (for direct byte-slice fields) or nested `<Child>Frame<'a>` structs
//!   (for `#[ddi(frame)]` children).
//! * A **`<Struct>FrameParams`** struct that bundles the parameters for
//!   `frame()` — lengths for slice fields, values for inline primitives,
//!   and nested `FrameParams` for `#[ddi(frame)]` children.
//! * A **`frame()`** associated function on the original struct.
//! * An **`impl MborFrameable`** that delegates to `frame()` via the params
//!   struct, enabling this struct to be nested inside another frame.
//!
//! Structs with only primitive/normal (non-frame) fields produce no output.

use quote::format_ident;
use quote::quote;

use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructField;
use crate::r#struct::DdiStructFieldKind;

/// Returns `true` if the field participates in the frame pattern —
/// either a direct non-optional slice, or a `#[ddi(frame)]` child.
fn is_frameable_field(f: &DdiStructField) -> bool {
    !f.opt && (f.kind == DdiStructFieldKind::Slice || f.frame)
}

/// Generates frame support: `Frame`, `FrameParams`, `frame()`, and
/// `MborFrameable` for structs with a frame path.
///
/// A struct has a frame path if it has at least one non-optional slice
/// field **or** at least one `#[ddi(frame)]` child.
pub(crate) fn struct_frame(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let has_frame_path = ddi.fields.iter().any(is_frameable_field);

    if !has_frame_path {
        return Ok(quote! {});
    }

    let ident = &ddi.ident;
    let frame_ident = format_ident!("{}Frame", ident);
    let params_ident = format_ident!("{}FrameParams", ident);

    // FrameParams needs lifetime parameters when Normal (non-frame)
    // fields carry borrowed data (e.g., `DdiTargetKeyProperties<'a>`).
    let params_needs_lifetime = ddi
        .fields
        .iter()
        .any(|f| !f.opt && !f.frame && f.kind == DdiStructFieldKind::Normal && has_lifetime(&f.ty));
    let lifetimes = &ddi.lifetimes;
    let params_lifetimes = if params_needs_lifetime {
        lifetimes.clone()
    } else {
        vec![]
    };

    // ── Frame struct fields ───────────────────────────────────────────
    let frame_fields = ddi
        .fields
        .iter()
        .filter(|f| is_frameable_field(f))
        .map(|f| {
            let name = &f.ident;
            if f.frame {
                // Nested frame: use child's Frame type via MborFrameable.
                let ty = strip_lifetime(&f.ty);
                quote! {
                    pub #name: <#ty as azihsm_fw_ddi_mbor::MborFrameable>::Frame<'a>
                }
            } else {
                // Direct slice: &'a mut [u8].
                quote! { pub #name: &'a mut [u8] }
            }
        })
        .collect::<Vec<_>>();

    // ── FrameParams struct fields ─────────────────────────────────────
    let params_fields = ddi
        .fields
        .iter()
        .filter(|f| !f.opt)
        .map(|f| {
            let name = &f.ident;
            if f.frame {
                let ty = strip_lifetime(&f.ty);
                quote! {
                    pub #name: <#ty as azihsm_fw_ddi_mbor::MborFrameable>::FrameParams
                }
            } else {
                match f.kind {
                    DdiStructFieldKind::Slice => {
                        let len_name = format_ident!("{}_len", name);
                        quote! { pub #len_name: usize }
                    }
                    DdiStructFieldKind::Normal | DdiStructFieldKind::Array => {
                        let ty = &f.ty;
                        quote! { pub #name: #ty }
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    // ── frame() parameters (positional, matching FrameParams order) ───
    let frame_params = ddi
        .fields
        .iter()
        .filter(|f| !f.opt)
        .map(|f| {
            let name = &f.ident;
            if f.frame {
                let ty = strip_lifetime(&f.ty);
                quote! {
                    #name: <#ty as azihsm_fw_ddi_mbor::MborFrameable>::FrameParams
                }
            } else {
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
            }
        })
        .collect::<Vec<_>>();

    // ── frame() body ──────────────────────────────────────────────────
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
        .filter(|f| is_frameable_field(f))
        .map(|f| {
            let name = &f.ident;
            quote! { #name }
        })
        .collect::<Vec<_>>();

    // ── MborFrameable impl (only when FrameParams is lifetime-free) ──
    // Structs whose FrameParams need lifetimes (because they have Normal
    // fields with borrowed data) cannot implement MborFrameable — they
    // are top-level response structs, not nested frame children.
    let frameable_impl = if params_needs_lifetime {
        quote! {}
    } else {
        let frameable_destructure = ddi
            .fields
            .iter()
            .filter(|f| !f.opt)
            .map(|f| {
                let name = &f.ident;
                if f.frame || f.kind != DdiStructFieldKind::Slice {
                    quote! { #name }
                } else {
                    let len_name = format_ident!("{}_len", name);
                    quote! { #len_name }
                }
            })
            .collect::<Vec<_>>();
        let frameable_call_args = frameable_destructure.clone();

        // Use <'_> for structs with lifetimes, bare ident for others.
        let self_ty = if lifetimes.is_empty() {
            quote! { #ident }
        } else {
            quote! { #ident<'_> }
        };

        quote! {
            impl azihsm_fw_ddi_mbor::MborFrameable for #self_ty {
                type FrameParams = #params_ident;
                type Frame<'a> = #frame_ident<'a>;

                fn mbor_frame<'a>(
                    encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'a>,
                    params: Self::FrameParams,
                ) -> Result<Self::Frame<'a>, azihsm_fw_ddi_mbor::MborEncodeError> {
                    let #params_ident { #(#frameable_destructure,)* } = params;
                    #ident::frame(encoder, #(#frameable_call_args,)*)
                }
            }
        }
    };

    Ok(quote! {
        /// Frame struct with mutable slices for in-place fill.
        ///
        /// Each `&mut [u8]` field points to a reserved region in the
        /// output buffer. Nested frame fields expose the child's frame
        /// struct for recursive in-place fill.
        pub struct #frame_ident<'a> {
            #(#frame_fields,)*
        }

        /// Bundled parameters for [`frame()`](#ident::frame).
        ///
        /// Lengths for slice fields, values for inline primitives, and
        /// nested `FrameParams` for `#[ddi(frame)]` children.
        pub struct #params_ident<#(#params_lifetimes,)*> {
            #(#params_fields,)*
        }

        impl #ident<'_> {
            /// Write MBOR structure and return mutable slices / nested
            /// frames for in-place fill.
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

        #frameable_impl
    })
}

/// Generate the frame encode body for a single non-optional field.
fn frame_encode_field(f: &DdiStructField) -> proc_macro2::TokenStream {
    let id = f.id;
    let name = &f.ident;

    if f.frame {
        // Nested frame: delegate to child's MborFrameable::mbor_frame.
        let ty = strip_lifetime(&f.ty);
        return quote! {
            (#id).mbor_encode(encoder)?;
            let #name = <#ty as azihsm_fw_ddi_mbor::MborFrameable>::mbor_frame(
                encoder, #name,
            )?;
        };
    }

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

/// Strip lifetime parameters from a type for use in trait bounds.
///
/// Converts `DdiPublicKey<'a>` → `DdiPublicKey<'static>` so that the
/// `MborFrameable` trait bound resolves correctly in generated struct
/// definitions and impl blocks.
fn strip_lifetime(ty: &syn::Type) -> proc_macro2::TokenStream {
    match ty {
        syn::Type::Path(type_path) => {
            let segments = type_path
                .path
                .segments
                .iter()
                .map(|seg| {
                    let ident = &seg.ident;
                    match &seg.arguments {
                        syn::PathArguments::AngleBracketed(args) => {
                            let replaced = args
                                .args
                                .iter()
                                .map(|arg| match arg {
                                    syn::GenericArgument::Lifetime(_) => {
                                        quote! { 'static }
                                    }
                                    other => quote! { #other },
                                })
                                .collect::<Vec<_>>();
                            quote! { #ident<#(#replaced),*> }
                        }
                        _ => quote! { #ident },
                    }
                })
                .collect::<Vec<_>>();
            quote! { #(#segments)::* }
        }
        _ => quote! { #ty },
    }
}

/// Returns `true` if a type contains any lifetime parameter.
fn has_lifetime(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(type_path) => type_path.path.segments.iter().any(|seg| {
            if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                args.args
                    .iter()
                    .any(|arg| matches!(arg, syn::GenericArgument::Lifetime(_)))
            } else {
                false
            }
        }),
        syn::Type::Reference(_) => true,
        _ => false,
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for the `frame()` encode-then-fill pattern.
//!
//! For structs that contain byte-slice fields or `#[ddi(frame)]` children,
//! this module generates:
//!
//! * A companion **`<Struct>Frame<'a>`** struct whose fields are `&'a mut DmaBuf`
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
    let layout_ident = format_ident!("{}Layout", ident);

    // `FrameParams` needs the struct's lifetime when any field carried *by
    // value* there borrows data. A field is carried by value in
    // `FrameParams` when it is optional (any kind — threaded through as its
    // own `Option<T>`, e.g. `Option<DdiPublicKey<'a>>` or `Option<&'a [u8]>`)
    // or a non-frame `Normal`/`Array` field (e.g. `DdiTargetKeyProperties<'a>`).
    // Reserved fields never contribute a lifetime: a non-optional slice
    // becomes a `usize` length, and a `#[ddi(frame)]` child becomes a
    // lifetime-free child `FrameParams`.
    let params_needs_lifetime = ddi.fields.iter().any(|f| {
        let by_value = f.opt
            || (!f.frame
                && matches!(
                    f.kind,
                    DdiStructFieldKind::Normal | DdiStructFieldKind::Array
                ));
        by_value && has_lifetime(&f.ty)
    });

    // A struct with any optional field is a top-level response frame, never
    // a nested `#[ddi(frame)]` child (whose fields must all be present), so
    // it does not implement `MborFrameable`.
    let has_optional_field = ddi.fields.iter().any(|f| f.opt);
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
                // Direct slice: &'a mut DmaBuf.
                quote! { pub #name: &'a mut azihsm_fw_ddi_mbor::DmaBuf }
            }
        })
        .collect::<Vec<_>>();

    // ── Layout struct fields ─────────────────────────────────────────
    let layout_fields = ddi
        .fields
        .iter()
        .filter(|f| is_frameable_field(f))
        .map(|f| {
            let name = &f.ident;
            if f.frame {
                let ty = strip_lifetime(&f.ty);
                quote! {
                    pub #name: <#ty as azihsm_fw_ddi_mbor::MborFrameable>::Layout
                }
            } else {
                quote! { pub #name: core::ops::Range<usize> }
            }
        })
        .collect::<Vec<_>>();

    // ── FrameParams struct fields ─────────────────────────────────────
    let params_fields = ddi
        .fields
        .iter()
        .map(|f| {
            let name = &f.ident;
            if f.opt {
                // By-value optional field (never reserved): carried as its
                // own `Option<T>` type and encoded only when present.
                let ty = &f.ty;
                quote! { pub #name: #ty }
            } else if f.frame {
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
        .map(|f| {
            let name = &f.ident;
            if f.opt {
                let ty = &f.ty;
                quote! { #name: #ty }
            } else if f.frame {
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
    // The map entry count is resolved at runtime: start from the total
    // field count and drop one for every `None` optional (mirroring the
    // normal `MborEncode` path). Reserved fields are always non-optional
    // and always present.
    let field_cnt = ddi.fields.len();
    let enc_cnt = {
        let checks = ddi.fields.iter().filter(|f| f.opt).map(|f| {
            let name = &f.ident;
            quote! { if #name.is_none() { cnt -= 1; } }
        });
        quote! { #(#checks)* }
    };
    let frame_body = ddi
        .fields
        .iter()
        .map(frame_encode_field)
        .collect::<Vec<_>>();

    // ── reserve() body — mirrors frame_body but uses reserve_offset
    //    for slice fields and mbor_reserve for nested frames.
    let reserve_body = ddi
        .fields
        .iter()
        .map(reserve_encode_field)
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

    // ── Layout struct construction (used by reserve()) ────────────────
    let layout_init = frame_init.clone();

    // ── from_layout() body — rebuild Frame from buf_ptr + Layout.
    let from_layout_fields = ddi
        .fields
        .iter()
        .filter(|f| is_frameable_field(f))
        .map(|f| {
            let name = &f.ident;
            if f.frame {
                let ty = strip_lifetime(&f.ty);
                quote! {
                    let #name = <#ty as azihsm_fw_ddi_mbor::MborFrameable>::mbor_from_layout(
                        buf_ptr,
                        &layout.#name,
                    );
                }
            } else {
                quote! {
                    let #name = azihsm_fw_ddi_mbor::DmaBuf::from_raw_mut(
                        core::slice::from_raw_parts_mut(
                            buf_ptr.add(layout.#name.start),
                            layout.#name.end - layout.#name.start,
                        )
                    );
                }
            }
        })
        .collect::<Vec<_>>();

    // ── MborFrameable impl (only when FrameParams is lifetime-free) ──
    // Structs whose FrameParams need lifetimes (because they have Normal
    // fields with borrowed data) cannot implement MborFrameable — they
    // are top-level response structs, not nested frame children.
    let frameable_impl = if params_needs_lifetime || has_optional_field {
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
        let reserve_call_args = frameable_destructure.clone();

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
                type Layout = #layout_ident;

                fn mbor_frame<'a>(
                    encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'a>,
                    params: Self::FrameParams,
                ) -> Result<Self::Frame<'a>, azihsm_fw_ddi_mbor::MborEncodeError> {
                    let #params_ident { #(#frameable_destructure,)* } = params;
                    #ident::frame(encoder, #(#frameable_call_args,)*)
                }

                fn mbor_reserve(
                    encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'_>,
                    params: Self::FrameParams,
                ) -> Result<Self::Layout, azihsm_fw_ddi_mbor::MborEncodeError> {
                    let #params_ident { #(#frameable_destructure,)* } = params;
                    #ident::reserve(encoder, #(#reserve_call_args,)*)
                }

                #[allow(unsafe_code)]
                unsafe fn mbor_from_layout<'a>(
                    buf_ptr: *mut u8,
                    layout: &Self::Layout,
                ) -> Self::Frame<'a> {
                    #ident::from_layout_raw(buf_ptr, layout)
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

        /// Layout describing where each reservable field of
        /// [`#frame_ident`] sits inside the encoder's output buffer.
        ///
        /// Produced by [`reserve()`](#ident::reserve) and consumed by
        /// [`from_layout()`](#ident::from_layout) to materialize a
        /// [`#frame_ident`] without holding the encoder borrow alive
        /// across an `await`.
        pub struct #layout_ident {
            #(#layout_fields,)*
        }

        impl #ident<'_> {
            /// Write MBOR structure and return mutable slices / nested
            /// frames for in-place fill.
            pub fn frame<'a>(
                encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'a>,
                #(#frame_params,)*
            ) -> Result<#frame_ident<'a>, azihsm_fw_ddi_mbor::MborEncodeError> {
                use azihsm_fw_ddi_mbor::MborEncode;

                let mut cnt = #field_cnt as azihsm_fw_ddi_mbor::MborId;
                #enc_cnt
                azihsm_fw_ddi_mbor::MborMap(cnt).mbor_encode(encoder)?;

                #(#frame_body)*

                Ok(#frame_ident {
                    #(#frame_init,)*
                })
            }

            /// Like [`frame()`](Self::frame), but records each reservable
            /// region's offset range in a [`#layout_ident`] instead of
            /// returning borrows. Pair with [`from_layout()`](Self::from_layout)
            /// to materialize the frame later.
            pub fn reserve<'a>(
                encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'_>,
                #(#frame_params,)*
            ) -> Result<#layout_ident, azihsm_fw_ddi_mbor::MborEncodeError> {
                use azihsm_fw_ddi_mbor::MborEncode;

                let mut cnt = #field_cnt as azihsm_fw_ddi_mbor::MborId;
                #enc_cnt
                azihsm_fw_ddi_mbor::MborMap(cnt).mbor_encode(encoder)?;

                #(#reserve_body)*

                Ok(#layout_ident {
                    #(#layout_init,)*
                })
            }

            /// Materialize a [`#frame_ident`] from a buffer and a layout
            /// produced by [`reserve()`](Self::reserve).
            ///
            /// `buf` must be the same buffer (or the encoder's underlying
            /// buffer) used when `layout` was produced. Otherwise the
            /// returned frame's slices will alias unrelated memory.
            #[allow(unsafe_code)]
            pub fn from_layout<'a>(
                buf: &'a mut azihsm_fw_ddi_mbor::DmaBuf,
                layout: &#layout_ident,
            ) -> #frame_ident<'a> {
                // SAFETY: `layout` was produced by `reserve()` writing into
                // a buffer of which `buf` is the same buffer (or a longer
                // prefix). `reserve()` only ever advances the encoder
                // cursor, so all recorded ranges are non-overlapping and
                // within the buffer's bounds.
                unsafe { Self::from_layout_raw(buf.as_mut_ptr(), layout) }
            }

            /// Raw-pointer variant of [`from_layout()`](Self::from_layout)
            /// used by the [`MborFrameable`] impl to recurse into nested
            /// frames without re-borrowing the parent buffer.
            ///
            /// # Safety
            ///
            /// `buf_ptr` must point to the start of the same buffer used
            /// when `layout` was produced, the buffer must be at least
            /// as long as the largest `end` recorded in `layout`, and no
            /// other live `&mut` references may alias any byte covered by
            /// `layout`'s recorded ranges for the lifetime `'a`.
            #[doc(hidden)]
            #[allow(unsafe_code)]
            pub unsafe fn from_layout_raw<'a>(
                buf_ptr: *mut u8,
                layout: &#layout_ident,
            ) -> #frame_ident<'a> {
                #(#from_layout_fields)*
                #frame_ident {
                    #(#frame_init,)*
                }
            }
        }

        #frameable_impl
    })
}

/// Generate the encode body for a **by-value optional field**, shared by the
/// frame and reserve paths.
///
/// Optional fields are never reserved (see [`is_frameable_field`]), so both
/// paths encode the value inline and identically. The `if let Some(name) =
/// name` binding moves the inner value out of the `Option<T>` param, so
/// `name` is the owned `T` — for a slice that is `&[u8]` (encoded via
/// [`MborByteSlice`]/[`MborPaddedByteSlice`], **not** `T::mbor_encode`), for
/// an array `[u8; N]`, and for a primitive/struct the value itself. This
/// mirrors [`crate::encode::encode_value`] so `frame`/`reserve` produce
/// byte-identical output to `MborEncode`.
fn opt_encode_field(f: &DdiStructField) -> proc_macro2::TokenStream {
    let id = f.id;
    let name = &f.ident;

    let value_encode = match f.kind {
        DdiStructFieldKind::Slice => {
            // Validate length like `encode.rs`, then encode: fixed-size
            // (`len`) slices are unpadded; variable-size (`max_len` or
            // unbounded) slices are padded to 4-byte alignment.
            let len_check = if let Some(exact) = f.len {
                quote! {
                    if #name.len() != #exact {
                        return Err(azihsm_fw_ddi_mbor::MborEncodeError::InvalidLen);
                    }
                }
            } else if let Some(max) = f.max_len {
                quote! {
                    if #name.len() > #max {
                        return Err(azihsm_fw_ddi_mbor::MborEncodeError::InvalidLen);
                    }
                }
            } else {
                quote! {}
            };
            let encode = if f.len.is_some() {
                quote! { azihsm_fw_ddi_mbor::MborByteSlice(#name).mbor_encode(encoder)?; }
            } else {
                quote! {
                    let pad = azihsm_fw_ddi_mbor::pad4(encoder.position() as u32 + 3) as u8;
                    azihsm_fw_ddi_mbor::MborPaddedByteSlice(#name, pad).mbor_encode(encoder)?;
                }
            };
            quote! {
                #len_check
                #encode
            }
        }
        DdiStructFieldKind::Array => {
            quote! { azihsm_fw_ddi_mbor::MborByteSlice(&#name).mbor_encode(encoder)?; }
        }
        DdiStructFieldKind::Normal => {
            quote! { #name.mbor_encode(encoder)?; }
        }
    };

    quote! {
        if let Some(#name) = #name {
            (#id).mbor_encode(encoder)?;
            #value_encode
        }
    }
}

/// Generate the frame encode body for a single non-optional field.
fn frame_encode_field(f: &DdiStructField) -> proc_macro2::TokenStream {
    let id = f.id;
    let name = &f.ident;

    if f.opt {
        // By-value optional field: emit the map entry only when present.
        return opt_encode_field(f);
    }

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
                // SAFETY: `encoder` was constructed from a `&mut DmaBuf`, so
                // the slice it returned is itself DMA-accessible.
                let #name = unsafe { azihsm_fw_ddi_mbor::DmaBuf::from_raw_mut(#name) };
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

/// Generate the reserve encode body for a single non-optional field.
///
/// Mirrors [`frame_encode_field`] but uses [`reserve_offset`] for slice
/// fields (returning a byte range) and [`mbor_reserve`] for nested
/// frames (returning the child's [`Layout`]).
fn reserve_encode_field(f: &DdiStructField) -> proc_macro2::TokenStream {
    let id = f.id;
    let name = &f.ident;

    if f.opt {
        // By-value optional field (never reserved): emit only when present.
        return opt_encode_field(f);
    }

    if f.frame {
        let ty = strip_lifetime(&f.ty);
        return quote! {
            (#id).mbor_encode(encoder)?;
            let #name = <#ty as azihsm_fw_ddi_mbor::MborFrameable>::mbor_reserve(
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
                let #name = encoder.reserve_offset(#len_name, pad)?;
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

/// Returns `true` if a type contains any lifetime parameter, recursing
/// into nested generic type arguments (so e.g. `Option<DdiPublicKey<'a>>`
/// is detected, not just a directly-applied `Foo<'a>`).
fn has_lifetime(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(type_path) => type_path.path.segments.iter().any(|seg| {
            if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                args.args.iter().any(|arg| match arg {
                    syn::GenericArgument::Lifetime(_) => true,
                    syn::GenericArgument::Type(inner) => has_lifetime(inner),
                    _ => false,
                })
            } else {
                false
            }
        }),
        syn::Type::Reference(_) => true,
        _ => false,
    }
}

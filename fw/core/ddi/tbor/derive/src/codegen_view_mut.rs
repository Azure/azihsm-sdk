// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for the `ViewMut` type (zero-copy mutable view).
//!
//! Emitted only when the schema has at least one `#[tbor(mutable)]`
//! field. Unlike `View` (a wrapper that hands out borrows lazily via
//! methods), `ViewMut` is a **destructured** struct: at construction
//! time `decode_mut` performs a pipelined `split_at_mut` of the
//! parent buffer and exposes each field as a directly-accessible
//! public field at the parent buffer's lifetime `'a`.
//!
//! * Mutable-marked buffer/sealed_key fields: `&'a mut DmaBuf`.
//! * Non-mutable buffer/sealed_key fields: `&'a DmaBuf` (reborrowed
//!   from a split-off mutable region; all field borrows are disjoint).
//! * Scalar fields (`u8`/`u16`/`u32`/`u64`/`SessionId`/`KeyId`): owned
//!   by value, copied out of the TOC during construction.
//!
//! ## Layout invariants
//!
//! The destructured construction performs a single forward
//! `split_at_mut` chain over the data section. This requires
//! data-section field offsets to be monotonically non-decreasing in
//! schema (TOC) order. The canonical encoder always produces this
//! layout; any wire message that violates the invariant is rejected
//! with [`azihsm_fw_ddi_tbor::DecodeError::NonMonotonicTocOffsets`].
//!
//! Schemas using `#[tbor(align = N)]` (which inject Padding TOC
//! entries between fields) are currently unsupported in combination
//! with `#[tbor(mutable)]`. None of the current targets need both.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;

use crate::schema::*;

/// Generate the `FooViewMut<'a>` struct definition.
///
/// Returns an empty `TokenStream` for schemas with no
/// `#[tbor(mutable)]` fields; the caller skips emission in that case.
pub fn gen_view_mut(schema: &Schema) -> TokenStream {
    if !schema.has_mutable_fields() {
        return TokenStream::new();
    }

    let vis = &schema.vis;
    let view_mut_name = format_ident!("{}ViewMut", schema.name);
    let name = &schema.name;

    let struct_fields = schema.fields.iter().map(|field| {
        let fname = &field.name;
        let ty = field_type_tokens(field);
        quote! { pub #fname: #ty, }
    });

    quote! {
        /// Destructured zero-copy view over an encoded message. All
        /// fields are pre-split from the parent `&mut DmaBuf` during
        #[doc = concat!("[`", stringify!(#name), "::decode_mut()`],")]
        /// so mutable-marked and shared-marked fields can be held
        /// simultaneously without borrow conflicts.
        #[derive(Debug)]
        #vis struct #view_mut_name<'a> {
            #(#struct_fields)*
        }
    }
}

/// Generate the body of the `decode_mut` function for the given
/// schema, or `None` when the schema has no `#[tbor(mutable)]` field.
///
/// The body validates the wire message via the standard validation
/// pass (using a shared reborrow of the input `&mut DmaBuf`), then
/// drops that borrow, performs a pipelined `split_at_mut` of the
/// data section, and constructs the `ViewMut` struct with all
/// per-field borrows pre-split.
pub fn gen_decode_mut_body(schema: &Schema) -> Option<TokenStream> {
    if !schema.has_mutable_fields() {
        return None;
    }

    let view_mut_name = format_ident!("{}ViewMut", schema.name);
    let header_len = match schema.kind {
        MessageKind::Request { .. } => quote! { azihsm_fw_ddi_tbor::REQ_HEADER_LEN },
        MessageKind::Response => quote! { azihsm_fw_ddi_tbor::RESP_HEADER_LEN },
        MessageKind::Fields => unreachable!(),
    };

    let layout = TocLayout::compute(&schema.fields);

    // Data-section fields (Buffer/SealedKey) in schema (TOC) order.
    // Today only Buffer/SealedKey can be `mutable`; other
    // data-section types (Uint32/Uint64) are admitted as shared
    // fields if present, since they still occupy data-section space.
    let data_fields: Vec<(usize, &SchemaField)> = schema
        .fields
        .iter()
        .enumerate()
        .filter(|(_, f)| f.wire_type.uses_data_section())
        .map(|(i, f)| (layout.field_toc_indices[i], f))
        .collect();

    // Scalar (inline-encoded) field captures: read directly via a
    // transient shared reborrow.
    let scalar_captures: Vec<TokenStream> = schema
        .fields
        .iter()
        .enumerate()
        .filter_map(|(i, field)| {
            let toc_idx = layout.field_toc_indices[i];
            let var = format_ident!("__scalar_{}", field.name);
            let body = match field.wire_type {
                WireType::Uint8 => Some(quote! {
                    azihsm_fw_ddi_tbor::toc::read_toc_inline_u8(&*buf, #header_len, #toc_idx)
                }),
                WireType::Uint16 => Some(quote! {
                    azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(&*buf, #header_len, #toc_idx)
                }),
                WireType::SessionId => Some(quote! {
                    azihsm_fw_ddi_tbor_api::SessionId(
                        azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(&*buf, #header_len, #toc_idx)
                    )
                }),
                WireType::KeyId => Some(quote! {
                    azihsm_fw_ddi_tbor_api::KeyId(
                        azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(&*buf, #header_len, #toc_idx)
                    )
                }),
                _ => None,
            }?;
            Some(quote! { let #var = #body; })
        })
        .collect();

    // (offset, length) captures for each data-section field.
    let offset_captures: Vec<TokenStream> = data_fields
        .iter()
        .map(|(toc_idx, field)| {
            let off_var = format_ident!("__off_{}", field.name);
            let len_var = format_ident!("__len_{}", field.name);
            quote! {
                let (#off_var, #len_var): (usize, usize) = {
                    let __word = azihsm_fw_ddi_tbor::toc::read_toc_word(
                        &*buf, #header_len, #toc_idx
                    );
                    (
                        azihsm_fw_ddi_tbor::toc::raw_toc_offset(__word),
                        azihsm_fw_ddi_tbor::toc::raw_toc_length(__word),
                    )
                };
            }
        })
        .collect();

    // Monotonic-offset check across consecutive data-section fields.
    let monotonic_checks: Vec<TokenStream> = data_fields
        .windows(2)
        .map(|w| {
            let prev_toc = w[0].0;
            let curr_toc = w[1].0;
            let prev_off = format_ident!("__off_{}", w[0].1.name);
            let prev_len = format_ident!("__len_{}", w[0].1.name);
            let curr_off = format_ident!("__off_{}", w[1].1.name);
            quote! {
                if #prev_off.checked_add(#prev_len).is_none_or(|end| end > #curr_off) {
                    return Err(azihsm_fw_ddi_tbor::DecodeError::NonMonotonicTocOffsets {
                        prev_entry: #prev_toc,
                        curr_entry: #curr_toc,
                    });
                }
            }
        })
        .collect();

    // Pipelined `split_at_mut` over the data section.
    let mut split_chain: Vec<TokenStream> = Vec::new();
    let mut prev_off: Option<syn::Ident> = None;
    let mut prev_len: Option<syn::Ident> = None;
    for (_, field) in &data_fields {
        let off_var = format_ident!("__off_{}", field.name);
        let len_var = format_ident!("__len_{}", field.name);
        let field_var = format_ident!("__field_{}", field.name);
        let gap_expr = if let (Some(po), Some(pl)) = (&prev_off, &prev_len) {
            quote! { #off_var - (#po + #pl) }
        } else {
            quote! { #off_var }
        };
        split_chain.push(quote! {
            // Peel the inter-field gap and discard it, then peel the
            // field's bytes. `__rest` is shadowed in each iteration.
            let (__gap, __rest_next) = __rest.split_at_mut(#gap_expr);
            let _ = __gap;
            let (#field_var, __rest) = __rest_next.split_at_mut(#len_var);
        });
        prev_off = Some(off_var);
        prev_len = Some(len_var);
    }
    // The last `let __rest = ...` shadowed is unused; silence warnings.
    split_chain.push(quote! { let _ = __rest; });

    // Reborrow non-mutable data fields as shared.
    let shared_reborrows: Vec<TokenStream> = data_fields
        .iter()
        .filter(|(_, f)| !f.mutable)
        .map(|(_, field)| {
            let field_var = format_ident!("__field_{}", field.name);
            quote! {
                let #field_var: &azihsm_fw_hsm_pal_traits::DmaBuf = &*#field_var;
            }
        })
        .collect();

    // Final struct construction.
    let struct_init: Vec<TokenStream> = schema
        .fields
        .iter()
        .map(|field| {
            let fname = &field.name;
            let value = match field.wire_type {
                WireType::Buffer | WireType::SealedKey => {
                    let v = format_ident!("__field_{}", field.name);
                    quote! { #v }
                }
                // Uint32/Uint64 occupy data-section bytes (so they
                // participate in the split-chain) but the destructured
                // `ViewMut` field type is `u32`/`u64`. Convert the
                // split slice to the numeric value; length was already
                // validated to be exactly 4/8 bytes during Phase 1a.
                WireType::Uint32 => {
                    let v = format_ident!("__field_{}", field.name);
                    quote! {
                        {
                            let __bytes: &[u8] = &**#v;
                            u32::from_le_bytes(
                                <[u8; 4]>::try_from(&__bytes[..4])
                                    .expect("validated length == 4"),
                            )
                        }
                    }
                }
                WireType::Uint64 => {
                    let v = format_ident!("__field_{}", field.name);
                    quote! {
                        {
                            let __bytes: &[u8] = &**#v;
                            u64::from_le_bytes(
                                <[u8; 8]>::try_from(&__bytes[..8])
                                    .expect("validated length == 8"),
                            )
                        }
                    }
                }
                _ => {
                    let v = format_ident!("__scalar_{}", field.name);
                    quote! { #v }
                }
            };
            quote! { #fname: #value, }
        })
        .collect();

    let validation = crate::codegen_view::gen_validation_standalone(schema);

    let data_start_expr = quote! {
        {
            let toc_count_idx: usize = if #header_len == 4 { 2 } else { 3 };
            let toc_count = ((&*buf)[toc_count_idx] & 0x1F) as usize + 1;
            #header_len + toc_count * 4
        }
    };

    Some(quote! {
        // ── Phase 1a: validation pass (shared reborrow).
        {
            let buf: &azihsm_fw_hsm_pal_traits::DmaBuf = &*buf;
            #validation
        }

        // ── Phase 1b: scalar reads, offset captures, monotonic check.
        // Each helper uses a transient shared reborrow of `&*buf`;
        // none outlive their statement, so the outer `&mut` borrow
        // remains usable for Phase 2 below.
        #(#scalar_captures)*
        #(#offset_captures)*
        #(#monotonic_checks)*
        let __data_start: usize = #data_start_expr;

        // ── Phase 2: pipelined split_at_mut over the parent buffer.
        let (__prefix, __rest) = buf.split_at_mut(__data_start);
        let _ = __prefix;
        #(#split_chain)*

        // ── Phase 3: reborrow shared data fields, then build struct.
        #(#shared_reborrows)*
        Ok(#view_mut_name {
            #(#struct_init)*
        })
    })
}

/// Compute the field type for the `ViewMut` struct.
fn field_type_tokens(field: &SchemaField) -> TokenStream {
    match field.wire_type {
        WireType::Uint8 => quote! { u8 },
        WireType::Uint16 => quote! { u16 },
        WireType::Uint32 => quote! { u32 },
        WireType::Uint64 => quote! { u64 },
        WireType::SessionId => quote! { azihsm_fw_ddi_tbor_api::SessionId },
        WireType::KeyId => quote! { azihsm_fw_ddi_tbor_api::KeyId },
        WireType::Buffer | WireType::SealedKey => {
            if field.mutable {
                quote! { &'a mut azihsm_fw_hsm_pal_traits::DmaBuf }
            } else {
                quote! { &'a azihsm_fw_hsm_pal_traits::DmaBuf }
            }
        }
    }
}

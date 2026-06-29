// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for field groups (`#[tbor(fields)]`).
//!
//! A field group generates:
//! - Constants: `TOC_COUNT`, `WORST_CASE_DATA_SIZE`
//! - Inner typestate encoder chain: `FooEnc<'a, S>` with states S0..SDone
//! - Sub-view type: `FooView<'a>` with typed accessors
//! - Validation helper: `validate(buf, header_len, toc_offset)`

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;

use crate::schema::*;

/// Generate all code for a field group (`#[tbor(fields)]`).
///
/// Produces:
/// - A unit struct with `TOC_COUNT`, `WORST_CASE_DATA_SIZE`, and `validate()`
/// - Typestate marker enums and encoder chain (`FooEnc<'a, S>`)
/// - A sub-view type (`FooView<'a>`) with typed accessors
pub fn gen_field_group(schema: &Schema) -> TokenStream {
    let vis = &schema.vis;
    let name = &schema.name;
    let layout = TocLayout::compute(&schema.fields);
    let n_fields = schema.fields.len();
    let local_toc_count = layout.total_toc_count;
    let worst_data = schema.worst_case_data_size();
    let align_assertions = schema.align_assertions();

    // TOC_COUNT expression includes nested group contributions.
    let group_toc_addends: Vec<_> = schema
        .fields
        .iter()
        .filter_map(|f| f.include_group.as_ref().map(|g| quote! { + #g::TOC_COUNT }))
        .collect();
    let toc_count_expr = quote! { #local_toc_count #(#group_toc_addends)* };

    // WORST_CASE_DATA_SIZE includes nested groups.
    let group_data_addends: Vec<_> = schema
        .fields
        .iter()
        .filter_map(|f| {
            f.include_group
                .as_ref()
                .map(|g| quote! { + #g::WORST_CASE_DATA_SIZE })
        })
        .collect();
    let worst_data_expr = quote! { #worst_data #(#group_data_addends)* };

    let enc_name = format_ident!("{}Enc", name);
    let view_name = format_ident!("{}View", name);
    let done_state = format_ident!("{}Done", name);

    // ── State markers ─────────────────────────────────────────────────
    let state_markers: Vec<_> = (0..n_fields)
        .map(|i| format_ident!("{}S{}", name, i))
        .collect();
    let s0 = &state_markers[0];

    let mut all_markers: Vec<_> = state_markers
        .iter()
        .map(|m| {
            quote! { #[doc(hidden)] #vis enum #m {} }
        })
        .collect();
    all_markers.push(quote! { #[doc(hidden)] #vis enum #done_state {} });

    // ── Inner typestate encoder methods ────────────────────────────────
    let padding_field_indices: std::collections::HashSet<usize> =
        layout.padding_positions.iter().map(|&(_, fi)| fi).collect();

    // Helper: compute the effective TOC index expression for field j.
    // This is: local_toc_index + sum(Group::TOC_COUNT for preceding include fields).
    let effective_toc_idx = |j: usize| -> TokenStream {
        let local_idx = layout.field_toc_indices[j];
        let group_addends: Vec<_> = schema.fields[..j]
            .iter()
            .filter_map(|pf| {
                pf.include_group
                    .as_ref()
                    .map(|pg| quote! { + #pg::TOC_COUNT })
            })
            .collect();
        if group_addends.is_empty() {
            quote! { #local_idx }
        } else {
            quote! { (#local_idx #(#group_addends)*) }
        }
    };

    let mut state_impls = Vec::new();

    for si in 0..=n_fields {
        let current_state = if si < n_fields {
            state_markers[si].clone()
        } else {
            done_state.clone()
        };
        let mut methods = Vec::new();

        for j in si..n_fields {
            let can_reach = (si..j).all(|k| schema.fields[k].optional);
            if !can_reach {
                break;
            }

            let f = &schema.fields[j];
            let field_name = &f.name;
            let _toc_type_id = f.toc_type_id;
            let field_toc_idx = effective_toc_idx(j);
            let target_state = if j + 1 < n_fields {
                state_markers[j + 1].clone()
            } else {
                done_state.clone()
            };

            // Emit None for skipped optional fields [si..j)
            let skip_nones = emit_none_range(schema, &layout, si, j);

            // ── Include field in group: closure-based delegation ───────
            if let Some(ref group_name) = f.include_group {
                let inner_enc_name = format_ident!("{}Enc", group_name);
                let inner_s0 = format_ident!("{}S0", group_name);
                let inner_done = format_ident!("{}Done", group_name);

                let local_toc_idx = layout.field_toc_indices[j];
                let preceding_group_addends: Vec<_> = schema.fields[..j]
                    .iter()
                    .filter_map(|pf| {
                        pf.include_group
                            .as_ref()
                            .map(|pg| quote! { + #pg::TOC_COUNT })
                    })
                    .collect();
                let inner_toc_offset =
                    quote! { self.toc_offset + #local_toc_idx #(#preceding_group_addends)* };

                if f.optional {
                    methods.push(quote! {
                        pub fn #field_name<F>(mut self, f: Option<F>) -> Result<#enc_name<'a, #target_state>, azihsm_fw_hsm_pal_traits::HsmError>
                        where F: FnOnce(#inner_enc_name<'a, #inner_s0>) -> Result<#inner_enc_name<'a, #inner_done>, azihsm_fw_hsm_pal_traits::HsmError>
                        {
                            let toc_offset: usize = #inner_toc_offset;
                            #skip_nones
                            match f {
                                Some(f) => {
                                    let inner = #inner_enc_name::__new(self.buf, self.data_offset, self.header_len, toc_offset, self.total_toc_count);
                                    let done = f(inner)?;
                                    let (buf, data_offset) = done.__finish();
                                    self.buf = buf;
                                    self.data_offset = data_offset;
                                }
                                None => {
                                    for i in 0..#group_name::TOC_COUNT {
                                        azihsm_fw_ddi_tbor::toc::write_toc_word(
                                            self.buf, self.header_len, toc_offset + i,
                                            azihsm_fw_ddi_tbor::toc::build_toc_none(),
                                        );
                                    }
                                }
                            }
                            Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, header_len: self.header_len, toc_offset: self.toc_offset, total_toc_count: self.total_toc_count, _state: core::marker::PhantomData })
                        }
                    });
                } else {
                    methods.push(quote! {
                        pub fn #field_name<F>(mut self, f: F) -> Result<#enc_name<'a, #target_state>, azihsm_fw_hsm_pal_traits::HsmError>
                        where F: FnOnce(#inner_enc_name<'a, #inner_s0>) -> Result<#inner_enc_name<'a, #inner_done>, azihsm_fw_hsm_pal_traits::HsmError>
                        {
                            let toc_offset: usize = #inner_toc_offset;
                            #skip_nones
                            let inner = #inner_enc_name::__new(self.buf, self.data_offset, self.header_len, toc_offset, self.total_toc_count);
                            let done = f(inner)?;
                            let (buf, data_offset) = done.__finish();
                            self.buf = buf;
                            self.data_offset = data_offset;
                            Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, header_len: self.header_len, toc_offset: self.toc_offset, total_toc_count: self.total_toc_count, _state: core::marker::PhantomData })
                        }
                    });
                }
                continue;
            }

            let has_padding = padding_field_indices.contains(&j);
            let align = f.align_expr().unwrap_or_else(|| quote! { 1 });
            let pad_toc_idx: TokenStream = if has_padding {
                let local_pad = layout
                    .padding_positions
                    .iter()
                    .find(|&&(_, fi)| fi == j)
                    .map(|&(ti, _)| ti)
                    .unwrap();
                let group_addends: Vec<_> = schema.fields[..j]
                    .iter()
                    .filter_map(|pf| {
                        pf.include_group
                            .as_ref()
                            .map(|pg| quote! { + #pg::TOC_COUNT })
                    })
                    .collect();
                if group_addends.is_empty() {
                    quote! { #local_pad }
                } else {
                    quote! { (#local_pad #(#group_addends)*) }
                }
            } else {
                quote! { 0usize }
            };

            let pad_write = if has_padding {
                quote! {
                    let pad_len = (#align - (self.data_offset % #align)) % #align;
                    let pad_end = data_start + self.data_offset + pad_len;
                    if pad_end > self.buf.len() {
                        return Err(azihsm_fw_hsm_pal_traits::HsmError::TborBufferTooSmall);
                    }
                    for j in 0..pad_len { self.buf[data_start + self.data_offset + j] = 0; }
                    let pad_word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(9, pad_len, self.data_offset);
                    azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #pad_toc_idx, pad_word);
                    self.data_offset += pad_len;
                }
            } else {
                quote! {}
            };

            let param_type = if let Some(ty) = &f.scalar_newtype {
                quote! { #ty }
            } else if let Some(ty) = &f.le_scalar {
                quote! { #ty }
            } else {
                match f.wire_type {
                    WireType::Uint8 => quote! { u8 },
                    WireType::Uint16 => quote! { u16 },
                    WireType::SessionId => quote! { azihsm_fw_ddi_tbor_api::SessionId },
                    WireType::KeyId => quote! { azihsm_fw_ddi_tbor_api::KeyId },
                    WireType::Uint32 => quote! { u32 },
                    WireType::Uint64 => quote! { u64 },
                    WireType::Buffer | WireType::SealedKey => {
                        if let Some(ty) = &f.single_pod {
                            quote! { &#ty }
                        } else if let Some(n) = f.fixed_len {
                            quote! { &[u8; #n] }
                        } else if let Some(elem) = &f.elem_type {
                            quote! { &[#elem] }
                        } else {
                            quote! { &[u8] }
                        }
                    }
                }
            };

            let val_bind = if f.scalar_newtype.is_some() {
                quote! { let v = v.0; }
            } else if f.le_scalar.is_some() {
                if f.le_scalar_is_byte {
                    quote! {}
                } else {
                    quote! { let v = v.get(); }
                }
            } else {
                match f.wire_type {
                    WireType::SessionId => quote! { let v = v.0; },
                    WireType::KeyId => quote! { let v = v.0; },
                    // Single typed-POD reference (`&T`): serialize to bytes.
                    WireType::Buffer if f.single_pod.is_some() => {
                        quote! { let v: &[u8] = ::zerocopy::IntoBytes::as_bytes(v); }
                    }
                    WireType::Buffer | WireType::SealedKey if f.fixed_len.is_some() => {
                        quote! { let v: &[u8] = v.as_slice(); }
                    }
                    // Typed-slice buffer (`&[T]`): serialize to its raw
                    // little-endian bytes so the shared write path operates
                    // on `&[u8]`.
                    WireType::Buffer if f.elem_type.is_some() => {
                        quote! { let v: &[u8] = ::zerocopy::IntoBytes::as_bytes(v); }
                    }
                    _ => quote! {},
                }
            };

            let write_code = gen_field_write_group(f, &field_toc_idx, &pad_write);

            if f.optional {
                let write_none = if has_padding {
                    quote! {
                        let pad_word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(9, 0, self.data_offset);
                        azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #pad_toc_idx, pad_word);
                        azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, azihsm_fw_ddi_tbor::toc::build_toc_none());
                    }
                } else {
                    quote! {
                        azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, azihsm_fw_ddi_tbor::toc::build_toc_none());
                    }
                };

                methods.push(quote! {
                    pub fn #field_name(mut self, v: Option<#param_type>) -> Result<#enc_name<'a, #target_state>, azihsm_fw_hsm_pal_traits::HsmError> {
                        let data_start = self.header_len + self.total_toc_count * 4;
                        #skip_nones
                        match v {
                            Some(v) => { #val_bind #write_code }
                            None => { #write_none }
                        }
                        Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, header_len: self.header_len, toc_offset: self.toc_offset, total_toc_count: self.total_toc_count, _state: core::marker::PhantomData })
                    }
                });
            } else {
                methods.push(quote! {
                    pub fn #field_name(mut self, v: #param_type) -> Result<#enc_name<'a, #target_state>, azihsm_fw_hsm_pal_traits::HsmError> {
                        let data_start = self.header_len + self.total_toc_count * 4;
                        #skip_nones
                        #val_bind
                        #write_code
                        Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, header_len: self.header_len, toc_offset: self.toc_offset, total_toc_count: self.total_toc_count, _state: core::marker::PhantomData })
                    }
                });
            }
        }

        // finish() on this state if all remaining fields are optional
        if si < n_fields {
            let all_remaining_optional = (si..n_fields).all(|k| schema.fields[k].optional);
            if all_remaining_optional {
                let finish_nones = emit_none_range(schema, &layout, si, n_fields);
                methods.push(quote! {
                    pub fn finish_group(mut self) -> #enc_name<'a, #done_state> {
                        let data_start = self.header_len + self.total_toc_count * 4;
                        #finish_nones
                        #enc_name { buf: self.buf, data_offset: self.data_offset, header_len: self.header_len, toc_offset: self.toc_offset, total_toc_count: self.total_toc_count, _state: core::marker::PhantomData }
                    }
                });
            }
        }

        state_impls.push(quote! {
            impl<'a> #enc_name<'a, #current_state> {
                #(#methods)*
            }
        });
    }

    // ── Sub-view type ─────────────────────────────────────────────────
    let view_accessors: Vec<_> = schema
        .fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let eidx = effective_toc_idx(i);
            gen_group_view_accessor(field, &eidx)
        })
        .collect();

    // ── Validation helper ─────────────────────────────────────────────
    let type_checks: Vec<_> = schema.fields.iter().enumerate().map(|(i, field)| {
        let toc_type_id = field.toc_type_id;
        let toc_idx = effective_toc_idx(i);
        if field.optional {
            let none_type_id = 8u8;
            quote! {
                {
                    let actual = azihsm_fw_ddi_tbor::toc::raw_toc_entry_type(
                        azihsm_fw_ddi_tbor::toc::read_toc_word(buf, header_len, toc_offset + #toc_idx)
                    );
                    if actual != #toc_type_id && actual != #none_type_id {
                        return Err(azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType);
                    }
                }
            }
        } else {
            quote! {
                {
                    let actual = azihsm_fw_ddi_tbor::toc::raw_toc_entry_type(
                        azihsm_fw_ddi_tbor::toc::read_toc_word(buf, header_len, toc_offset + #toc_idx)
                    );
                    if actual != #toc_type_id {
                        return Err(azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType);
                    }
                }
            }
        }
    }).collect();

    let padding_checks: Vec<_> = layout.padding_positions.iter().map(|&(toc_idx, field_idx)| {
        let group_addends: Vec<_> = schema.fields[..field_idx].iter().filter_map(|pf| {
            pf.include_group.as_ref().map(|pg| quote! { + #pg::TOC_COUNT })
        }).collect();
        let eff_toc_idx = if group_addends.is_empty() {
            quote! { #toc_idx }
        } else {
            quote! { (#toc_idx #(#group_addends)*) }
        };
        let padding_type_id = 9u8;
        quote! {
            {
                let actual = azihsm_fw_ddi_tbor::toc::raw_toc_entry_type(
                    azihsm_fw_ddi_tbor::toc::read_toc_word(buf, header_len, toc_offset + #eff_toc_idx)
                );
                if actual != #padding_type_id {
                    return Err(azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType);
                }
            }
        }
    }).collect();

    quote! {
        #vis struct #name;

        #align_assertions

        impl #name {
            /// Number of TOC entries this field group contributes.
            pub const TOC_COUNT: usize = #toc_count_expr;

            /// Worst-case data section contribution (bytes).
            pub const WORST_CASE_DATA_SIZE: usize = #worst_data_expr;

            /// Validate TOC entries for this group at the given offset.
            pub fn validate(buf: &[u8], header_len: usize, toc_offset: usize) -> Result<(), azihsm_fw_hsm_pal_traits::HsmError> {
                #(#padding_checks)*
                #(#type_checks)*
                Ok(())
            }
        }

        #(#all_markers)*

        /// Typestate encoder for this field group. Used inside closures
        /// when encoding messages that include this group.
        #vis struct #enc_name<'a, S> {
            buf: &'a mut [u8],
            data_offset: usize,
            header_len: usize,
            toc_offset: usize,
            total_toc_count: usize,
            _state: core::marker::PhantomData<S>,
        }

        impl<'a> #enc_name<'a, #s0> {
            /// Create a new group encoder. Called by the outer message encoder.
            #[doc(hidden)]
            pub fn __new(buf: &'a mut [u8], data_offset: usize, header_len: usize, toc_offset: usize, total_toc_count: usize) -> Self {
                #enc_name { buf, data_offset, header_len, toc_offset, total_toc_count, _state: core::marker::PhantomData }
            }
        }

        impl<'a> #enc_name<'a, #done_state> {
            /// Extract buffer and data_offset after all fields are written.
            #[doc(hidden)]
            pub fn __finish(self) -> (&'a mut [u8], usize) {
                (self.buf, self.data_offset)
            }
        }

        #(#state_impls)*

        /// Zero-copy sub-view over an encoded field group.
        #vis struct #view_name<'a> {
            buf: &'a azihsm_fw_hsm_pal_traits::DmaBuf,
            header_len: usize,
            toc_offset: usize,
        }

        impl<'a> #view_name<'a> {
            /// Construct from a validated buffer at the given TOC offset.
            #[doc(hidden)]
            pub fn __new(buf: &'a azihsm_fw_hsm_pal_traits::DmaBuf, header_len: usize, toc_offset: usize) -> Self {
                Self { buf, header_len, toc_offset }
            }

            #(#view_accessors)*
        }
    }
}

/// Generate the write code for a single field in a group context.
fn gen_field_write_group(
    f: &SchemaField,
    field_toc_idx: &TokenStream,
    pad_write: &TokenStream,
) -> TokenStream {
    let toc_type_id = f.toc_type_id;
    match f.wire_type {
        WireType::Uint8 => quote! {
            let word = azihsm_fw_ddi_tbor::toc::build_toc_inline_u8(#toc_type_id, v);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, word);
        },
        WireType::Uint16 | WireType::SessionId | WireType::KeyId => quote! {
            let word = azihsm_fw_ddi_tbor::toc::build_toc_inline_u16(#toc_type_id, v);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, word);
        },
        WireType::Uint32 => quote! {
            #pad_write
            let off = self.data_offset;
            let end = data_start + off + 4;
            if end > self.buf.len() {
                return Err(azihsm_fw_hsm_pal_traits::HsmError::TborBufferTooSmall);
            }
            self.buf[data_start + off..end].copy_from_slice(&v.to_le_bytes());
            self.data_offset += 4;
            let word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(#toc_type_id, 4, off);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, word);
        },
        WireType::Uint64 => quote! {
            #pad_write
            let off = self.data_offset;
            let end = data_start + off + 8;
            if end > self.buf.len() {
                return Err(azihsm_fw_hsm_pal_traits::HsmError::TborBufferTooSmall);
            }
            self.buf[data_start + off..end].copy_from_slice(&v.to_le_bytes());
            self.data_offset += 8;
            let word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(#toc_type_id, 8, off);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, word);
        },
        WireType::Buffer | WireType::SealedKey => {
            let min_l = f.min_len;
            let max_l = f.max_len;
            let len_check = if f.fixed_len.is_some() || min_l > 0 || max_l < 8191 {
                let effective_min = f.fixed_len.unwrap_or(min_l);
                let effective_max = f.fixed_len.unwrap_or(max_l);
                quote! {
                    if !(#effective_min..=#effective_max).contains(&len) {
                        return Err(azihsm_fw_hsm_pal_traits::HsmError::TborDataTooLarge);
                    }
                }
            } else {
                quote! {}
            };
            quote! {
                #pad_write
                let off = self.data_offset;
                let len = v.len();
                #len_check
                let end = data_start + off + len;
                if end > self.buf.len() {
                    return Err(azihsm_fw_hsm_pal_traits::HsmError::TborBufferTooSmall);
                }
                self.buf[data_start + off..end].copy_from_slice(v);
                self.data_offset += len;
                let word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(#toc_type_id, len, off);
                azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, word);
            }
        }
    }
}

/// Generate a view accessor for a group field.
fn gen_group_view_accessor(field: &SchemaField, toc_idx: &TokenStream) -> TokenStream {
    let name = &field.name;

    let body = match field.wire_type {
        WireType::Uint8 => quote! {
            azihsm_fw_ddi_tbor::toc::read_toc_inline_u8(self.buf, self.header_len, self.toc_offset + #toc_idx)
        },
        WireType::Uint16 => quote! {
            azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(self.buf, self.header_len, self.toc_offset + #toc_idx)
        },
        WireType::SessionId => quote! {
            azihsm_fw_ddi_tbor_api::SessionId(azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(self.buf, self.header_len, self.toc_offset + #toc_idx))
        },
        WireType::KeyId => quote! {
            azihsm_fw_ddi_tbor_api::KeyId(azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(self.buf, self.header_len, self.toc_offset + #toc_idx))
        },
        WireType::Uint32 | WireType::Uint64 | WireType::Buffer | WireType::SealedKey => {
            let ds = quote! {
                {
                    let toc_count_idx: usize = if self.header_len == 4 { 2 } else { 3 };
                    let tc = (self.buf[toc_count_idx] & 0x1F) as usize + 1;
                    self.header_len + tc * 4
                }
            };
            match field.wire_type {
                WireType::Uint32 => {
                    quote! { azihsm_fw_ddi_tbor::toc::read_toc_uint32(self.buf, self.header_len, self.toc_offset + #toc_idx, #ds) }
                }
                WireType::Uint64 => {
                    quote! { azihsm_fw_ddi_tbor::toc::read_toc_uint64(self.buf, self.header_len, self.toc_offset + #toc_idx, #ds) }
                }
                _ => {
                    if let Some(elem) = &field.elem_type {
                        // Typed-slice buffer: zero-copy cast the raw bytes
                        // to `&[T]`; a ragged blob falls back to `&[]`.
                        quote! {
                            {
                                let __b: &azihsm_fw_hsm_pal_traits::DmaBuf =
                                    azihsm_fw_ddi_tbor::toc::read_toc_buffer(self.buf, self.header_len, self.toc_offset + #toc_idx, #ds);
                                <[#elem] as ::zerocopy::TryFromBytes>::try_ref_from_bytes(&__b[..]).unwrap_or(&[])
                            }
                        }
                    } else if let Some(ty) = &field.single_pod {
                        // Single typed-POD buffer: borrow the
                        // `size_of::<T>()`-byte image as `&T`; an ill-sized
                        // blob falls back to a zeroed static.
                        quote! {
                            {
                                let __b: &azihsm_fw_hsm_pal_traits::DmaBuf =
                                    azihsm_fw_ddi_tbor::toc::read_toc_buffer(self.buf, self.header_len, self.toc_offset + #toc_idx, #ds);
                                match <#ty as ::zerocopy::TryFromBytes>::try_ref_from_bytes(&__b[..]) {
                                    ::core::result::Result::Ok(__r) => __r,
                                    ::core::result::Result::Err(_) => {
                                        static __ZERO: [u8; ::core::mem::size_of::<#ty>()] =
                                            [0u8; ::core::mem::size_of::<#ty>()];
                                        ::zerocopy::transmute_ref!(&__ZERO)
                                    }
                                }
                            }
                        }
                    } else {
                        quote! { azihsm_fw_ddi_tbor::toc::read_toc_buffer(self.buf, self.header_len, self.toc_offset + #toc_idx, #ds) }
                    }
                }
            }
        }
    };

    let ret_type = match field.wire_type {
        WireType::Uint8 => quote! { u8 },
        WireType::Uint16 => quote! { u16 },
        WireType::Uint32 => quote! { u32 },
        WireType::Uint64 => quote! { u64 },
        WireType::SessionId => quote! { azihsm_fw_ddi_tbor_api::SessionId },
        WireType::KeyId => quote! { azihsm_fw_ddi_tbor_api::KeyId },
        WireType::Buffer | WireType::SealedKey => {
            if let Some(ty) = &field.single_pod {
                quote! { &'a #ty }
            } else if let Some(n) = field.fixed_len {
                quote! { &'a [u8; #n] }
            } else if let Some(elem) = &field.elem_type {
                quote! { &'a [#elem] }
            } else {
                quote! { &'a azihsm_fw_hsm_pal_traits::DmaBuf }
            }
        }
    };

    let body = if let Some(n) = field.fixed_len.filter(|_| field.single_pod.is_none()) {
        let base = body;
        quote! {
            {
                let slice = #base;
                match <&[u8; #n]>::try_from(&slice[..]) {
                    Ok(arr) => arr,
                    Err(_) => { static ZERO: [u8; #n] = [0u8; #n]; &ZERO }
                }
            }
        }
    } else {
        body
    };

    if field.optional {
        let none_type_id = 8u8;
        quote! {
            #[inline]
            pub fn #name(&self) -> Option<#ret_type> {
                if azihsm_fw_ddi_tbor::toc::raw_toc_entry_type(
                    azihsm_fw_ddi_tbor::toc::read_toc_word(self.buf, self.header_len, self.toc_offset + #toc_idx)
                ) == #none_type_id {
                    None
                } else {
                    Some(#body)
                }
            }
        }
    } else {
        quote! {
            #[inline]
            pub fn #name(&self) -> #ret_type {
                #body
            }
        }
    }
}

/// Emit None TOC entries for skipped optional fields in a group.
fn emit_none_range(schema: &Schema, layout: &TocLayout, from: usize, to: usize) -> TokenStream {
    let mut tokens = quote! {};
    for j in from..to {
        let f = &schema.fields[j];
        if !f.optional {
            continue;
        } // shouldn't happen if caller checked

        // Compute effective group addends for preceding include fields.
        let group_addends: Vec<_> = schema.fields[..j]
            .iter()
            .filter_map(|pf| {
                pf.include_group
                    .as_ref()
                    .map(|pg| quote! { + #pg::TOC_COUNT })
            })
            .collect();

        // Handle include fields: emit None for all group TOC entries.
        if let Some(ref group_name) = f.include_group {
            let local_toc_idx = layout.field_toc_indices[j];
            let toc_offset_expr = if group_addends.is_empty() {
                quote! { #local_toc_idx }
            } else {
                quote! { (#local_toc_idx #(#group_addends)*) }
            };
            tokens = quote! {
                #tokens
                {
                    let toc_off: usize = self.toc_offset + #toc_offset_expr;
                    for i in 0..#group_name::TOC_COUNT {
                        azihsm_fw_ddi_tbor::toc::write_toc_word(
                            self.buf, self.header_len, toc_off + i,
                            azihsm_fw_ddi_tbor::toc::build_toc_none(),
                        );
                    }
                }
            };
            continue;
        }

        let local_idx = layout.field_toc_indices[j];
        let field_toc_idx = if group_addends.is_empty() {
            quote! { #local_idx }
        } else {
            quote! { (#local_idx #(#group_addends)*) }
        };

        if f.has_padding() {
            let local_pad = layout
                .padding_positions
                .iter()
                .find(|&&(_, fi)| fi == j)
                .map(|&(ti, _)| ti)
                .unwrap();
            let pad_toc_idx = if group_addends.is_empty() {
                quote! { #local_pad }
            } else {
                // Re-collect since group_addends was consumed
                let ga: Vec<_> = schema.fields[..j]
                    .iter()
                    .filter_map(|pf| {
                        pf.include_group
                            .as_ref()
                            .map(|pg| quote! { + #pg::TOC_COUNT })
                    })
                    .collect();
                quote! { (#local_pad #(#ga)*) }
            };
            tokens = quote! {
                #tokens
                {
                    let pad_word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(9, 0, self.data_offset);
                    azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #pad_toc_idx, pad_word);
                }
            };
        }
        tokens = quote! {
            #tokens
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, self.header_len, self.toc_offset + #field_toc_idx, azihsm_fw_ddi_tbor::toc::build_toc_none());
        };
    }
    tokens
}

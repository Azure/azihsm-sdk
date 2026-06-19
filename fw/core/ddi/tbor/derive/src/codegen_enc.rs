// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for the Encoder (typestate builder) and Frame types.
//!
//! The generated encoder uses a **typestate** pattern with zero field
//! storage. A single struct `FooEnc<'a, S>` carries `&mut [u8]` and
//! `data_offset`. Each field method writes directly to the buffer and
//! transitions to the next state. Phantom state markers enforce field
//! order at compile time.
//!
//! Optional fields can be skipped: each state has methods for all
//! reachable future fields (skipping only optional fields in between).
//! `finish()` is available when all remaining fields are optional.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;

use crate::schema::*;

/// Generate the typestate encoder, frame type, and all supporting items
/// for a message schema.
///
/// This is the main entry point for encoder code generation. It produces:
/// - Typestate marker enums (`FooS0`, `FooS1`, …)
/// - The encoder struct `FooEnc<'a, S>` with field-method `impl` blocks
/// - The `FooFrame<'a>` type with read accessors over the encoded message
pub fn gen_encoder_and_frame(schema: &Schema) -> TokenStream {
    let vis = &schema.vis;
    let enc_name = format_ident!("{}Enc", schema.name);
    let frame_name = format_ident!("{}Frame", schema.name);
    let layout = TocLayout::compute(&schema.fields);

    let toc_count_expr = build_toc_count_expr(&layout, &schema.fields);
    let (marker_defs, state_markers) = gen_state_markers(schema);
    let s0 = &state_markers[0];
    let encoder_alias = format_ident!("{}Encoder", schema.name);

    let (header_len_tokens, header_write, resp_extra_fields, resp_extra_pass) =
        gen_header_parts(schema);

    let new_fn = gen_new_fn(schema, &enc_name, s0, &header_len_tokens, &toc_count_expr);

    let state_impls = gen_state_impls(
        schema,
        &layout,
        &enc_name,
        &frame_name,
        &state_markers,
        &header_len_tokens,
        &header_write,
        &toc_count_expr,
        &resp_extra_pass,
    );

    let frame_tokens = gen_frame_type(schema, &layout, &frame_name, vis);

    quote! {
        #(#marker_defs)*

        /// Type alias for the initial encoder state.
        #vis type #encoder_alias<'a> = #enc_name<'a, #s0>;

        /// Typestate encoder. Each field method writes directly to the
        /// buffer and transitions to the next state. Zero field storage.
        #vis struct #enc_name<'a, S> {
            buf: &'a mut [u8],
            data_offset: usize,
            #resp_extra_fields
            _state: core::marker::PhantomData<S>,
        }

        impl<'a> #enc_name<'a, #s0> {
            #new_fn
        }

        #(#state_impls)*

        #frame_tokens
    }
}

// ── Helper: TOC count expression ──────────────────────────────────────

/// Build the compile-time `TOC_COUNT` expression including nested groups.
fn build_toc_count_expr(layout: &TocLayout, fields: &[SchemaField]) -> TokenStream {
    let local_toc_count = layout.total_toc_count;
    let group_addends: Vec<_> = fields
        .iter()
        .filter_map(|f| f.include_group.as_ref().map(|g| quote! { + #g::TOC_COUNT }))
        .collect();
    quote! { #local_toc_count #(#group_addends)* }
}

// ── Helper: state marker types ────────────────────────────────────────

/// Generate the `#[doc(hidden)]` marker enums used as typestate tags
/// (`FooS0`, `FooS1`, …, `FooSN`).
fn gen_state_markers(schema: &Schema) -> (Vec<TokenStream>, Vec<syn::Ident>) {
    let vis = &schema.vis;
    let n_fields = schema.fields.len();
    let state_markers: Vec<_> = (0..=n_fields)
        .map(|i| format_ident!("{}S{}", schema.name, i))
        .collect();
    let marker_defs: Vec<_> = state_markers
        .iter()
        .map(|m| {
            quote! {
                #[doc(hidden)]
                #vis enum #m {}
            }
        })
        .collect();
    (marker_defs, state_markers)
}

// ── Helper: header constants ──────────────────────────────────────────

/// Return `(header_len_tokens, header_write, resp_extra_fields, resp_extra_pass)`.
fn gen_header_parts(schema: &Schema) -> (TokenStream, TokenStream, TokenStream, TokenStream) {
    let (header_len_tokens, header_write) = match schema.kind {
        MessageKind::Request { opcode } => (
            quote! { azihsm_fw_ddi_tbor::REQ_HEADER_LEN },
            quote! {
                let hdr = u32::from_le_bytes([
                    azihsm_fw_ddi_tbor::PROTOCOL_VERSION,
                    0x00,
                    (TOC_COUNT - 1) as u8,
                    #opcode,
                ]);
                self.buf[..4].copy_from_slice(&hdr.to_le_bytes());
            },
        ),
        MessageKind::Response => (
            quote! { azihsm_fw_ddi_tbor::RESP_HEADER_LEN },
            quote! {
                let hdr0 = u32::from_le_bytes([
                    azihsm_fw_ddi_tbor::PROTOCOL_VERSION,
                    self.flags,
                    0x00,
                    (TOC_COUNT - 1) as u8,
                ]);
                self.buf[..4].copy_from_slice(&hdr0.to_le_bytes());
                self.buf[4..8].copy_from_slice(&self.status.to_le_bytes());
            },
        ),
        MessageKind::Fields => unreachable!(),
    };
    let resp_extra_fields = if matches!(schema.kind, MessageKind::Response) {
        quote! { status: u32, flags: u8, }
    } else {
        quote! {}
    };
    let resp_extra_pass = if matches!(schema.kind, MessageKind::Response) {
        quote! { status: self.status, flags: self.flags, }
    } else {
        quote! {}
    };
    (
        header_len_tokens,
        header_write,
        resp_extra_fields,
        resp_extra_pass,
    )
}

// ── Helper: new() constructor ─────────────────────────────────────────

/// Generate the `new()` constructor for the initial encoder state.
fn gen_new_fn(
    schema: &Schema,
    enc_name: &syn::Ident,
    s0: &syn::Ident,
    header_len_tokens: &TokenStream,
    toc_count_expr: &TokenStream,
) -> TokenStream {
    // For empty schemas the codec still requires `toc_count >= 1`; the
    // initial state writes a synthetic `None` placeholder at TOC[0] so
    // that `finish()` can produce a valid frame without exposing any
    // field methods.
    let write_empty_placeholder = if schema.fields.is_empty() {
        quote! {
            azihsm_fw_ddi_tbor::toc::write_toc_word(
                buf,
                HEADER_LEN,
                0,
                azihsm_fw_ddi_tbor::toc::build_toc_none(),
            );
        }
    } else {
        quote! {}
    };

    match schema.kind {
        MessageKind::Request { .. } => quote! {
            /// Create a new encoder, validating that `buf` is large enough.
            pub fn new(buf: &'a mut [u8]) -> Result<#enc_name<'a, #s0>, azihsm_fw_ddi_tbor::EncodeError> {
                const HEADER_LEN: usize = #header_len_tokens;
                const TOC_COUNT: usize = #toc_count_expr;
                const MIN_SIZE: usize = HEADER_LEN + TOC_COUNT * 4;
                if buf.len() < MIN_SIZE {
                    return Err(azihsm_fw_ddi_tbor::EncodeError::BufferTooSmall {
                        needed: MIN_SIZE,
                        available: buf.len(),
                    });
                }
                #write_empty_placeholder
                Ok(#enc_name { buf, data_offset: 0, _state: core::marker::PhantomData })
            }
        },
        MessageKind::Response => quote! {
            /// Create a new response encoder with the given status and FIPS flag.
            pub fn new(buf: &'a mut [u8], status: u32, fips_approved: bool) -> Result<#enc_name<'a, #s0>, azihsm_fw_ddi_tbor::EncodeError> {
                const HEADER_LEN: usize = #header_len_tokens;
                const TOC_COUNT: usize = #toc_count_expr;
                const MIN_SIZE: usize = HEADER_LEN + TOC_COUNT * 4;
                if buf.len() < MIN_SIZE {
                    return Err(azihsm_fw_ddi_tbor::EncodeError::BufferTooSmall {
                        needed: MIN_SIZE,
                        available: buf.len(),
                    });
                }
                let flags = if fips_approved { 0x01u8 } else { 0x00u8 };
                #write_empty_placeholder
                Ok(#enc_name { buf, data_offset: 0, status, flags, _state: core::marker::PhantomData })
            }
        },
        MessageKind::Fields => unreachable!(),
    }
}

// ── Helper: effective TOC index ───────────────────────────────────────

/// Compute the effective TOC index expression for field `i`, accounting
/// for preceding include-group contributions.
fn effective_toc_idx(i: usize, layout: &TocLayout, fields: &[SchemaField]) -> TokenStream {
    let local_idx = layout.field_toc_indices[i];
    let group_addends: Vec<_> = fields[..i]
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
}

// ── Helper: emit None for skipped optional fields ─────────────────────

/// Emit `None` TOC words for a range of skipped optional fields
/// (`skip_from..skip_to`) in a top-level message encoder context.
fn emit_none_range_enc(
    skip_from: usize,
    skip_to: usize,
    schema: &Schema,
    layout: &TocLayout,
) -> TokenStream {
    let mut tokens = quote! {};
    for j in skip_from..skip_to {
        let f = &schema.fields[j];
        assert!(f.optional, "cannot skip required field");

        if let Some(ref group_name) = f.include_group {
            let local_toc_idx = layout.field_toc_indices[j];
            let preceding: Vec<_> = schema.fields[..j]
                .iter()
                .filter_map(|pf| {
                    pf.include_group
                        .as_ref()
                        .map(|pg| quote! { + #pg::TOC_COUNT })
                })
                .collect();
            let toc_offset_expr = quote! { #local_toc_idx #(#preceding)* };
            tokens = quote! {
                #tokens
                {
                    let toc_off: usize = #toc_offset_expr;
                    for i in 0..#group_name::TOC_COUNT {
                        azihsm_fw_ddi_tbor::toc::write_toc_word(
                            self.buf, HEADER_LEN, toc_off + i,
                            azihsm_fw_ddi_tbor::toc::build_toc_none(),
                        );
                    }
                }
            };
            continue;
        }

        let field_toc_idx = effective_toc_idx(j, layout, &schema.fields);
        if f.align > 0 {
            let local_pad = layout
                .padding_positions
                .iter()
                .find(|&&(_, fi)| fi == j)
                .map(|&(ti, _)| ti)
                .unwrap();
            let ga: Vec<_> = schema.fields[..j]
                .iter()
                .filter_map(|pf| {
                    pf.include_group
                        .as_ref()
                        .map(|pg| quote! { + #pg::TOC_COUNT })
                })
                .collect();
            let pad_toc_idx = quote! { (#local_pad #(#ga)*) };
            tokens = quote! {
                #tokens
                {
                    let pad_word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(9, 0, self.data_offset);
                    azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #pad_toc_idx, pad_word);
                }
            };
        }
        tokens = quote! {
            #tokens
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, azihsm_fw_ddi_tbor::toc::build_toc_none());
        };
    }
    tokens
}

// ── Helper: field write code ──────────────────────────────────────────

/// Generate the token stream that writes a single field value into the
/// buffer (padding + TOC word + data section copy).
fn gen_field_write(i: usize, schema: &Schema, layout: &TocLayout) -> TokenStream {
    let f = &schema.fields[i];
    let toc_type_id = f.toc_type_id;
    let field_toc_idx = effective_toc_idx(i, layout, &schema.fields);
    let has_padding = f.align > 0;
    let align = f.align;

    let pad_toc_idx = if has_padding {
        let local_pad = layout
            .padding_positions
            .iter()
            .find(|&&(_, fi)| fi == i)
            .map(|&(ti, _)| ti)
            .unwrap();
        let ga: Vec<_> = schema.fields[..i]
            .iter()
            .filter_map(|pf| {
                pf.include_group
                    .as_ref()
                    .map(|pg| quote! { + #pg::TOC_COUNT })
            })
            .collect();
        quote! { (#local_pad #(#ga)*) }
    } else {
        quote! { 0 }
    };

    let pad_write = if has_padding {
        quote! {
            let pad_len = (#align - (self.data_offset % #align)) % #align;
            let pad_end = DATA_START + self.data_offset + pad_len;
            if pad_end > self.buf.len() {
                return Err(azihsm_fw_ddi_tbor::EncodeError::BufferTooSmall {
                    needed: pad_end, available: self.buf.len(),
                });
            }
            for j in 0..pad_len {
                self.buf[DATA_START + self.data_offset + j] = 0;
            }
            let pad_word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(9, pad_len, self.data_offset);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #pad_toc_idx, pad_word);
            self.data_offset += pad_len;
        }
    } else {
        quote! {}
    };

    match f.wire_type {
        WireType::Uint8 => quote! {
            let word = azihsm_fw_ddi_tbor::toc::build_toc_inline_u8(#toc_type_id, v);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, word);
        },
        WireType::Uint16 | WireType::SessionId | WireType::KeyId => quote! {
            let word = azihsm_fw_ddi_tbor::toc::build_toc_inline_u16(#toc_type_id, v);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, word);
        },
        WireType::Uint32 => quote! {
            #pad_write
            let off = self.data_offset;
            let end = DATA_START + off + 4;
            if end > self.buf.len() {
                return Err(azihsm_fw_ddi_tbor::EncodeError::BufferTooSmall { needed: end, available: self.buf.len() });
            }
            self.buf[DATA_START + off..end].copy_from_slice(&v.to_le_bytes());
            self.data_offset += 4;
            let word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(#toc_type_id, 4, off);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, word);
        },
        WireType::Uint64 => quote! {
            #pad_write
            let off = self.data_offset;
            let end = DATA_START + off + 8;
            if end > self.buf.len() {
                return Err(azihsm_fw_ddi_tbor::EncodeError::BufferTooSmall { needed: end, available: self.buf.len() });
            }
            self.buf[DATA_START + off..end].copy_from_slice(&v.to_le_bytes());
            self.data_offset += 8;
            let word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(#toc_type_id, 8, off);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, word);
        },
        WireType::Buffer | WireType::SealedKey => {
            let min_l = f.min_len;
            let max_l = f.max_len;
            let len_check = if f.fixed_len.is_some() || min_l > 0 || max_l < 8191 {
                let effective_min = f.fixed_len.unwrap_or(min_l);
                let effective_max = f.fixed_len.unwrap_or(max_l);
                quote! {
                    if !(#effective_min..=#effective_max).contains(&len) {
                        return Err(azihsm_fw_ddi_tbor::EncodeError::DataTooLarge { size: len });
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
                let end = DATA_START + off + len;
                if end > self.buf.len() {
                    return Err(azihsm_fw_ddi_tbor::EncodeError::BufferTooSmall { needed: end, available: self.buf.len() });
                }
                if self.data_offset + len > azihsm_fw_ddi_tbor::MAX_DATA_SIZE {
                    return Err(azihsm_fw_ddi_tbor::EncodeError::DataTooLarge { size: self.data_offset + len });
                }
                self.buf[DATA_START + off..end].copy_from_slice(v);
                self.data_offset += len;
                let word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(#toc_type_id, len, off);
                azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, word);
            }
        }
    }
}

// ── Helper: state impl blocks ─────────────────────────────────────────

/// Generate the `impl` blocks for each typestate, containing field setter
/// methods and `finish()`.
#[allow(clippy::too_many_arguments)]
fn gen_state_impls(
    schema: &Schema,
    layout: &TocLayout,
    enc_name: &syn::Ident,
    frame_name: &syn::Ident,
    state_markers: &[syn::Ident],
    header_len_tokens: &TokenStream,
    header_write: &TokenStream,
    toc_count_expr: &TokenStream,
    resp_extra_pass: &TokenStream,
) -> Vec<TokenStream> {
    let n_fields = schema.fields.len();
    let mut state_impls = Vec::new();

    for si in 0..=n_fields {
        let current_state = &state_markers[si];
        let mut methods = Vec::new();

        for j in si..n_fields {
            let can_reach = (si..j).all(|k| schema.fields[k].optional);
            if !can_reach {
                break;
            }

            let f = &schema.fields[j];
            let target_state = &state_markers[j + 1];
            let field_name = &f.name;
            let skip_nones = emit_none_range_enc(si, j, schema, layout);

            if f.include_group.is_some() {
                methods.push(gen_include_field_method(
                    j,
                    schema,
                    layout,
                    enc_name,
                    target_state,
                    header_len_tokens,
                    toc_count_expr,
                    resp_extra_pass,
                    &skip_nones,
                ));
                continue;
            }

            let param_type = field_param_type(f);
            let val_bind = field_val_bind(f);
            let write_code = gen_field_write(j, schema, layout);

            if f.optional {
                methods.push(gen_optional_field_method(
                    j,
                    f,
                    schema,
                    layout,
                    enc_name,
                    target_state,
                    header_len_tokens,
                    toc_count_expr,
                    resp_extra_pass,
                    &skip_nones,
                    &param_type,
                    &val_bind,
                    &write_code,
                ));
            } else {
                methods.push(quote! {
                    pub fn #field_name(mut self, v: #param_type) -> Result<#enc_name<'a, #target_state>, azihsm_fw_ddi_tbor::EncodeError> {
                        const HEADER_LEN: usize = #header_len_tokens;
                        const TOC_COUNT: usize = #toc_count_expr;
                        const DATA_START: usize = HEADER_LEN + TOC_COUNT * 4;
                        #skip_nones
                        #val_bind
                        #write_code
                        Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, #resp_extra_pass _state: core::marker::PhantomData })
                    }
                });
            }
        }

        // finish() when all remaining fields are optional.
        let all_remaining_optional = (si..n_fields).all(|k| schema.fields[k].optional);
        if all_remaining_optional {
            let finish_nones = emit_none_range_enc(si, n_fields, schema, layout);
            methods.push(quote! {
                /// Finalize the message: write header, emit None for
                /// remaining optional fields, return the frame.
                pub fn finish(mut self) -> #frame_name<'a> {
                    const HEADER_LEN: usize = #header_len_tokens;
                    const TOC_COUNT: usize = #toc_count_expr;
                    const DATA_START: usize = HEADER_LEN + TOC_COUNT * 4;
                    #finish_nones
                    let total = DATA_START + self.data_offset;
                    #header_write
                    #frame_name { buf: &self.buf[..total] }
                }
            });
        }

        state_impls.push(quote! {
            impl<'a> #enc_name<'a, #current_state> {
                #(#methods)*
            }
        });
    }

    state_impls
}

/// Generate a method for an include-group field (closure-based delegation).
#[allow(clippy::too_many_arguments)]
fn gen_include_field_method(
    j: usize,
    schema: &Schema,
    layout: &TocLayout,
    enc_name: &syn::Ident,
    target_state: &syn::Ident,
    header_len_tokens: &TokenStream,
    toc_count_expr: &TokenStream,
    resp_extra_pass: &TokenStream,
    skip_nones: &TokenStream,
) -> TokenStream {
    let f = &schema.fields[j];
    let field_name = &f.name;
    let group_name = f.include_group.as_ref().unwrap();
    let group_enc_name = format_ident!("{}Enc", group_name);
    let group_s0 = format_ident!("{}S0", group_name);
    let group_done = format_ident!("{}Done", group_name);

    let local_toc_idx = layout.field_toc_indices[j];
    let preceding: Vec<_> = schema.fields[..j]
        .iter()
        .filter_map(|pf| {
            pf.include_group
                .as_ref()
                .map(|pg| quote! { + #pg::TOC_COUNT })
        })
        .collect();
    let toc_offset_expr = quote! { #local_toc_idx #(#preceding)* };

    if f.optional {
        quote! {
            pub fn #field_name<F>(mut self, f: Option<F>) -> Result<#enc_name<'a, #target_state>, azihsm_fw_ddi_tbor::EncodeError>
            where F: FnOnce(#group_enc_name<'a, #group_s0>) -> Result<#group_enc_name<'a, #group_done>, azihsm_fw_ddi_tbor::EncodeError>
            {
                const HEADER_LEN: usize = #header_len_tokens;
                const TOC_COUNT: usize = #toc_count_expr;
                let toc_offset: usize = #toc_offset_expr;
                #skip_nones
                match f {
                    Some(f) => {
                        let inner = #group_enc_name::__new(self.buf, self.data_offset, HEADER_LEN, toc_offset, TOC_COUNT);
                        let done = f(inner)?;
                        let (buf, data_offset) = done.__finish();
                        self.buf = buf;
                        self.data_offset = data_offset;
                    }
                    None => {
                        for i in 0..#group_name::TOC_COUNT {
                            azihsm_fw_ddi_tbor::toc::write_toc_word(
                                self.buf, HEADER_LEN, toc_offset + i,
                                azihsm_fw_ddi_tbor::toc::build_toc_none(),
                            );
                        }
                    }
                }
                Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, #resp_extra_pass _state: core::marker::PhantomData })
            }
        }
    } else {
        quote! {
            pub fn #field_name<F>(mut self, f: F) -> Result<#enc_name<'a, #target_state>, azihsm_fw_ddi_tbor::EncodeError>
            where F: FnOnce(#group_enc_name<'a, #group_s0>) -> Result<#group_enc_name<'a, #group_done>, azihsm_fw_ddi_tbor::EncodeError>
            {
                const HEADER_LEN: usize = #header_len_tokens;
                const TOC_COUNT: usize = #toc_count_expr;
                let toc_offset: usize = #toc_offset_expr;
                #skip_nones
                let inner = #group_enc_name::__new(self.buf, self.data_offset, HEADER_LEN, toc_offset, TOC_COUNT);
                let done = f(inner)?;
                let (buf, data_offset) = done.__finish();
                self.buf = buf;
                self.data_offset = data_offset;
                Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, #resp_extra_pass _state: core::marker::PhantomData })
            }
        }
    }
}

/// Generate the method body for an optional regular field.
#[allow(clippy::too_many_arguments)]
fn gen_optional_field_method(
    j: usize,
    f: &SchemaField,
    schema: &Schema,
    layout: &TocLayout,
    enc_name: &syn::Ident,
    target_state: &syn::Ident,
    header_len_tokens: &TokenStream,
    toc_count_expr: &TokenStream,
    resp_extra_pass: &TokenStream,
    skip_nones: &TokenStream,
    param_type: &TokenStream,
    val_bind: &TokenStream,
    write_code: &TokenStream,
) -> TokenStream {
    let field_name = &f.name;
    let field_toc_idx = effective_toc_idx(j, layout, &schema.fields);
    let has_padding = f.align > 0;
    let pad_toc_idx_val = if has_padding {
        let local_pad = layout
            .padding_positions
            .iter()
            .find(|&&(_, fi)| fi == j)
            .map(|&(ti, _)| ti)
            .unwrap();
        let ga: Vec<_> = schema.fields[..j]
            .iter()
            .filter_map(|pf| {
                pf.include_group
                    .as_ref()
                    .map(|pg| quote! { + #pg::TOC_COUNT })
            })
            .collect();
        quote! { (#local_pad #(#ga)*) }
    } else {
        quote! { 0 }
    };

    let write_none = if has_padding {
        quote! {
            let pad_word = azihsm_fw_ddi_tbor::toc::build_toc_offset_len(9, 0, self.data_offset);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #pad_toc_idx_val, pad_word);
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, azihsm_fw_ddi_tbor::toc::build_toc_none());
        }
    } else {
        quote! {
            azihsm_fw_ddi_tbor::toc::write_toc_word(self.buf, HEADER_LEN, #field_toc_idx, azihsm_fw_ddi_tbor::toc::build_toc_none());
        }
    };

    quote! {
        pub fn #field_name(mut self, v: Option<#param_type>) -> Result<#enc_name<'a, #target_state>, azihsm_fw_ddi_tbor::EncodeError> {
            const HEADER_LEN: usize = #header_len_tokens;
            const TOC_COUNT: usize = #toc_count_expr;
            const DATA_START: usize = HEADER_LEN + TOC_COUNT * 4;
            #skip_nones
            match v {
                Some(v) => {
                    #val_bind
                    #write_code
                }
                None => {
                    #write_none
                }
            }
            Ok(#enc_name { buf: self.buf, data_offset: self.data_offset, #resp_extra_pass _state: core::marker::PhantomData })
        }
    }
}

/// Return the Rust parameter type token stream for a schema field.
fn field_param_type(f: &SchemaField) -> TokenStream {
    match f.wire_type {
        WireType::Uint8 => quote! { u8 },
        WireType::Uint16 => quote! { u16 },
        WireType::SessionId => quote! { azihsm_fw_ddi_tbor_api::SessionId },
        WireType::KeyId => quote! { azihsm_fw_ddi_tbor_api::KeyId },
        WireType::Uint32 => quote! { u32 },
        WireType::Uint64 => quote! { u64 },
        WireType::Buffer | WireType::SealedKey => {
            if let Some(n) = f.fixed_len {
                quote! { &[u8; #n] }
            } else {
                quote! { &[u8] }
            }
        }
    }
}

/// Return the value-binding code that unwraps newtypes or coerces arrays.
fn field_val_bind(f: &SchemaField) -> TokenStream {
    match f.wire_type {
        WireType::SessionId => quote! { let v = v.0; },
        WireType::KeyId => quote! { let v = v.0; },
        WireType::Buffer | WireType::SealedKey if f.fixed_len.is_some() => {
            quote! { let v: &[u8] = v.as_slice(); }
        }
        _ => quote! {},
    }
}

// ── Helper: Frame type ────────────────────────────────────────────────

/// Generate the `FooFrame<'a>` struct with `as_bytes()`, `len()`, and
/// per-field read accessors.
fn gen_frame_type(
    schema: &Schema,
    layout: &TocLayout,
    frame_name: &syn::Ident,
    vis: &syn::Visibility,
) -> TokenStream {
    let frame_accessors: Vec<_> = schema
        .fields
        .iter()
        .enumerate()
        .map(|(i, field)| gen_frame_accessor(field, layout.field_toc_indices[i], schema))
        .collect();

    quote! {
        /// The encoded message. Provides `as_bytes()` for sending and
        /// typed read accessors for verification.
        #[derive(Debug)]
        #vis struct #frame_name<'a> {
            buf: &'a [u8],
        }

        impl<'a> #frame_name<'a> {
            /// The complete wire message.
            #[inline]
            pub fn as_bytes(&self) -> &'a [u8] { self.buf }

            /// Total message length.
            #[inline]
            pub fn len(&self) -> usize { self.buf.len() }

            /// Returns `true` if the message is empty.
            #[inline]
            pub fn is_empty(&self) -> bool { self.buf.is_empty() }

            #(#frame_accessors)*
        }
    }
}

/// Generate a read accessor on the Frame type for a single field.
fn gen_frame_accessor(field: &SchemaField, toc_index: usize, schema: &Schema) -> TokenStream {
    let name = &field.name;

    let header_len = match schema.kind {
        MessageKind::Request { .. } => quote! { azihsm_fw_ddi_tbor::REQ_HEADER_LEN },
        MessageKind::Response => quote! { azihsm_fw_ddi_tbor::RESP_HEADER_LEN },
        MessageKind::Fields => unreachable!(),
    };

    let body = match field.wire_type {
        WireType::Uint8 => quote! {
            azihsm_fw_ddi_tbor::toc::read_toc_inline_u8(self.buf, #header_len, #toc_index)
        },
        WireType::Uint16 => quote! {
            azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(self.buf, #header_len, #toc_index)
        },
        WireType::SessionId => quote! {
            azihsm_fw_ddi_tbor_api::SessionId(azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(self.buf, #header_len, #toc_index))
        },
        WireType::KeyId => quote! {
            azihsm_fw_ddi_tbor_api::KeyId(azihsm_fw_ddi_tbor::toc::read_toc_inline_u16(self.buf, #header_len, #toc_index))
        },
        WireType::Uint32 | WireType::Uint64 | WireType::Buffer | WireType::SealedKey => {
            let ds = quote! {
                {
                    let toc_count_idx: usize = if #header_len == 4usize { 2 } else { 3 };
                    let tc = (self.buf[toc_count_idx] & 0x1F) as usize + 1;
                    #header_len + tc * 4
                }
            };
            match field.wire_type {
                WireType::Uint32 => {
                    quote! { azihsm_fw_ddi_tbor::toc::read_toc_uint32(self.buf, #header_len, #toc_index, #ds) }
                }
                WireType::Uint64 => {
                    quote! { azihsm_fw_ddi_tbor::toc::read_toc_uint64(self.buf, #header_len, #toc_index, #ds) }
                }
                _ => {
                    // Frame.buf is `&[u8]` (the encoder's raw backing
                    // buffer is not DMA-branded), so inline the slice
                    // extraction rather than calling the codec's
                    // `&DmaBuf`-typed `read_toc_buffer`.
                    quote! {
                        {
                            let word = azihsm_fw_ddi_tbor::toc::read_toc_word(self.buf, #header_len, #toc_index);
                            let length = azihsm_fw_ddi_tbor::toc::raw_toc_length(word);
                            let offset = azihsm_fw_ddi_tbor::toc::raw_toc_offset(word);
                            let ds = #ds;
                            &self.buf[ds + offset..ds + offset + length]
                        }
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
            if let Some(n) = field.fixed_len {
                quote! { &'a [u8; #n] }
            } else {
                quote! { &'a [u8] }
            }
        }
    };

    let body = if let Some(n) = field.fixed_len {
        let base_body = body;
        quote! {
            {
                let slice = #base_body;
                match <&[u8; #n]>::try_from(slice) {
                    Ok(arr) => arr,
                    Err(_) => {
                        static ZERO: [u8; #n] = [0u8; #n];
                        &ZERO
                    }
                }
            }
        }
    } else {
        body
    };

    if field.optional {
        let none_type_id = quote! { azihsm_fw_ddi_tbor::TocType::None as u8 };
        quote! {
            #[inline]
            pub fn #name(&self) -> Option<#ret_type> {
                if azihsm_fw_ddi_tbor::toc::raw_toc_entry_type(
                    azihsm_fw_ddi_tbor::toc::read_toc_word(self.buf, #header_len, #toc_index)
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

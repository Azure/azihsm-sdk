// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for the View type (zero-copy decoder).

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;

use crate::schema::*;

/// Generate the `FooView<'a>` struct with typed, infallible accessors
/// and a `Display` implementation.
pub fn gen_view(schema: &Schema) -> TokenStream {
    let vis = &schema.vis;
    let view_name = format_ident!("{}View", schema.name);
    let name = &schema.name;

    let (header_len, is_response) = match schema.kind {
        MessageKind::Request { .. } => (quote! { azihsm_fw_ddi_tbor::REQ_HEADER_LEN }, false),
        MessageKind::Response => (quote! { azihsm_fw_ddi_tbor::RESP_HEADER_LEN }, true),
        MessageKind::Fields => unreachable!(),
    };

    let layout = TocLayout::compute(&schema.fields);

    // Generate accessor methods.
    let accessors = schema.fields.iter().enumerate().map(|(i, field)| {
        let toc_idx = crate::codegen_enc::effective_toc_idx(i, &layout, &schema.fields);
        if let Some(group) = &field.include_group {
            // Included field group: expose a zero-copy sub-view
            // (`{Group}View`) anchored at the group's TOC offset.
            let name = &field.name;
            let group_view = format_ident!("{}View", group);
            quote! {
                #[inline]
                pub fn #name(&self) -> #group_view<'a> {
                    #group_view::__new(self.buf, #header_len, #toc_idx)
                }
            }
        } else {
            gen_accessor(field, toc_idx, &header_len, schema.needs_data_start)
        }
    });

    // Response-specific accessors.
    let response_accessors = if is_response {
        quote! {
            /// Status code (4-byte LE unsigned integer).
            #[inline]
            pub fn status(&self) -> u32 {
                u32::from_le_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]])
            }

            /// FIPS_APPROVED flag (bit 0 of flags).
            #[inline]
            pub fn fips_approved(&self) -> bool {
                self.buf[1] & 0x01 != 0
            }
        }
    } else {
        quote! {}
    };

    // Lifetime parameter — always 'a since the view borrows the buffer.
    let view_lifetime = quote! { <'a> };

    // Display impl.
    let display_impl = gen_display(schema, &view_name);

    quote! {
        /// Zero-copy view over an encoded message. All accessors are
        /// infallible after successful construction via
        #[doc = concat!("[`", stringify!(#name), "::decode()`].")]
        #[derive(Debug)]
        #vis struct #view_name #view_lifetime {
            buf: &'a azihsm_fw_hsm_pal_traits::DmaBuf,
        }

        impl<'a> #view_name<'a> {
            /// Construct from a validated buffer. Not public — use
            #[doc = concat!("[`", stringify!(#name), "::decode()`] instead.")]
            fn from_validated(buf: &'a azihsm_fw_hsm_pal_traits::DmaBuf) -> Self {
                Self { buf }
            }

            /// Total message length.
            #[inline]
            pub fn len(&self) -> usize { self.buf.len() }

            /// Returns `true` if the message is empty.
            #[inline]
            pub fn is_empty(&self) -> bool { self.buf.is_empty() }

            /// The raw message bytes.
            #[inline]
            pub fn as_bytes(&self) -> &'a azihsm_fw_hsm_pal_traits::DmaBuf { self.buf }

            #response_accessors

            #(#accessors)*
        }

        #display_impl
    }
}

/// Generate a single field accessor method for the View type.
fn gen_accessor(
    field: &SchemaField,
    toc_index: TokenStream,
    header_len: &TokenStream,
    needs_data_start: bool,
) -> TokenStream {
    let name = &field.name;

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
        WireType::Uint32 => {
            let ds = data_start_expr(header_len, needs_data_start);
            quote! { azihsm_fw_ddi_tbor::toc::read_toc_uint32(self.buf, #header_len, #toc_index, #ds) }
        }
        WireType::Uint64 => {
            let ds = data_start_expr(header_len, needs_data_start);
            quote! { azihsm_fw_ddi_tbor::toc::read_toc_uint64(self.buf, #header_len, #toc_index, #ds) }
        }
        WireType::Buffer | WireType::SealedKey => {
            let ds = data_start_expr(header_len, needs_data_start);
            if let Some(elem) = &field.elem_type {
                // Typed-slice buffer: zero-copy cast the raw bytes to
                // `&[T]`.  Length is validated to be a multiple of
                // `size_of::<T>()` at decode time; a ragged blob falls
                // back to an empty slice rather than panicking.
                quote! {
                    {
                        let __b: &azihsm_fw_hsm_pal_traits::DmaBuf =
                            azihsm_fw_ddi_tbor::toc::read_toc_buffer(self.buf, #header_len, #toc_index, #ds);
                        <[#elem] as ::zerocopy::TryFromBytes>::try_ref_from_bytes(&__b[..]).unwrap_or(&[])
                    }
                }
            } else if let Some(ty) = &field.single_pod {
                // Single typed-POD buffer: zero-copy borrow the
                // `size_of::<T>()`-byte image as `&T`; an ill-sized blob
                // falls back to a zeroed static rather than panicking.
                quote! {
                    {
                        let __b: &azihsm_fw_hsm_pal_traits::DmaBuf =
                            azihsm_fw_ddi_tbor::toc::read_toc_buffer(self.buf, #header_len, #toc_index, #ds);
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
                quote! { azihsm_fw_ddi_tbor::toc::read_toc_buffer(self.buf, #header_len, #toc_index, #ds) }
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
            if let Some(elem) = &field.elem_type {
                quote! { &'a [#elem] }
            } else if let Some(ty) = &field.single_pod {
                quote! { &'a #ty }
            } else {
                quote! { &'a azihsm_fw_hsm_pal_traits::DmaBuf }
            }
        }
    };

    // Inline scalar carried as a typed newtype (`#[tbor(U8)] f: T`):
    // wrap the raw integer in `T(..)` and return `T`. `T` is a
    // single-field tuple newtype over the matching primitive.
    let (body, ret_type) = if let Some(ty) = &field.scalar_newtype {
        (quote! { #ty(#body) }, quote! { #ty })
    } else if let Some(ty) = &field.le_scalar {
        if field.le_scalar_is_byte {
            // `U8` aliases `u8`: identity body, typed return.
            (body, quote! { #ty })
        } else {
            // `U16`/`U32`/`U64`: bridge the raw int via `T::new(..)`.
            (quote! { #ty::new(#body) }, quote! { #ty })
        }
    } else {
        (body, ret_type)
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

/// Compute the `data_start` expression used by data-section accessors.
fn data_start_expr(header_len: &TokenStream, _needs_data_start: bool) -> TokenStream {
    // TOC count byte position:
    //   Request: byte 2 (REQ_HEADER_LEN = 4)
    //   Response: byte 3 (RESP_HEADER_LEN = 8)
    // Compute from header_len: request → 4-2=2, response → 8-5=3
    quote! {
        {
            let toc_count_idx: usize = if #header_len == 4 { 2 } else { 3 };
            let toc_count = (self.buf[toc_count_idx] & 0x1F) as usize + 1;
            #header_len + toc_count * 4
        }
    }
}

/// Generate validation code as a standalone block (used by `lib.rs` for
/// the top-level `decode()` function).
pub fn gen_validation_standalone(schema: &Schema) -> TokenStream {
    gen_validation(schema)
}

/// Generate the full validation block for a message schema.
fn gen_validation(schema: &Schema) -> TokenStream {
    let layout = TocLayout::compute(&schema.fields);
    let total_toc_count = layout.total_toc_count;

    let (parse_call, _header_len_val, opcode_check) = match schema.kind {
        MessageKind::Request { opcode } => (
            quote! { azihsm_fw_ddi_tbor::RequestView::parse(buf)? },
            quote! { azihsm_fw_ddi_tbor::REQ_HEADER_LEN },
            quote! {
                if raw.opcode() != #opcode {
                    return Err(azihsm_fw_hsm_pal_traits::HsmError::TborOpcodeMismatch);
                }
            },
        ),
        MessageKind::Response => (
            quote! { azihsm_fw_ddi_tbor::ResponseView::parse(buf)? },
            quote! { azihsm_fw_ddi_tbor::RESP_HEADER_LEN },
            quote! {},
        ),
        MessageKind::Fields => unreachable!(),
    };

    let type_checks = gen_type_checks(schema, &layout);
    let padding_checks = gen_padding_checks(&layout);
    let len_checks = gen_len_checks(schema, &layout);

    // Included field groups expand the TOC dynamically, so fold their
    // `TOC_COUNT` constants into the expected total.
    let group_toc_addends: Vec<_> = schema
        .fields
        .iter()
        .filter_map(|f| f.include_group.as_ref().map(|g| quote! { + #g::TOC_COUNT }))
        .collect();
    let total_toc_count_expr = quote! { #total_toc_count #(#group_toc_addends)* };

    // Empty schemas synthesise a single `None` TOC placeholder; the
    // decoder must reject any other entry type at TOC[0]. See
    // [`crate::schema::TocLayout::compute`].
    let empty_body_check = if schema.fields.is_empty() {
        let none_type_id = quote! { azihsm_fw_ddi_tbor::TocType::None as u8 };
        quote! {
            if raw.toc_entry_type(0) != #none_type_id {
                return Err(azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType);
            }
        }
    } else {
        quote! {}
    };

    quote! {
        let raw = #parse_call;
        #opcode_check

        // Exact TOC count validation (fields + padding + group entries).
        if raw.toc_count() != #total_toc_count_expr {
            return Err(azihsm_fw_hsm_pal_traits::HsmError::TborMessageTruncated);
        }

        // Validate padding entries.
        #(#padding_checks)*

        // Validate each field TOC entry type at expected position.
        #(#type_checks)*

        // Validate length constraints.
        #(#len_checks)*

        // Empty schemas: validate the synthetic `None` placeholder.
        #empty_body_check
    }
}

/// Generate TOC entry type checks for each schema field.
fn gen_type_checks(schema: &Schema, layout: &TocLayout) -> Vec<TokenStream> {
    let header_len_val = match schema.kind {
        MessageKind::Request { .. } => quote! { azihsm_fw_ddi_tbor::REQ_HEADER_LEN },
        MessageKind::Response => quote! { azihsm_fw_ddi_tbor::RESP_HEADER_LEN },
        MessageKind::Fields => unreachable!(),
    };
    schema
        .fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let toc_idx = crate::codegen_enc::effective_toc_idx(i, layout, &schema.fields);
            // Included field group: delegate to the group's own validator,
            // anchored at the group's TOC offset.
            if let Some(group) = &field.include_group {
                return quote! {
                    #group::validate(buf, #header_len_val, #toc_idx)?;
                };
            }
            let toc_type_id = field.toc_type_id;
            if field.optional {
                let none_type_id = quote! { azihsm_fw_ddi_tbor::TocType::None as u8 };
                quote! {
                    {
                        let actual = raw.toc_entry_type(#toc_idx);
                        if actual != #toc_type_id && actual != #none_type_id {
                            return Err(azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType);
                        }
                    }
                }
            } else {
                quote! {
                    if raw.toc_entry_type(#toc_idx) != #toc_type_id {
                        return Err(azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType);
                    }
                }
            }
        })
        .collect()
}

/// Generate validation checks for padding TOC entries.
fn gen_padding_checks(layout: &TocLayout) -> Vec<TokenStream> {
    let padding_type_id = 9u8;
    layout
        .padding_positions
        .iter()
        .map(|&(toc_idx, _)| {
            quote! {
                if raw.toc_entry_type(#toc_idx) != #padding_type_id {
                    return Err(azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType);
                }
            }
        })
        .collect()
}

/// Generate length-constraint checks for buffer/sealed_key fields that
/// have `fixed_len`, `min_len`, or `max_len` constraints.
fn gen_len_checks(schema: &Schema, layout: &TocLayout) -> Vec<TokenStream> {
    let header_len_val = match schema.kind {
        MessageKind::Request { .. } => quote! { azihsm_fw_ddi_tbor::REQ_HEADER_LEN },
        MessageKind::Response => quote! { azihsm_fw_ddi_tbor::RESP_HEADER_LEN },
        MessageKind::Fields => unreachable!(),
    };
    schema
        .fields
        .iter()
        .enumerate()
        .filter_map(|(i, field)| {
            if !matches!(field.wire_type, WireType::Buffer | WireType::SealedKey) {
                return None;
            }
            let has_constraint =
                field.fixed_len.is_some() || field.min_len > 0 || field.max_len < 8191;
            if !has_constraint {
                return None;
            }
            let toc_idx = crate::codegen_enc::effective_toc_idx(i, layout, &schema.fields);
            let min_l = field.fixed_len.unwrap_or(field.min_len);
            let max_l = field.fixed_len.unwrap_or(field.max_len);

            if field.optional {
                let none_type_id = quote! { azihsm_fw_ddi_tbor::TocType::None as u8 };
                Some(quote! {
                    if raw.toc_entry_type(#toc_idx) != #none_type_id {
                        let len = azihsm_fw_ddi_tbor::toc::raw_toc_length(
                            azihsm_fw_ddi_tbor::toc::read_toc_word(raw.as_bytes(), #header_len_val, #toc_idx)
                        );
                        if !(#min_l..=#max_l).contains(&len) {
                            return Err(azihsm_fw_hsm_pal_traits::HsmError::TborInvalidFixedLength);
                        }
                    }
                })
            } else {
                Some(quote! {
                    {
                        let len = azihsm_fw_ddi_tbor::toc::raw_toc_length(
                            azihsm_fw_ddi_tbor::toc::read_toc_word(raw.as_bytes(), #header_len_val, #toc_idx)
                        );
                        if !(#min_l..=#max_l).contains(&len) {
                            return Err(azihsm_fw_hsm_pal_traits::HsmError::TborInvalidFixedLength);
                        }
                    }
                })
            }
        })
        .collect()
}

/// Generate the `Display` implementation for the View type.
fn gen_display(schema: &Schema, view_name: &syn::Ident) -> TokenStream {
    let struct_name_str = schema.name.to_string();

    let field_displays = schema.fields.iter().map(|field| {
        let name = &field.name;
        let name_str = field.name.to_string();
        let pad = 16usize.saturating_sub(name_str.len());
        let padding = " ".repeat(pad);

        if let Some(group) = &field.include_group {
            // Included field group: print a summary line; the group's own
            // fields are not recursed into here.
            let group_str = group.to_string();
            return quote! {
                writeln!(f, "  {}{}: [group {}]", #name_str, #padding, #group_str)?;
            };
        }

        if field.optional {
            // Optional fields: display "None" or the value.
            if field.scalar_newtype.is_some() {
                return quote! {
                    match self.#name() {
                        Some(v) => writeln!(f, "  {}{}: {}", #name_str, #padding, v.0)?,
                        None => writeln!(f, "  {}{}: None", #name_str, #padding)?,
                    }
                };
            }
            if let Some(_ty) = &field.le_scalar {
                let val = if field.le_scalar_is_byte {
                    quote! { v }
                } else {
                    quote! { v.get() }
                };
                return quote! {
                    match self.#name() {
                        Some(v) => writeln!(f, "  {}{}: {}", #name_str, #padding, #val)?,
                        None => writeln!(f, "  {}{}: None", #name_str, #padding)?,
                    }
                };
            }
            if field.elem_type.is_some() {
                return quote! {
                    match self.#name() {
                        Some(items) => writeln!(f, "  {}{}: [{} items]", #name_str, #padding, items.len())?,
                        None => writeln!(f, "  {}{}: None", #name_str, #padding)?,
                    }
                };
            }
            if field.single_pod.is_some() {
                return quote! {
                    match self.#name() {
                        Some(v) => writeln!(f, "  {}{}: {:?}", #name_str, #padding, v)?,
                        None => writeln!(f, "  {}{}: None", #name_str, #padding)?,
                    }
                };
            }
            match field.wire_type {
                WireType::Buffer | WireType::SealedKey => quote! {
                    match self.#name() {
                        Some(data) => {
                            let show = if data.len() > 16 { 16 } else { data.len() };
                            write!(f, "  {}{}: [{} bytes] ", #name_str, #padding, data.len())?;
                            for (i, b) in data[..show].iter().enumerate() {
                                if i > 0 { write!(f, " ")?; }
                                write!(f, "{:02x}", b)?;
                            }
                            if data.len() > 16 { write!(f, " ...")?; }
                            writeln!(f)?;
                        }
                        None => {
                            writeln!(f, "  {}{}: None", #name_str, #padding)?;
                        }
                    }
                },
                WireType::SessionId | WireType::KeyId => quote! {
                    match self.#name() {
                        Some(v) => writeln!(f, "  {}{}: {}", #name_str, #padding, v.0)?,
                        None => writeln!(f, "  {}{}: None", #name_str, #padding)?,
                    }
                },
                _ => quote! {
                    match self.#name() {
                        Some(v) => writeln!(f, "  {}{}: {}", #name_str, #padding, v)?,
                        None => writeln!(f, "  {}{}: None", #name_str, #padding)?,
                    }
                },
            }
        } else {
            if field.scalar_newtype.is_some() {
                return quote! {
                    writeln!(f, "  {}{}: {}", #name_str, #padding, self.#name().0)?;
                };
            }
            if let Some(_ty) = &field.le_scalar {
                let val = if field.le_scalar_is_byte {
                    quote! { self.#name() }
                } else {
                    quote! { self.#name().get() }
                };
                return quote! {
                    writeln!(f, "  {}{}: {}", #name_str, #padding, #val)?;
                };
            }
            if field.elem_type.is_some() {
                return quote! {
                    writeln!(f, "  {}{}: [{} items]", #name_str, #padding, self.#name().len())?;
                };
            }
            if field.single_pod.is_some() {
                return quote! {
                    writeln!(f, "  {}{}: {:?}", #name_str, #padding, self.#name())?;
                };
            }
            match field.wire_type {
                WireType::Buffer | WireType::SealedKey => quote! {
                    {
                        let data = self.#name();
                        let show = if data.len() > 16 { 16 } else { data.len() };
                        write!(f, "  {}{}: [{} bytes] ", #name_str, #padding, data.len())?;
                        for (i, b) in data[..show].iter().enumerate() {
                            if i > 0 { write!(f, " ")?; }
                            write!(f, "{:02x}", b)?;
                        }
                        if data.len() > 16 { write!(f, " ...")?; }
                        writeln!(f)?;
                    }
                },
                WireType::SessionId | WireType::KeyId => quote! {
                    writeln!(f, "  {}{}: {}", #name_str, #padding, self.#name().0)?;
                },
                _ => quote! {
                    writeln!(f, "  {}{}: {}", #name_str, #padding, self.#name())?;
                },
            }
        }
    });

    let header_info = match schema.kind {
        MessageKind::Request { opcode } => quote! {
            writeln!(f, "{} (opcode=0x{:02X}, {} bytes)", #struct_name_str, #opcode, self.len())?;
        },
        MessageKind::Response => quote! {
            writeln!(f, "{} (status=0x{:08X}, {} bytes)", #struct_name_str, self.status(), self.len())?;
        },
        MessageKind::Fields => unreachable!(),
    };

    quote! {
        impl core::fmt::Display for #view_name<'_> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                #header_info
                #(#field_displays)*
                Ok(())
            }
        }
    }
}

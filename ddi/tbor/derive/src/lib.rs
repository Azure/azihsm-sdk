// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side TBOR derive macros.
//!
//! Provides the `#[tbor]` attribute macro for host-side request /
//! response value types.  Mirrors the attribute spelling used by the
//! firmware `#[tbor]` macro
//! ([`azihsm_fw_ddi_tbor_derive`](../azihsm_fw_ddi_tbor_derive/index.html))
//! but emits **owned** wrappers — `Default` (opt-in via field types)
//! plus the [`TborOpReq`] / [`TborResp`] trait impls — that drive the
//! host-side [`azihsm_ddi_tbor_codec`](../azihsm_ddi_tbor_codec/index.html)
//! encoder/decoder directly.  Host-side codegen has no compile-time
//! or runtime dependency on any firmware crate.
//!
//! This is a pure proc-macro crate: it has no Cargo dependency on any
//! firmware crate (it just transforms tokens).  The **generated** code
//! references only [`azihsm_ddi_tbor_codec`] and
//! [`azihsm_ddi_tbor_types`](../azihsm_ddi_tbor_types/index.html).
//!
//! # Surface
//!
//! ## Struct-level attributes
//!
//! | Form | Meaning |
//! |---|---|
//! | `#[tbor(opcode = N, session_ctrl = <v>)]` | **request — both required.** Sets the wire opcode and the SQE `session_flags.ctrl` byte; `session_ctrl` is one of `no_session`, `open`, `close`, `in_session` |
//! | `#[tbor(opcode = N, session_ctrl = <v>, resp = TborFooResp)]` | request with explicit response type |
//! | `#[tbor(response)]` | response (no `session_ctrl`, no `opcode`) |
//!
//! `OpResp` defaults to a `Req → Resp` name swap when `resp` is
//! omitted.  A request struct without `session_ctrl` or `opcode` is
//! a compile error.
//!
//! ## Field-level attributes
//!
//! | Attr | Meaning |
//! |---|---|
//! | `#[tbor(session_id)]` | field is a `u16` carried as `SessionId` on the wire |
//! | `#[tbor(key_id)]` | field is a `u16` carried as `KeyId` on the wire |
//! | `#[tbor(min_len = N)]` | accepted for parity with FW; not host-side enforced — the FW codec validates |
//! | `#[tbor(max_len = N)]` | accepted for parity with FW; not host-side enforced — the FW encoder validates |
//!
//! ## Field-type inference rules
//!
//! | Rust type | Wire op |
//! |---|---|
//! | `u8`/`u16`/`u32`/`u64` | inline primitive |
//! | `u16` + `#[tbor(session_id)]` | typed inline as `SessionId` |
//! | `u16` + `#[tbor(key_id)]` | typed inline as `KeyId` |
//! | `[u8; N]` | fixed-length buffer |
//! | `Vec<u8>` | variable buffer |
//! | `Option<Vec<u8>>` | optional variable buffer |
//!
//! [`TborOpReq`]: ../azihsm_ddi_tbor_types/trait.TborOpReq.html
//! [`TborResp`]: ../azihsm_ddi_tbor_types/trait.TborResp.html

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::format_ident;
use quote::quote;
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::Fields;
use syn::FieldsNamed;
use syn::Ident;
use syn::ItemStruct;
use syn::Type;

mod parse;

use parse::FieldShape;
use parse::ParsedField;
use parse::StructAttrs;
use parse::StructKind;

/// Host-side `#[tbor]` attribute macro — see crate-level docs.
#[proc_macro_attribute]
pub fn tbor(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemStruct);
    let attr: TokenStream2 = attr.into();

    match expand(attr, &item) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand(attr: TokenStream2, item: &ItemStruct) -> syn::Result<TokenStream2> {
    let struct_attrs = StructAttrs::parse(attr)?;
    let fields = collect_fields(item)?;

    // Re-emit the user's struct verbatim, but strip any field-level
    // `#[tbor(...)]` helper attributes (they're consumed by this macro
    // and would otherwise be unknown to rustc).
    let stripped = strip_field_tbor_attrs(item);

    let body = match struct_attrs.kind {
        StructKind::Request => gen_request(&struct_attrs, item, &fields)?,
        StructKind::Response => gen_response(item, &fields),
    };

    Ok(quote! {
        #stripped
        #body
    })
}

fn collect_fields(item: &ItemStruct) -> syn::Result<Vec<ParsedField>> {
    match &item.fields {
        Fields::Unit => Ok(Vec::new()),
        Fields::Named(FieldsNamed { named, .. }) => named.iter().map(ParsedField::parse).collect(),
        Fields::Unnamed(_) => Err(syn::Error::new(
            item.fields.span(),
            "#[tbor] does not support tuple structs",
        )),
    }
}

fn strip_field_tbor_attrs(item: &ItemStruct) -> ItemStruct {
    let mut clone = item.clone();
    if let Fields::Named(named) = &mut clone.fields {
        for f in named.named.iter_mut() {
            f.attrs.retain(|a| !a.path().is_ident("tbor"));
        }
    }
    clone
}

/// Default response type: replace a trailing `Req` with `Resp` in the
/// struct name; fall back to appending `Resp` if no trailing `Req`.
fn default_resp_type(name: &Ident) -> Ident {
    let s = name.to_string();
    let stem = s.strip_suffix("Req").unwrap_or(s.as_str());
    format_ident!("{stem}Resp")
}

fn gen_request(
    attrs: &StructAttrs,
    item: &ItemStruct,
    fields: &[ParsedField],
) -> syn::Result<TokenStream2> {
    let name = &item.ident;
    let opcode = attrs.opcode.as_ref().ok_or_else(|| {
        syn::Error::new(
            name.span(),
            "missing required `opcode` attribute on request struct.\n\
             example: #[tbor(opcode = 0x30, session_ctrl = in_session)]",
        )
    })?;
    let resp_ty: Type = match &attrs.resp {
        Some(p) => syn::parse_quote!(#p),
        None => {
            let r = default_resp_type(name);
            syn::parse_quote!(#r)
        }
    };

    let encode_chain: TokenStream2 = if fields.is_empty() {
        // Codec requires `toc_count >= 1`; emit a synthetic None
        // placeholder so empty-body requests can still encode.
        quote! { let __enc = __enc.none()?; }
    } else {
        fields.iter().map(gen_encode_step).collect()
    };

    let session_id_field = fields
        .iter()
        .find(|f| matches!(f.shape, crate::parse::FieldShape::SessionId))
        .map(|f| f.name.clone());

    let get_session_id_impl = match &session_id_field {
        Some(name) => quote! {
            fn get_session_id(&self) -> ::core::option::Option<u16> {
                ::core::option::Option::Some(self.#name)
            }
        },
        None => quote! {},
    };

    let ctrl_variant = attrs.session_ctrl.as_ref().ok_or_else(|| {
        syn::Error::new(
            name.span(),
            "missing required `session_ctrl` attribute on request struct.\n\
             example: #[tbor(opcode = 0x30, session_ctrl = no_session)]\n\
             allowed variants: no_session, open, close, in_session",
        )
    })?;
    let session_ctrl_impl = quote! {
        fn session_ctrl(&self) -> ::azihsm_ddi_tbor_types::SessionControlKind {
            ::azihsm_ddi_tbor_types::SessionControlKind::#ctrl_variant
        }
    };

    Ok(quote! {
        impl ::azihsm_ddi_tbor_types::TborOpReq for #name {
            const OPCODE: u8 = #opcode;
            type OpResp = #resp_ty;

            #get_session_id_impl
            #session_ctrl_impl

            fn encode_request<'__b>(
                &self,
                __buf: &'__b mut [u8],
            ) -> ::core::result::Result<&'__b [u8], ::azihsm_ddi_tbor_codec::EncodeError> {
                let __enc = ::azihsm_ddi_tbor_codec::RequestEncoder::new(
                    __buf,
                    ::azihsm_ddi_tbor_codec::PROTOCOL_VERSION,
                    <Self as ::azihsm_ddi_tbor_types::TborOpReq>::OPCODE,
                );
                #encode_chain
                __enc.finish()
            }
        }
    })
}
fn gen_response(item: &ItemStruct, fields: &[ParsedField]) -> TokenStream2 {
    let name = &item.ident;

    // Compute the TOC layout. Typed-slice elements are `Unaligned`, so no
    // alignment padding entry precedes them — every field maps to a single
    // sequential TOC slot, matching the firmware derive's layout.
    let mut toc_idx = 0usize;
    let mut decode_steps_vec: Vec<TokenStream2> = Vec::with_capacity(fields.len());
    for f in fields {
        decode_steps_vec.push(gen_decode_step(toc_idx, f));
        toc_idx += 1;
    }
    let decode_steps: TokenStream2 = decode_steps_vec.into_iter().collect();

    // Empty bodies still carry one synthetic `None` TOC entry (see
    // `gen_request` encode chain), so toc_count is always `>= 1`.
    let expected_toc = toc_idx.max(1);

    let construct = if fields.is_empty() {
        quote! { Self }
    } else {
        let names = fields.iter().map(|f| &f.name);
        quote! { Self { #(#names,)* } }
    };

    quote! {
        impl ::azihsm_ddi_tbor_types::TborResp for #name {
            fn decode_response(
                __buf: &[u8],
            ) -> ::core::result::Result<Self, ::azihsm_ddi_tbor_codec::DecodeError> {
                let __raw = ::azihsm_ddi_tbor_codec::ResponseView::parse(__buf)?;
                if __raw.status() != 0 {
                    return ::core::result::Result::Err(
                        ::azihsm_ddi_tbor_codec::DecodeError::FwError(__raw.status()),
                    );
                }
                if __raw.toc_count() < #expected_toc {
                    return ::core::result::Result::Err(
                        ::azihsm_ddi_tbor_codec::DecodeError::MessageTruncated,
                    );
                }
                // Forward-compat: trailing TOC entries beyond the
                // schema we know are ignored so a newer FW can append
                // fields without breaking host decode of the known
                // prefix.
                #decode_steps
                ::core::result::Result::Ok(#construct)
            }
        }
    }
}

/// Emit one statement that rebinds `__enc` by applying a single codec
/// primitive call for the field.
fn gen_encode_step(f: &ParsedField) -> TokenStream2 {
    let name = &f.name;
    match &f.shape {
        FieldShape::U8 => quote! {
            let __enc = __enc.uint8(self.#name)?;
        },
        FieldShape::U16 => quote! {
            let __enc = __enc.uint16(self.#name)?;
        },
        FieldShape::U32 => quote! {
            let __enc = __enc.uint32(self.#name)?;
        },
        FieldShape::U64 => quote! {
            let __enc = __enc.uint64(self.#name)?;
        },
        FieldShape::LeU16 => quote! {
            let __enc = __enc.uint16(self.#name.get())?;
        },
        FieldShape::LeU32 => quote! {
            let __enc = __enc.uint32(self.#name.get())?;
        },
        FieldShape::LeU64 => quote! {
            let __enc = __enc.uint64(self.#name.get())?;
        },
        FieldShape::SessionId => quote! {
            let __enc = __enc.session_id(self.#name)?;
        },
        FieldShape::KeyId => quote! {
            let __enc = __enc.key_id(self.#name)?;
        },
        FieldShape::FixedBuf | FieldShape::VarBuf => quote! {
            let __enc = __enc.buffer(&self.#name)?;
        },
        FieldShape::TypedVarBuf(_) => quote! {
            // `CertDescriptor`-style typed slice elements are `Unaligned`
            // (alignment 1), so the data needs no alignment padding — the
            // packed little-endian element bytes encode 1:1 with the
            // firmware derive's zero-copy layout.
            let __enc = __enc.buffer(
                ::zerocopy::IntoBytes::as_bytes(&self.#name[..]),
            )?;
        },
        FieldShape::TypedFixed(_) => quote! {
            let __enc = __enc.buffer(
                ::zerocopy::IntoBytes::as_bytes(&self.#name),
            )?;
        },
        FieldShape::OptVarBuf => quote! {
            let __enc = match self.#name.as_deref() {
                ::core::option::Option::Some(__b) => __enc.buffer(__b)?,
                ::core::option::Option::None => __enc.none()?,
            };
        },
    }
}

/// Emit one statement that binds a local with the field's name by
/// matching the expected `TocEntry` variant at TOC index `idx`.
fn gen_decode_step(idx: usize, f: &ParsedField) -> TokenStream2 {
    let name = &f.name;
    let ty = &f.ty;

    let unexpected = quote! {
        _ => return ::core::result::Result::Err(
            ::azihsm_ddi_tbor_codec::DecodeError::UnexpectedTocType,
        ),
    };

    // Shared shape for the 5 inline-primitive variants: pull the value
    // straight out of the matching `TocEntry` arm, or bail out.
    let primitive = |variant: Ident| {
        quote! {
            match __raw.toc_entry(#idx) {
                ::azihsm_ddi_tbor_codec::TocEntry::#variant(__v) => __v,
                #unexpected
            }
        }
    };

    let body = match &f.shape {
        FieldShape::SessionId => primitive(format_ident!("SessionId")),
        FieldShape::KeyId => primitive(format_ident!("KeyId")),
        FieldShape::U8 => primitive(format_ident!("Uint8")),
        FieldShape::U16 => primitive(format_ident!("Uint16")),
        FieldShape::U32 => primitive(format_ident!("Uint32")),
        FieldShape::U64 => primitive(format_ident!("Uint64")),
        FieldShape::LeU16 => {
            let inner = primitive(format_ident!("Uint16"));
            quote! { <#ty>::new(#inner) }
        }
        FieldShape::LeU32 => {
            let inner = primitive(format_ident!("Uint32"));
            quote! { <#ty>::new(#inner) }
        }
        FieldShape::LeU64 => {
            let inner = primitive(format_ident!("Uint64"));
            quote! { <#ty>::new(#inner) }
        }
        FieldShape::FixedBuf => quote! {
            match __raw.toc_entry(#idx) {
                ::azihsm_ddi_tbor_codec::TocEntry::Buffer(__b) => {
                    <#ty as ::core::convert::TryFrom<&[u8]>>::try_from(__b)
                        .map_err(|_| ::azihsm_ddi_tbor_codec::DecodeError::InvalidFixedLength)?
                }
                #unexpected
            }
        },
        FieldShape::VarBuf => quote! {
            match __raw.toc_entry(#idx) {
                ::azihsm_ddi_tbor_codec::TocEntry::Buffer(__b) => ::alloc::vec::Vec::from(__b),
                #unexpected
            }
        },
        FieldShape::TypedVarBuf(elem) => {
            let elem = &**elem;
            quote! {
                match __raw.toc_entry(#idx) {
                    ::azihsm_ddi_tbor_codec::TocEntry::Buffer(__b) => {
                        let __sz = ::core::mem::size_of::<#elem>();
                        if __sz == 0 || __b.len() % __sz != 0 {
                            return ::core::result::Result::Err(
                                ::azihsm_ddi_tbor_codec::DecodeError::InvalidFixedLength,
                            );
                        }
                        let mut __v = ::alloc::vec::Vec::with_capacity(__b.len() / __sz);
                        for __c in __b.chunks_exact(__sz) {
                            __v.push(
                                <#elem as ::zerocopy::FromBytes>::read_from_bytes(__c)
                                    .map_err(|_| ::azihsm_ddi_tbor_codec::DecodeError::InvalidFixedLength)?,
                            );
                        }
                        __v
                    }
                    #unexpected
                }
            }
        }
        FieldShape::TypedFixed(ty) => {
            let ty = &**ty;
            quote! {
                match __raw.toc_entry(#idx) {
                    ::azihsm_ddi_tbor_codec::TocEntry::Buffer(__b) => {
                        // Copy into an owned value via `try_read_from_bytes`
                        // (no alignment requirement), since TBOR buffer
                        // payloads can start at arbitrary offsets.
                        <#ty as ::zerocopy::TryFromBytes>::try_read_from_bytes(__b)
                            .map_err(|_| ::azihsm_ddi_tbor_codec::DecodeError::InvalidFixedLength)?
                    }
                    #unexpected
                }
            }
        }
        FieldShape::OptVarBuf => quote! {
            match __raw.toc_entry(#idx) {
                ::azihsm_ddi_tbor_codec::TocEntry::Buffer(__b) =>
                    ::core::option::Option::Some(::alloc::vec::Vec::from(__b)),
                ::azihsm_ddi_tbor_codec::TocEntry::None =>
                    ::core::option::Option::None,
                #unexpected
            }
        },
    };
    quote! {
        let #name = #body;
    }
}

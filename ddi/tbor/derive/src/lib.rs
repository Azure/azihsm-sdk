// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side TBOR derive macros.
//!
//! Provides the `#[tbor]` attribute macro for host-side request /
//! response value types.  Mirrors the attribute spelling used by the
//! firmware `#[tbor]` macro
//! ([`azihsm_fw_ddi_tbor_derive`](../azihsm_fw_ddi_tbor_derive/index.html))
//! but emits **owned** wrappers — `Default` (opt-in via field types)
//! plus the [`TborOpReq`] / [`TborResp`] trait impls — that delegate
//! to the firmware-side zero-copy typestate encoder/decoder.
//!
//! This is a pure proc-macro crate: it has no Cargo dependency on any
//! firmware crate (it just transforms tokens).  The **generated** code
//! references the shared no_std crates
//! [`azihsm_fw_ddi_tbor_types`](../azihsm_fw_ddi_tbor_types/index.html)
//! (for the wire schema) and
//! [`azihsm_ddi_tbor_codec`](../azihsm_ddi_tbor_codec/index.html)
//! (for `EncodeError`/`DecodeError`/`TborRequest`), which the host
//! types crate already depends on.
//!
//! # Surface
//!
//! ## Struct-level attributes
//!
//! | Form | Meaning |
//! |---|---|
//! | `#[tbor]` | request; opcode pulled from the FW schema's `TborRequest::OPCODE` impl; `OpResp` defaults to `Req → Resp` name swap |
//! | `#[tbor(resp = TborFooResp)]` | request with explicit response type |
//! | `#[tbor(schema = path::Type)]` | request/response with explicit FW schema path |
//! | `#[tbor(response)]` | response |
//!
//! ## Field-level attributes
//!
//! | Attr | Meaning |
//! |---|---|
//! | `#[tbor(session_id)]` | field is a `u16` carried as `SessionId` on the wire |
//! | `#[tbor(min_len = N)]` | accepted for parity with FW; not host-side enforced — the FW codec validates |
//! | `#[tbor(max_len = N)]` | accepted for parity with FW; not host-side enforced — the FW encoder validates |
//!
//! ## Field-type inference rules
//!
//! | Rust type | Wire op |
//! |---|---|
//! | `u8`/`u16`/`u32`/`u64` | inline primitive |
//! | `u16` + `#[tbor(session_id)]` | typed inline as `SessionId` |
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
use syn::Path;
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
        StructKind::Response => gen_response(&struct_attrs, item, &fields)?,
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

/// Default FW schema path: `azihsm_fw_ddi_tbor_types::<SameName>`.
fn default_schema_path(name: &Ident) -> Path {
    syn::parse_quote!(::azihsm_fw_ddi_tbor_types::#name)
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
    let schema = attrs
        .schema
        .clone()
        .unwrap_or_else(|| default_schema_path(name));
    let resp_ty: Type = match &attrs.resp {
        Some(p) => syn::parse_quote!(#p),
        None => {
            let r = default_resp_type(name);
            syn::parse_quote!(#r)
        }
    };

    let encode_chain = fields
        .iter()
        .map(gen_encode_call)
        .collect::<syn::Result<TokenStream2>>()?;

    Ok(quote! {
        impl ::azihsm_ddi_tbor_types::TborOpReq for #name {
            const OPCODE: u8 = <#schema as ::azihsm_ddi_tbor_codec::TborRequest>::OPCODE;
            type OpResp = #resp_ty;

            fn encode_request<'__b>(
                &self,
                __buf: &'__b mut [u8],
            ) -> ::core::result::Result<&'__b [u8], ::azihsm_ddi_tbor_codec::EncodeError> {
                let __frame = #schema::encode(__buf)?
                    #encode_chain
                    .finish();
                ::core::result::Result::Ok(__frame.as_bytes())
            }
        }
    })
}

fn gen_response(
    attrs: &StructAttrs,
    item: &ItemStruct,
    fields: &[ParsedField],
) -> syn::Result<TokenStream2> {
    let name = &item.ident;
    let schema = attrs
        .schema
        .clone()
        .unwrap_or_else(|| default_schema_path(name));

    if fields.is_empty() {
        return Ok(quote! {
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
                    let _ = #schema::decode(__buf)?;
                    ::core::result::Result::Ok(Self)
                }
            }
        });
    }

    let init = fields
        .iter()
        .map(gen_decode_field)
        .collect::<syn::Result<TokenStream2>>()?;

    Ok(quote! {
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
                let __view = #schema::decode(__buf)?;
                ::core::result::Result::Ok(Self { #init })
            }
        }
    })
}

/// Emit one `.field(arg)?` link of the encoder chain for a field.
fn gen_encode_call(f: &ParsedField) -> syn::Result<TokenStream2> {
    let name = &f.name;
    Ok(match &f.shape {
        FieldShape::U8 | FieldShape::U16 | FieldShape::U32 | FieldShape::U64 => quote! {
            .#name(self.#name)?
        },
        FieldShape::SessionId => quote! {
            .#name(self.#name.into())?
        },
        FieldShape::FixedBuf => quote! {
            .#name(&self.#name)?
        },
        FieldShape::VarBuf => quote! {
            .#name(&self.#name)?
        },
        FieldShape::OptVarBuf => quote! {
            .#name(self.#name.as_deref())?
        },
    })
}

/// Emit one `field: <expr>,` initializer for the struct literal that
/// rebuilds the decoded response value.
fn gen_decode_field(f: &ParsedField) -> syn::Result<TokenStream2> {
    let name = &f.name;
    let ty = &f.ty;
    let value = match &f.shape {
        FieldShape::U8 | FieldShape::U16 | FieldShape::U32 | FieldShape::U64 => quote! {
            __view.#name()
        },
        FieldShape::SessionId => quote! {
            __view.#name().into()
        },
        FieldShape::FixedBuf => quote! {
            // FW codec validated the length on decode; the slice is
            // guaranteed to be exactly the declared size.  The struct
            // field's `[u8; N]` annotation drives the array size.
            {
                let __slice: &[u8] = __view.#name();
                <#ty as ::core::convert::TryFrom<&[u8]>>::try_from(__slice)
                    .expect("FW codec validated #[tbor(len = N)]")
            }
        },
        FieldShape::VarBuf => quote! {
            ::alloc::vec::Vec::from(__view.#name())
        },
        FieldShape::OptVarBuf => quote! {
            __view.#name().map(::alloc::vec::Vec::from)
        },
    };
    Ok(quote! { #name: #value, })
}

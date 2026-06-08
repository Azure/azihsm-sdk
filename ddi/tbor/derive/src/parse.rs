// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Attribute and field parsing for the host `#[tbor]` macro.

use proc_macro2::TokenStream as TokenStream2;
use syn::spanned::Spanned;
use syn::Attribute;
use syn::Field;
use syn::GenericArgument;
use syn::Ident;
use syn::Path;
use syn::PathArguments;
use syn::Type;

/// Whether the annotated struct is a request or a response.
pub enum StructKind {
    Request,
    Response,
}

/// Struct-level `#[tbor(...)]` options.
pub struct StructAttrs {
    pub kind: StructKind,
    /// Explicit response type for a request struct (`#[tbor(resp = T)]`).
    /// Ignored on response structs.
    pub resp: Option<Path>,
    /// Explicit FW schema path (`#[tbor(schema = path::T)]`).  Defaults
    /// to `::azihsm_fw_ddi_tbor_types::<SameStructName>` when omitted.
    pub schema: Option<Path>,
}

impl StructAttrs {
    pub fn parse(attr: TokenStream2) -> syn::Result<Self> {
        let mut kind = StructKind::Request;
        let mut resp: Option<Path> = None;
        let mut schema: Option<Path> = None;
        let mut saw_response = false;
        let mut saw_resp = false;
        let mut saw_schema = false;

        if !attr.is_empty() {
            let parser = syn::meta::parser(|m| {
                if m.path.is_ident("response") {
                    if saw_response {
                        return Err(m.error("duplicate `response`"));
                    }
                    saw_response = true;
                    kind = StructKind::Response;
                    Ok(())
                } else if m.path.is_ident("resp") {
                    if saw_resp {
                        return Err(m.error("duplicate `resp`"));
                    }
                    saw_resp = true;
                    resp = Some(m.value()?.parse()?);
                    Ok(())
                } else if m.path.is_ident("schema") {
                    if saw_schema {
                        return Err(m.error("duplicate `schema`"));
                    }
                    saw_schema = true;
                    schema = Some(m.value()?.parse()?);
                    Ok(())
                } else {
                    Err(m.error(format!(
                        "unknown #[tbor] option `{}` — expected one of: \
                         `response`, `resp = T`, `schema = path::T`",
                        m.path
                            .get_ident()
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "<path>".to_string()),
                    )))
                }
            });
            syn::parse::Parser::parse2(parser, attr)?;
        }

        if saw_response && saw_resp {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "#[tbor(response)] is mutually exclusive with `resp = ...`",
            ));
        }

        Ok(Self { kind, resp, schema })
    }
}

/// Wire shape of a field, inferred from the Rust type plus any
/// field-level `#[tbor(...)]` attributes.
pub enum FieldShape {
    U8,
    U16,
    U32,
    U64,
    /// `u16` + `#[tbor(session_id)]`.
    SessionId,
    /// `[u8; N]`.  N is not tracked here — the FW codec is the length
    /// authority; we just need to know the value is a fixed-size byte
    /// array so we can use `try_into()` in the decode codegen.
    FixedBuf,
    /// `Vec<u8>`.
    VarBuf,
    /// `Option<Vec<u8>>`.
    OptVarBuf,
}

/// One field of the user struct, parsed.
pub struct ParsedField {
    pub name: Ident,
    pub ty: Type,
    pub shape: FieldShape,
}

impl ParsedField {
    pub fn parse(f: &Field) -> syn::Result<Self> {
        let name = f
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new(f.span(), "expected a named field"))?;
        let flags = FieldFlags::collect(&f.attrs)?;

        let base = classify_type(&f.ty).ok_or_else(|| {
            syn::Error::new(
                f.ty.span(),
                "#[tbor] field type must be one of: u8, u16, u32, u64, \
                 [u8; N], Vec<u8>, Option<Vec<u8>>",
            )
        })?;

        // Promote `u16 + #[tbor(session_id)]` to SessionId.  The flag is
        // invalid on any other type.
        let shape = if flags.session_id {
            match base {
                FieldShape::U16 => FieldShape::SessionId,
                _ => {
                    return Err(syn::Error::new(
                        f.span(),
                        "#[tbor(session_id)] requires a `u16` field",
                    ))
                }
            }
        } else {
            base
        };

        // `min_len` / `max_len` are documentation parity only; reject
        // if put on a non-variable field.
        if (flags.has_max_len || flags.has_min_len)
            && !matches!(shape, FieldShape::VarBuf | FieldShape::OptVarBuf)
        {
            return Err(syn::Error::new(
                f.span(),
                "#[tbor(min_len = N)] / #[tbor(max_len = N)] are only valid \
                 on `Vec<u8>` / `Option<Vec<u8>>` fields",
            ));
        }

        Ok(Self {
            name,
            ty: f.ty.clone(),
            shape,
        })
    }
}

#[derive(Default)]
struct FieldFlags {
    session_id: bool,
    has_max_len: bool,
    has_min_len: bool,
}

impl FieldFlags {
    fn collect(attrs: &[Attribute]) -> syn::Result<Self> {
        let mut out = Self::default();
        for a in attrs {
            if !a.path().is_ident("tbor") {
                continue;
            }
            a.parse_nested_meta(|m| {
                if m.path.is_ident("session_id") {
                    out.session_id = true;
                    Ok(())
                } else if m.path.is_ident("max_len") {
                    out.has_max_len = true;
                    let _ = m.value()?.parse::<syn::LitInt>()?;
                    Ok(())
                } else if m.path.is_ident("min_len") {
                    out.has_min_len = true;
                    let _ = m.value()?.parse::<syn::LitInt>()?;
                    Ok(())
                } else if m.path.is_ident("len") {
                    Err(m.error(
                        "#[tbor(len = N)] is redundant on host — \
                         the `[u8; N]` field type already encodes the \
                         length; the FW codec is the length authority",
                    ))
                } else {
                    Err(m.error(format!(
                        "unknown #[tbor] field option `{}` — expected one of: \
                         `session_id`, `min_len = N`, `max_len = N`",
                        m.path
                            .get_ident()
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "<path>".to_string()),
                    )))
                }
            })?;
        }
        Ok(out)
    }
}

fn classify_type(ty: &Type) -> Option<FieldShape> {
    // Fixed buffer: `[u8; N]` (any N).
    if let Type::Array(arr) = ty {
        if is_u8(&arr.elem) {
            return Some(FieldShape::FixedBuf);
        }
        return None;
    }

    let path = match ty {
        Type::Path(p) if p.qself.is_none() => &p.path,
        _ => return None,
    };
    let last = path.segments.last()?;
    let name = last.ident.to_string();

    match name.as_str() {
        "u8" if matches!(last.arguments, PathArguments::None) => Some(FieldShape::U8),
        "u16" if matches!(last.arguments, PathArguments::None) => Some(FieldShape::U16),
        "u32" if matches!(last.arguments, PathArguments::None) => Some(FieldShape::U32),
        "u64" if matches!(last.arguments, PathArguments::None) => Some(FieldShape::U64),
        "Vec" => {
            let inner = single_generic_type(&last.arguments)?;
            if is_u8(inner) {
                Some(FieldShape::VarBuf)
            } else {
                None
            }
        }
        "Option" => {
            let inner = single_generic_type(&last.arguments)?;
            if let Some(FieldShape::VarBuf) = classify_type(inner) {
                Some(FieldShape::OptVarBuf)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_u8(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.qself.is_none() && p.path.is_ident("u8"))
}

fn single_generic_type(args: &PathArguments) -> Option<&Type> {
    let bracketed = match args {
        PathArguments::AngleBracketed(b) => b,
        _ => return None,
    };
    if bracketed.args.len() != 1 {
        return None;
    }
    match bracketed.args.first()? {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Attribute and field parsing for the host `#[tbor]` macro.

use proc_macro2::Span;
use proc_macro2::TokenStream as TokenStream2;
use syn::meta::ParseNestedMeta;
use syn::spanned::Spanned;
use syn::Attribute;
use syn::Field;
use syn::GenericArgument;
use syn::Ident;
use syn::Path;
use syn::PathArguments;
use syn::Type;

/// Allowed struct-level option names, for error messages.
const STRUCT_OPTS: &str = "`response`, `resp = T`, `opcode = N`, `session_ctrl = variant`";

/// Allowed field-level option names, for error messages.
const FIELD_OPTS: &str = "`session_id`, `min_len = N`, `max_len = N`";

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
    /// Required opcode for a request struct (`#[tbor(opcode = 0xNN)]`).
    /// Ignored on response structs.
    pub opcode: Option<syn::Expr>,
    /// Required `session_ctrl()` value.  Mandatory on request
    /// structs (no default — explicit only).  Accepts the
    /// lower-case identifier of a [`SessionControlKind`] variant:
    /// `no_session`, `open`, `close`, or `in_session`.  Stored as
    /// the matching CamelCase ident for code generation.
    pub session_ctrl: Option<Ident>,
}

impl StructAttrs {
    pub fn parse(attr: TokenStream2) -> syn::Result<Self> {
        if attr.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("#[tbor] requires at least one option — expected one of: {STRUCT_OPTS}"),
            ));
        }

        let mut response: Option<()> = None;
        let mut resp: Option<Path> = None;
        let mut opcode: Option<syn::Expr> = None;
        let mut session_ctrl: Option<Ident> = None;

        let parser = syn::meta::parser(|m| {
            if m.path.is_ident("response") {
                set_once(&mut response, &m, "response", ())
            } else if m.path.is_ident("resp") {
                let v = m.value()?.parse()?;
                set_once(&mut resp, &m, "resp", v)
            } else if m.path.is_ident("opcode") {
                let v = m.value()?.parse()?;
                set_once(&mut opcode, &m, "opcode", v)
            } else if m.path.is_ident("session_ctrl") {
                let raw: Ident = m.value()?.parse()?;
                let variant = session_ctrl_variant(&raw).ok_or_else(|| {
                    m.error(
                        "session_ctrl must be one of: \
                         no_session, open, close, in_session",
                    )
                })?;
                set_once(&mut session_ctrl, &m, "session_ctrl", variant)
            } else {
                Err(unknown_option(&m, "#[tbor]", STRUCT_OPTS))
            }
        });
        syn::parse::Parser::parse2(parser, attr)?;

        if response.is_some() && resp.is_some() {
            return Err(syn::Error::new(
                Span::call_site(),
                "#[tbor(response)] is mutually exclusive with `resp = ...`",
            ));
        }

        if response.is_some() && opcode.is_some() {
            return Err(syn::Error::new(
                Span::call_site(),
                "#[tbor(response)] does not accept `opcode = ...` \
                 (responses do not carry an opcode)",
            ));
        }

        if response.is_some() && session_ctrl.is_some() {
            return Err(syn::Error::new(
                Span::call_site(),
                "#[tbor(response)] does not accept `session_ctrl = ...` \
                 (session control lives on the request)",
            ));
        }

        let kind = if response.is_some() {
            StructKind::Response
        } else {
            StructKind::Request
        };

        Ok(Self {
            kind,
            resp,
            opcode,
            session_ctrl,
        })
    }
}

/// Map a lower-case `session_ctrl` identifier to its `SessionControlKind`
/// CamelCase variant ident, preserving the source span for diagnostics.
fn session_ctrl_variant(ident: &Ident) -> Option<Ident> {
    let camel = match ident.to_string().as_str() {
        "no_session" => "NoSession",
        "open" => "Open",
        "close" => "Close",
        "in_session" => "InSession",
        _ => return None,
    };
    Some(Ident::new(camel, ident.span()))
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
        let shape = resolve_shape(f, &flags)?;

        Ok(Self {
            name,
            ty: f.ty.clone(),
            shape,
        })
    }
}

/// Combine the Rust type and the parsed field-level flags into a final
/// [`FieldShape`], rejecting flag/type combinations that are invalid.
fn resolve_shape(f: &Field, flags: &FieldFlags) -> syn::Result<FieldShape> {
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
        if matches!(base, FieldShape::U16) {
            FieldShape::SessionId
        } else {
            return Err(syn::Error::new(
                f.span(),
                "#[tbor(session_id)] requires a `u16` field",
            ));
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

    Ok(shape)
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
                    m.value()?.parse::<syn::LitInt>().map(|_| ())
                } else if m.path.is_ident("min_len") {
                    out.has_min_len = true;
                    m.value()?.parse::<syn::LitInt>().map(|_| ())
                } else if m.path.is_ident("len") {
                    Err(m.error(
                        "#[tbor(len = N)] is redundant on host — \
                         the `[u8; N]` field type already encodes the \
                         length; the FW codec is the length authority",
                    ))
                } else {
                    Err(unknown_option(&m, "#[tbor] field", FIELD_OPTS))
                }
            })?;
        }
        Ok(out)
    }
}

/// Set `slot` to `value`, erroring at the meta's span if it was already set.
fn set_once<T>(
    slot: &mut Option<T>,
    m: &ParseNestedMeta<'_>,
    name: &str,
    value: T,
) -> syn::Result<()> {
    if slot.is_some() {
        return Err(m.error(format!("duplicate `{name}`")));
    }
    *slot = Some(value);
    Ok(())
}

/// Format a consistent "unknown option" diagnostic for a `#[tbor(...)]` meta.
fn unknown_option(m: &ParseNestedMeta<'_>, scope: &str, allowed: &str) -> syn::Error {
    let opt = m
        .path
        .get_ident()
        .map(|i| i.to_string())
        .unwrap_or_else(|| "<path>".to_string());
    m.error(format!(
        "unknown {scope} option `{opt}` — expected one of: {allowed}"
    ))
}

fn classify_type(ty: &Type) -> Option<FieldShape> {
    // Fixed buffer: `[u8; N]` (any N).
    if let Type::Array(arr) = ty {
        return is_u8(&arr.elem).then_some(FieldShape::FixedBuf);
    }

    let Type::Path(p) = ty else {
        return None;
    };
    if p.qself.is_some() {
        return None;
    }
    let last = p.path.segments.last()?;
    let no_args = matches!(last.arguments, PathArguments::None);

    match last.ident.to_string().as_str() {
        "u8" if no_args => Some(FieldShape::U8),
        "u16" if no_args => Some(FieldShape::U16),
        "u32" if no_args => Some(FieldShape::U32),
        "u64" if no_args => Some(FieldShape::U64),
        "Vec" => {
            let inner = single_generic_type(&last.arguments)?;
            is_u8(inner).then_some(FieldShape::VarBuf)
        }
        "Option" => {
            let inner = single_generic_type(&last.arguments)?;
            matches!(classify_type(inner), Some(FieldShape::VarBuf))
                .then_some(FieldShape::OptVarBuf)
        }
        _ => None,
    }
}

fn is_u8(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.qself.is_none() && p.path.is_ident("u8"))
}

fn single_generic_type(args: &PathArguments) -> Option<&Type> {
    let PathArguments::AngleBracketed(bracketed) = args else {
        return None;
    };
    if bracketed.args.len() != 1 {
        return None;
    }
    match bracketed.args.first()? {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    }
}

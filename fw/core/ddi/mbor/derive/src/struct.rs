// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parsing of `#[ddi(map)]` attributes on named structs.
//!
//! A **DDI map struct** represents an MBOR map — a sequence of `(field-ID,
//! value)` pairs. Each field is annotated with `#[ddi(id = N)]` and may carry
//! additional attributes:
//!
//! * `len = N` — the field is a fixed-length byte slice (no padding).
//! * `max_len = N` — the field is a variable-length byte slice with an upper
//!   bound (padded to 4-byte alignment).
//!
//! This module validates the derive input, classifies each field into a
//! [`DdiStructFieldKind`], and produces a [`DdiStruct`] descriptor used by the
//! code-generation modules ([`crate::encode`], [`crate::decode`],
//! [`crate::len`], [`crate::frame`]).

use std::vec;

use darling::ast;
use darling::FromDeriveInput;
use darling::FromField;
use syn::spanned::Spanned;
use syn::GenericArgument;
use syn::PathArguments::AngleBracketed;

/// Darling helper for extracting per-field `#[ddi(…)]` attributes.
#[derive(Debug, FromField)]
#[darling(attributes(ddi))]
struct DdiStructFieldAttr {
    /// Field name (always `Some` for named structs).
    ident: Option<syn::Ident>,
    /// The declared type of the field.
    ty: syn::Type,
    /// MBOR field ID — must be unique and sequential within the struct.
    id: u8,
    /// Exact byte length for fixed-size byte-slice fields (no padding).
    len: Option<usize>,
    /// Maximum byte length for variable-size byte-slice fields.
    max_len: Option<usize>,
    /// Opt-in for nested frame-then-fill encoding. Only valid on
    /// non-optional `Normal` fields whose type implements `MborFrameable`.
    #[darling(default)]
    frame: bool,
}

/// Darling helper for extracting top-level `#[ddi(…)]` attributes from a
/// named struct derive input.
#[derive(Debug, FromDeriveInput)]
#[darling(attributes(ddi), supports(struct_named))]
struct DdiStructAttr {
    /// The identifier of the struct.
    ident: syn::Ident,
    /// Generic parameters (lifetime parameters are forwarded to impls).
    generics: syn::Generics,
    /// Whether the `#[ddi(map)]` flag is present.
    map: bool,
    /// Parsed field data from the struct body.
    data: ast::Data<(), DdiStructFieldAttr>,
}

/// Classification of a struct field for MBOR encoding/decoding purposes.
#[derive(Eq, PartialEq)]
pub(crate) enum DdiStructFieldKind {
    /// Primitive types (`u8`, `u16`, `u32`, `u64`, `bool`) or nested DDI map
    /// structs. Encoded/decoded via the type's own `MborEncode`/`MborDecode`.
    Normal,
    /// Fixed-size byte array: `[u8; N]`. Encoded as an MBOR byte string
    /// without padding.
    Array,
    /// Borrowed byte slice: `&'a [u8]`. May be fixed-length (`len` attr) or
    /// variable-length (`max_len` attr / unbounded). Variable-length slices
    /// are padded to 4-byte alignment in the MBOR encoding.
    Slice,
}

/// Parsed metadata for a single field of a `#[ddi(map)]` struct.
pub(crate) struct DdiStructField {
    /// The field name.
    pub ident: syn::Ident,
    /// The declared Rust type of the field.
    pub ty: syn::Type,
    /// `true` if the field type is `Option<T>`.
    pub opt: bool,
    /// The MBOR field ID from `#[ddi(id = N)]`.
    pub id: u8,
    /// The encoding category for this field.
    pub kind: DdiStructFieldKind,
    /// Exact byte length constraint (`#[ddi(len = N)]`), if any.
    pub len: Option<usize>,
    /// Maximum byte length constraint (`#[ddi(max_len = N)]`), if any.
    pub max_len: Option<usize>,
    /// Whether this field opts in to nested frame-then-fill encoding.
    pub frame: bool,
}

/// Parsed descriptor for a `#[ddi(map)]` named struct.
///
/// Produced by [`parse_struct`] and consumed by the code-generation modules
/// to emit [`MborEncode`], [`MborDecode`], [`MborLen`], and frame impls.
pub(crate) struct DdiStruct {
    /// The identifier of the struct (e.g., `GetKeyRequest`).
    pub ident: syn::Ident,
    /// The struct's fields, sorted by ascending field ID.
    pub fields: Vec<DdiStructField>,
    /// Lifetime parameters from the struct's generic declaration.
    pub lifetimes: Vec<syn::Lifetime>,
}

/// Parses a `#[derive(Ddi)]` input as a `#[ddi(map)]` named struct and
/// returns a [`DdiStruct`] descriptor.
///
/// # Validation
/// - The struct must be a named-field struct with the `#[ddi(map)]` attribute.
/// - Each field must have a `#[ddi(id = N)]` attribute with a unique `u8` ID.
/// - Field IDs must form a contiguous sequence (gaps are rejected).
/// - Field types are classified into [`DdiStructFieldKind`] variants:
///   - `[u8; N]` or `Option<[u8; N]>` → [`Array`](DdiStructFieldKind::Array)
///   - `&'a [u8]` or `Option<&'a [u8]>` → [`Slice`](DdiStructFieldKind::Slice)
///   - Everything else → [`Normal`](DdiStructFieldKind::Normal)
///
/// # Parameters
/// - `input`: The raw `syn::DeriveInput` from the proc-macro invocation.
///
/// # Errors
/// Returns a compile-time error if the struct is missing `#[ddi(map)]`, has
/// non-contiguous field IDs, or contains unsupported field types.
pub(crate) fn parse_struct(input: &syn::DeriveInput) -> syn::Result<DdiStruct> {
    let struct_attr = DdiStructAttr::from_derive_input(input)?;

    if !struct_attr.map {
        let msg = format!(
            "#[ddi(map)] attribute is required for struct {}.",
            struct_attr.ident
        );
        return Err(syn::Error::new(struct_attr.ident.span(), msg));
    }

    let mut fields = if let Some(fields) = struct_attr.data.take_struct() {
        fields.iter().map(parse_field).collect::<syn::Result<_>>()?
    } else {
        vec![]
    };
    fields.sort_by_key(|f| f.id);
    let start_id = fields.first().map(|f| f.id).unwrap_or(0);
    fields.iter().enumerate().try_for_each(|(i, f)| {
        if f.id as usize != i + start_id as usize {
            let msg = format!("Invalid field id. Expected {} instead of {}.", i, f.id);
            return Err(syn::Error::new(f.ident.span(), msg));
        }
        Ok::<(), syn::Error>(())
    })?;

    let mut lifetimes = vec![];

    for lifetime in struct_attr.generics.lifetimes() {
        lifetimes.push(lifetime.lifetime.clone());
    }

    Ok(DdiStruct {
        ident: struct_attr.ident,
        fields,
        lifetimes,
    })
}

fn parse_field(field: &DdiStructFieldAttr) -> syn::Result<DdiStructField> {
    let (opt, kind) = match field.ty {
        syn::Type::Path(ref type_path) => (is_opt(type_path), parse_type_path(type_path)?),
        syn::Type::Array(ref type_arr) => (false, parse_type_array(type_arr)?),
        syn::Type::Reference(_) => (false, DdiStructFieldKind::Slice),
        _ => {
            let msg = "Invalid struct field type. Only Path, Array and Reference are supported.";
            return Err(syn::Error::new(field.ty.span(), msg));
        }
    };

    // Validate #[ddi(frame)] constraints.
    if field.frame {
        let span = field
            .ident
            .as_ref()
            .map_or_else(|| field.ty.span(), |i| i.span());
        if opt {
            let msg = "#[ddi(frame)] is not supported on optional fields.";
            return Err(syn::Error::new(span, msg));
        }
        if kind != DdiStructFieldKind::Normal {
            let msg = "#[ddi(frame)] is only valid on struct (Normal) fields, \
                       not on byte slices or arrays.";
            return Err(syn::Error::new(span, msg));
        }
    }

    Ok(DdiStructField {
        ident: field.ident.clone().ok_or_else(|| {
            let msg = "Failed to clone field identifier.";
            syn::Error::new(field.ty.span(), msg)
        })?,
        ty: field.ty.clone(),
        opt,
        id: field.id,
        kind,
        len: field.len,
        max_len: field.max_len,
        frame: field.frame,
    })
}

fn is_opt(type_path: &syn::TypePath) -> bool {
    type_path
        .path
        .segments
        .last()
        .is_some_and(|s| s.ident == "Option")
}

/// Determine the field kind from a `Type::Path` (e.g., `u16`, `Option<[u8; 32]>`,
/// `Option<&'a [u8]>`).
fn parse_type_path(type_path: &syn::TypePath) -> syn::Result<DdiStructFieldKind> {
    let inner_type = extract_angle_bracketed_last(type_path);

    // Check for [u8; N] inside Option<[u8; N]>
    if let Some(syn::Type::Array(arr)) = &inner_type {
        return validate_u8_array_element(arr);
    }

    // Check for &'a [u8] inside Option<&'a [u8]>
    if let Some(syn::Type::Reference(_)) = &inner_type {
        return Ok(DdiStructFieldKind::Slice);
    }

    Ok(DdiStructFieldKind::Normal)
}

/// Extract the last type argument from angle brackets, if present.
///
/// e.g., `Option<[u8; 32]>` → `Some(Type::Array(...))`
fn extract_angle_bracketed_last(type_path: &syn::TypePath) -> Option<syn::Type> {
    let seg = type_path.path.segments.last()?;
    if let AngleBracketed(a) = &seg.arguments {
        if let Some(GenericArgument::Type(t)) = a.args.last() {
            return Some(t.clone());
        }
    }
    None
}

/// Validate that an array element type is `u8`, returning `Array` kind.
fn validate_u8_array_element(arr: &syn::TypeArray) -> syn::Result<DdiStructFieldKind> {
    let elem_ident = array_elem_ident(arr)?;
    if elem_ident != "u8" {
        return Err(syn::Error::new(
            elem_ident.span(),
            "Invalid array type. Only u8 is supported.",
        ));
    }
    Ok(DdiStructFieldKind::Array)
}

/// Extract the identifier of a `[T; N]` array element type.
fn array_elem_ident(arr: &syn::TypeArray) -> syn::Result<&syn::Ident> {
    match arr.elem.as_ref() {
        syn::Type::Path(p) => {
            p.path.segments.first().map(|s| &s.ident).ok_or_else(|| {
                syn::Error::new(arr.elem.span(), "Empty path in array element type.")
            })
        }
        _ => Err(syn::Error::new(
            arr.elem.span(),
            "Invalid array element type. Only u8 is supported.",
        )),
    }
}

/// Determine the field kind from a bare `[u8; N]` array type.
fn parse_type_array(type_arr: &syn::TypeArray) -> syn::Result<DdiStructFieldKind> {
    validate_u8_array_element(type_arr)
}

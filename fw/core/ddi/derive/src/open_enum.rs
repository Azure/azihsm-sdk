// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parsing of `#[ddi(enumeration)]` attributes on open-enum newtype structs.
//!
//! An **open enum** in the DDI schema is a single-field newtype wrapping `u32`,
//! annotated with `#[ddi(enumeration)]`. Unlike a Rust `enum`, it allows any
//! `u32` value — named variants are provided as associated constants by the
//! user, and unknown values pass through without error.
//!
//! This module validates the derive input and extracts a [`DdiOpenEnum`]
//! descriptor that downstream code-generation modules ([`crate::encode`],
//! [`crate::decode`], [`crate::len`]) use to emit trait impls.

use darling::ast;
use darling::FromDeriveInput;
use darling::FromField;

/// Darling helper for extracting the field type of the newtype's inner field.
#[derive(Debug, FromField)]
#[darling(attributes(ddi))]
struct DdiOpenEnumFieldAttr {
    /// The type of the single inner field (must resolve to `u32`).
    ty: syn::Type,
}

/// Darling helper for extracting top-level `#[ddi(…)]` attributes from a
/// newtype struct derive input.
#[derive(Debug, FromDeriveInput)]
#[darling(attributes(ddi), supports(struct_newtype))]
struct DdiOpenEnumAttr {
    /// The identifier of the newtype struct.
    ident: syn::Ident,
    /// Whether the `#[ddi(enumeration)]` flag is present.
    enumeration: bool,
    /// Parsed field data from the newtype body.
    data: ast::Data<(), DdiOpenEnumFieldAttr>,
}

/// Parsed descriptor for a `#[ddi(enumeration)]` open-enum newtype.
///
/// Produced by [`parse_open_enum`] and consumed by the code-generation modules
/// to emit [`MborEncode`], [`MborDecode`], and [`MborLen`] impls.
pub(crate) struct DdiOpenEnum {
    /// The identifier of the newtype struct (e.g., `AlgorithmId`).
    pub ident: syn::Ident,
}

/// Parses a `#[derive(Ddi)]` input as a `#[ddi(enumeration)]` open-enum
/// newtype and returns a [`DdiOpenEnum`] descriptor.
///
/// # Validation
/// - The struct must be a single-field newtype (`struct Foo(u32)`).
/// - The `#[ddi(enumeration)]` attribute must be present.
/// - The inner field type must be exactly `u32`.
///
/// # Parameters
/// - `input`: The raw `syn::DeriveInput` from the proc-macro invocation.
///
/// # Errors
/// Returns a compile-time error if any validation check fails.
pub(crate) fn parse_open_enum(input: &syn::DeriveInput) -> syn::Result<DdiOpenEnum> {
    let enum_attr = DdiOpenEnumAttr::from_derive_input(input)?;
    let span = syn::spanned::Spanned::span(&enum_attr.ident);

    if !enum_attr.enumeration {
        return Err(syn::Error::new(
            span,
            format!(
                "#[ddi(enumeration)] attribute is required for open_enum {}.",
                enum_attr.ident
            ),
        ));
    }

    let fields = match enum_attr.data {
        ast::Data::Struct(f) => f,
        ast::Data::Enum(_) => {
            return Err(syn::Error::new(
                span,
                format!(
                    "#[ddi(enumeration)] attribute provided but is not open_enum {}.",
                    enum_attr.ident
                ),
            ));
        }
    };

    if fields.style != ast::Style::Tuple || fields.fields.len() != 1 {
        return Err(syn::Error::new(
            span,
            format!(
                "#[ddi(enumeration)] must be a single-field newtype for {}.",
                enum_attr.ident
            ),
        ));
    }

    let field = fields.fields.into_iter().next().ok_or_else(|| {
        syn::Error::new(
            span,
            format!("Failed to unwrap field for open_enum {}.", enum_attr.ident),
        )
    })?;

    let field_ident = match field.ty {
        syn::Type::Path(p) if p.path.segments.len() == 1 => {
            // SAFETY: len() == 1 guarantees next() returns Some.
            #[allow(clippy::unwrap_used)]
            p.path.segments.into_iter().next().unwrap().ident
        }
        _ => {
            return Err(syn::Error::new(
                span,
                format!(
                    "#[ddi(enumeration)] field must be a simple type for {}.",
                    enum_attr.ident
                ),
            ));
        }
    };

    if field_ident != "u32" {
        return Err(syn::Error::new(
            span,
            format!(
                "#[ddi(enumeration)] field type is not u32 for {}.",
                enum_attr.ident
            ),
        ));
    }

    Ok(DdiOpenEnum {
        ident: enum_attr.ident,
    })
}

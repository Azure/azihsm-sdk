// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::vec;

use darling::FromDeriveInput;
use darling::FromField;
use darling::ast;
use syn::GenericArgument;
use syn::PathArguments::AngleBracketed;
use syn::spanned::Spanned;

#[derive(Debug, FromField)]
#[darling(attributes(ddi))]
struct DdiStructFieldAttr {
    ident: Option<syn::Ident>,
    ty: syn::Type,
    id: u8,
    len: Option<usize>,
    max_len: Option<usize>,
}

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(ddi), supports(struct_named))]
struct DdiStructAttr {
    ident: syn::Ident,
    generics: syn::Generics,
    map: bool,
    data: ast::Data<(), DdiStructFieldAttr>,
}

#[derive(Eq, PartialEq)]
pub(crate) enum DdiStructFieldKind {
    /// Primitive types (u8, u16, u32, u64, bool) or nested structs.
    Normal,
    /// Fixed-size byte array: `[u8; N]`.
    Array,
    /// Borrowed byte slice: `&'a [u8]`.
    Slice,
}

pub(crate) struct DdiStructField {
    pub ident: syn::Ident,
    pub ty: syn::Type,
    pub opt: bool,
    pub id: u8,
    pub kind: DdiStructFieldKind,
    pub len: Option<usize>,
    pub max_len: Option<usize>,
}

pub(crate) struct DdiStruct {
    pub ident: syn::Ident,
    pub fields: Vec<DdiStructField>,
    pub lifetimes: Vec<syn::Lifetime>,
}

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
    })
}

fn is_opt(type_path: &syn::TypePath) -> bool {
    if let Some(s) = type_path.path.segments.last() {
        if s.ident == "Option" {
            return true;
        }
    }
    false
}

fn parse_type_path(type_path: &syn::TypePath) -> syn::Result<DdiStructFieldKind> {
    if let Some(s) = type_path.path.segments.last() {
        if let AngleBracketed(a) = s.arguments.clone() {
            if let Some(GenericArgument::Type(syn::Type::Array(arr))) = a.args.last() {
                if let syn::Type::Path(p) = arr.elem.as_ref() {
                    if p.path
                        .segments
                        .last()
                        .ok_or_else(|| {
                            let msg = "Failed to unwrap last path segment for array element type.";
                            syn::Error::new(arr.elem.span(), msg)
                        })?
                        .ident
                        != "u8"
                    {
                        let msg = "Invalid array type. Only u8 is supported.";
                        return Err(syn::Error::new(
                            p.path
                                .segments
                                .last()
                                .ok_or_else(|| {
                                    let msg = "Failed to unwrap last path segment.";
                                    syn::Error::new(arr.elem.span(), msg)
                                })?
                                .ident
                                .span(),
                            msg,
                        ));
                    }

                    return Ok(DdiStructFieldKind::Array);
                }
            }
            // Check for Option<&'a [u8]> — inner type is a reference
            if let Some(GenericArgument::Type(syn::Type::Reference(_))) = a.args.last() {
                return Ok(DdiStructFieldKind::Slice);
            }
        }
    }

    Ok(DdiStructFieldKind::Normal)
}

fn parse_type_array(type_arr: &syn::TypeArray) -> syn::Result<DdiStructFieldKind> {
    match type_arr.elem.as_ref() {
        syn::Type::Path(p) => {
            if p.path
                .segments
                .first()
                .ok_or_else(|| {
                    let msg = "Failed to unwrap first path segment for path type.";
                    syn::Error::new(type_arr.elem.span(), msg)
                })?
                .ident
                != "u8"
            {
                let msg = "Invalid array type. Only u8 is supported.";
                return Err(syn::Error::new(
                    p.path
                        .segments
                        .first()
                        .ok_or_else(|| {
                            let msg = "Failed to unwrap first path segment for path type.";
                            syn::Error::new(type_arr.elem.span(), msg)
                        })?
                        .ident
                        .span(),
                    msg,
                ));
            }
            Ok(DdiStructFieldKind::Array)
        }
        _ => {
            let msg = "Invalid array element type. Only u8 is supported.";
            Err(syn::Error::new(type_arr.elem.span(), msg))
        }
    }
}

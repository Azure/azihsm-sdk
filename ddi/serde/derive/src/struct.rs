// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::vec;

use darling::ast;
use darling::FromDeriveInput;
use darling::FromField;
use syn::spanned::Spanned;
use syn::GenericArgument;
use syn::PathArguments::AngleBracketed;
use syn::Type;
use syn::Type::Array;

#[derive(Debug, FromField)]
#[darling(attributes(ddi))]
struct DdiStructFieldAttr {
    ident: Option<syn::Ident>,
    ty: syn::Type,
    id: u8,
    pre_encode_fn: Option<String>,
    post_decode_fn: Option<String>,
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
    Normal,
    Array,
    MborArray,
}

pub(crate) struct DdiStructField {
    pub ident: syn::Ident,
    pub ty: syn::Type,
    pub opt: bool,
    pub id: u8,
    pub kind: DdiStructFieldKind,
    pub pre_encode_fn: Option<String>,
    pub post_decode_fn: Option<String>,
}

pub(crate) struct DdiStruct {
    pub ident: syn::Ident,
    pub fields: Vec<DdiStructField>,
    pub lifetimes: Vec<syn::Lifetime>,
}

pub(crate) fn prase_struct(input: &syn::DeriveInput) -> syn::Result<DdiStruct> {
    let struct_attr = DdiStructAttr::from_derive_input(input)?;

    if !struct_attr.map {
        let msg = format!(
            "#[ddi(map)] attribute is required for struct {}.",
            struct_attr.ident
        );
        Err(syn::Error::new(struct_attr.ident.span(), msg))?
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
            Err(syn::Error::new(f.ident.span(), msg))?
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
        _ => {
            let msg = "Invalid struct field type. Only Path, Array and Reference are supported.";
            Err(syn::Error::new(field.ty.span(), msg))?
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
        pre_encode_fn: field.pre_encode_fn.clone(),
        post_decode_fn: field.post_decode_fn.clone(),
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
            if let Some(GenericArgument::Type(Array(arr))) = a.args.last() {
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
                        Err(syn::Error::new(
                            p.path.segments.last().ok_or_else(|| {
                                let msg = "Failed to unwrap last path segment for array element type.";
                                syn::Error::new(arr.elem.span(), msg)
                            })?.ident.span(),
                            msg,
                        ))?
                    }

                    return Ok(DdiStructFieldKind::Array);
                }
            }
            if let Some(GenericArgument::Type(Type::Path(p))) = a.args.last() {
                if p.path
                    .segments
                    .last()
                    .ok_or_else(|| {
                        let msg = "Failed to unwrap last path segment for path type.";
                        syn::Error::new(p.path.span(), msg)
                    })?
                    .ident
                    == "MborByteArray"
                {
                    return Ok(DdiStructFieldKind::MborArray);
                }
            }
        }

        if s.ident == "MborByteArray" {
            return Ok(DdiStructFieldKind::MborArray);
        }
    }

    Ok(DdiStructFieldKind::Normal)
}

fn parse_type_array(type_arr: &syn::TypeArray) -> syn::Result<DdiStructFieldKind> {
    let kind = match type_arr.elem.as_ref() {
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
                Err(syn::Error::new(
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
                ))?
            }
            DdiStructFieldKind::Array
        }
        _ => {
            let msg = "Invalid struct field type. Only [u8; N] is supported.";
            Err(syn::Error::new(type_arr.elem.span(), msg))?
        }
    };

    Ok(kind)
}

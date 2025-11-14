// Copyright (C) Microsoft Corporation. All rights reserved.

use darling::ast;
use darling::FromDeriveInput;
use darling::FromField;
use syn::Ident;

#[derive(Debug, FromField)]
#[darling(attributes(ddi))]
struct DdiOpenEnumFieldAttr {
    ty: syn::Type,
}

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(ddi), supports(struct_newtype))]
struct DdiOpenEnumAttr {
    ident: syn::Ident,
    enumeration: bool,
    data: ast::Data<(), DdiOpenEnumFieldAttr>,
}

pub(crate) struct DdiOpenEnum {
    pub ident: syn::Ident,
}

pub(crate) fn prase_open_enum(input: &syn::DeriveInput) -> syn::Result<DdiOpenEnum> {
    let enum_attr = DdiOpenEnumAttr::from_derive_input(input)?;

    if !enum_attr.enumeration {
        let msg = format!(
            "#[ddi(enumeration)] attribute is required for open_enum {}.",
            enum_attr.ident
        );
        Err(syn::Error::new(enum_attr.ident.span(), msg))?
    }

    match enum_attr.data {
        ast::Data::Enum(_) => {
            let msg = format!(
                "#[ddi(enumeration)] attribute provided but is not open_enum {}.",
                enum_attr.ident
            );
            Err(syn::Error::new(enum_attr.ident.span(), msg))?
        }
        ast::Data::Struct(fields) => {
            if fields.style != ast::Style::Tuple {
                let msg = format!(
                    "#[ddi(enumeration)] attribute provided but is not open_enum {}.",
                    enum_attr.ident
                );
                Err(syn::Error::new(enum_attr.ident.span(), msg))?
            }

            if fields.fields.len() != 1 {
                let msg = format!(
                    "#[ddi(enumeration)] attribute provided but is not open_enum {}.",
                    enum_attr.ident
                );
                Err(syn::Error::new(enum_attr.ident.span(), msg))?
            }

            let field = fields.fields.into_iter().next().unwrap();
            let field_segments = match field.ty {
                syn::Type::Path(p) => p.path.segments,
                _ => {
                    let msg = format!(
                        "#[ddi(enumeration)] attribute provided but is not open_enum {}.",
                        enum_attr.ident
                    );
                    Err(syn::Error::new(enum_attr.ident.span(), msg))?
                }
            };

            if field_segments.len() != 1 {
                let msg = format!(
                    "#[ddi(enumeration)] attribute provided but is not open_enum {}.",
                    enum_attr.ident
                );
                Err(syn::Error::new(enum_attr.ident.span(), msg))?
            }

            let ident = field_segments.first().unwrap().ident.clone();
            let u32_ident = Ident::new("u32", ident.span());

            if ident.cmp(&u32_ident) != std::cmp::Ordering::Equal {
                let msg = format!(
                    "#[ddi(enumeration)] attribute provided but is not u32 {}.",
                    enum_attr.ident
                );
                Err(syn::Error::new(enum_attr.ident.span(), msg))?
            }

            Ok(DdiOpenEnum {
                ident: enum_attr.ident,
            })
        }
    }
}

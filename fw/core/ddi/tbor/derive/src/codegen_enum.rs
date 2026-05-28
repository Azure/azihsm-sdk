// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generation for enum types: TryFrom and Into implementations.

use proc_macro2::TokenStream;
use quote::quote;

/// Generate `TryFrom<repr>` and `From<Self>` implementations for a
/// `#[tbor]`-annotated enum.
///
/// The enum must have `#[repr(u8)]`, `#[repr(u16)]`, or `#[repr(u32)]`
/// and every variant must have an explicit discriminant.
pub fn gen_enum(input: &syn::ItemEnum) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let _vis = &input.vis;

    // Determine repr type.
    let repr = find_repr(input)?;

    // Collect variant name → discriminant pairs.
    let variants: Vec<(&syn::Ident, &syn::Expr)> = input
        .variants
        .iter()
        .map(|v| {
            let disc = v
                .discriminant
                .as_ref()
                .map(|(_, expr)| expr)
                .ok_or_else(|| {
                    syn::Error::new_spanned(
                        v,
                        "#[tbor] enum variants must have explicit discriminants",
                    )
                });
            disc.map(|d| (&v.ident, d))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let match_arms_try_from = variants.iter().map(|(ident, disc)| {
        quote! { #disc => Ok(#name::#ident), }
    });

    let repr_ty = &repr;

    // Re-emit the original enum unchanged, plus TryFrom and From impls.
    Ok(quote! {
        #input

        impl core::convert::TryFrom<#repr_ty> for #name {
            type Error = #repr_ty;

            fn try_from(v: #repr_ty) -> Result<Self, #repr_ty> {
                match v {
                    #(#match_arms_try_from)*
                    _ => Err(v),
                }
            }
        }

        impl From<#name> for #repr_ty {
            #[inline]
            fn from(v: #name) -> #repr_ty {
                v as #repr_ty
            }
        }
    })
}

/// Find the `#[repr(u8)]`, `#[repr(u16)]`, or `#[repr(u32)]` attribute.
fn find_repr(input: &syn::ItemEnum) -> syn::Result<syn::Ident> {
    for attr in &input.attrs {
        if attr.path().is_ident("repr") {
            let mut found = None;
            attr.parse_nested_meta(|meta| {
                if let Some(ident) = meta.path.get_ident() {
                    let s = ident.to_string();
                    if s == "u8" || s == "u16" || s == "u32" || s == "u64" {
                        found = Some(ident.clone());
                    }
                }
                Ok(())
            })?;
            if let Some(repr) = found {
                return Ok(repr);
            }
        }
    }

    Err(syn::Error::new_spanned(
        &input.ident,
        "#[tbor] enums must have #[repr(u8)], #[repr(u16)], or #[repr(u32)]",
    ))
}

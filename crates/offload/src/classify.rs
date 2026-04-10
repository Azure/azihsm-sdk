// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parameter type classification for the `offload` macro.
//!
//! Determines how each handler parameter should be converted between the
//! borrowed form (handler function) and the owned form (enum variant / async method).

use proc_macro2::TokenStream;
use quote::quote;
use syn::Type;

/// Classification of a handler parameter type.
pub(crate) enum ParamKind {
    /// `&[T]` — store `Vec<T>`, accept `&[T]`, pack with `.to_vec()`, unpack with `&field`.
    SliceRef { elem: Box<Type> },
    /// `&mut [T]` — store `Vec<T>`, accept `&mut [T]`, pack with `.to_vec()`,
    /// unpack with `&mut field`.
    MutSliceRef { elem: Box<Type> },
    /// `&T` (non-slice) — store `T`, accept `T` by value, pack by move, unpack with `&field`.
    Ref { inner: Box<Type> },
    /// `Option<&[T]>` — store `Option<Vec<T>>`, accept `Option<&[T]>`,
    /// pack with `.map(|v| v.to_vec())`, unpack with `.as_deref()`.
    OptionSliceRef { elem: Box<Type> },
    /// `Option<&mut [T]>` — store `Option<Vec<T>>`, accept `Option<&mut [T]>`,
    /// pack with `.as_deref().map(|v| v.to_vec())`, unpack with `.as_deref_mut()`.
    OptionMutSliceRef { elem: Box<Type> },
    /// `Option<&T>` (non-slice) — store `Option<T>`, accept `Option<T>` by value,
    /// pack by move, unpack with `.as_ref()`.
    OptionRef { inner: Box<Type> },
    /// `T` by value — stored, accepted, packed, and unpacked as-is.
    ByValue,
}

/// Inspect a `syn::Type` and classify it for owned/borrowed conversion.
pub(crate) fn classify(ty: &Type) -> ParamKind {
    // &[T] or &T
    if let Type::Reference(r) = ty {
        if let Type::Slice(slice) = r.elem.as_ref() {
            if r.mutability.is_some() {
                return ParamKind::MutSliceRef {
                    elem: slice.elem.clone(),
                };
            }
            return ParamKind::SliceRef {
                elem: slice.elem.clone(),
            };
        }
        return ParamKind::Ref {
            inner: r.elem.clone(),
        };
    }

    // Option<&[T]>, Option<&mut [T]>, or Option<&T>
    if let Some(Type::Reference(r)) = extract_option_inner(ty) {
        if let Type::Slice(slice) = r.elem.as_ref() {
            if r.mutability.is_some() {
                return ParamKind::OptionMutSliceRef {
                    elem: slice.elem.clone(),
                };
            }
            return ParamKind::OptionSliceRef {
                elem: slice.elem.clone(),
            };
        }
        return ParamKind::OptionRef {
            inner: r.elem.clone(),
        };
    }

    ParamKind::ByValue
}

impl ParamKind {
    /// The type to store in the enum variant field.
    pub(crate) fn enum_field_type(&self, original_type: &Type) -> TokenStream {
        match self {
            ParamKind::SliceRef { elem } => quote! { Vec<#elem> },
            ParamKind::MutSliceRef { elem } => quote! { Vec<#elem> },
            ParamKind::Ref { inner } => quote! { #inner },
            ParamKind::OptionSliceRef { elem } => quote! { Option<Vec<#elem>> },
            ParamKind::OptionMutSliceRef { elem } => quote! { Option<Vec<#elem>> },
            ParamKind::OptionRef { inner } => quote! { Option<#inner> },
            ParamKind::ByValue => quote! { #original_type },
        }
    }

    /// The type for the async method parameter (what the caller passes).
    pub(crate) fn async_param_type(&self, original_type: &Type) -> TokenStream {
        match self {
            ParamKind::SliceRef { .. }
            | ParamKind::MutSliceRef { .. }
            | ParamKind::OptionSliceRef { .. }
            | ParamKind::OptionMutSliceRef { .. } => {
                // Keep the original borrowed type for the public API.
                quote! { #original_type }
            }
            ParamKind::Ref { inner } => quote! { #inner },
            ParamKind::OptionRef { inner } => quote! { Option<#inner> },
            ParamKind::ByValue => quote! { #original_type },
        }
    }

    /// Expression in the async method body to convert from the async param to the enum field.
    pub(crate) fn pack_expr(&self, param_name: &syn::Ident) -> TokenStream {
        match self {
            ParamKind::SliceRef { .. } => quote! { #param_name.to_vec() },
            ParamKind::MutSliceRef { .. } => quote! { #param_name.to_vec() },
            ParamKind::Ref { .. } => quote! { #param_name },
            ParamKind::OptionSliceRef { .. } => {
                quote! { #param_name.map(|__v| __v.to_vec()) }
            }
            ParamKind::OptionMutSliceRef { .. } => {
                quote! { #param_name.as_deref().map(|__v| __v.to_vec()) }
            }
            ParamKind::OptionRef { .. } => quote! { #param_name },
            ParamKind::ByValue => quote! { #param_name },
        }
    }

    /// Expression in the dispatch match arm to convert from the enum field to the handler param.
    pub(crate) fn unpack_expr(&self, param_name: &syn::Ident) -> TokenStream {
        match self {
            ParamKind::SliceRef { .. } => quote! { &#param_name },
            ParamKind::MutSliceRef { .. } => quote! { &mut #param_name },
            ParamKind::Ref { .. } => quote! { &#param_name },
            ParamKind::OptionSliceRef { .. } => quote! { #param_name.as_deref() },
            ParamKind::OptionMutSliceRef { .. } => quote! { #param_name.as_deref_mut() },
            ParamKind::OptionRef { .. } => quote! { #param_name.as_ref() },
            ParamKind::ByValue => quote! { #param_name },
        }
    }
}

/// If `ty` is `Option<T>`, returns `Some(T)`. Otherwise `None`.
fn extract_option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let segment = type_path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    let syn::GenericArgument::Type(inner) = &args.args[0] else {
        return None;
    };
    Some(inner)
}

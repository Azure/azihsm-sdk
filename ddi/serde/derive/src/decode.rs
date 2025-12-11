// Copyright (C) Microsoft Corporation. All rights reserved.

use quote::format_ident;
use quote::quote;
use syn::GenericArgument;
use syn::PathArguments::AngleBracketed;

use crate::open_enum::DdiOpenEnum;
use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructFieldKind;

pub(crate) fn struct_decode(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;
    let lifetimes = &ddi.lifetimes;
    let map = quote! { let mut cnt = MborMap::mbor_decode(dec)?; };

    let post_decode_calls = ddi
        .fields
        .iter()
        .map(|field| {
            if field.kind == DdiStructFieldKind::MborArray {
                let name = &field.ident;
                if let Some(post_decode_fn) = &field.post_decode_fn {
                    let post_decode_fn = format_ident!("{}", post_decode_fn);
                    quote! {
                        #[cfg(feature = "post_decode")]
                        if dec.post_decode() {
                            obj.#name = obj.#post_decode_fn(&obj.#name)?;
                        }
                    }
                } else {
                    quote!()
                }
            } else {
                quote!()
            }
        })
        .collect::<Vec<_>>();

    let fields = ddi
        .fields
        .iter()
        .map(|f| {
            let fname = &f.ident;
            let ftype = &f.ty;
            let id = f.id;

            if f.opt {
                let ftype = opt_type(ftype);
                quote! {
                    #fname: {
                        if cnt.0 > 0 {
                            if let Some(id) = dec.peek_u8() {
                                if id == #id  {
                                    cnt.0 -= 1;
                                    u8::mbor_decode(dec)?;
                                    Some(<#ftype>::mbor_decode(dec)?)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                }
            } else {
                quote! {
                    #fname: {
                        if cnt.0 == 0 {
                            Err(mcr_ddi_mbor::MborDecodeError::InvalidId)?
                        }
                        let id = u8::mbor_decode(dec)?;
                        cnt.0 -= 1;
                        if id != #id {
                            Err(mcr_ddi_mbor::MborDecodeError::InvalidId)?
                        } else {
                            <#ftype>::mbor_decode(dec)?
                        }
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<'bytes:#(#lifetimes +)* , #(#lifetimes,)*> mcr_ddi_mbor::MborDecode<'bytes> for #ident<#(#lifetimes,)*> {
            fn mbor_decode(dec: &mut mcr_ddi_mbor::MborDecoder<'bytes>) -> Result<Self, mcr_ddi_mbor::MborDecodeError>
            {
                #map
                let mut obj =Self {
                    #(#fields,)*
                };

                if cnt.0 != 0 {
                    Err(mcr_ddi_mbor::MborDecodeError::InvalidLen)?;
                }

                #(#post_decode_calls)*

                Ok(obj)
            }
        }
    })
}

fn opt_type(ftype: &syn::Type) -> proc_macro2::TokenStream {
    let ftype = if let syn::Type::Path(p) = ftype {
        if let Some(s) = p.path.segments.last() {
            if let AngleBracketed(a) = s.arguments.clone() {
                if let Some(GenericArgument::Type(t)) = a.args.last() {
                    quote! { #t }
                } else {
                    quote!()
                }
            } else {
                quote!()
            }
        } else {
            quote!()
        }
    } else {
        quote!()
    };
    ftype
}

pub(crate) fn open_enum_decode(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl<'bytes> mcr_ddi_mbor::MborDecode<'bytes> for #ident {
            fn mbor_decode(dec: &mut mcr_ddi_mbor::MborDecoder<'bytes>) -> Result<Self, mcr_ddi_mbor::MborDecodeError>
            {
                let val = u32::mbor_decode(dec)?;
                Ok(Self(val))
            }
        }
    })
}

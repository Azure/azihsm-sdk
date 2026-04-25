// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use quote::quote;
use syn::GenericArgument;
use syn::PathArguments::AngleBracketed;

use crate::open_enum::DdiOpenEnum;
use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructFieldKind;

pub(crate) fn struct_decode(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;
    let lifetimes = &ddi.lifetimes;
    let map = quote! { let mut cnt = azihsm_fw_ddi_mbor::MborMap::mbor_decode(dec)?; };

    let fields = ddi
        .fields
        .iter()
        .map(|f| {
            let fname = &f.ident;
            let ftype = &f.ty;
            let id = f.id;

            if f.opt && f.kind == DdiStructFieldKind::Slice {
                // Optional borrowed byte slice
                let decode_slice = slice_decode_expr(&f.len, &f.max_len);
                quote! {
                    #fname: {
                        if cnt.0 > 0 {
                            if let Some(id) = dec.peek_u8() {
                                if id == #id {
                                    cnt.0 -= 1;
                                    u8::mbor_decode(dec)?;
                                    let data = { #decode_slice };
                                    Some(data)
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
            } else if f.opt {
                let ftype = opt_type(ftype);
                quote! {
                    #fname: {
                        if cnt.0 > 0 {
                            if let Some(id) = dec.peek_u8() {
                                if id == #id {
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
            } else if f.kind == DdiStructFieldKind::Slice {
                // Required borrowed byte slice
                let decode_slice = slice_decode_expr(&f.len, &f.max_len);
                quote! {
                    #fname: {
                        if cnt.0 == 0 {
                            Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidId)?
                        }
                        let id = u8::mbor_decode(dec)?;
                        cnt.0 -= 1;
                        if id != #id {
                            Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidId)?
                        } else {
                            #decode_slice
                        }
                    }
                }
            } else {
                quote! {
                    #fname: {
                        if cnt.0 == 0 {
                            Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidId)?
                        }
                        let id = u8::mbor_decode(dec)?;
                        cnt.0 -= 1;
                        if id != #id {
                            Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidId)?
                        } else {
                            <#ftype>::mbor_decode(dec)?
                        }
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<'bytes: #(#lifetimes +)* , #(#lifetimes,)*> azihsm_fw_ddi_mbor::MborDecode<'bytes> for #ident<#(#lifetimes,)*> {
            fn mbor_decode(dec: &mut azihsm_fw_ddi_mbor::MborDecoder<'bytes>) -> Result<Self, azihsm_fw_ddi_mbor::MborDecodeError>
            {
                #map
                let obj = Self {
                    #(#fields,)*
                };

                if cnt.0 != 0 {
                    Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidLen)?;
                }

                Ok(obj)
            }
        }
    })
}

fn opt_type(ftype: &syn::Type) -> proc_macro2::TokenStream {
    if let syn::Type::Path(p) = ftype {
        if let Some(s) = p.path.segments.last() {
            if let AngleBracketed(a) = s.arguments.clone() {
                if let Some(GenericArgument::Type(t)) = a.args.last() {
                    return quote! { #t };
                }
            }
        }
    }
    quote!()
}

pub(crate) fn open_enum_decode(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl<'bytes> azihsm_fw_ddi_mbor::MborDecode<'bytes> for #ident {
            fn mbor_decode(dec: &mut azihsm_fw_ddi_mbor::MborDecoder<'bytes>) -> Result<Self, azihsm_fw_ddi_mbor::MborDecodeError>
            {
                let val = u32::mbor_decode(dec)?;
                Ok(Self(val))
            }
        }
    })
}

/// Generate the decode expression for a byte-slice field.
///
/// - `len = N`:     exact length, no padding → `decode_byte_slice_exact(N)`
/// - `max_len = N`: variable length, padded  → `decode_byte_slice()` + max check
/// - neither:       variable length, padded  → `decode_byte_slice()`, no check
fn slice_decode_expr(len: &Option<usize>, max_len: &Option<usize>) -> proc_macro2::TokenStream {
    if let Some(exact) = len {
        // Fixed-size, no padding
        quote! {
            dec.decode_byte_slice_exact(#exact)?
        }
    } else if let Some(max) = max_len {
        // Variable-size, padded, with upper bound
        quote! {
            {
                let (_pad, data) = dec.decode_byte_slice()?;
                if data.len() > #max {
                    Err(azihsm_fw_ddi_mbor::MborDecodeError::InvalidLen)?
                }
                data
            }
        }
    } else {
        // Variable-size, padded, no bound
        quote! {
            {
                let (_pad, data) = dec.decode_byte_slice()?;
                data
            }
        }
    }
}

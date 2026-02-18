// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use quote::format_ident;
use quote::quote;

use crate::open_enum::DdiOpenEnum;
use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructField;
use crate::r#struct::DdiStructFieldKind;

pub(crate) fn struct_encode(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;
    let field_cnt = ddi.fields.len();
    let lifetimes = &ddi.lifetimes;

    let enc_cnt = ddi
        .fields
        .iter()
        .map(|f| {
            if f.opt {
                let fname = &f.ident;
                quote! { if self.#fname.is_none() { cnt -= 1; } }
            } else {
                quote!()
            }
        })
        .collect::<Vec<_>>();

    let enc_fields = ddi
        .fields
        .iter()
        .map(|f| {
            let name = &f.ident;
            let encode_field = mbor_encode_field(f);

            if f.opt {
                quote! {
                    if let Some(#name) = &self.#name {
                        #encode_field
                    }
                }
            } else {
                quote! {
                    let #name = &self.#name;
                    #encode_field
                }
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<#(#lifetimes,)*> azihsm_ddi_mbor::MborEncode for #ident<#(#lifetimes,)*> {
            fn mbor_encode(
                &self,
                encoder: &mut azihsm_ddi_mbor::MborEncoder,
            ) -> Result<(), azihsm_ddi_mbor::MborEncodeError>
            {
                let mut cnt = #field_cnt as MborId;
                #(#enc_cnt)*
                MborMap(cnt).mbor_encode(encoder)?;
                #( #enc_fields )*
                Ok(())
            }
        }
    })
}

fn mbor_encode_field(field: &DdiStructField) -> proc_macro2::TokenStream {
    let id = field.id;
    let name = &field.ident;

    let pre_encode = if let Some(pre_encode_fn) = &field.pre_encode_fn {
        let pre_encode_fn = format_ident!("{}", pre_encode_fn);
        quote! {
            let ret = if encoder.pre_encode() {
                MborPaddedByteArray(&self.#pre_encode_fn(#name)?, pad).mbor_encode(encoder)
            } else {
                MborPaddedByteArray(#name, pad).mbor_encode(encoder)
            };
        }
    } else {
        quote! {
            let ret = MborPaddedByteArray(#name, pad).mbor_encode(encoder);
        }
    };

    match field.kind {
        DdiStructFieldKind::Array => {
            quote! {
                #id.mbor_encode(encoder)?;
                MborByteSlice(#name).mbor_encode(encoder)?;
            }
        }
        DdiStructFieldKind::MborArray => {
            quote! {
                #id.mbor_encode(encoder)?;
                let pad = azihsm_ddi_mbor::pad4(encoder.position() as u32 + 3) as u8;
                #[cfg(test)]
                assert_eq!((encoder.position() + 3 + pad as usize) % 4, 0);
                #[cfg(feature = "pre_encode")]
                #pre_encode
                #[cfg(not(feature = "pre_encode"))]
                let ret = MborPaddedByteArray(#name, pad).mbor_encode(encoder);
                ret?;
            }
        }
        _ => quote! {
            #id.mbor_encode(encoder)?;
            #name.mbor_encode(encoder)?;
        },
    }
}

pub(crate) fn open_enum_encode(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl azihsm_ddi_mbor::MborEncode for #ident {
            fn mbor_encode(
                &self,
                encoder: &mut azihsm_ddi_mbor::MborEncoder
            ) -> Result<(), azihsm_ddi_mbor::MborEncodeError>
            {
                self.0.mbor_encode(encoder)
            }
        }
    })
}

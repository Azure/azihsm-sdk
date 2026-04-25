// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
        impl<#(#lifetimes,)*> azihsm_fw_ddi_mbor::MborEncode for #ident<#(#lifetimes,)*> {
            fn mbor_encode(
                &self,
                encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'_>,
            ) -> Result<(), azihsm_fw_ddi_mbor::MborEncodeError>
            {
                let mut cnt = #field_cnt as azihsm_fw_ddi_mbor::MborId;
                #(#enc_cnt)*
                azihsm_fw_ddi_mbor::MborMap(cnt).mbor_encode(encoder)?;
                #( #enc_fields )*
                Ok(())
            }
        }
    })
}

fn mbor_encode_field(field: &DdiStructField) -> proc_macro2::TokenStream {
    let id = field.id;
    let name = &field.ident;

    match field.kind {
        DdiStructFieldKind::Array => {
            quote! {
                #id.mbor_encode(encoder)?;
                azihsm_fw_ddi_mbor::MborByteSlice(#name).mbor_encode(encoder)?;
            }
        }
        DdiStructFieldKind::Slice => {
            if let Some(exact) = field.len {
                // Fixed-size, no padding (was [u8; N])
                let encode_check = quote! {
                    if #name.len() != #exact {
                        return Err(azihsm_fw_ddi_mbor::MborEncodeError::InvalidLen);
                    }
                };
                quote! {
                    #encode_check
                    #id.mbor_encode(encoder)?;
                    azihsm_fw_ddi_mbor::MborByteSlice(#name).mbor_encode(encoder)?;
                }
            } else {
                // Variable-size, padded (was MborByteArray<N>)
                let encode_check = if let Some(max) = field.max_len {
                    quote! {
                        if #name.len() > #max {
                            return Err(azihsm_fw_ddi_mbor::MborEncodeError::InvalidLen);
                        }
                    }
                } else {
                    quote! {}
                };
                if field.opt {
                    quote! {
                        #encode_check
                        #id.mbor_encode(encoder)?;
                        let pad = azihsm_fw_ddi_mbor::pad4(encoder.position() as u32 + 3) as u8;
                        azihsm_fw_ddi_mbor::MborPaddedByteSlice(*#name, pad).mbor_encode(encoder)?;
                    }
                } else {
                    quote! {
                        #encode_check
                        #id.mbor_encode(encoder)?;
                        let pad = azihsm_fw_ddi_mbor::pad4(encoder.position() as u32 + 3) as u8;
                        azihsm_fw_ddi_mbor::MborPaddedByteSlice(#name, pad).mbor_encode(encoder)?;
                    }
                }
            }
        }
        DdiStructFieldKind::Normal => {
            quote! {
                #id.mbor_encode(encoder)?;
                #name.mbor_encode(encoder)?;
            }
        }
    }
}

pub(crate) fn open_enum_encode(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl azihsm_fw_ddi_mbor::MborEncode for #ident {
            fn mbor_encode(
                &self,
                encoder: &mut azihsm_fw_ddi_mbor::MborEncoder<'_>,
            ) -> Result<(), azihsm_fw_ddi_mbor::MborEncodeError>
            {
                self.0.mbor_encode(encoder)
            }
        }
    })
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use quote::quote;

use crate::open_enum::DdiOpenEnum;
use crate::r#struct::DdiStruct;
use crate::r#struct::DdiStructFieldKind;

pub(crate) fn struct_len(ddi: &DdiStruct) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;
    let field_cnt = ddi.fields.len() as u8;
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

    let lens = ddi
        .fields
        .iter()
        .map(|f| {
            let name = &f.ident;
            let id = &f.id;
            if f.opt {
                match f.kind {
                    DdiStructFieldKind::Array => {
                        quote! {
                            if let Some(value) = &self.#name {
                                #id.mbor_len(acc);
                                azihsm_fw_ddi_mbor::MborByteSlice(value).mbor_len(acc);
                            }
                        }
                    }
                    DdiStructFieldKind::Slice => {
                        if f.len.is_some() {
                            // Fixed-size, no padding
                            quote! {
                                if let Some(value) = &self.#name {
                                    #id.mbor_len(acc);
                                    azihsm_fw_ddi_mbor::MborByteSlice(*value).mbor_len(acc);
                                }
                            }
                        } else {
                            // Variable-size, padded
                            quote! {
                                if let Some(value) = &self.#name {
                                    #id.mbor_len(acc);
                                    let pad = azihsm_fw_ddi_mbor::pad4(acc.len() as u32 + 3);
                                    azihsm_fw_ddi_mbor::MborPaddedByteSlice(*value, pad as u8).mbor_len(acc);
                                }
                            }
                        }
                    }
                    DdiStructFieldKind::Normal => {
                        quote! {
                            if let Some(value) = &self.#name {
                                #id.mbor_len(acc);
                                value.mbor_len(acc);
                            }
                        }
                    }
                }
            } else {
                match f.kind {
                    DdiStructFieldKind::Array => {
                        quote! {
                            #id.mbor_len(acc);
                            azihsm_fw_ddi_mbor::MborByteSlice(&self.#name).mbor_len(acc);
                        }
                    }
                    DdiStructFieldKind::Slice => {
                        if f.len.is_some() {
                            // Fixed-size, no padding
                            quote! {
                                #id.mbor_len(acc);
                                azihsm_fw_ddi_mbor::MborByteSlice(self.#name).mbor_len(acc);
                            }
                        } else {
                            // Variable-size, padded
                            quote! {
                                #id.mbor_len(acc);
                                let pad = azihsm_fw_ddi_mbor::pad4(acc.len() as u32 + 3);
                                azihsm_fw_ddi_mbor::MborPaddedByteSlice(self.#name, pad as u8).mbor_len(acc);
                            }
                        }
                    }
                    DdiStructFieldKind::Normal => {
                        quote! {
                            #id.mbor_len(acc);
                            self.#name.mbor_len(acc);
                        }
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<#(#lifetimes,)*> azihsm_fw_ddi_mbor::MborLen for #ident<#(#lifetimes,)*> {
            fn mbor_len(&self, acc: &mut azihsm_fw_ddi_mbor::MborLenAccumulator) {
                let mut cnt = #field_cnt as azihsm_fw_ddi_mbor::MborId;
                #(#enc_cnt)*
                azihsm_fw_ddi_mbor::MborMap(cnt).mbor_len(acc);
                #(#lens)*
            }
        }
    })
}

pub(crate) fn open_enum_len(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl azihsm_fw_ddi_mbor::MborLen for #ident {
            fn mbor_len(&self, acc: &mut azihsm_fw_ddi_mbor::MborLenAccumulator) {
                self.0.mbor_len(acc);
            }
        }
    })
}

// Copyright (c) Microsoft Corporation. All rights reserved.

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
                                MborByteSlice(value).mbor_len(acc);
                            }
                        }
                    }
                    DdiStructFieldKind::MborArray => {
                        quote! {
                            if let Some(value) = &self.#name {
                                #id.mbor_len(acc);
                                let pad = mcr_ddi_mbor::pad4(acc.len() as u32 + 3);
                                #[cfg(test)]
                                assert_eq!((acc.len() + 3 + pad as usize) % 4, 0);
                                MborPaddedByteArray(value, pad as u8).mbor_len(acc);
                            }
                        }
                    }
                    _ => quote! {
                        if let Some(value) = &self.#name {
                            #id.mbor_len(acc);
                            value.mbor_len(acc);
                        }
                    },
                }
            } else {
                match f.kind {
                    DdiStructFieldKind::Array => {
                        quote! {
                            #id.mbor_len(acc);
                            MborByteSlice(&self.#name).mbor_len(acc);
                        }
                    }
                    DdiStructFieldKind::MborArray => {
                        quote! {
                            #id.mbor_len(acc);
                            let pad = mcr_ddi_mbor::pad4(acc.len() as u32 + 3);
                            #[cfg(test)]
                            assert_eq!((acc.len() + 3 + pad as usize) % 4, 0);
                            MborPaddedByteArray(&self.#name, pad as u8).mbor_len(acc);
                        }
                    }
                    _ => quote! {
                        #id.mbor_len(acc);
                        self.#name.mbor_len(acc);
                    },
                }
            }
        })
        .collect::<Vec<_>>();

    Ok(quote! {
        impl<#(#lifetimes,)*> mcr_ddi_mbor::MborLen for #ident<#(#lifetimes,)*> {
            fn mbor_len(&self, acc: &mut mcr_ddi_mbor::MborLenAccumulator) {
                let mut cnt = #field_cnt as MborId;
                #(#enc_cnt)*
                MborMap(cnt).mbor_len(acc);
                #(#lens)*
            }
        }
    })
}

pub(crate) fn open_enum_len(ddi: &DdiOpenEnum) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &ddi.ident;

    Ok(quote! {
        impl mcr_ddi_mbor::MborLen for #ident {
            fn mbor_len(&self, acc: &mut mcr_ddi_mbor::MborLenAccumulator) {
                self.0.mbor_len(acc);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use mcr_ddi_mbor::*;
    use rand::Rng;

    #[test]
    fn test_mbor_uint_len() {
        let mut rng = rand::thread_rng();

        let mut acc = MborLenAccumulator::default();
        rng.gen::<u8>().mbor_len(&mut acc);
        assert_eq!(2, acc.len());

        let mut acc = MborLenAccumulator::default();
        rng.gen::<u16>().mbor_len(&mut acc);
        assert_eq!(3, acc.len());

        let mut acc = MborLenAccumulator::default();
        rng.gen::<u32>().mbor_len(&mut acc);
        assert_eq!(5, acc.len());
    }
    #[test]
    fn test_mbor_bool_len() {
        let mut acc = MborLenAccumulator::default();
        true.mbor_len(&mut acc);
        assert_eq!(1, acc.len());

        let mut acc = MborLenAccumulator::default();
        false.mbor_len(&mut acc);
        assert_eq!(1, acc.len());
    }
    #[test]
    fn test_mbor_map_len() {
        let mut acc = MborLenAccumulator::default();
        MborMap(0).mbor_len(&mut acc);
        assert_eq!(1, acc.len());
    }
    #[test]
    fn test_mbor_slice_len() {
        let mut rng = rand::thread_rng();
        let data = &vec![rng.gen(); rng.gen_range(0..u16::MAX) as usize];
        let slice = MborByteSlice(data);
        let mut acc = MborLenAccumulator::default();
        slice.mbor_len(&mut acc);
        assert_eq!(1 + 2 + data.len(), acc.len());
    }
}

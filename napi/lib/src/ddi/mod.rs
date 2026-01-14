// Copyright (C) Microsoft Corporation. All rights reserved.

mod aes;
mod dev;
mod ecc;
mod hkdf;
mod key;
mod partition;
mod rsa;
mod session;

pub(crate) use aes::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor::*;
use azihsm_ddi_types::*;
pub(crate) use dev::*;
pub(crate) use ecc::*;
pub(crate) use hkdf::*;
pub(crate) use key::*;
pub(crate) use partition::*;
pub(crate) use rsa::*;
pub(crate) use session::*;

use super::*;

pub(crate) type HsmKeyHandle = u16;

impl TryFrom<&HsmKeyProps> for DdiTargetKeyProperties {
    type Error = HsmError;
    fn try_from(props: &HsmKeyProps) -> Result<Self, Self::Error> {
        Ok(Self {
            key_metadata: props.flags().into(),
            key_label: MborByteArray::from_slice(props.label())
                .map_hsm_err(HsmError::InternalError)?,
        })
    }
}

impl From<HsmKeyFlags> for DdiTargetKeyMetadata {
    fn from(flags: HsmKeyFlags) -> Self {
        let mut meta = Self::default()
            .with_session(flags.is_session())
            .with_modifiable(flags.is_modifiable())
            .with_wrap(flags.can_wrap())
            .with_unwrap(flags.can_unwrap())
            .with_derive(flags.can_derive())
            .with_sign(flags.can_sign())
            .with_verify(flags.can_verify())
            .with_encrypt(flags.can_encrypt())
            .with_decrypt(flags.can_decrypt());

        if meta.encrypt() || meta.decrypt() {
            meta.set_encrypt(true);
            meta.set_decrypt(true);
        }

        if meta.sign() || meta.verify() {
            meta.set_sign(true);
            meta.set_verify(true);
        }

        if meta.wrap() || meta.unwrap() {
            meta.set_wrap(true);
            meta.set_unwrap(true);
        }

        meta
    }
}

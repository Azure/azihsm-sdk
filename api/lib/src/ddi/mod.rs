// Copyright (C) Microsoft Corporation. All rights reserved.

mod aes;
mod aes_xts_key;
mod dev;
mod ecc;
mod hkdf;
mod hmac;
mod key;
mod masked_key;
mod partition;
mod rsa;
mod session;

pub(crate) use aes::*;
pub(crate) use aes_xts_key::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor::*;
use azihsm_ddi_types::*;
pub(crate) use dev::*;
pub(crate) use ecc::*;
pub(crate) use hkdf::*;
pub(crate) use hmac::*;
pub(crate) use key::*;
pub(crate) use masked_key::*;
pub(crate) use partition::*;
pub(crate) use rsa::*;
pub(crate) use session::*;

use super::*;

pub(crate) type HsmKeyHandle = u16;

/// Builds a DDI request header with optional session ID and API revision.
///
/// Creates a `DdiReqHdr` for various types of DDI operations:
/// - Device-level operations: neither `rev` nor `sess_id` (e.g., `GetApiRev`)
/// - Session-less operations: `rev` only (e.g., `OpenSession`, `GetSessionEncryptionKey`)
/// - Operations with explicit session: both `rev` and `sess_id` (e.g., `CloseSession`)
///
/// # Arguments
///
/// * `op` - The DDI operation to include in the header
/// * `rev` - Optional API revision to use
/// * `sess_id` - Optional session ID to include
///
/// # Returns
///
/// A `DdiReqHdr` configured for the specified operation and parameters.
pub(crate) fn build_ddi_req_hdr(
    op: DdiOp,
    rev: Option<HsmApiRev>,
    sess_id: Option<u16>,
) -> DdiReqHdr {
    DdiReqHdr {
        op,
        rev: rev.map(|r| r.into()),
        sess_id,
    }
}

/// Builds a DDI request header using the provided session.
///
/// # Arguments
///
/// * `op` - The DDI operation to include in the header
/// * `sess` - The HSM session context
///
/// # Returns
///
/// A `DdiReqHdr` configured for the specified operation and session.
pub(crate) fn build_ddi_req_hdr_sess(op: DdiOp, sess: &HsmSession) -> DdiReqHdr {
    build_ddi_req_hdr(op, Some(sess.api_rev()), Some(sess.id()))
}

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

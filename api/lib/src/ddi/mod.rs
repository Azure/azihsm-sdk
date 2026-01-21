// Copyright (C) Microsoft Corporation. All rights reserved.

mod aes;
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

/// Builds a DDI request header for session-less operations.
///
/// Creates a `DdiReqHdr` for operations that don't require an active session,
/// such as `OpenSession` and `GetSessionEncryptionKey`.
///
/// # Arguments
///
/// * `op` - The DDI operation to include in the header
/// * `rev` - The API revision to use
///
/// # Returns
///
/// A `DdiReqHdr` configured for the specified operation and API revision.
pub(crate) fn build_ddi_req_hdr_sessionless(op: DdiOp, rev: HsmApiRev) -> DdiReqHdr {
    DdiReqHdr {
        op,
        rev: Some(rev.into()),
        sess_id: None,
    }
}

/// Builds a DDI request header with explicit session ID and API revision.
///
/// Creates a `DdiReqHdr` for operations that need to specify a session ID
/// but don't have a session object available, such as `CloseSession`.
///
/// # Arguments
///
/// * `op` - The DDI operation to include in the header
/// * `sess_id` - The session ID to include
/// * `rev` - The API revision to use
///
/// # Returns
///
/// A `DdiReqHdr` configured for the specified operation, session ID, and API revision.
pub(crate) fn build_ddi_req_hdr_with_session_id(
    op: DdiOp,
    sess_id: u16,
    rev: HsmApiRev,
) -> DdiReqHdr {
    DdiReqHdr {
        op,
        rev: Some(rev.into()),
        sess_id: Some(sess_id),
    }
}

/// Builds a DDI request header for device-level operations.
///
/// Creates a `DdiReqHdr` for operations that don't require a session or API revision,
/// such as `GetApiRev`.
///
/// # Arguments
///
/// * `op` - The DDI operation to include in the header
///
/// # Returns
///
/// A `DdiReqHdr` configured for the specified device operation.
pub(crate) fn build_ddi_req_hdr_device(op: DdiOp) -> DdiReqHdr {
    DdiReqHdr {
        op,
        rev: None,
        sess_id: None,
    }
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

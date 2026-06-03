// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-key import path of [`RsaUnwrap`](super::rsa_unwrap).
//!
//! Stores a raw 16 / 24 / 32-byte AES key (recovered by the
//! caller from the OAEP + KWP unwrap) into the partition vault
//! and returns the vault guard + the response payload the parent
//! handler will encode.  Any other byte length is a host contract
//! violation.

use azihsm_fw_ddi_mbor_types::rsa_unwrap::DdiRsaUnwrapReq;
use azihsm_fw_ddi_mbor_types::rsa_unwrap::DdiRsaUnwrapResp;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::super::*;

pub(super) fn import<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    sess_id: u16,
    body: &DdiRsaUnwrapReq<'_>,
    key_bytes: &DmaBuf,
) -> HsmResult<(<P as HsmVault>::KeyGuard<'p>, DdiRsaUnwrapResp<'p>)> {
    let (vault_kind, key_kind) = match key_bytes.len() {
        16 => (HsmVaultKeyKind::Aes128, DdiKeyType::Aes128),
        24 => (HsmVaultKeyKind::Aes192, DdiKeyType::Aes192),
        32 => (HsmVaultKeyKind::Aes256, DdiKeyType::Aes256),
        _ => return Err(HsmError::InvalidArg),
    };

    let attrs = super::super::key_attrs::prepare_aes(
        &body.key_properties.key_metadata,
        body.key_tag,
        /* local = */ false,
    )?;

    let session_binding = attrs.session().then_some(HsmSessId::from(sess_id));
    let guard = pal.vault_key_create(
        io,
        key_bytes,
        vault_kind,
        session_binding,
        attrs,
        body.key_properties.key_label,
    )?;
    let key_id: u16 = guard.key_id().into();

    // Symmetric AES import — no `pub_key`, no `bulk_key_id`, empty
    // `masked_key` placeholder.
    let resp = DdiRsaUnwrapResp {
        key_id,
        pub_key: None,
        bulk_key_id: None,
        kind: key_kind,
        masked_key: &[],
    };
    Ok((guard, resp))
}
